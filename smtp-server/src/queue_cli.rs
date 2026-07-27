//! Queue inspection and migration CLI (`hedwig queue …`, docs/plans/2026-07-20-durable-log-queue.md §25
//! "Operator tooling" and §23 "Migration from the current filesystem
//! spool").
//!
//! `list`/`show`/`stats` must be side-effect free against the spool: no
//! locks, no journal truncation, no file or directory creation. They
//! deliberately do not use [`crate::logqueue::spool::Spool`] (exclusive
//! lock, creates `format-version`/shard directories) or
//! [`crate::logqueue::shard::ShardDir`] (creates the shard directory);
//! shard directories are enumerated directly instead.
//!
//! They re-implement, in a read-only form, just enough of the log-queue's
//! discovery logic (see `logqueue::dispatcher::discover_shard`): recover
//! checkpoint + journal state via
//! [`crate::logqueue::state::load_state_readonly`], then scan payload
//! segments from the recovered cursor onward for messages a checkpoint
//! hasn't folded in yet.
//!
//! `migrate` is the one subcommand here that WRITES: it takes the exclusive
//! spool lock and moves live messages out of the legacy filesystem spool.
//! See [`crate::migrate`] for its implementation.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use clap::{Args, Subcommand};
use miette::{bail, IntoDiagnostic, Result, WrapErr};

use crate::logqueue::record::{self, RecordHeader};
use crate::logqueue::segment::{self, open_segment_reader, scan_headers, SegmentKind};
use crate::logqueue::state::{self, RecoveredState};
use crate::logqueue::{JobLocation, MessageId, QueueError, FORMAT_VERSION};

const FORMAT_VERSION_FILE: &str = "format-version";

#[derive(Args)]
pub struct QueueArgs {
    #[command(subcommand)]
    command: QueueCommand,
}

#[derive(Subcommand)]
enum QueueCommand {
    /// List live (ready/deferred) messages across all shards
    List(ListArgs),
    /// Show one message's envelope, state, and location
    Show(ShowArgs),
    /// Show per-shard and per-segment storage statistics
    Stats(StatsArgs),
    /// One-time migration from the legacy filesystem spool to the log queue
    /// (docs/plans/2026-07-20-durable-log-queue.md §23). WRITES to the spool; stop the server first.
    Migrate(MigrateArgs),
}

#[derive(Args)]
struct ListArgs {
    /// Log-queue spool root (contains shard-NNNN directories)
    #[arg(long)]
    spool: PathBuf,
    /// Only show ready messages
    #[arg(long, conflicts_with = "deferred")]
    ready: bool,
    /// Only show deferred messages
    #[arg(long, conflicts_with = "ready")]
    deferred: bool,
}

#[derive(Args)]
struct ShowArgs {
    /// Log-queue spool root (contains shard-NNNN directories)
    #[arg(long)]
    spool: PathBuf,
    /// Message ID (ULID string)
    message_id: String,
}

#[derive(Args)]
struct StatsArgs {
    /// Log-queue spool root (contains shard-NNNN directories)
    #[arg(long)]
    spool: PathBuf,
}

#[derive(Args)]
struct MigrateArgs {
    /// Path to the hedwig config file. Must already have
    /// storage.storage_type = "log" — switch the config first, then run
    /// this migration; the server (and any other process using this spool)
    /// must be stopped.
    #[arg(long)]
    config: String,
}

pub async fn run(args: QueueArgs) -> Result<()> {
    match args.command {
        QueueCommand::List(a) => cmd_list(a),
        QueueCommand::Show(a) => cmd_show(a),
        QueueCommand::Stats(a) => cmd_stats(a),
        QueueCommand::Migrate(a) => cmd_migrate(a).await,
    }
}

// ---------------------------------------------------------------------------
// `queue migrate` — the only subcommand here that writes to the spool.

async fn cmd_migrate(args: MigrateArgs) -> Result<()> {
    let cfg = crate::config::Cfg::load(&args.config).wrap_err("error loading configuration")?;

    if cfg.storage.storage_type != "log" {
        bail!(
            "queue migrate requires storage.storage_type = \"log\" in {}, found {:?}; \
             switch the config to the log backend first, then run this migration",
            args.config,
            cfg.storage.storage_type
        );
    }

    println!(
        "Migrating legacy filesystem spool at {} to the log queue.",
        cfg.storage.base_path
    );
    println!(
        "IMPORTANT: the hedwig server (or any other process using this spool) must be \
         stopped before running this command — there is no lock on the legacy spool."
    );

    let legacy_base_path = camino::Utf8PathBuf::from(cfg.storage.base_path.clone());
    let spool_root = std::path::Path::new(&cfg.storage.base_path).join("spool");

    let qcfg = cfg.queue();
    let max_message_size = cfg.server.max_message_size.unwrap_or(25 * 1024 * 1024);
    qcfg.validate(max_message_size)
        .wrap_err("invalid [queue] configuration")?;
    let max_record_len = (max_message_size as u64
        + crate::logqueue::spool::ENVELOPE_ALLOWANCE
        + crate::logqueue::record::FIXED_HEADER_LEN as u64) as u32;
    let writer_config = crate::logqueue::writer::WriterConfig {
        segment_target_bytes: qcfg.segment_target_bytes(),
        max_record_len,
        pending_append_bytes: qcfg.pending_append_bytes(),
    };

    let summary = crate::migrate::migrate(&legacy_base_path, &spool_root, qcfg.append_writers(), writer_config)
        .await?;

    summary.print();

    if !summary.failed.is_empty() {
        bail!(
            "migration completed with {} failed message(s) (see above); the legacy spool \
             was left in place — safe to re-run this command after investigating",
            summary.failed.len()
        );
    }

    println!("migration complete.");
    Ok(())
}

// ---------------------------------------------------------------------------
// Spool/shard enumeration (read-only: no Spool::open, no ShardDir).

fn check_format_version(spool_root: &Path) -> Result<()> {
    let path = spool_root.join(FORMAT_VERSION_FILE);
    let contents = std::fs::read_to_string(&path).into_diagnostic().wrap_err_with(|| {
        format!(
            "could not read {}; is {} a hedwig log-queue spool root?",
            path.display(),
            spool_root.display()
        )
    })?;
    let found: u16 = contents.trim().parse().into_diagnostic().wrap_err_with(|| {
        format!(
            "{} does not contain a version number: {contents:?}",
            path.display()
        )
    })?;
    if found != FORMAT_VERSION {
        bail!(
            "spool at {} has format version {found}, this build of hedwig supports {FORMAT_VERSION}",
            spool_root.display()
        );
    }
    Ok(())
}

fn parse_shard_dir_name(name: &str) -> Option<u16> {
    let digits = name.strip_prefix("shard-")?;
    if digits.len() != 4 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// Enumerate `shard-NNNN` directories directly under the spool root, sorted
/// by shard number. Never creates anything.
fn list_shard_dirs(spool_root: &Path) -> Result<Vec<(u16, PathBuf)>> {
    let mut shards = Vec::new();
    let entries = std::fs::read_dir(spool_root)
        .into_diagnostic()
        .wrap_err_with(|| format!("could not read spool root {}", spool_root.display()))?;
    for entry in entries {
        let entry = entry.into_diagnostic()?;
        if !entry.file_type().into_diagnostic()?.is_dir() {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if let Some(shard) = parse_shard_dir_name(&name) {
            shards.push((shard, entry.path()));
        }
    }
    shards.sort_unstable_by_key(|(shard, _)| *shard);
    Ok(shards)
}

/// A segment file present on disk right now, as seen by a point-in-time
/// directory listing.
#[derive(Debug, Clone)]
struct SegmentFile {
    ordinal: u64,
    kind: SegmentKind,
    len: u64,
}

/// List segment files directly (no `ShardDir`, which creates the directory
/// if missing). Sorted by ordinal; a shard has at most one active segment,
/// which — being the newest — sorts last.
fn list_segment_files(shard_dir: &Path) -> Result<Vec<SegmentFile>, QueueError> {
    let mut out = Vec::new();
    let entries = match std::fs::read_dir(shard_dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(QueueError::io(shard_dir, e)),
    };
    for entry in entries {
        let entry = entry.map_err(|e| QueueError::io(shard_dir, e))?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Some((ordinal, kind)) = segment::parse_file_name(&name) else {
            continue;
        };
        let len = entry.metadata().map_err(|e| QueueError::io(shard_dir, e))?.len();
        out.push(SegmentFile { ordinal, kind, len });
    }
    out.sort_unstable_by_key(|s| s.ordinal);
    Ok(out)
}

// ---------------------------------------------------------------------------
// Read-only discovery: checkpoint/journal state + a scan for messages not
// yet folded into a checkpoint.

/// A message found only by scanning past the recovered cursor: not yet
/// known to any checkpoint or journal entry.
#[derive(Debug, Clone, Copy)]
struct ScannedReady {
    location: JobLocation,
    enqueue_ms: i64,
}

struct ShardData {
    shard: u16,
    dir: PathBuf,
    state: RecoveredState,
    segments: Vec<SegmentFile>,
    /// Live messages discovered by scanning segments past `state.cursor`,
    /// keyed by message id.
    scanned: HashMap<MessageId, ScannedReady>,
}

/// Load one shard's read-only snapshot: recovered checkpoint/journal state,
/// the segment files present on disk, and anything a scan from the
/// checkpoint's cursor finds that the checkpoint doesn't know about yet.
fn load_shard(shard: u16, dir: PathBuf) -> Result<ShardData, QueueError> {
    let state = state::load_state_readonly(&dir)?;
    let segments = list_segment_files(&dir)?;
    let scanned = scan_undiscovered(shard, &dir, &state, &segments);
    Ok(ShardData {
        shard,
        dir,
        state,
        segments,
        scanned,
    })
}

/// Walk sealed+active segments in ordinal order from the recovered cursor to
/// each segment's end, skipping records already known (checkpointed ready
/// or deferred) or tombstoned in that segment. Best-effort: a corrupt or
/// torn record stops the scan of that segment (logged to stderr) without
/// failing the whole command — an active segment's tail is routinely torn
/// mid-append on a live spool, and this tool must keep working against one.
fn scan_undiscovered(
    shard: u16,
    dir: &Path,
    state: &RecoveredState,
    segments: &[SegmentFile],
) -> HashMap<MessageId, ScannedReady> {
    let mut found = HashMap::new();
    let (start_segment, start_offset) = match state.cursor {
        Some(cursor) => cursor,
        None => match segments.first() {
            Some(first) => (first.ordinal, 0),
            None => return found,
        },
    };
    let max_record_len = record::MAX_RECORD_LEN;

    for seg in segments {
        if seg.ordinal < start_segment {
            continue;
        }
        let start = if seg.ordinal == start_segment {
            start_offset
        } else {
            0
        };
        if start >= seg.len {
            continue;
        }
        let reader = match open_segment_reader(dir, seg.ordinal) {
            Ok(r) => r,
            Err(e) => {
                eprintln!(
                    "warning: shard {shard} segment {}: could not open for scanning: {e}",
                    seg.ordinal
                );
                continue;
            }
        };
        let ordinal = seg.ordinal;
        let result = scan_headers(&reader, start, seg.len, max_record_len, |offset, header| {
            if record_undiscovered(state, &found, ordinal, &header) {
                found.insert(
                    header.message_id,
                    ScannedReady {
                        location: JobLocation {
                            shard,
                            segment: ordinal,
                            offset,
                            length: header.record_len,
                            ordinal: header.ordinal,
                            generation: header.generation,
                        },
                        enqueue_ms: header.enqueue_ms,
                    },
                );
            }
            true
        });
        if let Err(e) = result {
            eprintln!(
                "warning: shard {shard} segment {}: stopped scan early at a corrupt or torn record: {e}",
                seg.ordinal
            );
        }
    }
    found
}

/// Whether `header` is not yet known: not checkpointed (ready or deferred),
/// not already scanned this pass, and not tombstoned in its own segment.
fn record_undiscovered(
    state: &RecoveredState,
    found: &HashMap<MessageId, ScannedReady>,
    segment: u64,
    header: &RecordHeader,
) -> bool {
    !state.is_terminal(segment, &header.message_id)
        && !state.ready.contains_key(&header.message_id)
        && !state.deferred.contains_key(&header.message_id)
        && !found.contains_key(&header.message_id)
}

// ---------------------------------------------------------------------------
// Unified live-message view shared by `list` and `stats`.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MsgState {
    Ready,
    Deferred,
}

impl MsgState {
    fn as_str(self) -> &'static str {
        match self {
            MsgState::Ready => "ready",
            MsgState::Deferred => "deferred",
        }
    }
}

struct LiveMessage {
    id: MessageId,
    shard: u16,
    location: JobLocation,
    state: MsgState,
    /// `None` when a checkpointed deferred entry doesn't carry the original
    /// enqueue time.
    enqueue_ms: Option<i64>,
    attempts: u32,
    next_attempt_ms: Option<i64>,
}

fn shard_live_messages(shard: &ShardData) -> Vec<LiveMessage> {
    let mut out = Vec::with_capacity(shard.state.ready.len() + shard.state.deferred.len() + shard.scanned.len());
    for r in shard.state.ready.values() {
        out.push(LiveMessage {
            id: r.id,
            shard: shard.shard,
            location: r.location,
            state: MsgState::Ready,
            enqueue_ms: Some(r.enqueue_ms),
            attempts: r.attempts,
            next_attempt_ms: None,
        });
    }
    for d in shard.state.deferred.values() {
        out.push(LiveMessage {
            id: d.id,
            shard: shard.shard,
            location: d.location,
            state: MsgState::Deferred,
            enqueue_ms: None,
            attempts: d.attempts,
            next_attempt_ms: Some(d.next_attempt_ms),
        });
    }
    for (id, s) in &shard.scanned {
        out.push(LiveMessage {
            id: *id,
            shard: shard.shard,
            location: s.location,
            state: MsgState::Ready,
            enqueue_ms: Some(s.enqueue_ms),
            attempts: 0,
            next_attempt_ms: None,
        });
    }
    out
}

// ---------------------------------------------------------------------------
// `queue list`

fn cmd_list(args: ListArgs) -> Result<()> {
    check_format_version(&args.spool)?;
    let shard_dirs = list_shard_dirs(&args.spool)?;

    let mut messages = Vec::new();
    for (shard, dir) in shard_dirs {
        let data = load_shard(shard, dir)
            .into_diagnostic()
            .wrap_err_with(|| format!("loading shard {shard}"))?;
        messages.extend(shard_live_messages(&data));
    }

    if args.ready {
        messages.retain(|m| m.state == MsgState::Ready);
    } else if args.deferred {
        messages.retain(|m| m.state == MsgState::Deferred);
    }

    let now = now_ms();
    // Age descending (oldest first). Messages with an unknown enqueue time
    // (a checkpointed deferred entry) sort after every message with a known
    // age, ordered by id for determinism.
    messages.sort_unstable_by(|a, b| match (a.enqueue_ms, b.enqueue_ms) {
        (Some(a_ms), Some(b_ms)) => (now - a_ms).cmp(&(now - b_ms)).reverse(),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => a.id.cmp(&b.id),
    });

    if messages.is_empty() {
        println!("no live messages in {}", args.spool.display());
        return Ok(());
    }

    let rows: Vec<[String; 7]> = messages
        .iter()
        .map(|m| {
            [
                m.id.to_string(),
                m.state.as_str().to_string(),
                m.enqueue_ms.map_or_else(|| "-".to_string(), |ms| humanize_age(now - ms)),
                m.attempts.to_string(),
                m.next_attempt_ms.map_or_else(|| "-".to_string(), format_iso8601),
                m.shard.to_string(),
                m.location.segment.to_string(),
            ]
        })
        .collect();
    print_table(
        &["MESSAGE ID", "STATE", "AGE", "ATTEMPTS", "NEXT-ATTEMPT (UTC)", "SHARD", "SEGMENT"],
        &rows,
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// `queue show`

fn cmd_show(args: ShowArgs) -> Result<()> {
    check_format_version(&args.spool)?;
    let target = MessageId::parse(&args.message_id).into_diagnostic()?;
    let shard_dirs = list_shard_dirs(&args.spool)?;

    for (shard, dir) in shard_dirs {
        let data = load_shard(shard, dir)
            .into_diagnostic()
            .wrap_err_with(|| format!("loading shard {shard}"))?;

        let found = if let Some(r) = data.state.ready.get(&target) {
            Some((r.location, MsgState::Ready, r.attempts, None, None, None))
        } else if let Some(d) = data.state.deferred.get(&target) {
            Some((
                d.location,
                MsgState::Deferred,
                d.attempts,
                Some(d.next_attempt_ms),
                Some(&d.remaining_recipients),
                Some(d.last_error.as_str()),
            ))
        } else {
            data.scanned
                .get(&target)
                .map(|s| (s.location, MsgState::Ready, 0, None, None, None))
        };

        let Some((location, state, attempts, next_attempt_ms, remaining, last_error)) = found else {
            continue;
        };

        let reader = open_segment_reader(&data.dir, location.segment)
            .into_diagnostic()
            .wrap_err("opening segment to read the message envelope")?;
        let header = reader
            .read_header_at(location.offset, record::MAX_RECORD_LEN)
            .into_diagnostic()
            .wrap_err("reading payload record header")?;

        println!("id:                {}", target);
        println!("state:              {}", state.as_str());
        println!("sender:             {}", header.sender);
        println!("recipients:         {}", header.recipients.join(", "));
        if let Some(remaining) = remaining {
            println!("remaining:          {}", remaining.join(", "));
        }
        println!("attempts:           {attempts}");
        if let Some(last_error) = last_error {
            println!("last error:         {last_error}");
        }
        if let Some(next_attempt_ms) = next_attempt_ms {
            println!("next attempt (UTC): {}", format_iso8601(next_attempt_ms));
        }
        println!("enqueued (UTC):     {}", format_iso8601(header.enqueue_ms));
        println!(
            "location:           shard={} segment={} offset={} length={} generation={}",
            location.shard, location.segment, location.offset, location.length, location.generation
        );
        println!("body size:          {} bytes", header.body_len());
        return Ok(());
    }

    bail!(
        "message {} not found in spool {}",
        args.message_id,
        args.spool.display()
    );
}

// ---------------------------------------------------------------------------
// `queue stats`

fn cmd_stats(args: StatsArgs) -> Result<()> {
    check_format_version(&args.spool)?;
    let shard_dirs = list_shard_dirs(&args.spool)?;

    let mut grand_total_bytes = 0u64;
    let mut grand_dead_bytes = 0u64;
    let mut grand_ready = 0usize;
    let mut grand_deferred = 0usize;

    for (shard, dir) in shard_dirs {
        let data = load_shard(shard, dir)
            .into_diagnostic()
            .wrap_err_with(|| format!("loading shard {shard}"))?;

        println!("shard {:04}:", shard);
        if data.segments.is_empty() {
            println!("  (no segments)");
        }
        let mut shard_total_bytes = 0u64;
        let mut shard_dead_bytes = 0u64;
        let rows: Vec<[String; 5]> = data
            .segments
            .iter()
            .map(|seg| {
                let file_kind = match seg.kind {
                    SegmentKind::Sealed => "sealed",
                    SegmentKind::Active => "active",
                };
                let dead_bytes = data
                    .state
                    .segment_stats
                    .get(&seg.ordinal)
                    .map(|s| s.dead_bytes)
                    .unwrap_or(0);
                let tombstones = data
                    .state
                    .tombstones
                    .get(&seg.ordinal)
                    .map(|s| s.len())
                    .unwrap_or(0);
                let ratio = if seg.len > 0 {
                    dead_bytes as f64 / seg.len as f64
                } else {
                    0.0
                };
                shard_total_bytes += seg.len;
                shard_dead_bytes += dead_bytes;
                [
                    format!("{:012} ({file_kind})", seg.ordinal),
                    seg.len.to_string(),
                    dead_bytes.to_string(),
                    format!("{:.1}%", ratio * 100.0),
                    tombstones.to_string(),
                ]
            })
            .collect();
        if !rows.is_empty() {
            print_table(
                &["SEGMENT", "TOTAL BYTES", "DEAD BYTES", "DEAD RATIO", "TOMBSTONES"],
                &rows,
            );
        }

        let live = shard_live_messages(&data);
        let shard_ready = live.iter().filter(|m| m.state == MsgState::Ready).count();
        let shard_deferred = live.iter().filter(|m| m.state == MsgState::Deferred).count();
        println!(
            "  shard totals: {shard_total_bytes} bytes, {shard_dead_bytes} dead, {shard_ready} ready, {shard_deferred} deferred"
        );
        println!();

        grand_total_bytes += shard_total_bytes;
        grand_dead_bytes += shard_dead_bytes;
        grand_ready += shard_ready;
        grand_deferred += shard_deferred;
    }

    let grand_ratio = if grand_total_bytes > 0 {
        grand_dead_bytes as f64 / grand_total_bytes as f64
    } else {
        0.0
    };
    println!(
        "grand totals: {grand_total_bytes} bytes, {grand_dead_bytes} dead ({:.1}%), {grand_ready} ready, {grand_deferred} deferred",
        grand_ratio * 100.0
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Formatting helpers.

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

fn format_iso8601(ms: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp_millis(ms)
        .map(|dt| dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        .unwrap_or_else(|| format!("invalid-timestamp({ms})"))
}

/// Rough humanized duration, e.g. "3m12s", "1h4m", "2d3h", "45s".
fn humanize_age(age_ms: i64) -> String {
    let secs = (age_ms.max(0)) / 1000;
    let days = secs / 86_400;
    let hours = (secs % 86_400) / 3600;
    let minutes = (secs % 3600) / 60;
    let seconds = secs % 60;
    if days > 0 {
        format!("{days}d{hours}h")
    } else if hours > 0 {
        format!("{hours}h{minutes}m")
    } else if minutes > 0 {
        format!("{minutes}m{seconds}s")
    } else {
        format!("{seconds}s")
    }
}

/// Print a plain-text table with column padding; no extra dependencies.
fn print_table<const N: usize>(header: &[&str; N], rows: &[[String; N]]) {
    let mut widths: [usize; N] = std::array::from_fn(|i| header[i].len());
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            widths[i] = widths[i].max(cell.len());
        }
    }
    let print_row = |cells: &[&str]| {
        let line: Vec<String> = cells
            .iter()
            .enumerate()
            .map(|(i, cell)| format!("{:<width$}", cell, width = widths[i]))
            .collect();
        println!("{}", line.join("  ").trim_end());
    };
    print_row(header);
    for row in rows {
        let cells: Vec<&str> = row.iter().map(String::as_str).collect();
        print_row(&cells);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logqueue::spool::Spool;
    use crate::logqueue::state::{Checkpoint, ReadyJob, ShardStateStore, StateEntry};
    use crate::logqueue::writer::{AppendMessage, LogWriters, WriterConfig};
    use bytes::Bytes;

    fn writer_config() -> WriterConfig {
        WriterConfig {
            segment_target_bytes: 64 * 1024 * 1024,
            max_record_len: record::MAX_RECORD_LEN,
            pending_append_bytes: 16 * 1024 * 1024,
        }
    }

    fn message(seq: u64, enqueue_ms: i64, rcpt: &str) -> AppendMessage {
        AppendMessage {
            message_id: MessageId::from_ulid(ulid::Ulid::from_parts(seq, (seq * 7 + 1) as u128)),
            enqueue_ms,
            generation: 0,
            sender: "sender@example.com".into(),
            recipients: vec![rcpt.into()],
            body: Bytes::from(format!("body {seq}")),
        }
    }

    #[test]
    fn humanize_age_formats() {
        assert_eq!(humanize_age(45_000), "45s");
        assert_eq!(humanize_age(3 * 60_000 + 12_000), "3m12s");
        assert_eq!(humanize_age(60 * 60_000 + 4 * 60_000), "1h4m");
        assert_eq!(humanize_age(2 * 86_400_000 + 3 * 3_600_000), "2d3h");
    }

    #[test]
    fn shard_dir_name_parses_only_well_formed_names() {
        assert_eq!(parse_shard_dir_name("shard-0000"), Some(0));
        assert_eq!(parse_shard_dir_name("shard-0042"), Some(42));
        assert_eq!(parse_shard_dir_name("shard-42"), None);
        assert_eq!(parse_shard_dir_name("shard-abcd"), None);
        assert_eq!(parse_shard_dir_name("checkpoint"), None);
    }

    #[tokio::test]
    async fn list_logic_finds_checkpointed_and_scanned_messages() {
        let dir = tempfile::tempdir().unwrap();
        let spool = Spool::open(dir.path().join("spool"), 1).unwrap();
        let writers = LogWriters::start(&spool, writer_config()).unwrap();
        let handle = writers.handle();

        let base = 1_752_000_000_000i64;
        let m1 = message(1, base, "r1@example.com");
        let m1_id = m1.message_id;
        let loc1 = handle.append(m1).await.unwrap();

        let m2 = message(2, base + 1, "r2@example.com");
        let m2_id = m2.message_id;
        let loc2 = handle.append(m2).await.unwrap();

        let m3 = message(3, base + 2, "r3@example.com");
        let m3_id = m3.message_id;
        let _loc3 = handle.append(m3).await.unwrap();

        writers.shutdown().await;

        let shard_dir = spool.shard(0).path().to_path_buf();

        // Build a checkpoint that has already discovered m1 (as ready) and
        // whose cursor sits right after it — m2 and m3 are not yet
        // discovered by the checkpoint itself.
        {
            let (mut store, _) = ShardStateStore::recover(&shard_dir, 0).unwrap();
            let cp = Checkpoint {
                cursor: Some((loc1.segment, loc1.offset + loc1.length as u64)),
                ready: vec![ReadyJob {
                    id: m1_id,
                    location: loc1,
                    attempts: 0,
                    enqueue_ms: base,
                    remaining_recipients: vec![],
                }],
                ..Default::default()
            };
            store.write_checkpoint(&cp).unwrap();
            // m2 gets deferred via a journal entry on top of the checkpoint,
            // so it's "already known" even though the checkpoint's cursor
            // never passed it.
            store
                .append(&StateEntry::Deferred {
                    id: m2_id,
                    location: loc2,
                    attempts: 1,
                    next_attempt_ms: base + 60_000,
                    remaining_recipients: vec!["r2@example.com".into()],
                    last_error: "451 try later".into(),
                })
                .unwrap();
        }

        let data = load_shard(0, shard_dir).unwrap();

        // m1: known via the checkpoint's ready list.
        assert!(data.state.ready.contains_key(&m1_id));
        // m2: known via the journal (deferred), not by scanning.
        assert!(data.state.deferred.contains_key(&m2_id));
        assert!(!data.scanned.contains_key(&m2_id));
        // m3: undiscovered by any checkpoint/journal entry, found only by
        // scanning segments past the cursor.
        assert!(data.scanned.contains_key(&m3_id));
        assert_eq!(data.scanned[&m3_id].enqueue_ms, base + 2);

        let live = shard_live_messages(&data);
        assert_eq!(live.len(), 3);
        let live_by_id: HashMap<MessageId, &LiveMessage> =
            live.iter().map(|m| (m.id, m)).collect();
        assert_eq!(live_by_id[&m1_id].state, MsgState::Ready);
        assert_eq!(live_by_id[&m1_id].enqueue_ms, Some(base));
        assert_eq!(live_by_id[&m2_id].state, MsgState::Deferred);
        assert_eq!(live_by_id[&m2_id].attempts, 1);
        assert_eq!(live_by_id[&m3_id].state, MsgState::Ready);
        assert_eq!(live_by_id[&m3_id].enqueue_ms, Some(base + 2));
        assert_eq!(live_by_id[&m3_id].attempts, 0);
    }

    #[tokio::test]
    async fn scan_skips_tombstoned_records() {
        let dir = tempfile::tempdir().unwrap();
        let spool = Spool::open(dir.path().join("spool"), 1).unwrap();
        let writers = LogWriters::start(&spool, writer_config()).unwrap();
        let handle = writers.handle();

        let base = 1_752_000_000_000i64;
        let m1 = message(1, base, "r1@example.com");
        let m1_id = m1.message_id;
        let loc1 = handle.append(m1).await.unwrap();
        writers.shutdown().await;

        let shard_dir = spool.shard(0).path().to_path_buf();
        {
            let (mut store, _) = ShardStateStore::recover(&shard_dir, 0).unwrap();
            store
                .append(&StateEntry::Delivered {
                    id: m1_id,
                    location: loc1,
                    timestamp_ms: base + 1000,
                })
                .unwrap();
        }

        let data = load_shard(0, shard_dir).unwrap();
        assert!(data.state.is_terminal(loc1.segment, &m1_id));
        assert!(!data.scanned.contains_key(&m1_id), "tombstoned, not live");
        assert!(shard_live_messages(&data).is_empty());
    }

    #[test]
    fn empty_spool_root_has_no_shards() {
        let dir = tempfile::tempdir().unwrap();
        let spool = Spool::open(dir.path().join("spool"), 2).unwrap();
        drop(spool);
        let shards = list_shard_dirs(&dir.path().join("spool")).unwrap();
        assert_eq!(shards.len(), 2);
        for (shard, shard_dir) in shards {
            let data = load_shard(shard, shard_dir).unwrap();
            assert!(shard_live_messages(&data).is_empty());
        }
    }
}
