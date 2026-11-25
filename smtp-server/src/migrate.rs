//! One-time, restart-safe migration from the legacy filesystem spool to the
//! log queue (docs/plans/2026-07-20-durable-log-queue.md §23 "Migration from the current filesystem spool").
//!
//! Unlike `queue_cli`, this module WRITES to the new spool: it takes the
//! exclusive spool lock (refusing to run if another process — including a
//! live `hedwig` server on the log backend — already holds it), appends
//! every live legacy message to its shard, fsyncs destination segments,
//! state journals, and spool directories, verifies every migrated id and its
//! required retry state landed, and only then renames the legacy
//! `queued/`/`deferred/` directories to timestamped backups. Legacy data is
//! never deleted.
//!
//! There is no lock on the legacy filesystem spool itself, so the operator
//! must ensure no other process (in particular a `hedwig` server still
//! running against the old `fs` config) is mutating it while this runs.
//!
//! Restart-safety: re-running after a crash, interruption, or failed run is
//! safe. Already migrated ids are reconciled against actual payload records
//! and required deferred state: terminal messages and complete migrations are
//! skipped, while half-migrated deferred entries (payload without deferred
//! journal entry, or journal entry whose payload was torn) are repaired from
//! the legacy copy without duplicating payloads.

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use camino::{Utf8Path, Utf8PathBuf};
use chrono::Utc;
use miette::{bail, IntoDiagnostic, Result, WrapErr};
use tokio_util::sync::CancellationToken;

use crate::config::Cfg;
use crate::logqueue::record;
use crate::logqueue::segment::{open_segment_reader, scan_headers};
use crate::logqueue::spool::{sync_dir, Spool};
use crate::logqueue::state::{load_state_readonly, ShardStateStore, StateEntry};
use crate::logqueue::writer::{AppendHandle, AppendMessage, LogWriters, WriterConfig};
use crate::logqueue::{JobLocation, MessageId};
use crate::storage::fs_storage::FileSystemStorage;
use crate::storage::{Storage, StoredEmail};
use crate::worker::EmailMetadata;

/// Housekeeping files commonly dropped into directories by packaging or OS
/// tools. Ignored during legacy spool detection so they never trigger a
/// zero-message migration.
const HOUSEKEEPING_FILES: &[&str] = &[".keep", ".gitkeep", ".DS_Store"];

/// Classification of entries in legacy `queued/` and `deferred/` directories.
/// Shared between startup detection and migration import so both agree on
/// what counts as live mail vs. metadata vs. unexpected entries.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct LegacySpoolInventory {
    pub queued_files: Vec<Utf8PathBuf>,
    pub deferred_files: Vec<Utf8PathBuf>,
    pub had_paired_meta: bool,
    pub orphaned_meta: Vec<Utf8PathBuf>,
    pub unexpected: Vec<Utf8PathBuf>,
}

impl LegacySpoolInventory {
    pub fn message_count(&self) -> usize {
        self.queued_files.len() + self.deferred_files.len()
    }

    pub fn has_messages(&self) -> bool {
        self.message_count() > 0
    }

    pub fn describe_messages(&self, base_path: &Path) -> String {
        let mut parts = Vec::new();
        if !self.queued_files.is_empty() {
            parts.push(format!(
                "{} message(s) in {}",
                self.queued_files.len(),
                base_path.join("queued").display()
            ));
        }
        if !self.deferred_files.is_empty() {
            parts.push(format!(
                "{} message(s) in {}",
                self.deferred_files.len(),
                base_path.join("deferred").display()
            ));
        }
        parts.join(", ")
    }
}

fn is_housekeeping_name(name: &str) -> bool {
    HOUSEKEEPING_FILES.contains(&name)
}

/// Inspect legacy `queued/` and `deferred/` directories under `base_path`.
/// Missing directories are treated as empty; other I/O errors are returned.
pub fn inspect_legacy_spool(base_path: &Path) -> Result<LegacySpoolInventory> {
    let mut inv = LegacySpoolInventory::default();
    let mut message_stems: HashSet<String> = HashSet::new();
    let mut deferred_meta: Vec<(String, Utf8PathBuf)> = Vec::new();
    let mut deferred_meta_stems: HashSet<String> = HashSet::new();
    let mut deferred_meta_tmps: Vec<(String, Utf8PathBuf)> = Vec::new();

    for (dir_name, is_deferred) in [("queued", false), ("deferred", true)] {
        let dir_path = base_path.join(dir_name);
        let entries = match std::fs::read_dir(&dir_path) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                return Err(e).into_diagnostic().wrap_err_with(|| {
                    format!("reading legacy spool directory {}", dir_path.display())
                });
            }
        };

        for entry in entries {
            let entry = entry
                .into_diagnostic()
                .wrap_err_with(|| format!("reading entry in {}", dir_path.display()))?;
            let path = entry.path();
            let file_type = entry
                .file_type()
                .into_diagnostic()
                .wrap_err_with(|| format!("inspecting {}", path.display()))?;
            let utf8_path = Utf8PathBuf::from_path_buf(path.clone())
                .unwrap_or_else(|p| Utf8PathBuf::from(p.to_string_lossy().into_owned()));

            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                inv.unexpected.push(utf8_path);
                continue;
            };

            if file_type.is_file() && is_housekeeping_name(&name) {
                continue;
            }

            if !file_type.is_file() {
                inv.unexpected.push(utf8_path);
                continue;
            }

            if is_deferred {
                if let Some(stem) = name.strip_suffix(".meta.json.tmp") {
                    deferred_meta_tmps.push((stem.to_string(), utf8_path));
                    continue;
                }
                if let Some(stem) = name.strip_suffix(".meta.json") {
                    deferred_meta_stems.insert(stem.to_string());
                    deferred_meta.push((stem.to_string(), utf8_path));
                    continue;
                }
            }

            if let Some(stem) = name.strip_suffix(".json") {
                if !name.ends_with(".meta.json") {
                    message_stems.insert(stem.to_string());
                    if is_deferred {
                        inv.deferred_files.push(utf8_path);
                    } else {
                        inv.queued_files.push(utf8_path);
                    }
                    continue;
                }
            }

            inv.unexpected.push(utf8_path);
        }
    }

    // Legacy `FileSystemStorage::put_meta` writes `<id>.meta.json.tmp` before
    // renaming over `<id>.meta.json`. Ignore a leftover staging file when its
    // authoritative `<id>.meta.json` exists and parses cleanly; otherwise
    // flag it as unexpected so uncommitted retry state is not silently hidden.
    for (stem, tmp_path) in deferred_meta_tmps {
        let authoritative_valid = deferred_meta_stems.contains(&stem)
            && std::fs::read(base_path.join("deferred").join(format!("{stem}.meta.json")))
                .ok()
                .and_then(|bytes| serde_json::from_slice::<EmailMetadata>(&bytes).ok())
                .is_some();
        if !authoritative_valid {
            inv.unexpected.push(tmp_path);
        }
    }

    for (stem, path) in deferred_meta {
        if message_stems.contains(&stem) {
            inv.had_paired_meta = true;
        } else {
            inv.orphaned_meta.push(path);
        }
    }

    inv.queued_files.sort();
    inv.deferred_files.sort();
    inv.orphaned_meta.sort();
    inv.unexpected.sort();

    Ok(inv)
}

fn log_inventory_anomalies(inv: &LegacySpoolInventory) {
    if !inv.orphaned_meta.is_empty() {
        let paths: Vec<&str> = inv.orphaned_meta.iter().map(|p| p.as_str()).collect();
        tracing::warn!(
            count = paths.len(),
            paths = %paths.join(", "),
            "orphaned legacy retry metadata file(s) without matching message body"
        );
    }
    if !inv.unexpected.is_empty() {
        let paths: Vec<&str> = inv.unexpected.iter().map(|p| p.as_str()).collect();
        tracing::warn!(
            count = paths.len(),
            paths = %paths.join(", "),
            "unexpected non-mail entry(ies) found in legacy spool directories"
        );
    }
}

/// The log backend never reads the legacy one-file-per-message spool; mail
/// sitting there is preserved but undelivered until migrated. Make that state
/// loud at startup instead of silently ignoring it.
pub fn warn_about_unmigrated_legacy_spool(base_path: &str) {
    let base = Path::new(base_path);
    let inv = match inspect_legacy_spool(base) {
        Ok(inv) => inv,
        Err(err) => {
            tracing::warn!(
                base_path = %base_path,
                error = %err,
                "could not inspect legacy spool directories"
            );
            return;
        }
    };
    log_inventory_anomalies(&inv);
    if inv.has_messages() {
        tracing::warn!(
            "unmigrated legacy spool detected ({}); this mail is preserved but will NOT be \
             delivered until you enable `storage.auto_migrate = true` and restart, or stop the \
             server and run `hedwig queue migrate --config <config>`",
            inv.describe_messages(base)
        );
    }
}

/// Outcome of a one-time migration run.
#[derive(Debug, Default)]
pub struct MigrationSummary {
    pub migrated_queued: usize,
    pub migrated_deferred: usize,
    pub skipped: usize,
    /// `(legacy_id, derived_id)` pairs for non-ULID legacy message ids that
    /// were successfully migrated.
    pub remapped_ids: Vec<(String, String)>,
    /// `(src, dest)` pairs for legacy spool directories renamed to backups.
    pub renamed: Vec<(String, String)>,
    /// Orphaned `deferred/*.meta.json` files with no matching message body.
    pub orphaned_meta: Vec<String>,
    /// Unexpected non-mail entries discovered in `queued/` or `deferred/`.
    pub unexpected: Vec<String>,
    /// True if migration stopped early due to a shutdown/cancellation signal.
    pub interrupted: bool,
    /// `(path_or_id, error)` for anything that could not be migrated, synced,
    /// verified, or archived. Non-empty means legacy directories with errors
    /// were not fully archived.
    pub failed: Vec<(String, String)>,
}

impl MigrationSummary {
    pub fn print(&self) {
        for (legacy_id, new_id) in &self.remapped_ids {
            println!(
                "note: legacy id {legacy_id} is not a valid ULID; migrated under derived id {new_id}"
            );
        }
        for path in &self.orphaned_meta {
            println!("warning: orphaned legacy retry metadata (no matching body): {path}");
        }
        for path in &self.unexpected {
            println!("warning: unexpected non-mail entry in legacy spool: {path}");
        }
        for (src, dest) in &self.renamed {
            println!("renamed {src} -> {dest}");
        }
        if self.interrupted {
            println!(
                "migration interrupted by shutdown signal; legacy directories were left in place \
                 (safe to re-run this command)"
            );
        } else if !self.failed.is_empty() {
            println!(
                "migration had failures; remaining legacy directories were left in place \
                 (safe to re-run this command)"
            );
        }
        println!("migration summary:");
        println!("  migrated (was queued):     {}", self.migrated_queued);
        println!("  migrated (was deferred):   {}", self.migrated_deferred);
        println!("  skipped (already present): {}", self.skipped);
        println!("  failed:                    {}", self.failed.len());
        for (id, err) in &self.failed {
            println!("    {id}: {err}");
        }
    }
}

/// Run the one-time migration using settings resolved from `cfg`.
pub async fn migrate_from_cfg(cfg: &Cfg) -> Result<MigrationSummary> {
    migrate_from_cfg_with_cancel(cfg, None).await
}

/// Run the one-time migration using settings resolved from `cfg`, polling
/// `cancel` between messages so a shutdown signal stops cleanly.
pub async fn migrate_from_cfg_with_cancel(
    cfg: &Cfg,
    cancel: Option<&CancellationToken>,
) -> Result<MigrationSummary> {
    if cfg.storage.storage_type != "log" {
        bail!(
            "migration requires storage.storage_type = \"log\", found {:?}",
            cfg.storage.storage_type
        );
    }

    let legacy_base_path = Utf8PathBuf::from(cfg.storage.base_path.clone());
    let spool_root = Path::new(&cfg.storage.base_path).join("spool");

    let qcfg = cfg.queue();
    let max_message_size = cfg.server.max_message_size.unwrap_or(25 * 1024 * 1024);
    qcfg.validate(max_message_size)
        .wrap_err("invalid [queue] configuration")?;
    let max_record_len = qcfg
        .max_record_len(max_message_size)
        .wrap_err("invalid max_message_size for log queue")?;
    let writer_config = WriterConfig {
        segment_target_bytes: qcfg.segment_target_bytes(),
        max_record_len,
        pending_append_bytes: qcfg.pending_append_bytes(),
    };

    migrate_with_cancel(
        &legacy_base_path,
        &spool_root,
        qcfg.append_writers(),
        writer_config,
        cancel,
    )
    .await
}

/// Handle any remaining legacy filesystem spool at server startup when the log
/// backend is active.
pub async fn maybe_auto_migrate(cfg: &Cfg) -> Result<Option<MigrationSummary>> {
    maybe_auto_migrate_with_cancel(cfg, None).await
}

/// Same as [`maybe_auto_migrate`], polling `cancel` between messages so
/// `SIGINT`/`SIGTERM` interrupts a long migration cleanly without archiving
/// the legacy spool.
pub async fn maybe_auto_migrate_with_cancel(
    cfg: &Cfg,
    cancel: Option<&CancellationToken>,
) -> Result<Option<MigrationSummary>> {
    if cfg.storage.storage_type != "log" {
        return Ok(None);
    }
    if !cfg.storage.auto_migrate {
        warn_about_unmigrated_legacy_spool(&cfg.storage.base_path);
        return Ok(None);
    }

    let base = Path::new(&cfg.storage.base_path);
    let inv = inspect_legacy_spool(base)?;
    log_inventory_anomalies(&inv);
    if !inv.has_messages() {
        if !inv.unexpected.is_empty() {
            for path in &inv.unexpected {
                tracing::error!(
                    entry = %path,
                    "unexpected non-mail entry in legacy spool; inspect or remove before starting"
                );
            }
            bail!(
                "unexpected non-mail entry(ies) found in legacy spool ({}); inspect or remove \
                 before starting with storage.auto_migrate = true",
                inv.unexpected
                    .iter()
                    .map(|p| p.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        return Ok(None);
    }

    tracing::info!(
        queued = inv.queued_files.len(),
        deferred = inv.deferred_files.len(),
        base_path = %cfg.storage.base_path,
        "unmigrated legacy spool detected with storage.auto_migrate enabled; migrating to log queue"
    );

    let summary = migrate_from_cfg_with_cancel(cfg, cancel).await?;
    if summary.interrupted {
        tracing::info!(
            migrated_queued = summary.migrated_queued,
            migrated_deferred = summary.migrated_deferred,
            skipped = summary.skipped,
            "automatic legacy spool migration interrupted by shutdown signal; legacy directories left in place"
        );
        return Ok(Some(summary));
    }

    if !summary.failed.is_empty() {
        for (src, dest) in &summary.renamed {
            tracing::warn!(
                from = %src,
                to = %dest,
                "legacy directory was renamed before a later migration error occurred"
            );
        }
        for (id, err) in &summary.failed {
            tracing::error!(entry = %id, error = %err, "failed to migrate legacy spool entry");
        }
        bail!(
            "automatic legacy spool migration failed with {} error(s); remaining legacy \
             directories were left in place (fix the error and restart to retry)",
            summary.failed.len()
        );
    }

    tracing::info!(
        migrated_queued = summary.migrated_queued,
        migrated_deferred = summary.migrated_deferred,
        skipped = summary.skipped,
        "automatic legacy spool migration complete"
    );
    Ok(Some(summary))
}

/// Run the migration.
///
/// * `legacy_base_path` — the filesystem spool's base path (contains
///   `queued/`, `deferred/`, `bounced/`).
/// * `spool_root` — the new log-queue spool root (`<base_path>/spool`).
pub async fn migrate(
    legacy_base_path: &Utf8Path,
    spool_root: &Path,
    shard_count: u16,
    writer_config: WriterConfig,
) -> Result<MigrationSummary> {
    migrate_with_cancel(
        legacy_base_path,
        spool_root,
        shard_count,
        writer_config,
        None,
    )
    .await
}

/// Run the migration with optional cooperative cancellation between messages.
pub async fn migrate_with_cancel(
    legacy_base_path: &Utf8Path,
    spool_root: &Path,
    shard_count: u16,
    writer_config: WriterConfig,
    cancel: Option<&CancellationToken>,
) -> Result<MigrationSummary> {
    let inv = inspect_legacy_spool(legacy_base_path.as_std_path())?;
    log_inventory_anomalies(&inv);

    let mut summary = MigrationSummary {
        orphaned_meta: inv.orphaned_meta.iter().map(ToString::to_string).collect(),
        unexpected: inv.unexpected.iter().map(ToString::to_string).collect(),
        ..MigrationSummary::default()
    };
    for path in &inv.unexpected {
        summary.failed.push((
            path.to_string(),
            "unexpected non-mail entry in legacy spool; inspect or remove before archiving"
                .to_string(),
        ));
    }

    // Nothing to migrate and no unexpected entries to report: return cleanly
    // without touching or creating the log-queue spool.
    if !inv.has_messages() && summary.failed.is_empty() {
        return Ok(summary);
    }

    // If only unexpected entries exist (zero messages), report them without
    // creating the spool or renaming anything.
    if !inv.has_messages() {
        return Ok(summary);
    }

    let legacy = FileSystemStorage::new(legacy_base_path)
        .await
        .wrap_err("opening legacy filesystem spool")?;

    // Exclusive lock: guarantees no other process is concurrently appending
    // to (or recovering) this spool root. There is no equivalent lock on the
    // legacy spool; the caller is responsible for having stopped the server.
    let spool = Spool::open(spool_root, shard_count)
        .map_err(miette::Report::new)
        .wrap_err("opening log-queue spool (is another hedwig process using it?)")?;

    let writers = LogWriters::start(&spool, writer_config)
        .map_err(miette::Report::new)
        .wrap_err("starting append writers")?;
    let handle = writers.handle();

    // Reconcile every shard's checkpoint and journal state against the
    // writer-validated segment chain and publish a fresh checkpoint BEFORE
    // appending any migrated messages. This mirrors `Dispatcher::start`: a
    // stale checkpoint cursor past a truncated active tail would otherwise
    // leave newly migrated records appended at recycled offsets invisible to
    // discovery, and `write_checkpoint` also ensures recovered journals are
    // durably synced before any skip can archive legacy mail.
    let mut state_stores: HashMap<u16, ShardStateStore> = HashMap::new();
    for shard_dir in spool.shards() {
        let shard = shard_dir.shard();
        let (mut store, mut recovered) = ShardStateStore::recover(shard_dir.path(), shard)
            .map_err(miette::Report::new)
            .wrap_err_with(|| format!("recovering shard {shard} state before migration"))?;
        let chain = handle.shard_shared(shard).chain();
        recovered.reconcile_against_chain(shard, &chain);
        store
            .write_checkpoint(&recovered.to_checkpoint())
            .map_err(miette::Report::new)
            .wrap_err_with(|| format!("checkpointing reconciled shard {shard} before migration"))?;
        state_stores.insert(shard, store);
    }

    let mut existing = scan_existing_spool(&spool, &handle)
        .wrap_err("scanning existing log-queue spool for already-migrated messages")?;

    let mut migrated: Vec<MigratedRecord> = Vec::new();

    migrate_file_list(
        &legacy,
        &inv.queued_files,
        false,
        &handle,
        &spool,
        &mut existing,
        &mut state_stores,
        &mut migrated,
        &mut summary,
        cancel,
    )
    .await;

    if !summary.interrupted {
        migrate_file_list(
            &legacy,
            &inv.deferred_files,
            true,
            &handle,
            &spool,
            &mut existing,
            &mut state_stores,
            &mut migrated,
            &mut summary,
            cancel,
        )
        .await;
    }

    // Deferred state must be durable before we ever consider renaming the
    // legacy spool away.
    for (shard, store) in &mut state_stores {
        if let Err(e) = store.fsync_journal() {
            summary
                .failed
                .push((format!("<shard {shard} state journal>"), e.to_string()));
        }
    }
    drop(state_stores);

    writers.shutdown().await;

    // Durability barrier: run blocking fsyncs and verification on the blocking
    // thread pool so shutdown signals (`SIGINT`/`SIGTERM`) remain responsive
    // during final durability syncs.
    let shard_dirs: Vec<(u16, std::path::PathBuf)> = spool
        .shards()
        .iter()
        .map(|s| (s.shard(), s.path().to_path_buf()))
        .collect();
    let spool_root_buf = spool_root.to_path_buf();
    let spool_parent_buf = legacy_base_path.as_std_path().to_path_buf();
    let migrated_for_verify = migrated.clone();

    let (sync_failures, verify_failures) = tokio::task::spawn_blocking(move || -> Result<_> {
        let mut sync_errs = Vec::new();
        sync_spool_durably(
            &shard_dirs,
            &spool_root_buf,
            &spool_parent_buf,
            &mut sync_errs,
        );
        let mut verify_errs = Vec::new();
        verify_migrated(&shard_dirs, &migrated_for_verify, &mut verify_errs)?;
        Ok((sync_errs, verify_errs))
    })
    .await
    .into_diagnostic()
    .wrap_err("joining migration durability/verification task")??;

    summary.failed.extend(sync_failures);
    summary.failed.extend(verify_failures);

    // Yield once so a cancellation signal received during the blocking sync
    // phase is observed before archiving the legacy spool.
    tokio::task::yield_now().await;
    if cancel.is_some_and(CancellationToken::is_cancelled) {
        summary.interrupted = true;
    }

    if !summary.interrupted && summary.failed.is_empty() {
        rename_legacy_dirs(legacy_base_path, &inv, &mut summary);
    } else if summary.interrupted {
        tracing::info!(
            migrated_queued = summary.migrated_queued,
            migrated_deferred = summary.migrated_deferred,
            "migration interrupted before archiving legacy directories"
        );
    } else {
        tracing::warn!(
            failed = summary.failed.len(),
            "migration had failures; legacy queued/deferred directories were left in place"
        );
    }

    Ok(summary)
}

#[derive(Debug, Clone, Copy)]
struct MigratedRecord {
    id: MessageId,
    shard: u16,
    deferred: bool,
}

/// Reconciled view of what already exists in the destination log-queue spool.
#[derive(Debug, Default)]
struct ExistingSpoolState {
    /// Non-tombstoned payload records present on disk, keyed by message id
    /// (keeping the highest relocation generation when multiple copies exist).
    live_payloads: HashMap<MessageId, JobLocation>,
    /// Persisted deferred entries keyed by message id: `(shard, location)`.
    deferred_state: HashMap<MessageId, (u16, JobLocation)>,
    /// Message ids that have already reached a terminal state (delivered or
    /// bounced) in the new spool and have no live payload or state entry.
    terminal: HashSet<MessageId>,
}

/// Inspect every shard's segments and persisted state to determine which
/// messages are already complete, terminal, or half-migrated.
///
/// Uses `record::MAX_RECORD_LEN` (the format cap, not the current SMTP
/// `max_message_size`) so lowering `max_message_size` never makes valid
/// historical records look corrupt.
fn scan_existing_spool(spool: &Spool, handle: &AppendHandle) -> Result<ExistingSpoolState> {
    let mut existing = ExistingSpoolState::default();
    let mut all_ready: HashSet<MessageId> = HashSet::new();
    let mut all_tombstones: HashSet<MessageId> = HashSet::new();

    for shard_dir in spool.shards() {
        let shard = shard_dir.shard();
        let dir = shard_dir.path();

        let state = load_state_readonly(dir)
            .map_err(miette::Report::new)
            .wrap_err_with(|| format!("loading shard {shard} state"))?;
        all_ready.extend(state.ready.keys().copied());
        for (id, job) in &state.deferred {
            existing.deferred_state.insert(*id, (shard, job.location));
        }
        for tomb_ids in state.tombstones.values() {
            all_tombstones.extend(tomb_ids.iter().copied());
        }

        // Committed length for the active segment (if any) comes from the
        // writer's validated tail; sealed segments (including compaction
        // outputs not in the append chain) are scanned to their full length.
        let active_committed: HashMap<u64, u64> = handle
            .shard_shared(shard)
            .chain()
            .into_iter()
            .filter(|h| !h.sealed)
            .map(|h| (h.segment, h.committed))
            .collect();

        let segs = shard_dir
            .list_segments()
            .map_err(miette::Report::new)
            .wrap_err_with(|| format!("listing shard {shard} segments"))?;

        let mut to_scan: Vec<(u64, u64)> = Vec::new();
        for (ordinal, path) in &segs.sealed {
            let len = std::fs::metadata(path)
                .into_diagnostic()
                .wrap_err_with(|| format!("stat {}", path.display()))?
                .len();
            to_scan.push((*ordinal, len));
        }
        if let Some((ordinal, _)) = &segs.active {
            let committed = active_committed.get(ordinal).copied().unwrap_or(0);
            to_scan.push((*ordinal, committed));
        }

        for (ordinal, limit) in to_scan {
            if limit == 0 {
                continue;
            }
            let reader = open_segment_reader(dir, ordinal)
                .map_err(miette::Report::new)
                .wrap_err_with(|| format!("opening shard {shard} segment {ordinal}"))?;
            scan_headers(
                &reader,
                0,
                limit,
                record::MAX_RECORD_LEN,
                |offset, header| {
                    if state.is_terminal(ordinal, &header.message_id) {
                        return true;
                    }
                    let loc = JobLocation {
                        shard,
                        segment: ordinal,
                        offset,
                        length: header.record_len,
                        ordinal: header.ordinal,
                        generation: header.generation,
                    };
                    match existing.live_payloads.get(&header.message_id) {
                        Some(prev) if prev.generation >= loc.generation => {}
                        _ => {
                            existing.live_payloads.insert(header.message_id, loc);
                        }
                    }
                    true
                },
            )
            .map_err(miette::Report::new)
            .wrap_err_with(|| format!("scanning shard {shard} segment {ordinal}"))?;
        }
    }

    for id in all_tombstones {
        if !existing.live_payloads.contains_key(&id)
            && !all_ready.contains(&id)
            && !existing.deferred_state.contains_key(&id)
        {
            existing.terminal.insert(id);
        }
    }

    Ok(existing)
}

enum Outcome {
    Migrated {
        deferred: bool,
        remapped: Option<(String, String)>,
    },
    Skipped,
}

#[allow(clippy::too_many_arguments)]
async fn migrate_file_list(
    legacy: &FileSystemStorage,
    files: &[Utf8PathBuf],
    origin_is_deferred: bool,
    handle: &AppendHandle,
    spool: &Spool,
    existing: &mut ExistingSpoolState,
    state_stores: &mut HashMap<u16, ShardStateStore>,
    migrated: &mut Vec<MigratedRecord>,
    summary: &mut MigrationSummary,
    cancel: Option<&CancellationToken>,
) {
    for path in files {
        if cancel.is_some_and(CancellationToken::is_cancelled) {
            summary.interrupted = true;
            return;
        }
        let stored = match FileSystemStorage::read_email_file(path).await {
            Ok(s) => s,
            Err(e) => {
                summary.failed.push((path.to_string(), format!("{e:#}")));
                continue;
            }
        };
        let message_id = stored.message_id.clone();
        match migrate_one(
            legacy,
            stored,
            origin_is_deferred,
            handle,
            spool,
            existing,
            state_stores,
            migrated,
        )
        .await
        {
            Ok(Outcome::Migrated { deferred, remapped }) => {
                if deferred {
                    summary.migrated_deferred += 1;
                } else {
                    summary.migrated_queued += 1;
                }
                if let Some(pair) = remapped {
                    summary.remapped_ids.push(pair);
                }
            }
            Ok(Outcome::Skipped) => summary.skipped += 1,
            Err(e) => summary
                .failed
                .push((format!("{path} ({message_id})"), format!("{e:#}"))),
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn migrate_one(
    legacy: &FileSystemStorage,
    stored: StoredEmail,
    origin_is_deferred: bool,
    handle: &AppendHandle,
    spool: &Spool,
    existing: &mut ExistingSpoolState,
    state_stores: &mut HashMap<u16, ShardStateStore>,
    migrated: &mut Vec<MigratedRecord>,
) -> Result<Outcome> {
    let (id, remapped) = match MessageId::parse(&stored.message_id) {
        Ok(id) => (id, None),
        Err(_) => {
            // Deterministic remap: derive the new id from the legacy id so
            // a re-run after a crash produces the same id and reconciliation
            // catches it instead of appending a duplicate.
            let fresh = derived_message_id(&stored.message_id);
            tracing::warn!(
                legacy_id = %stored.message_id,
                new_id = %fresh,
                "legacy message id is not a valid ULID; derived a stable replacement id"
            );
            (fresh, Some((stored.message_id.clone(), fresh.to_string())))
        }
    };

    if existing.terminal.contains(&id) {
        return Ok(Outcome::Skipped);
    }

    // A queued message may still carry meta from a mid-retry restart (the
    // legacy worker leaves meta in place while the body sits in queued/);
    // honor it so the migrated message keeps its attempt count.
    let meta = legacy
        .get_meta(&stored.message_id)
        .await
        .wrap_err("reading legacy retry metadata")?;
    let is_deferred = origin_is_deferred || meta.as_ref().is_some_and(|m| m.attempts > 0);

    let existing_payload = existing.live_payloads.get(&id).copied();
    let existing_deferred = existing.deferred_state.get(&id).copied();

    if !is_deferred {
        if existing_payload.is_some() {
            return Ok(Outcome::Skipped);
        }
    } else if let (Some(payload_loc), Some((_, def_loc))) = (existing_payload, existing_deferred) {
        if def_loc == payload_loc {
            return Ok(Outcome::Skipped);
        }
    }

    let recipients = stored.to.clone();
    let location = match existing_payload {
        Some(loc) => {
            // Payload is already on disk, but deferred state is missing or
            // points elsewhere; repair only the state entry without
            // appending a duplicate payload.
            loc
        }
        None => {
            let enqueue_ms = stored
                .queued_at
                .map(|dt| dt.timestamp_millis())
                .unwrap_or_else(|| Utc::now().timestamp_millis());
            let body = Bytes::from(stored.body.into_bytes());
            let msg = AppendMessage {
                message_id: id,
                enqueue_ms,
                generation: 0,
                sender: stored.from,
                recipients: recipients.clone(),
                body,
            };
            // If a stale deferred journal entry already exists on a shard
            // (e.g. after a crash/power-loss tore away its payload), re-append
            // to that same shard so the repaired StateEntry::Deferred replaces
            // the stale entry on that shard.
            let loc = match existing_deferred {
                Some((stale_shard, _)) => handle.append_to_shard(stale_shard, msg).await,
                None => handle.append(msg).await,
            }
            .map_err(miette::Report::new)
            .wrap_err("appending message body to the log queue")?;
            existing.live_payloads.insert(id, loc);
            loc
        }
    };

    if is_deferred {
        let store = get_or_open_state_store(spool, state_stores, location.shard)?;
        let (attempts, next_attempt_ms, last_error) = deferred_fields(meta.as_ref());
        store
            .append(&StateEntry::Deferred {
                id,
                location,
                attempts,
                next_attempt_ms,
                remaining_recipients: recipients,
                last_error,
            })
            .map_err(miette::Report::new)
            .wrap_err("writing deferred state entry")?;
        existing
            .deferred_state
            .insert(id, (location.shard, location));
    }

    migrated.push(MigratedRecord {
        id,
        shard: location.shard,
        deferred: is_deferred,
    });
    Ok(Outcome::Migrated {
        deferred: is_deferred,
        remapped,
    })
}

/// Attempts/next-attempt/last-error for a deferred `StateEntry`, from legacy
/// meta. A message routed here without meta (unexpected — the legacy worker
/// always writes meta before moving a message to deferred/) is migrated
/// defensively: one attempt already happened, retry immediately.
fn deferred_fields(meta: Option<&EmailMetadata>) -> (u32, i64, String) {
    match meta {
        Some(m) => (
            m.attempts.max(1),
            system_time_to_ms(m.next_attempt),
            m.last_error.clone().unwrap_or_default(),
        ),
        None => (1, Utc::now().timestamp_millis(), String::new()),
    }
}

fn system_time_to_ms(t: SystemTime) -> i64 {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_millis() as i64,
        Err(e) => -(e.duration().as_millis() as i64),
    }
}

/// Stable 16-byte id derived from a non-ULID legacy id (HMAC-free: this is
/// dedup identity, not security). Re-running migration maps the same legacy
/// id to the same new id.
fn derived_message_id(legacy_id: &str) -> MessageId {
    use hmac::{KeyInit, Mac};
    // md-5 is already in the tree (CRAM-MD5); collision resistance is not a
    // requirement here, only stability across runs.
    let mut mac = hmac::Hmac::<md5::Md5>::new_from_slice(b"hedwig-migrate-id")
        .expect("HMAC accepts any key length");
    mac.update(legacy_id.as_bytes());
    let digest = mac.finalize().into_bytes();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    MessageId(bytes)
}

fn get_or_open_state_store<'a>(
    spool: &Spool,
    state_stores: &'a mut HashMap<u16, ShardStateStore>,
    shard: u16,
) -> Result<&'a mut ShardStateStore> {
    if let std::collections::hash_map::Entry::Vacant(entry) = state_stores.entry(shard) {
        let dir = spool.shard(shard).path();
        let (store, _recovered) = ShardStateStore::recover(dir, shard)
            .map_err(miette::Report::new)
            .wrap_err_with(|| format!("opening state store for shard {shard}"))?;
        entry.insert(store);
    }
    Ok(state_stores.get_mut(&shard).expect("just inserted"))
}

/// Fsync every segment file, journal/checkpoint file, shard directory,
/// format-version file, spool root directory, and its parent directory so
/// migrated payloads and layout metadata are durable on disk before legacy
/// directories are renamed.
fn sync_spool_durably(
    shard_dirs: &[(u16, std::path::PathBuf)],
    spool_root: &Path,
    spool_parent: &Path,
    failures: &mut Vec<(String, String)>,
) {
    for (shard, dir) in shard_dirs {
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(e) => {
                failures.push((
                    format!("<shard {shard} durability sync>"),
                    format!("reading shard directory {}: {e}", dir.display()),
                ));
                continue;
            }
        };
        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    failures.push((
                        dir.display().to_string(),
                        format!("reading shard entry: {e}"),
                    ));
                    continue;
                }
            };
            let path = entry.path();
            if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
                continue;
            }
            if let Err(e) = File::open(&path).and_then(|f| f.sync_all()) {
                failures.push((
                    path.display().to_string(),
                    format!("fsyncing migrated spool file: {e}"),
                ));
            }
        }
        if let Err(e) = sync_dir(dir) {
            failures.push((
                dir.display().to_string(),
                format!("fsyncing shard directory: {e}"),
            ));
        }
    }

    let version_file = spool_root.join("format-version");
    if version_file.exists() {
        if let Err(e) = File::open(&version_file).and_then(|f| f.sync_all()) {
            failures.push((
                version_file.display().to_string(),
                format!("fsyncing format-version: {e}"),
            ));
        }
    }
    if let Err(e) = sync_dir(spool_root) {
        failures.push((
            spool_root.display().to_string(),
            format!("fsyncing spool root directory: {e}"),
        ));
    }
    if let Err(e) = sync_dir(spool_parent) {
        failures.push((
            spool_parent.display().to_string(),
            format!("fsyncing spool parent directory: {e}"),
        ));
    }
}

/// Re-scan every affected shard's segments (writers already shut down, so
/// files are stable) and confirm every migrated/repaired id is present with
/// its required deferred state.
fn verify_migrated(
    shard_dirs: &[(u16, std::path::PathBuf)],
    migrated: &[MigratedRecord],
    failures: &mut Vec<(String, String)>,
) -> Result<()> {
    let dir_by_shard: HashMap<u16, &Path> =
        shard_dirs.iter().map(|(s, p)| (*s, p.as_path())).collect();
    let mut by_shard: HashMap<u16, HashMap<MessageId, bool>> = HashMap::new();
    for rec in migrated {
        let entry = by_shard
            .entry(rec.shard)
            .or_default()
            .entry(rec.id)
            .or_insert(false);
        *entry |= rec.deferred;
    }

    for (shard, wanted) in &by_shard {
        let dir = *dir_by_shard
            .get(shard)
            .expect("migrated shard exists in spool");
        let shard_dir = crate::logqueue::shard::ShardDir::open_or_create(
            dir.parent().expect("shard dir has spool parent"),
            *shard,
        )
        .map_err(miette::Report::new)
        .wrap_err_with(|| format!("opening shard {shard} for verification"))?;
        let segs = shard_dir
            .list_segments()
            .map_err(miette::Report::new)
            .wrap_err_with(|| format!("listing shard {shard} segments"))?;
        let state = load_state_readonly(dir)
            .map_err(miette::Report::new)
            .wrap_err_with(|| format!("loading shard {shard} state for verification"))?;

        let mut found: HashMap<MessageId, HashSet<JobLocation>> = HashMap::new();
        for (ordinal, path) in segs.sealed.iter().chain(segs.active.iter()) {
            let len = std::fs::metadata(path)
                .into_diagnostic()
                .wrap_err_with(|| format!("stat {}", path.display()))?
                .len();
            if len == 0 {
                continue;
            }
            let reader = open_segment_reader(dir, *ordinal)
                .map_err(miette::Report::new)
                .wrap_err_with(|| format!("opening shard {shard} segment {ordinal}"))?;
            scan_headers(&reader, 0, len, record::MAX_RECORD_LEN, |offset, header| {
                if !state.is_terminal(*ordinal, &header.message_id) {
                    let loc = JobLocation {
                        shard: *shard,
                        segment: *ordinal,
                        offset,
                        length: header.record_len,
                        ordinal: header.ordinal,
                        generation: header.generation,
                    };
                    found.entry(header.message_id).or_default().insert(loc);
                }
                true
            })
            .map_err(miette::Report::new)
            .wrap_err_with(|| format!("scanning shard {shard} segment {ordinal}"))?;
        }

        for (id, expect_deferred) in wanted {
            let Some(locs) = found.get(id) else {
                failures.push((
                    id.to_string(),
                    "missing from spool after migration (verification failed)".to_string(),
                ));
                continue;
            };
            if *expect_deferred {
                match state.deferred.get(id) {
                    Some(job) if locs.contains(&job.location) => {}
                    Some(_) => {
                        failures.push((
                            id.to_string(),
                            "deferred state points to a missing payload location (verification failed)"
                                .to_string(),
                        ));
                    }
                    None => {
                        failures.push((
                            id.to_string(),
                            "missing deferred state entry after migration (verification failed)"
                                .to_string(),
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}

/// Rename migrated `queued/` and `deferred/` directories to timestamped
/// backups. `bounced/` is left untouched: it remains the live bounce archive
/// under the log backend. Never deletes anything.
fn rename_legacy_dirs(
    legacy_base_path: &Utf8Path,
    inv: &LegacySpoolInventory,
    summary: &mut MigrationSummary,
) {
    let epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    rename_legacy_dirs_at(legacy_base_path, inv, epoch, summary);
}

/// Deterministic-timestamp implementation of [`rename_legacy_dirs`].
///
/// Preflights all backup destinations before executing any rename so a
/// destination collision never splits a paired `queued/` + `deferred/` spool.
/// If a later rename fails unexpectedly at runtime, attempts to roll back
/// earlier renames and preserves any un-rolled-back rename in `summary.renamed`.
fn rename_legacy_dirs_at(
    legacy_base_path: &Utf8Path,
    inv: &LegacySpoolInventory,
    epoch: u64,
    summary: &mut MigrationSummary,
) {
    let mut plan: Vec<(Utf8PathBuf, Utf8PathBuf)> = Vec::new();
    for (name, should_archive) in [
        ("queued", !inv.queued_files.is_empty()),
        (
            "deferred",
            !inv.deferred_files.is_empty() || inv.had_paired_meta,
        ),
    ] {
        if !should_archive {
            continue;
        }
        let src = legacy_base_path.join(name);
        if !src.exists() {
            continue;
        }
        let dest = legacy_base_path.join(format!("{name}.migrated-{epoch}"));
        plan.push((src, dest));
    }

    // Preflight all destinations so a collision on deferred/ never leaves
    // queued/ already renamed without its paired deferred metadata.
    let mut preflight_failed = false;
    for (src, dest) in &plan {
        if dest.exists() {
            summary.failed.push((
                src.to_string(),
                format!("backup destination {dest} already exists"),
            ));
            preflight_failed = true;
        }
    }
    if preflight_failed {
        return;
    }

    let mut completed: Vec<(Utf8PathBuf, Utf8PathBuf)> = Vec::new();
    for (src, dest) in plan {
        match std::fs::rename(&src, &dest) {
            Ok(()) => {
                tracing::info!(from = %src, to = %dest, "renamed legacy spool directory to backup");
                completed.push((src, dest));
            }
            Err(e) => {
                summary
                    .failed
                    .push((src.to_string(), format!("renaming {src} to {dest}: {e}")));
                // Best-effort rollback of earlier renames so paired legacy
                // directories stay intact for the next retry.
                while let Some((prev_src, prev_dest)) = completed.pop() {
                    if let Err(rb_err) = std::fs::rename(&prev_dest, &prev_src) {
                        summary
                            .renamed
                            .push((prev_src.to_string(), prev_dest.to_string()));
                        summary.failed.push((
                            prev_dest.to_string(),
                            format!("rolling back rename to {prev_src}: {rb_err}"),
                        ));
                    }
                }
                return;
            }
        }
    }

    if !completed.is_empty() {
        for (src, dest) in completed {
            summary.renamed.push((src.to_string(), dest.to_string()));
        }
        if let Err(e) = sync_dir(legacy_base_path.as_std_path()) {
            summary.failed.push((
                legacy_base_path.to_string(),
                format!("fsyncing legacy spool parent directory after rename: {e}"),
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logqueue::record;
    use crate::logqueue::state::ShardStateStore as StateStore;
    use crate::storage::Status;
    use crate::worker::EmailMetadata;
    use std::time::Duration;

    fn writer_config() -> WriterConfig {
        WriterConfig {
            segment_target_bytes: 64 * 1024 * 1024,
            max_record_len: record::MAX_RECORD_LEN,
            pending_append_bytes: 16 * 1024 * 1024,
        }
    }

    fn email(id: &str, to: &[&str], body: &str) -> StoredEmail {
        StoredEmail {
            message_id: id.to_string(),
            from: "sender@example.com".to_string(),
            to: to.iter().map(|s| s.to_string()).collect(),
            body: body.to_string(),
            queued_at: Some(Utc::now()),
        }
    }

    fn meta(id: &str, attempts: u32, last_error: Option<&str>) -> EmailMetadata {
        EmailMetadata {
            msg_id: id.to_string(),
            attempts,
            last_attempt: SystemTime::now(),
            next_attempt: SystemTime::now() + Duration::from_secs(300),
            last_error: last_error.map(|s| s.to_string()),
        }
    }

    fn new_ulid() -> String {
        ulid::Ulid::generate().to_string()
    }

    /// Every message id found by scanning a shard's payload segments,
    /// counting how many times each appears (should always be 1 — more than
    /// that would mean migration appended a duplicate).
    fn count_payload_records(spool_root: &Path, shard: u16) -> HashMap<MessageId, u32> {
        let mut counts = HashMap::new();
        let dir = spool_root.join(crate::logqueue::shard::shard_dir_name(shard));
        if !dir.exists() {
            return counts;
        }
        let shard_dir =
            crate::logqueue::shard::ShardDir::open_or_create(spool_root, shard).unwrap();
        let segs = shard_dir.list_segments().unwrap();
        for (ordinal, path) in segs.sealed.iter().chain(segs.active.iter()) {
            let reader = open_segment_reader(&dir, *ordinal).unwrap();
            let len = std::fs::metadata(path).unwrap().len();
            if len == 0 {
                continue;
            }
            scan_headers(&reader, 0, len, record::MAX_RECORD_LEN, |_, header| {
                *counts.entry(header.message_id).or_insert(0) += 1;
                true
            })
            .unwrap();
        }
        counts
    }

    async fn find_ready(
        spool_root: &Path,
        shard_count: u16,
        id: MessageId,
    ) -> Option<(String, String, Vec<u8>)> {
        for shard in 0..shard_count {
            let dir = spool_root.join(crate::logqueue::shard::shard_dir_name(shard));
            if !dir.exists() {
                continue;
            }
            let shard_dir =
                crate::logqueue::shard::ShardDir::open_or_create(spool_root, shard).unwrap();
            let segs = shard_dir.list_segments().unwrap();
            for (ordinal, path) in segs.sealed.iter().chain(segs.active.iter()) {
                let reader = open_segment_reader(&dir, *ordinal).unwrap();
                let len = std::fs::metadata(path).unwrap().len();
                if len == 0 {
                    continue;
                }
                let mut result = None;
                scan_headers(&reader, 0, len, record::MAX_RECORD_LEN, |offset, header| {
                    if header.message_id == id {
                        let body = reader.read_body(&header, offset).unwrap();
                        result = Some((header.sender.clone(), header.recipients.join(","), body));
                        false
                    } else {
                        true
                    }
                })
                .unwrap();
                if result.is_some() {
                    return result;
                }
            }
        }
        None
    }

    fn deferred_entry(
        spool_root: &Path,
        shard_count: u16,
        id: MessageId,
    ) -> Option<crate::logqueue::state::DeferredJob> {
        for shard in 0..shard_count {
            let dir = spool_root.join(crate::logqueue::shard::shard_dir_name(shard));
            if !dir.exists() {
                continue;
            }
            let (_, recovered) = StateStore::recover(&dir, shard).unwrap();
            if let Some(d) = recovered.deferred.get(&id) {
                return Some(d.clone());
            }
        }
        None
    }

    fn log_cfg(base_path: &Path, auto_migrate: bool) -> Cfg {
        use crate::config::{CfgLog, CfgServer, CfgStorage};
        Cfg {
            log: CfgLog::default(),
            server: CfgServer {
                listeners: vec![],
                workers: None,
                max_retries: None,
                auth: None,
                dkim: None,
                disable_outbound: None,
                outbound_local: None,
                helo_hostname: None,
                hostname: None,
                smtp: None,
                pool_size: None,
                rate_limits: None,
                metrics: None,
                health: None,
                queue_buffer: None,
                max_connections: None,
                max_message_size: None,
                cmd_timeout: None,
                data_timeout: None,
            },
            storage: CfgStorage {
                storage_type: "log".to_string(),
                base_path: base_path.to_string_lossy().into_owned(),
                auto_migrate,
                cleanup: None,
            },
            filters: None,
            queue: None,
        }
    }

    #[tokio::test]
    async fn migrates_queued_and_deferred_with_meta() {
        let dir = tempfile::tempdir().unwrap();
        let legacy_base = Utf8PathBuf::from_path_buf(dir.path().join("legacy")).unwrap();
        let spool_root = dir.path().join("legacy").join("spool");

        let legacy = FileSystemStorage::new(&legacy_base).await.unwrap();

        let q1_id = new_ulid();
        legacy
            .put(
                email(&q1_id, &["r1@example.com"], "queued body"),
                Status::Queued,
            )
            .await
            .unwrap();

        let q2_id = new_ulid();
        legacy
            .put(
                email(&q2_id, &["r2@example.com"], "mid-retry body"),
                Status::Queued,
            )
            .await
            .unwrap();
        legacy
            .put_meta(&q2_id, &meta(&q2_id, 2, Some("451 try later")))
            .await
            .unwrap();

        let d1_id = new_ulid();
        legacy
            .put(
                email(&d1_id, &["r3@example.com"], "deferred body"),
                Status::Deferred,
            )
            .await
            .unwrap();
        legacy
            .put_meta(&d1_id, &meta(&d1_id, 3, Some("450 backoff")))
            .await
            .unwrap();

        let summary = migrate(&legacy_base, &spool_root, 2, writer_config())
            .await
            .unwrap();
        assert_eq!(summary.migrated_queued, 1, "{summary:?}");
        assert_eq!(summary.migrated_deferred, 2);
        assert_eq!(summary.skipped, 0);
        assert!(
            summary.failed.is_empty(),
            "unexpected failures: {:?}",
            summary.failed
        );

        let q1 = MessageId::parse(&q1_id).unwrap();
        let (sender, rcpts, body) = find_ready(&spool_root, 2, q1).await.unwrap();
        assert_eq!(sender, "sender@example.com");
        assert_eq!(rcpts, "r1@example.com");
        assert_eq!(body, b"queued body");
        assert!(deferred_entry(&spool_root, 2, q1).is_none());

        let q2 = MessageId::parse(&q2_id).unwrap();
        assert!(find_ready(&spool_root, 2, q2).await.is_some());
        let d =
            deferred_entry(&spool_root, 2, q2).expect("mid-retry meta migrates as deferred state");
        assert_eq!(d.attempts, 2);
        assert_eq!(d.remaining_recipients, vec!["r2@example.com".to_string()]);
        assert_eq!(d.last_error, "451 try later");

        let d1 = MessageId::parse(&d1_id).unwrap();
        assert!(find_ready(&spool_root, 2, d1).await.is_some());
        let d = deferred_entry(&spool_root, 2, d1).expect("deferred message has state");
        assert_eq!(d.attempts, 3);
        assert_eq!(d.remaining_recipients, vec!["r3@example.com".to_string()]);
        assert_eq!(d.last_error, "450 backoff");

        assert!(!legacy_base.join("queued").exists());
        assert!(!legacy_base.join("deferred").exists());
        let mut saw_queued_backup = false;
        let mut saw_deferred_backup = false;
        for entry in std::fs::read_dir(legacy_base.as_std_path()).unwrap() {
            let name = entry.unwrap().file_name().to_string_lossy().to_string();
            if name.starts_with("queued.migrated-") {
                saw_queued_backup = true;
            }
            if name.starts_with("deferred.migrated-") {
                saw_deferred_backup = true;
            }
        }
        assert!(saw_queued_backup);
        assert!(saw_deferred_backup);
    }

    #[tokio::test]
    async fn rerun_after_success_migrates_nothing_new() {
        let dir = tempfile::tempdir().unwrap();
        let legacy_base = Utf8PathBuf::from_path_buf(dir.path().join("legacy")).unwrap();
        let spool_root = dir.path().join("legacy").join("spool");

        let legacy = FileSystemStorage::new(&legacy_base).await.unwrap();
        let id = new_ulid();
        legacy
            .put(email(&id, &["r@example.com"], "body"), Status::Queued)
            .await
            .unwrap();

        let first = migrate(&legacy_base, &spool_root, 1, writer_config())
            .await
            .unwrap();
        assert_eq!(first.migrated_queued, 1);
        assert!(first.failed.is_empty());

        let second = migrate(&legacy_base, &spool_root, 1, writer_config())
            .await
            .unwrap();
        assert_eq!(second.migrated_queued, 0);
        assert_eq!(second.migrated_deferred, 0);
        assert_eq!(second.skipped, 0);
        assert!(second.failed.is_empty());

        let parsed = MessageId::parse(&id).unwrap();
        assert!(find_ready(&spool_root, 1, parsed).await.is_some());
    }

    #[tokio::test]
    async fn already_migrated_id_left_in_legacy_spool_is_skipped_not_duplicated() {
        let dir = tempfile::tempdir().unwrap();
        let legacy_base = Utf8PathBuf::from_path_buf(dir.path().join("legacy")).unwrap();
        let spool_root = dir.path().join("legacy").join("spool");

        let legacy = FileSystemStorage::new(&legacy_base).await.unwrap();
        let id = new_ulid();
        legacy
            .put(email(&id, &["r@example.com"], "body"), Status::Queued)
            .await
            .unwrap();

        {
            let spool = Spool::open(&spool_root, 1).unwrap();
            let writers = LogWriters::start(&spool, writer_config()).unwrap();
            let handle = writers.handle();
            handle
                .append(AppendMessage {
                    message_id: MessageId::parse(&id).unwrap(),
                    enqueue_ms: Utc::now().timestamp_millis(),
                    generation: 0,
                    sender: "sender@example.com".into(),
                    recipients: vec!["r@example.com".into()],
                    body: Bytes::from_static(b"body"),
                })
                .await
                .unwrap();
            writers.shutdown().await;
        }

        let summary = migrate(&legacy_base, &spool_root, 1, writer_config())
            .await
            .unwrap();
        assert_eq!(summary.migrated_queued, 0);
        assert_eq!(summary.skipped, 1);
        assert!(summary.failed.is_empty());

        let target = MessageId::parse(&id).unwrap();
        let counts = count_payload_records(&spool_root, 0);
        assert_eq!(counts.get(&target).copied().unwrap_or(0), 1);
    }

    #[tokio::test]
    async fn crash_recovery_repairs_deferred_with_payload_only_without_duplicating() {
        let dir = tempfile::tempdir().unwrap();
        let legacy_base = Utf8PathBuf::from_path_buf(dir.path().join("legacy")).unwrap();
        let spool_root = dir.path().join("legacy").join("spool");

        let legacy = FileSystemStorage::new(&legacy_base).await.unwrap();
        let id = new_ulid();
        legacy
            .put(
                email(&id, &["r@example.com"], "deferred body"),
                Status::Deferred,
            )
            .await
            .unwrap();
        legacy
            .put_meta(&id, &meta(&id, 4, Some("421 temporary")))
            .await
            .unwrap();

        // Simulate crash after payload append, before StateEntry::Deferred write.
        let parsed = MessageId::parse(&id).unwrap();
        {
            let spool = Spool::open(&spool_root, 1).unwrap();
            let writers = LogWriters::start(&spool, writer_config()).unwrap();
            writers
                .handle()
                .append(AppendMessage {
                    message_id: parsed,
                    enqueue_ms: Utc::now().timestamp_millis(),
                    generation: 0,
                    sender: "sender@example.com".into(),
                    recipients: vec!["r@example.com".into()],
                    body: Bytes::from_static(b"deferred body"),
                })
                .await
                .unwrap();
            writers.shutdown().await;
        }

        let summary = migrate(&legacy_base, &spool_root, 1, writer_config())
            .await
            .unwrap();
        assert_eq!(summary.migrated_deferred, 1);
        assert_eq!(summary.skipped, 0);
        assert!(summary.failed.is_empty(), "{:?}", summary.failed);

        // No duplicate payload appended, and deferred retry state is repaired.
        let counts = count_payload_records(&spool_root, 0);
        assert_eq!(counts.get(&parsed).copied(), Some(1));
        let d = deferred_entry(&spool_root, 1, parsed).expect("repaired deferred entry");
        assert_eq!(d.attempts, 4);
        assert_eq!(d.last_error, "421 temporary");
    }

    #[tokio::test]
    async fn crash_recovery_repairs_deferred_with_journal_only_and_missing_payload() {
        let dir = tempfile::tempdir().unwrap();
        let legacy_base = Utf8PathBuf::from_path_buf(dir.path().join("legacy")).unwrap();
        let spool_root = dir.path().join("legacy").join("spool");

        let legacy = FileSystemStorage::new(&legacy_base).await.unwrap();
        let id = new_ulid();
        legacy
            .put(
                email(&id, &["r@example.com"], "deferred body"),
                Status::Deferred,
            )
            .await
            .unwrap();
        legacy
            .put_meta(&id, &meta(&id, 4, Some("421 temporary")))
            .await
            .unwrap();

        // Simulate crash/power-loss where StateEntry::Deferred survived in the
        // journal, but the payload record was torn away (0-byte segment).
        let parsed = MessageId::parse(&id).unwrap();
        {
            let spool = Spool::open(&spool_root, 2).unwrap();
            let stale_shard = 1;
            let (mut store, _) =
                StateStore::recover(spool.shard(stale_shard).path(), stale_shard).unwrap();
            store
                .append(&StateEntry::Deferred {
                    id: parsed,
                    location: JobLocation {
                        shard: stale_shard,
                        segment: 1,
                        offset: 0,
                        length: 128,
                        ordinal: 0,
                        generation: 0,
                    },
                    attempts: 4,
                    next_attempt_ms: Utc::now().timestamp_millis() + 300_000,
                    remaining_recipients: vec!["r@example.com".into()],
                    last_error: "421 temporary".into(),
                })
                .unwrap();
            store.fsync_journal().unwrap();
        }

        let summary = migrate(&legacy_base, &spool_root, 2, writer_config())
            .await
            .unwrap();
        assert_eq!(summary.migrated_deferred, 1);
        assert_eq!(summary.skipped, 0);
        assert!(summary.failed.is_empty(), "{:?}", summary.failed);

        // Reconcile-before-append dropped the dangling journal entry on shard 1
        // and migration re-appended the payload + deferred state cleanly.
        let (_, _, body) = find_ready(&spool_root, 2, parsed)
            .await
            .expect("payload repaired");
        assert_eq!(body, b"deferred body");
        let mut found_deferred = Vec::new();
        for shard in 0..2u16 {
            let (_, recovered) =
                StateStore::recover(&spool_root.join(format!("shard-{shard:04}")), shard).unwrap();
            if let Some(d) = recovered.deferred.get(&parsed) {
                found_deferred.push((shard, d.clone()));
            }
        }
        assert_eq!(
            found_deferred.len(),
            1,
            "no dangling deferred entry left behind"
        );
        let (owner_shard, d) = &found_deferred[0];
        assert_eq!(d.location.shard, *owner_shard);
        assert_eq!(d.attempts, 4);
        assert_eq!(d.last_error, "421 temporary");
    }

    #[tokio::test]
    async fn terminal_tombstoned_message_is_skipped_and_never_resurrected() {
        let dir = tempfile::tempdir().unwrap();
        let legacy_base = Utf8PathBuf::from_path_buf(dir.path().join("legacy")).unwrap();
        let spool_root = dir.path().join("legacy").join("spool");

        let legacy = FileSystemStorage::new(&legacy_base).await.unwrap();
        let id = new_ulid();
        legacy
            .put(
                email(&id, &["r@example.com"], "already delivered"),
                Status::Queued,
            )
            .await
            .unwrap();

        let parsed = MessageId::parse(&id).unwrap();
        {
            let spool = Spool::open(&spool_root, 1).unwrap();
            let writers = LogWriters::start(&spool, writer_config()).unwrap();
            let loc = writers
                .handle()
                .append(AppendMessage {
                    message_id: parsed,
                    enqueue_ms: Utc::now().timestamp_millis(),
                    generation: 0,
                    sender: "sender@example.com".into(),
                    recipients: vec!["r@example.com".into()],
                    body: Bytes::from_static(b"already delivered"),
                })
                .await
                .unwrap();
            let (mut store, _) = StateStore::recover(spool.shard(0).path(), 0).unwrap();
            store
                .append(&StateEntry::Delivered {
                    id: parsed,
                    location: loc,
                    timestamp_ms: Utc::now().timestamp_millis(),
                })
                .unwrap();
            store.fsync_journal().unwrap();
            writers.shutdown().await;
        }

        let summary = migrate(&legacy_base, &spool_root, 1, writer_config())
            .await
            .unwrap();
        assert_eq!(summary.migrated_queued, 0);
        assert_eq!(summary.skipped, 1);
        assert!(summary.failed.is_empty());
        assert_eq!(
            count_payload_records(&spool_root, 0).get(&parsed).copied(),
            Some(1)
        );
    }

    #[tokio::test]
    async fn lowering_max_message_size_does_not_fail_scanning_historical_records() {
        let dir = tempfile::tempdir().unwrap();
        let legacy_base = Utf8PathBuf::from_path_buf(dir.path().join("legacy")).unwrap();
        let spool_root = dir.path().join("legacy").join("spool");

        // Pre-populate spool with an incompressible 2 MiB historical record
        // so its on-disk encoded size genuinely exceeds the lowered limit
        // (1 KiB + 1 MiB envelope allowance).
        let mut incompressible = vec![0u8; 2 * 1024 * 1024];
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        for chunk in incompressible.as_chunks_mut::<8>().0 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *chunk = x.to_le_bytes();
        }

        let big_id = MessageId::parse(&new_ulid()).unwrap();
        let historical_loc = {
            let spool = Spool::open(&spool_root, 1).unwrap();
            let writers = LogWriters::start(&spool, writer_config()).unwrap();
            let loc = writers
                .handle()
                .append(AppendMessage {
                    message_id: big_id,
                    enqueue_ms: Utc::now().timestamp_millis(),
                    generation: 0,
                    sender: "sender@example.com".into(),
                    recipients: vec!["r@example.com".into()],
                    body: Bytes::from(incompressible),
                })
                .await
                .unwrap();
            writers.shutdown().await;
            loc
        };

        let mut cfg = log_cfg(legacy_base.as_std_path(), true);
        cfg.server.max_message_size = Some(1024);
        let lowered_limit = cfg.queue().max_record_len(1024).unwrap();
        assert!(
            historical_loc.length > lowered_limit,
            "fixture must exceed lowered limit on disk ({} <= {})",
            historical_loc.length,
            lowered_limit
        );

        let legacy = FileSystemStorage::new(&legacy_base).await.unwrap();
        let small_id = new_ulid();
        legacy
            .put(email(&small_id, &["r@example.com"], "tiny"), Status::Queued)
            .await
            .unwrap();

        let summary = maybe_auto_migrate(&cfg).await.unwrap().expect("migrated");
        assert_eq!(summary.migrated_queued, 1);
        assert!(summary.failed.is_empty());
    }

    #[tokio::test]
    async fn non_ulid_legacy_id_is_remapped_only_when_migration_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let legacy_base = Utf8PathBuf::from_path_buf(dir.path().join("legacy")).unwrap();
        let spool_root = dir.path().join("legacy").join("spool");

        let legacy = FileSystemStorage::new(&legacy_base).await.unwrap();
        legacy
            .put(
                email(
                    "not-a-ulid",
                    &["r@example.com"],
                    "body that exceeds tiny limit",
                ),
                Status::Queued,
            )
            .await
            .unwrap();

        // Force append failure with a tiny max_record_len: remapped_ids must remain empty.
        let tiny_cfg = WriterConfig {
            segment_target_bytes: 64 * 1024 * 1024,
            max_record_len: 32,
            pending_append_bytes: 16 * 1024 * 1024,
        };
        let failed = migrate(&legacy_base, &spool_root, 1, tiny_cfg)
            .await
            .unwrap();
        assert_eq!(failed.migrated_queued, 0);
        assert_eq!(failed.failed.len(), 1);
        assert!(failed.remapped_ids.is_empty());

        // Succeeding with normal config records the remap.
        let ok = migrate(&legacy_base, &spool_root, 1, writer_config())
            .await
            .unwrap();
        assert_eq!(ok.migrated_queued, 1);
        assert_eq!(ok.remapped_ids.len(), 1);
        assert!(ok.failed.is_empty());
    }

    #[tokio::test]
    async fn housekeeping_and_orphaned_meta_do_not_trigger_zero_message_migration() {
        let dir = tempfile::tempdir().unwrap();
        let legacy_base = Utf8PathBuf::from_path_buf(dir.path().join("mail")).unwrap();
        let legacy = FileSystemStorage::new(&legacy_base).await.unwrap();
        std::fs::write(legacy_base.join("queued").join(".keep"), b"").unwrap();
        let orphan_id = new_ulid();
        legacy
            .put_meta(&orphan_id, &meta(&orphan_id, 1, Some("orphan")))
            .await
            .unwrap();

        let cfg = log_cfg(legacy_base.as_std_path(), true);
        assert!(maybe_auto_migrate(&cfg).await.unwrap().is_none());
        assert!(!legacy_base.join("spool").exists());
        assert!(legacy_base.join("queued").join(".keep").exists());
        assert!(legacy_base
            .join("deferred")
            .join(format!("{orphan_id}.meta.json"))
            .exists());
    }

    #[tokio::test]
    async fn unexpected_subdir_blocks_archiving_and_reports_path() {
        let dir = tempfile::tempdir().unwrap();
        let legacy_base = Utf8PathBuf::from_path_buf(dir.path().join("mail")).unwrap();
        let legacy = FileSystemStorage::new(&legacy_base).await.unwrap();
        let id = new_ulid();
        legacy
            .put(email(&id, &["r@example.com"], "body"), Status::Queued)
            .await
            .unwrap();
        let extra_dir = legacy_base.join("queued").join("extra_subdir");
        std::fs::create_dir_all(&extra_dir).unwrap();
        std::fs::write(extra_dir.join("notes.txt"), b"keep me").unwrap();

        let summary = migrate(
            &legacy_base,
            &legacy_base.as_std_path().join("spool"),
            1,
            writer_config(),
        )
        .await
        .unwrap();
        assert_eq!(summary.migrated_queued, 1);
        assert_eq!(summary.unexpected.len(), 1);
        assert!(summary
            .failed
            .iter()
            .any(|(p, _)| p.contains("extra_subdir")));
        assert!(legacy_base.join("queued").exists());
        assert!(extra_dir.join("notes.txt").exists());
    }

    #[tokio::test]
    async fn multiple_corrupt_files_are_all_reported_with_paths() {
        let dir = tempfile::tempdir().unwrap();
        let legacy_base = Utf8PathBuf::from_path_buf(dir.path().join("mail")).unwrap();
        let _legacy = FileSystemStorage::new(&legacy_base).await.unwrap();

        let bad1 = legacy_base.join("deferred").join("bad1.json");
        let bad2 = legacy_base.join("deferred").join("bad2.json");
        std::fs::write(&bad1, b"{not json 1").unwrap();
        std::fs::write(&bad2, b"{not json 2").unwrap();

        let summary = migrate(
            &legacy_base,
            &legacy_base.as_std_path().join("spool"),
            1,
            writer_config(),
        )
        .await
        .unwrap();
        assert_eq!(summary.failed.len(), 2, "{:?}", summary.failed);
        assert!(summary.failed.iter().any(|(p, _)| p.ends_with("bad1.json")));
        assert!(summary.failed.iter().any(|(p, _)| p.ends_with("bad2.json")));
        assert!(legacy_base.join("deferred").exists());
    }

    #[tokio::test]
    async fn cancellation_stops_migration_without_archiving_legacy_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let legacy_base = Utf8PathBuf::from_path_buf(dir.path().join("mail")).unwrap();
        let spool_root = legacy_base.as_std_path().join("spool");
        let legacy = FileSystemStorage::new(&legacy_base).await.unwrap();
        let id = new_ulid();
        legacy
            .put(email(&id, &["r@example.com"], "body"), Status::Queued)
            .await
            .unwrap();

        let token = CancellationToken::new();
        token.cancel();
        let summary =
            migrate_with_cancel(&legacy_base, &spool_root, 1, writer_config(), Some(&token))
                .await
                .unwrap();
        assert!(summary.interrupted);
        assert_eq!(summary.migrated_queued, 0);
        assert!(legacy_base.join("queued").exists());
        assert!(summary.renamed.is_empty());
    }

    #[tokio::test]
    async fn shrinking_empty_spool_allows_migration_then_startup_and_restart() {
        let dir = tempfile::tempdir().unwrap();
        let legacy_base = Utf8PathBuf::from_path_buf(dir.path().join("mail")).unwrap();
        let spool_root = legacy_base.as_std_path().join("spool");

        // Pre-create a 2-shard empty spool.
        {
            let _spool = Spool::open(&spool_root, 2).unwrap();
        }
        let legacy = FileSystemStorage::new(&legacy_base).await.unwrap();
        let id = new_ulid();
        legacy
            .put(email(&id, &["r@example.com"], "body"), Status::Queued)
            .await
            .unwrap();

        // Configure 1 writer + auto_migrate = true.
        let mut cfg = log_cfg(legacy_base.as_std_path(), true);
        cfg.queue = Some(crate::config::CfgQueue {
            append_writers: Some(1),
            ..Default::default()
        });

        let summary = maybe_auto_migrate(&cfg).await.unwrap().expect("migrated");
        assert_eq!(summary.migrated_queued, 1);
        assert!(summary.failed.is_empty());

        // Subsequent server Spool::open + restart with 1 writer must succeed.
        {
            let spool = Spool::open(&spool_root, 1).unwrap();
            assert_eq!(spool.shard_count(), 1);
        }
        assert!(maybe_auto_migrate(&cfg).await.unwrap().is_none());
        let spool = Spool::open(&spool_root, 1).unwrap();
        assert_eq!(spool.shard_count(), 1);
    }

    #[tokio::test]
    async fn backup_destination_collision_preflights_without_splitting_pair() {
        let dir = tempfile::tempdir().unwrap();
        let legacy_base = Utf8PathBuf::from_path_buf(dir.path().join("mail")).unwrap();
        let legacy = FileSystemStorage::new(&legacy_base).await.unwrap();
        let q_id = new_ulid();
        let d_id = new_ulid();
        legacy
            .put(email(&q_id, &["r1@example.com"], "q"), Status::Queued)
            .await
            .unwrap();
        legacy
            .put(email(&d_id, &["r2@example.com"], "d"), Status::Deferred)
            .await
            .unwrap();
        legacy
            .put_meta(&d_id, &meta(&d_id, 1, Some("421")))
            .await
            .unwrap();

        let inv = inspect_legacy_spool(legacy_base.as_std_path()).unwrap();
        let fixed_epoch = 1_700_000_000;
        std::fs::create_dir_all(legacy_base.join(format!("deferred.migrated-{fixed_epoch}")))
            .unwrap();

        let mut summary = MigrationSummary::default();
        rename_legacy_dirs_at(&legacy_base, &inv, fixed_epoch, &mut summary);
        // Preflight aborts before renaming queued/ so the pair is not split.
        assert!(summary.renamed.is_empty());
        assert_eq!(summary.failed.len(), 1);
        assert!(summary.failed[0].0.ends_with("deferred"));
        assert!(legacy_base.join("queued").exists());
        assert!(legacy_base.join("deferred").exists());
    }

    #[tokio::test]
    async fn stale_checkpoint_cursor_does_not_strand_migrated_mail() {
        let dir = tempfile::tempdir().unwrap();
        let legacy_base = Utf8PathBuf::from_path_buf(dir.path().join("mail")).unwrap();
        let spool_root = legacy_base.as_std_path().join("spool");

        // Append a message, write a checkpoint with cursor past it, then
        // simulate a crash that tore away the active segment tail.
        let lost_id = MessageId::parse(&new_ulid()).unwrap();
        {
            let spool = Spool::open(&spool_root, 1).unwrap();
            let writers = LogWriters::start(&spool, writer_config()).unwrap();
            let loc = writers
                .handle()
                .append(AppendMessage {
                    message_id: lost_id,
                    enqueue_ms: Utc::now().timestamp_millis(),
                    generation: 0,
                    sender: "sender@example.com".into(),
                    recipients: vec!["r@example.com".into()],
                    body: Bytes::from_static(b"same-size-body"),
                })
                .await
                .unwrap();
            writers.shutdown().await;

            let (mut store, _) = StateStore::recover(spool.shard(0).path(), 0).unwrap();
            store
                .write_checkpoint(&crate::logqueue::state::Checkpoint {
                    cursor: Some((loc.segment, loc.offset + loc.length as u64)),
                    ready: vec![],
                    deferred: vec![],
                    tombstones: vec![],
                    segment_stats: vec![],
                })
                .unwrap();

            // Truncate active segment back to 0 bytes (torn tail).
            let segs = spool.shard(0).list_segments().unwrap();
            let (_, active_path) = segs.active.expect("active segment");
            std::fs::OpenOptions::new()
                .write(true)
                .open(&active_path)
                .unwrap()
                .set_len(0)
                .unwrap();
        }

        // Now migrate a replacement legacy message of the same size.
        let legacy = FileSystemStorage::new(&legacy_base).await.unwrap();
        let replacement_id = new_ulid();
        legacy
            .put(
                email(&replacement_id, &["r@example.com"], "same-size-body"),
                Status::Queued,
            )
            .await
            .unwrap();

        let cfg = log_cfg(legacy_base.as_std_path(), true);
        let summary = maybe_auto_migrate(&cfg).await.unwrap().expect("migrated");
        assert_eq!(summary.migrated_queued, 1);
        assert!(summary.failed.is_empty());

        // Checkpoint cursor must have been clamped to 0 BEFORE the append so
        // server startup discovers the replacement message.
        let (_, recovered) = StateStore::recover(&spool_root.join("shard-0000"), 0).unwrap();
        assert_eq!(recovered.cursor, Some((1, 0)));
    }

    #[tokio::test]
    async fn meta_tmp_with_valid_authoritative_meta_does_not_block_migration() {
        let dir = tempfile::tempdir().unwrap();
        let legacy_base = Utf8PathBuf::from_path_buf(dir.path().join("mail")).unwrap();
        let legacy = FileSystemStorage::new(&legacy_base).await.unwrap();

        let id = new_ulid();
        legacy
            .put(
                email(&id, &["r@example.com"], "deferred body"),
                Status::Deferred,
            )
            .await
            .unwrap();
        legacy
            .put_meta(&id, &meta(&id, 2, Some("421 retry")))
            .await
            .unwrap();
        // Leftover staging file from a crash mid-put_meta.
        std::fs::write(
            legacy_base
                .join("deferred")
                .join(format!("{id}.meta.json.tmp")),
            b"partial",
        )
        .unwrap();

        let cfg = log_cfg(legacy_base.as_std_path(), true);
        let summary = maybe_auto_migrate(&cfg).await.unwrap().expect("migrated");
        assert_eq!(summary.migrated_deferred, 1);
        assert!(summary.failed.is_empty());
        assert!(!legacy_base.join("deferred").exists());
    }

    #[tokio::test]
    async fn unpaired_meta_tmp_blocks_startup_auto_migrate() {
        let dir = tempfile::tempdir().unwrap();
        let legacy_base = Utf8PathBuf::from_path_buf(dir.path().join("mail")).unwrap();
        let _legacy = FileSystemStorage::new(&legacy_base).await.unwrap();
        let id = new_ulid();
        std::fs::write(
            legacy_base
                .join("deferred")
                .join(format!("{id}.meta.json.tmp")),
            b"uncommitted",
        )
        .unwrap();

        let cfg = log_cfg(legacy_base.as_std_path(), true);
        let err = maybe_auto_migrate(&cfg).await.unwrap_err();
        assert!(
            err.to_string().contains("unexpected non-mail entry"),
            "{err:#}"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unexpected_only_symlink_fails_startup_auto_migrate() {
        let dir = tempfile::tempdir().unwrap();
        let legacy_base = Utf8PathBuf::from_path_buf(dir.path().join("mail")).unwrap();
        let _legacy = FileSystemStorage::new(&legacy_base).await.unwrap();
        let target = dir.path().join("outside.json");
        std::fs::write(&target, b"{}").unwrap();
        std::os::unix::fs::symlink(&target, legacy_base.join("queued").join("link.json")).unwrap();

        let cfg = log_cfg(legacy_base.as_std_path(), true);
        let err = maybe_auto_migrate(&cfg).await.unwrap_err();
        assert!(err.to_string().contains("link.json"), "{err:#}");
    }

    #[tokio::test]
    async fn auto_migrate_disabled_leaves_legacy_spool_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let legacy_base = Utf8PathBuf::from_path_buf(dir.path().join("mail")).unwrap();
        let legacy = FileSystemStorage::new(&legacy_base).await.unwrap();
        let id = new_ulid();
        legacy
            .put(email(&id, &["r@example.com"], "body"), Status::Queued)
            .await
            .unwrap();

        let cfg = log_cfg(legacy_base.as_std_path(), false);
        let outcome = maybe_auto_migrate(&cfg).await.unwrap();
        assert!(outcome.is_none());
        assert!(legacy_base.join("queued").exists());
        assert!(!legacy_base.join("spool").exists());
    }

    #[tokio::test]
    async fn auto_migrate_enabled_migrates_once_then_is_noop_on_restart() {
        let dir = tempfile::tempdir().unwrap();
        let legacy_base = Utf8PathBuf::from_path_buf(dir.path().join("mail")).unwrap();
        let legacy = FileSystemStorage::new(&legacy_base).await.unwrap();

        let q_id = new_ulid();
        legacy
            .put(email(&q_id, &["r1@example.com"], "queued"), Status::Queued)
            .await
            .unwrap();
        let d_id = new_ulid();
        legacy
            .put(
                email(&d_id, &["r2@example.com"], "deferred"),
                Status::Deferred,
            )
            .await
            .unwrap();
        legacy
            .put_meta(&d_id, &meta(&d_id, 2, Some("451 tempfail")))
            .await
            .unwrap();
        let b_id = new_ulid();
        legacy
            .put(
                email(&b_id, &["r3@example.com"], "bounced"),
                Status::Bounced,
            )
            .await
            .unwrap();

        let cfg = log_cfg(legacy_base.as_std_path(), true);
        let summary = maybe_auto_migrate(&cfg)
            .await
            .unwrap()
            .expect("first boot should run migration");
        assert_eq!(summary.migrated_queued, 1);
        assert_eq!(summary.migrated_deferred, 1);
        assert_eq!(summary.renamed.len(), 2);
        assert!(summary.failed.is_empty());

        let bounce_store = FileSystemStorage::new(&legacy_base).await.unwrap();
        assert!(bounce_store.exists(&b_id, Status::Bounced).await.unwrap());

        let second = maybe_auto_migrate(&cfg).await.unwrap();
        assert!(second.is_none());

        let spool_root = legacy_base.as_std_path().join("spool");
        assert!(find_ready(&spool_root, 1, MessageId::parse(&q_id).unwrap())
            .await
            .is_some());
        let recovered_d = deferred_entry(&spool_root, 1, MessageId::parse(&d_id).unwrap())
            .expect("deferred message preserved");
        assert_eq!(recovered_d.attempts, 2);
        assert_eq!(recovered_d.last_error, "451 tempfail");
    }

    #[tokio::test]
    async fn auto_migrate_enabled_on_empty_dir_does_not_create_spool() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("fresh");
        std::fs::create_dir_all(&base).unwrap();

        let cfg = log_cfg(&base, true);
        assert!(maybe_auto_migrate(&cfg).await.unwrap().is_none());
        assert!(!base.join("spool").exists());
    }

    #[tokio::test]
    async fn auto_migrate_fails_fast_on_corrupt_file_and_recovers_on_retry() {
        let dir = tempfile::tempdir().unwrap();
        let legacy_base = Utf8PathBuf::from_path_buf(dir.path().join("mail")).unwrap();
        let legacy = FileSystemStorage::new(&legacy_base).await.unwrap();

        let good_id = new_ulid();
        legacy
            .put(email(&good_id, &["r@example.com"], "good"), Status::Queued)
            .await
            .unwrap();
        let bad_file = legacy_base.join("deferred").join("corrupt.json");
        std::fs::write(&bad_file, b"{not valid json").unwrap();

        let cfg = log_cfg(legacy_base.as_std_path(), true);
        let err = maybe_auto_migrate(&cfg).await.unwrap_err();
        assert!(
            err.to_string()
                .contains("automatic legacy spool migration failed"),
            "unexpected error: {err:#}"
        );
        assert!(legacy_base.join("queued").exists());
        assert!(legacy_base.join("deferred").exists());

        std::fs::remove_file(&bad_file).unwrap();
        let retry = maybe_auto_migrate(&cfg)
            .await
            .unwrap()
            .expect("retry should run migration");
        assert_eq!(retry.migrated_queued, 0);
        assert_eq!(retry.migrated_deferred, 0);
        assert_eq!(retry.skipped, 1);
        assert!(retry.failed.is_empty());
        assert!(!legacy_base.join("queued").exists());

        let counts = count_payload_records(&legacy_base.as_std_path().join("spool"), 0);
        assert_eq!(
            counts.get(&MessageId::parse(&good_id).unwrap()).copied(),
            Some(1)
        );
    }

    #[tokio::test]
    async fn auto_migrate_fails_when_spool_lock_is_held() {
        let dir = tempfile::tempdir().unwrap();
        let legacy_base = Utf8PathBuf::from_path_buf(dir.path().join("mail")).unwrap();
        let legacy = FileSystemStorage::new(&legacy_base).await.unwrap();
        let id = new_ulid();
        legacy
            .put(email(&id, &["r@example.com"], "body"), Status::Queued)
            .await
            .unwrap();

        let _lock_holder = Spool::open(legacy_base.as_std_path().join("spool"), 1).unwrap();
        let cfg = log_cfg(legacy_base.as_std_path(), true);
        assert!(maybe_auto_migrate(&cfg).await.is_err());
        assert!(legacy_base.join("queued").exists());
    }
}
