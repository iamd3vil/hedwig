//! One-time, restart-safe migration from the legacy filesystem spool to the
//! log queue (PLAN.md §23 "Migration from the current filesystem spool").
//!
//! Unlike `queue_cli`, this module WRITES to the new spool: it takes the
//! exclusive spool lock (refusing to run if another process — including a
//! live `hedwig` server on the log backend — already holds it), appends
//! every live legacy message to its shard, and only after verifying every
//! appended id landed does it rename the legacy `queued/`/`deferred/`
//! directories to timestamped backups. Legacy data is never deleted.
//!
//! There is no lock on the legacy filesystem spool itself, so the operator
//! must ensure no other process (in particular a `hedwig` server still
//! running against the old `fs`/`sqlite` config) is mutating it while this
//! runs.
//!
//! Restart-safety: re-running after a crash or a failed run is safe. Already
//! migrated ids are detected by [`scan_already_present`] and skipped; the
//! legacy directories are only renamed once every append has been verified,
//! so a partial run simply leaves work for the next invocation to finish.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use camino::Utf8Path;
use chrono::Utc;
use futures::StreamExt;
use miette::{IntoDiagnostic, Result, WrapErr};

use crate::logqueue::segment::{open_segment_reader, scan_headers};
use crate::logqueue::spool::Spool;
use crate::logqueue::state::{load_state_readonly, ShardStateStore, StateEntry};
use crate::logqueue::writer::{AppendHandle, AppendMessage, LogWriters, WriterConfig};
use crate::logqueue::MessageId;
use crate::storage::fs_storage::FileSystemStorage;
use crate::storage::{Status, Storage, StoredEmail};
use crate::worker::EmailMetadata;

/// Outcome of a one-time migration run.
#[derive(Debug, Default)]
pub struct MigrationSummary {
    pub migrated_queued: usize,
    pub migrated_deferred: usize,
    pub skipped: usize,
    /// (legacy message id or a synthetic marker, error message) for anything
    /// that could not be migrated or verified. Non-empty means the legacy
    /// spool was NOT renamed to a backup.
    pub failed: Vec<(String, String)>,
}

impl MigrationSummary {
    pub fn print(&self) {
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
    let legacy = FileSystemStorage::new(legacy_base_path)
        .await
        .wrap_err("opening legacy filesystem spool")?;

    // Exclusive lock: guarantees no other process is concurrently appending
    // to (or recovering) this spool root. There is no equivalent lock on the
    // legacy spool; the caller is responsible for having stopped the server.
    let spool = Spool::open(spool_root, shard_count)
        .map_err(miette::Report::new)
        .wrap_err("opening log-queue spool (is another hedwig process using it?)")?;

    let writers = LogWriters::start(&spool, writer_config.clone())
        .map_err(miette::Report::new)
        .wrap_err("starting append writers")?;
    let handle = writers.handle();

    let already_present = scan_already_present(&spool, &handle, writer_config.max_record_len)
        .wrap_err("scanning existing log-queue spool for already-migrated messages")?;

    let mut summary = MigrationSummary::default();
    let mut state_stores: HashMap<u16, ShardStateStore> = HashMap::new();
    let mut migrated: Vec<(MessageId, u16)> = Vec::new();

    migrate_status(
        &legacy,
        Status::Queued,
        &handle,
        &spool,
        &already_present,
        &mut state_stores,
        &mut migrated,
        &mut summary,
    )
    .await;
    migrate_status(
        &legacy,
        Status::Deferred,
        &handle,
        &spool,
        &already_present,
        &mut state_stores,
        &mut migrated,
        &mut summary,
    )
    .await;

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

    // Verification: every id appended in this run must be discoverable as a
    // payload record in its shard now that the writer has flushed and
    // finished. Run this even if earlier steps already recorded failures, so
    // the report is complete.
    verify_migrated(&spool, &migrated, writer_config.max_record_len, &mut summary)
        .wrap_err("verifying migrated messages")?;

    if summary.failed.is_empty() {
        rename_legacy_dirs(legacy_base_path).wrap_err("renaming legacy spool directories to backups")?;
    } else {
        println!(
            "migration had failures; legacy queued/deferred directories were left in place \
             (safe to re-run this command)"
        );
    }

    Ok(summary)
}

/// Every message id already present in the new spool: discovered either as a
/// payload record (scanning every segment in each shard's append chain) or
/// referenced by the shard's persisted state (checkpointed/journaled ready,
/// deferred, or tombstoned ids — covers ids whose original segment a prior
/// compaction run may since have removed).
fn scan_already_present(
    spool: &Spool,
    handle: &AppendHandle,
    max_record_len: u32,
) -> Result<HashSet<MessageId>> {
    let mut ids = HashSet::new();
    for shard_dir in spool.shards() {
        let shard = shard_dir.shard();
        let dir = shard_dir.path();

        let chain = handle.shard_shared(shard).chain();
        for head in &chain {
            if head.committed == 0 {
                continue;
            }
            let reader = open_segment_reader(dir, head.segment)
                .map_err(miette::Report::new)
                .wrap_err_with(|| format!("opening shard {shard} segment {}", head.segment))?;
            scan_headers(&reader, 0, head.committed, max_record_len, |_, header| {
                ids.insert(header.message_id);
                true
            })
            .map_err(miette::Report::new)
            .wrap_err_with(|| format!("scanning shard {shard} segment {}", head.segment))?;
        }

        let state = load_state_readonly(dir)
            .map_err(miette::Report::new)
            .wrap_err_with(|| format!("loading shard {shard} state"))?;
        ids.extend(state.ready.keys().copied());
        ids.extend(state.deferred.keys().copied());
        for tomb_ids in state.tombstones.values() {
            ids.extend(tomb_ids.iter().copied());
        }
    }
    Ok(ids)
}

enum Outcome {
    Migrated { deferred: bool },
    Skipped,
}

#[allow(clippy::too_many_arguments)]
async fn migrate_status(
    legacy: &FileSystemStorage,
    status: Status,
    handle: &AppendHandle,
    spool: &Spool,
    already_present: &HashSet<MessageId>,
    state_stores: &mut HashMap<u16, ShardStateStore>,
    migrated: &mut Vec<(MessageId, u16)>,
    summary: &mut MigrationSummary,
) {
    let origin_is_deferred = matches!(status, Status::Deferred);
    let mut stream = legacy.list(status);
    while let Some(item) = stream.next().await {
        let stored = match item {
            Ok(s) => s,
            Err(e) => {
                summary
                    .failed
                    .push(("<unknown>".to_string(), format!("listing legacy spool: {e:#}")));
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
            already_present,
            state_stores,
            migrated,
        )
        .await
        {
            Ok(Outcome::Migrated { deferred }) => {
                if deferred {
                    summary.migrated_deferred += 1;
                } else {
                    summary.migrated_queued += 1;
                }
            }
            Ok(Outcome::Skipped) => summary.skipped += 1,
            Err(e) => summary.failed.push((message_id, format!("{e:#}"))),
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
    already_present: &HashSet<MessageId>,
    state_stores: &mut HashMap<u16, ShardStateStore>,
    migrated: &mut Vec<(MessageId, u16)>,
) -> Result<Outcome> {
    let id = match MessageId::parse(&stored.message_id) {
        Ok(id) => id,
        Err(_) => {
            // Deterministic remap: derive the new id from the legacy id so
            // a re-run after a crash produces the same id and the dedup set
            // catches it, instead of appending a duplicate under a second
            // random id.
            let fresh = derived_message_id(&stored.message_id);
            tracing::warn!(
                legacy_id = %stored.message_id,
                new_id = %fresh,
                "legacy message id is not a valid ULID; derived a stable replacement id"
            );
            println!(
                "note: legacy id {} is not a valid ULID; migrating under derived id {}",
                stored.message_id, fresh
            );
            fresh
        }
    };

    if already_present.contains(&id) {
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

    let enqueue_ms = stored
        .queued_at
        .map(|dt| dt.timestamp_millis())
        .unwrap_or_else(|| Utc::now().timestamp_millis());
    let recipients = stored.to.clone();
    let body = Bytes::from(stored.body.into_bytes());

    let msg = AppendMessage {
        message_id: id,
        enqueue_ms,
        generation: 0,
        sender: stored.from,
        recipients: recipients.clone(),
        body,
    };
    let location = handle
        .append(msg)
        .await
        .map_err(miette::Report::new)
        .wrap_err("appending message body to the log queue")?;

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
    }

    migrated.push((id, location.shard));
    Ok(Outcome::Migrated { deferred: is_deferred })
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
    use hmac::Mac;
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

/// Re-scan every shard's segments (writers already shut down, so files are
/// stable) and confirm every id appended in this run is present.
fn verify_migrated(
    spool: &Spool,
    migrated: &[(MessageId, u16)],
    max_record_len: u32,
    summary: &mut MigrationSummary,
) -> Result<()> {
    let mut by_shard: HashMap<u16, HashSet<MessageId>> = HashMap::new();
    for (id, shard) in migrated {
        by_shard.entry(*shard).or_default().insert(*id);
    }

    for (shard, wanted) in &by_shard {
        let shard_dir = spool.shard(*shard);
        let segs = shard_dir
            .list_segments()
            .map_err(miette::Report::new)
            .wrap_err_with(|| format!("listing shard {shard} segments"))?;
        let mut found = HashSet::new();
        for (ordinal, path) in segs.sealed.iter().chain(segs.active.iter()) {
            let len = std::fs::metadata(path)
                .into_diagnostic()
                .wrap_err_with(|| format!("stat {}", path.display()))?
                .len();
            let reader = open_segment_reader(shard_dir.path(), *ordinal)
                .map_err(miette::Report::new)
                .wrap_err_with(|| format!("opening shard {shard} segment {ordinal}"))?;
            scan_headers(&reader, 0, len, max_record_len, |_, header| {
                found.insert(header.message_id);
                true
            })
            .map_err(miette::Report::new)
            .wrap_err_with(|| format!("scanning shard {shard} segment {ordinal}"))?;
        }
        for id in wanted {
            if !found.contains(id) {
                summary.failed.push((
                    id.to_string(),
                    "missing from spool after migration (verification failed)".to_string(),
                ));
            }
        }
    }
    Ok(())
}

/// Rename `queued/` and `deferred/` to timestamped backups. `bounced/` is
/// left untouched: it remains the live bounce archive under the log backend.
/// Never deletes anything.
fn rename_legacy_dirs(legacy_base_path: &Utf8Path) -> Result<()> {
    let epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    for name in ["queued", "deferred"] {
        let src = legacy_base_path.join(name);
        if !src.exists() {
            continue;
        }
        // Nothing to preserve, and nothing renamed: a re-run after a prior
        // success recreates an empty dir here (`FileSystemStorage::new`
        // always ensures queued/deferred/bounced exist) with no messages
        // left to migrate. Renaming it would risk colliding with a backup
        // this same command already created a moment ago.
        if dir_is_empty(&src)? {
            continue;
        }
        let dest = legacy_base_path.join(format!("{name}.migrated-{epoch}"));
        std::fs::rename(&src, &dest)
            .into_diagnostic()
            .wrap_err_with(|| format!("renaming {src} to {dest}"))?;
        println!("renamed {src} -> {dest}");
    }
    Ok(())
}

fn dir_is_empty(path: &Utf8Path) -> Result<bool> {
    let mut entries = std::fs::read_dir(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("reading {path}"))?;
    Ok(entries.next().is_none())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logqueue::record;
    use crate::logqueue::state::ShardStateStore as StateStore;
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
        ulid::Ulid::new().to_string()
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
        let shard_dir = crate::logqueue::shard::ShardDir::open_or_create(spool_root, shard).unwrap();
        let segs = shard_dir.list_segments().unwrap();
        for (ordinal, path) in segs.sealed.iter().chain(segs.active.iter()) {
            let reader = open_segment_reader(&dir, *ordinal).unwrap();
            let len = std::fs::metadata(path).unwrap().len();
            scan_headers(&reader, 0, len, record::MAX_RECORD_LEN, |_, header| {
                *counts.entry(header.message_id).or_insert(0) += 1;
                true
            })
            .unwrap();
        }
        counts
    }

    async fn find_ready(spool_root: &Path, shard_count: u16, id: MessageId) -> Option<(String, String, Vec<u8>)> {
        for shard in 0..shard_count {
            let dir = spool_root.join(crate::logqueue::shard::shard_dir_name(shard));
            if !dir.exists() {
                continue;
            }
            let shard_dir = crate::logqueue::shard::ShardDir::open_or_create(spool_root, shard).unwrap();
            let segs = shard_dir.list_segments().unwrap();
            for (ordinal, path) in segs.sealed.iter().chain(segs.active.iter()) {
                let reader = open_segment_reader(&dir, *ordinal).unwrap();
                let len = std::fs::metadata(path).unwrap().len();
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

    fn deferred_entry(spool_root: &Path, shard_count: u16, id: MessageId) -> Option<crate::logqueue::state::DeferredJob> {
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

    #[tokio::test]
    async fn migrates_queued_and_deferred_with_meta() {
        let dir = tempfile::tempdir().unwrap();
        let legacy_base = camino::Utf8PathBuf::from_path_buf(dir.path().join("legacy")).unwrap();
        let spool_root = dir.path().join("legacy").join("spool");

        let legacy = FileSystemStorage::new(&legacy_base).await.unwrap();

        // A plain queued message, never retried.
        let q1_id = new_ulid();
        legacy
            .put(email(&q1_id, &["r1@example.com"], "queued body"), Status::Queued)
            .await
            .unwrap();

        // A queued message that is mid-retry: body still in queued/, but a
        // meta file records a prior failed attempt.
        let q2_id = new_ulid();
        legacy
            .put(email(&q2_id, &["r2@example.com"], "mid-retry body"), Status::Queued)
            .await
            .unwrap();
        legacy.put_meta(&q2_id, &meta(&q2_id, 2, Some("451 try later"))).await.unwrap();

        // A fully deferred message.
        let d1_id = new_ulid();
        legacy
            .put(email(&d1_id, &["r3@example.com"], "deferred body"), Status::Deferred)
            .await
            .unwrap();
        legacy.put_meta(&d1_id, &meta(&d1_id, 3, Some("450 backoff"))).await.unwrap();

        let summary = migrate(&legacy_base, &spool_root, 2, writer_config()).await.unwrap();
        assert_eq!(summary.migrated_queued, 1, "{summary:?}");
        assert_eq!(summary.migrated_deferred, 2);
        assert_eq!(summary.skipped, 0);
        assert!(summary.failed.is_empty(), "unexpected failures: {:?}", summary.failed);

        let q1 = MessageId::parse(&q1_id).unwrap();
        let (sender, rcpts, body) = find_ready(&spool_root, 2, q1).await.unwrap();
        assert_eq!(sender, "sender@example.com");
        assert_eq!(rcpts, "r1@example.com");
        assert_eq!(body, b"queued body");
        assert!(deferred_entry(&spool_root, 2, q1).is_none());

        let q2 = MessageId::parse(&q2_id).unwrap();
        assert!(find_ready(&spool_root, 2, q2).await.is_some());
        let d = deferred_entry(&spool_root, 2, q2).expect("mid-retry meta migrates as deferred state");
        assert_eq!(d.attempts, 2);
        assert_eq!(d.remaining_recipients, vec!["r2@example.com".to_string()]);
        assert_eq!(d.last_error, "451 try later");

        let d1 = MessageId::parse(&d1_id).unwrap();
        assert!(find_ready(&spool_root, 2, d1).await.is_some());
        let d = deferred_entry(&spool_root, 2, d1).expect("deferred message has state");
        assert_eq!(d.attempts, 3);
        assert_eq!(d.remaining_recipients, vec!["r3@example.com".to_string()]);
        assert_eq!(d.last_error, "450 backoff");

        // Backup directories exist; bounced/ untouched (never created here,
        // but queued/deferred must be renamed away).
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
        let legacy_base = camino::Utf8PathBuf::from_path_buf(dir.path().join("legacy")).unwrap();
        let spool_root = dir.path().join("legacy").join("spool");

        let legacy = FileSystemStorage::new(&legacy_base).await.unwrap();
        let id = new_ulid();
        legacy.put(email(&id, &["r@example.com"], "body"), Status::Queued).await.unwrap();

        let first = migrate(&legacy_base, &spool_root, 1, writer_config()).await.unwrap();
        assert_eq!(first.migrated_queued, 1);
        assert!(first.failed.is_empty());

        // Nothing left in queued/ (renamed away), so a second run finds
        // nothing new to migrate and nothing to skip either.
        let second = migrate(&legacy_base, &spool_root, 1, writer_config()).await.unwrap();
        assert_eq!(second.migrated_queued, 0);
        assert_eq!(second.migrated_deferred, 0);
        assert_eq!(second.skipped, 0);
        assert!(second.failed.is_empty());

        let parsed = MessageId::parse(&id).unwrap();
        assert!(find_ready(&spool_root, 1, parsed).await.is_some());
    }

    #[tokio::test]
    async fn already_migrated_id_left_in_legacy_spool_is_skipped_not_duplicated() {
        // Simulates re-running after a crash right before the backup rename:
        // the message already has a payload record in the new spool AND its
        // body is still sitting in the legacy queued/ directory.
        let dir = tempfile::tempdir().unwrap();
        let legacy_base = camino::Utf8PathBuf::from_path_buf(dir.path().join("legacy")).unwrap();
        let spool_root = dir.path().join("legacy").join("spool");

        let legacy = FileSystemStorage::new(&legacy_base).await.unwrap();
        let id = new_ulid();
        legacy.put(email(&id, &["r@example.com"], "body"), Status::Queued).await.unwrap();

        // Pre-seed the new spool with this id's payload record directly, as
        // if a prior migration run had appended it before crashing.
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

        let summary = migrate(&legacy_base, &spool_root, 1, writer_config()).await.unwrap();
        assert_eq!(summary.migrated_queued, 0);
        assert_eq!(summary.skipped, 1);
        assert!(summary.failed.is_empty());

        // Exactly one payload record for this id (no duplicate append).
        let target = MessageId::parse(&id).unwrap();
        let counts = count_payload_records(&spool_root, 0);
        assert_eq!(counts.get(&target).copied().unwrap_or(0), 1);
    }

    #[tokio::test]
    async fn non_ulid_legacy_id_is_remapped_to_a_fresh_ulid() {
        let dir = tempfile::tempdir().unwrap();
        let legacy_base = camino::Utf8PathBuf::from_path_buf(dir.path().join("legacy")).unwrap();
        let spool_root = dir.path().join("legacy").join("spool");

        let legacy = FileSystemStorage::new(&legacy_base).await.unwrap();
        legacy
            .put(email("not-a-ulid", &["r@example.com"], "body"), Status::Queued)
            .await
            .unwrap();

        let summary = migrate(&legacy_base, &spool_root, 1, writer_config()).await.unwrap();
        assert_eq!(summary.migrated_queued, 1);
        assert!(summary.failed.is_empty());
    }
}
