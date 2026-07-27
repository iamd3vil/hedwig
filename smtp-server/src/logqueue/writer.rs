//! Append writers: one per shard, each exclusively owning its shard's
//! active segment.
//!
//! Admission is bounded by pending bytes (not request count): a permit for
//! the encoded record size is acquired before the request is queued and
//! released once the bytes have been handed to the kernel page cache. SMTP
//! acceptance awaits only this append completion.
//!
//! Publish ordering per record (PLAN §9.5): write the complete record, then
//! advance the shard's committed head under the state lock, then notify the
//! dispatcher, then complete the request. The committed head never exposes
//! a partial record.

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use tokio::sync::{mpsc, oneshot, Notify, Semaphore};

use super::record::{self, RecordParams};
use super::segment::{validate_active_tail, ActiveSegment};
use super::shard::ShardDir;
use super::spool::Spool;
use super::{JobLocation, MessageId, QueueError};

/// Configuration for the writer set. Values come from `[queue]` config;
/// validation (segment sizing vs. max message size) happens at startup.
#[derive(Debug, Clone)]
pub struct WriterConfig {
    /// Seal the active segment once it reaches this size.
    pub segment_target_bytes: u64,
    /// Hard cap on one encoded record; also the scan bound. Derived from
    /// the configured maximum message size plus envelope allowance.
    pub max_record_len: u32,
    /// Total bytes of not-yet-written admission buffering across all shards.
    pub pending_append_bytes: u64,
}

/// One committed segment head. `committed` is the offset one past the last
/// complete record; for sealed entries it is the segment's final length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentHead {
    pub segment: u64,
    pub committed: u64,
    pub sealed: bool,
}

/// State a shard's writer shares with the dispatcher: the ordered chain of
/// append segments (last entry is the active one) and a wake-up hint.
///
/// The chain contains only segments used as append targets, in append
/// order. Compaction outputs never appear here, which is what keeps them
/// out of discovery. Fully-consumed sealed entries are pruned by the
/// dispatcher/GC via [`ShardShared::prune`].
pub struct ShardShared {
    shard: u16,
    chain: Mutex<Vec<SegmentHead>>,
    /// Lossy wake-up hint for the dispatcher; the chain is authoritative.
    pub notify: Notify,
}

impl ShardShared {
    fn new(shard: u16, initial: Vec<SegmentHead>) -> Self {
        Self {
            shard,
            chain: Mutex::new(initial),
            notify: Notify::new(),
        }
    }

    pub fn shard(&self) -> u16 {
        self.shard
    }

    /// Snapshot of the append chain.
    pub fn chain(&self) -> Vec<SegmentHead> {
        self.chain.lock().unwrap().clone()
    }

    /// Remove sealed chain entries the caller no longer needs (everything
    /// strictly below `segment`). The active entry is never pruned.
    pub fn prune(&self, segment: u64) {
        let mut chain = self.chain.lock().unwrap();
        chain.retain(|h| h.segment >= segment || !h.sealed);
    }

    /// Remove one sealed segment from the chain (it was deleted by GC).
    /// The active entry is never removed.
    pub fn remove_segment(&self, segment: u64) {
        let mut chain = self.chain.lock().unwrap();
        chain.retain(|h| h.segment != segment || !h.sealed);
    }

    fn advance_committed(&self, segment: u64, committed: u64) {
        let mut chain = self.chain.lock().unwrap();
        let head = chain
            .last_mut()
            .expect("advance_committed on empty chain");
        debug_assert_eq!(head.segment, segment);
        debug_assert!(!head.sealed && committed > head.committed);
        head.committed = committed;
    }

    fn seal_segment(&self, sealed_segment: u64, final_len: u64) {
        let mut chain = self.chain.lock().unwrap();
        let head = chain.last_mut().expect("seal_segment on empty chain");
        debug_assert_eq!(head.segment, sealed_segment);
        head.committed = final_len;
        head.sealed = true;
    }

    fn open_segment(&self, next_segment: u64) {
        let mut chain = self.chain.lock().unwrap();
        debug_assert!(chain.last().is_none_or(|h| h.sealed));
        chain.push(SegmentHead {
            segment: next_segment,
            committed: 0,
            sealed: false,
        });
    }
}

/// A message to be appended. `enqueue_ms` is stamped by the caller so queue
/// age survives relocation and restarts. `generation` is 0 for new mail;
/// compaction re-appends live records with a higher relocation generation.
pub struct AppendMessage {
    pub message_id: MessageId,
    pub enqueue_ms: i64,
    pub generation: u32,
    pub sender: String,
    pub recipients: Vec<String>,
    pub body: Bytes,
}

struct AppendRequest {
    msg: AppendMessage,
    encoded_len: u32,
    completion: oneshot::Sender<Result<JobLocation, QueueError>>,
}

enum WriterMsg {
    Append(AppendRequest),
    /// Close admission: the writer finishes everything queued before this
    /// sentinel and exits; anything queued after it fails `WriterClosed`.
    Shutdown,
}

struct ShardChannel {
    tx: mpsc::UnboundedSender<WriterMsg>,
    shared: Arc<ShardShared>,
}

/// Cloneable admission handle used by the SMTP acceptance path.
#[derive(Clone)]
pub struct AppendHandle {
    shards: Arc<Vec<ShardChannel>>,
    /// Byte-bounded admission shared across shards.
    pending_bytes: Arc<Semaphore>,
    pending_limit: u64,
    max_record_len: u32,
}

impl AppendHandle {
    /// Route a message id to its shard: the low bytes of a ULID are random,
    /// so a modulo over them distributes uniformly. Only ever used for NEW
    /// messages — existing records carry their explicit location.
    pub fn shard_for(&self, id: &MessageId) -> u16 {
        (u16::from_le_bytes([id.0[14], id.0[15]])) % self.shards.len() as u16
    }

    pub fn shard_shared(&self, shard: u16) -> Arc<ShardShared> {
        Arc::clone(&self.shards[shard as usize].shared)
    }

    #[cfg(test)]
    pub fn shard_count(&self) -> u16 {
        self.shards.len() as u16
    }

    /// Append a message and wait until it is accepted by the kernel page
    /// cache. Returns its physical location. Applies byte-bounded admission
    /// backpressure while the writer is behind.
    pub async fn append(&self, msg: AppendMessage) -> Result<JobLocation, QueueError> {
        let shard = self.shard_for(&msg.message_id);
        self.append_to_shard(shard, msg).await
    }

    /// Append to an explicit shard. New mail must use [`Self::append`]
    /// (stable hash routing); this exists for compaction, which relocates a
    /// record within the shard that owns its state journal.
    pub async fn append_to_shard(
        &self,
        shard: u16,
        msg: AppendMessage,
    ) -> Result<JobLocation, QueueError> {
        let params = RecordParams {
            message_id: msg.message_id,
            enqueue_ms: msg.enqueue_ms,
            generation: msg.generation,
            ordinal: 0, // assigned by the writer; same encoded size
            sender: &msg.sender,
            recipients: &msg.recipients,
            body: &msg.body,
        };
        let encoded_len = record::encoded_len(&params)?;
        if encoded_len > self.max_record_len {
            return Err(QueueError::RecordTooLarge {
                len: encoded_len as u64,
                limit: self.max_record_len as u64,
            });
        }

        // Acquire admission permits for the encoded size, clamped so one
        // huge record cannot exceed the whole semaphore (it then simply
        // occupies all admission capacity while queued).
        let permits = (encoded_len as u64).min(self.pending_limit) as u32;
        let permit = Arc::clone(&self.pending_bytes)
            .acquire_many_owned(permits)
            .await
            .expect("admission semaphore is never closed");
        crate::metrics::logqueue_pending_append_bytes_set(
            self.pending_limit - self.pending_bytes.available_permits() as u64,
        );

        let (tx, rx) = oneshot::channel();
        self.shards[shard as usize]
            .tx
            .send(WriterMsg::Append(AppendRequest {
                msg,
                encoded_len,
                completion: tx,
            }))
            .map_err(|_| QueueError::WriterClosed(shard))?;

        let result = rx.await.map_err(|_| QueueError::WriterClosed(shard))?;
        // Bytes are in the page cache (or failed); admission capacity frees
        // either way.
        drop(permit);
        result
    }
}

/// The writer set: spawns one blocking writer task per shard.
pub struct LogWriters {
    handle: AppendHandle,
    join: Vec<tokio::task::JoinHandle<()>>,
}

impl LogWriters {
    /// Recover every shard (validating and truncating active tails) and
    /// start the writer tasks.
    pub fn start(spool: &Spool, config: WriterConfig) -> Result<Self, QueueError> {
        let mut shards = Vec::with_capacity(spool.shard_count() as usize);
        let mut join = Vec::with_capacity(spool.shard_count() as usize);

        for shard_dir in spool.shards() {
            let (state, shared) = ShardWriter::recover(shard_dir)?;
            let shared = Arc::new(shared);
            let (tx, rx) = mpsc::unbounded_channel();
            let writer_shared = Arc::clone(&shared);
            let cfg = config.clone();
            join.push(tokio::task::spawn_blocking(move || {
                ShardWriter::run(state, rx, writer_shared, cfg)
            }));
            shards.push(ShardChannel { tx, shared });
        }

        Ok(Self {
            handle: AppendHandle {
                shards: Arc::new(shards),
                pending_bytes: Arc::new(Semaphore::new(config.pending_append_bytes as usize)),
                pending_limit: config.pending_append_bytes,
                max_record_len: config.max_record_len,
            },
            join,
        })
    }

    pub fn handle(&self) -> AppendHandle {
        self.handle.clone()
    }

    /// Close admission and wait for every writer to finish everything
    /// queued so far. Appends submitted after this fail with
    /// [`QueueError::WriterClosed`], even through surviving handle clones.
    pub async fn shutdown(self) {
        for shard in self.handle.shards.iter() {
            let _ = shard.tx.send(WriterMsg::Shutdown);
        }
        for task in self.join {
            if let Err(e) = task.await {
                tracing::error!(error = %e, "append writer task failed during shutdown");
            }
        }
    }
}

/// Per-shard writer state, owned by one blocking task. `active` is `None`
/// only in the window after a seal succeeded but creating the replacement
/// failed; the next append retries the create instead of ever writing into
/// the sealed file.
struct ShardWriter {
    dir: ShardDir,
    active: Option<ActiveSegment>,
    next_segment: u64,
}

impl ShardWriter {
    /// Open the shard: validate/truncate the active tail if one exists,
    /// otherwise create the next segment. Returns the writer state and the
    /// initial shared chain (sealed segments + active head).
    fn recover(dir: &ShardDir) -> Result<(Self, ShardShared), QueueError> {
        let segments = dir.list_segments()?;
        let mut chain: Vec<SegmentHead> = Vec::new();

        // Sealed segments enter the chain in ordinal order with their file
        // length as the committed length. (Once compaction exists, its
        // output segments are excluded from the chain by recovery — that
        // arrives with the phase that writes them.)
        for (segment, path) in &segments.sealed {
            let len = std::fs::metadata(path)
                .map_err(|e| QueueError::io(path, e))?
                .len();
            chain.push(SegmentHead {
                segment: *segment,
                committed: len,
                sealed: true,
            });
        }

        let active = match segments.active {
            Some((segment, path)) => {
                // Validate against the format's absolute bound, not the
                // configured one: shrinking max_message_size must never
                // make previously accepted records look corrupt and get
                // truncated (destroying queued mail).
                let tail = validate_active_tail(&path, record::MAX_RECORD_LEN)?;
                if tail.truncated_bytes > 0 {
                    tracing::warn!(
                        shard = dir.shard(),
                        segment,
                        truncated_bytes = tail.truncated_bytes,
                        "discarded torn tail during shard recovery"
                    );
                }
                let seg = ActiveSegment::recover(path, segment, &tail)?;
                chain.push(SegmentHead {
                    segment,
                    committed: tail.committed_len,
                    sealed: false,
                });
                seg
            }
            None => {
                let seg = ActiveSegment::create(dir.path(), segments.next_segment)?;
                chain.push(SegmentHead {
                    segment: seg.segment(),
                    committed: 0,
                    sealed: false,
                });
                seg
            }
        };

        let shared = ShardShared::new(dir.shard(), chain);
        let next_segment = active.segment() + 1;
        Ok((
            Self {
                dir: dir.clone(),
                active: Some(active),
                next_segment,
            },
            shared,
        ))
    }

    /// Writer loop: runs on a blocking task until the admission channel
    /// closes and drains.
    fn run(
        mut self,
        mut rx: mpsc::UnboundedReceiver<WriterMsg>,
        shared: Arc<ShardShared>,
        config: WriterConfig,
    ) {
        while let Some(msg) = rx.blocking_recv() {
            let req = match msg {
                WriterMsg::Append(req) => req,
                // Dropping the receiver fails any requests queued after the
                // sentinel with WriterClosed (their completions drop).
                WriterMsg::Shutdown => break,
            };
            let result = self.write_one(&req, &shared, &config);
            if let Err(e) = &result {
                crate::metrics::logqueue_append_error();
                tracing::error!(
                    shard = shared.shard(),
                    message_id = %req.msg.message_id,
                    error = %e,
                    "append failed"
                );
            }
            // Publish ordering: head advanced and dispatcher notified inside
            // write_one BEFORE this completion is sent.
            let _ = req.completion.send(result);
        }
        tracing::debug!(shard = shared.shard(), "append writer drained and stopped");
    }

    fn write_one(
        &mut self,
        req: &AppendRequest,
        shared: &ShardShared,
        config: &WriterConfig,
    ) -> Result<JobLocation, QueueError> {
        // Recreate the active segment if the previous rotation sealed the
        // old one but failed to create its replacement.
        if self.active.is_none() {
            let seg = ActiveSegment::create(self.dir.path(), self.next_segment)?;
            self.next_segment += 1;
            shared.open_segment(seg.segment());
            self.active = Some(seg);
        }
        // Rotate if this record would overflow the target size (never on an
        // empty segment: sizing validation guarantees any legal record fits
        // within a full segment).
        let active = self.active.as_ref().expect("just ensured");
        if active.len() > 0
            && active.len() + req.encoded_len as u64 > config.segment_target_bytes
        {
            self.rotate(shared)?;
        }

        let active = self.active.as_mut().expect("rotate keeps an active segment");
        let ordinal = active.next_ordinal();
        let encoded = record::encode(&RecordParams {
            message_id: req.msg.message_id,
            enqueue_ms: req.msg.enqueue_ms,
            generation: req.msg.generation,
            ordinal,
            sender: &req.msg.sender,
            recipients: &req.msg.recipients,
            body: &req.msg.body,
        })?;
        debug_assert_eq!(encoded.len() as u32, req.encoded_len);

        let write_started = std::time::Instant::now();
        let offset = active.append(&encoded)?;
        crate::metrics::logqueue_append_duration_observe(shared.shard(), write_started.elapsed());
        crate::metrics::logqueue_records_appended(shared.shard(), 1);
        crate::metrics::logqueue_bytes_appended(shared.shard(), encoded.len() as u64);
        crate::metrics::logqueue_active_segment_bytes_set(shared.shard(), active.len());
        let location = JobLocation {
            shard: shared.shard(),
            segment: active.segment(),
            offset,
            length: req.encoded_len,
            ordinal,
            generation: req.msg.generation,
        };

        shared.advance_committed(location.segment, active.len());
        shared.notify.notify_one();
        Ok(location)
    }

    fn rotate(&mut self, shared: &ShardShared) -> Result<(), QueueError> {
        let old = self.active.as_ref().expect("rotate requires an active segment");
        let sealed_segment = old.segment();
        // Seal FIRST, create second: a crash in between leaves no active
        // segment (recovery simply creates one) — never two, which would be
        // an unrecoverable layout error. If create fails, `active` becomes
        // None and the next append retries the create.
        let (_, final_len) = old.seal_in_place()?;
        self.active = None;
        shared.seal_segment(sealed_segment, final_len);
        let next_segment = self.next_segment;
        let seg = ActiveSegment::create(self.dir.path(), next_segment)?;
        self.next_segment += 1;
        self.active = Some(seg);
        shared.open_segment(next_segment);
        shared.notify.notify_one();
        crate::metrics::logqueue_segment_rotation(shared.shard());
        crate::metrics::logqueue_active_segment_bytes_set(shared.shard(), 0);
        tracing::debug!(
            shard = shared.shard(),
            sealed = sealed_segment,
            final_len,
            next = next_segment,
            "rotated active segment"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logqueue::record::MAX_RECORD_LEN;
    use crate::logqueue::segment::SegmentReader;

    fn config() -> WriterConfig {
        WriterConfig {
            segment_target_bytes: 64 * 1024 * 1024,
            max_record_len: MAX_RECORD_LEN,
            pending_append_bytes: 16 * 1024 * 1024,
        }
    }

    fn message(seq: u64, body: &[u8]) -> AppendMessage {
        AppendMessage {
            message_id: MessageId::from_ulid(ulid::Ulid::from_parts(seq, (seq * 7 + 1) as u128)),
            enqueue_ms: 1_752_000_000_000 + seq as i64,
            generation: 0,
            sender: "sender@example.com".into(),
            recipients: vec!["rcpt@example.com".into()],
            body: Bytes::copy_from_slice(body),
        }
    }

    #[tokio::test]
    async fn append_returns_readable_location() {
        let dir = tempfile::tempdir().unwrap();
        let spool = Spool::open(dir.path().join("spool"), 1).unwrap();
        let writers = LogWriters::start(&spool, config()).unwrap();
        let handle = writers.handle();

        let loc = handle.append(message(1, b"hello queue")).await.unwrap();
        assert_eq!(loc.shard, 0);
        assert_eq!(loc.ordinal, 0);
        assert_eq!(loc.generation, 0);

        let path = spool
            .shard(0)
            .path()
            .join(crate::logqueue::segment::active_file_name(loc.segment));
        let reader = SegmentReader::open(path).unwrap();
        let (header, body) = reader.read_record_at(loc.offset, MAX_RECORD_LEN).unwrap();
        assert_eq!(body, b"hello queue");
        assert_eq!(header.sender, "sender@example.com");
        assert_eq!(header.record_len, loc.length);

        writers.shutdown().await;
    }

    #[tokio::test]
    async fn concurrent_appends_all_land() {
        let dir = tempfile::tempdir().unwrap();
        let spool = Spool::open(dir.path().join("spool"), 2).unwrap();
        let writers = LogWriters::start(&spool, config()).unwrap();
        let handle = writers.handle();

        let mut tasks = Vec::new();
        for i in 0..200u64 {
            let handle = handle.clone();
            tasks.push(tokio::spawn(async move {
                let body = vec![b'x'; (i % 977 + 1) as usize];
                handle.append(message(i, &body)).await.unwrap()
            }));
        }
        let mut locations = Vec::new();
        for t in tasks {
            locations.push(t.await.unwrap());
        }

        // Every location must be unique and readable.
        let mut seen = std::collections::HashSet::new();
        for loc in &locations {
            assert!(seen.insert((loc.shard, loc.segment, loc.offset)));
        }

        // Committed heads cover every record; offsets within a shard's
        // segment are dense (offset of ordinal n+1 = offset + length of n).
        for shard in 0..handle.shard_count() {
            let chain = handle.shard_shared(shard).chain();
            let mut per_seg: Vec<_> = locations
                .iter()
                .filter(|l| l.shard == shard)
                .collect();
            per_seg.sort_by_key(|l| (l.segment, l.offset));
            let mut expected_offset = std::collections::HashMap::new();
            for loc in per_seg {
                let e = expected_offset.entry(loc.segment).or_insert(0u64);
                assert_eq!(loc.offset, *e, "hole in shard {shard} segment {}", loc.segment);
                *e += loc.length as u64;
                let head = chain.iter().find(|h| h.segment == loc.segment).unwrap();
                assert!(head.committed >= loc.offset + loc.length as u64);
            }
        }

        writers.shutdown().await;
    }

    #[tokio::test]
    async fn rotation_at_target_size() {
        let dir = tempfile::tempdir().unwrap();
        let spool = Spool::open(dir.path().join("spool"), 1).unwrap();
        let mut cfg = config();
        cfg.segment_target_bytes = 4096;
        let writers = LogWriters::start(&spool, cfg).unwrap();
        let handle = writers.handle();

        for i in 0..20u64 {
            handle.append(message(i, &vec![b'y'; 1024])).await.unwrap();
        }

        let chain = handle.shard_shared(0).chain();
        assert!(chain.len() > 1, "expected rotation, chain: {chain:?}");
        // All but the last entry are sealed, exist on disk as .log, and
        // their committed length equals the file length.
        for head in &chain[..chain.len() - 1] {
            assert!(head.sealed);
            let path = spool
                .shard(0)
                .path()
                .join(crate::logqueue::segment::sealed_file_name(head.segment));
            assert_eq!(std::fs::metadata(&path).unwrap().len(), head.committed);
            assert!(head.committed <= 4096 + 1024 + 4096); // target + slack
        }
        assert!(!chain.last().unwrap().sealed);

        // Records must be discoverable across the rotation boundary.
        let mut total = 0;
        for head in &chain {
            let name = if head.sealed {
                crate::logqueue::segment::sealed_file_name(head.segment)
            } else {
                crate::logqueue::segment::active_file_name(head.segment)
            };
            let reader = SegmentReader::open(spool.shard(0).path().join(name)).unwrap();
            crate::logqueue::segment::scan_headers(
                &reader,
                0,
                head.committed,
                MAX_RECORD_LEN,
                |_, _| {
                    total += 1;
                    true
                },
            )
            .unwrap();
        }
        assert_eq!(total, 20);

        writers.shutdown().await;
    }

    #[tokio::test]
    async fn oversized_record_is_rejected_up_front() {
        let dir = tempfile::tempdir().unwrap();
        let spool = Spool::open(dir.path().join("spool"), 1).unwrap();
        let mut cfg = config();
        cfg.max_record_len = 2048;
        let writers = LogWriters::start(&spool, cfg).unwrap();
        let handle = writers.handle();

        let err = handle
            .append(message(1, &vec![b'z'; 4096]))
            .await
            .unwrap_err();
        assert!(matches!(err, QueueError::RecordTooLarge { .. }));

        writers.shutdown().await;
    }

    #[tokio::test]
    async fn writer_recovers_torn_tail_and_continues() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("spool");
        let loc = {
            let spool = Spool::open(&root, 1).unwrap();
            let writers = LogWriters::start(&spool, config()).unwrap();
            let handle = writers.handle();
            let loc = handle.append(message(1, b"survives")).await.unwrap();
            handle.append(message(2, b"gets torn")).await.unwrap();
            writers.shutdown().await;
            loc
        };

        // Tear the second record's tail.
        let seg_path = root
            .join("shard-0000")
            .join(crate::logqueue::segment::active_file_name(loc.segment));
        let len = std::fs::metadata(&seg_path).unwrap().len();
        let f = std::fs::OpenOptions::new()
            .write(true)
            .open(&seg_path)
            .unwrap();
        f.set_len(len - 3).unwrap();

        // Restart: the torn record is truncated, appends continue after the
        // survivor with the correct ordinal.
        let spool = Spool::open(&root, 1).unwrap();
        let writers = LogWriters::start(&spool, config()).unwrap();
        let handle = writers.handle();
        let chain = handle.shard_shared(0).chain();
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].committed, loc.offset + loc.length as u64);

        let loc3 = handle.append(message(3, b"after recovery")).await.unwrap();
        assert_eq!(loc3.ordinal, 1);
        assert_eq!(loc3.offset, loc.offset + loc.length as u64);

        let reader = SegmentReader::open(&seg_path).unwrap();
        let (_, body) = reader.read_record_at(loc3.offset, MAX_RECORD_LEN).unwrap();
        assert_eq!(body, b"after recovery");

        writers.shutdown().await;
    }

    #[tokio::test]
    async fn shard_routing_is_stable_and_in_range() {
        let dir = tempfile::tempdir().unwrap();
        let spool = Spool::open(dir.path().join("spool"), 4).unwrap();
        let writers = LogWriters::start(&spool, config()).unwrap();
        let handle = writers.handle();

        let mut hits = vec![0u32; 4];
        for i in 0..1000u64 {
            let id = MessageId::from_ulid(ulid::Ulid::from_parts(i, (i * 31 + 7) as u128));
            let s = handle.shard_for(&id);
            assert_eq!(s, handle.shard_for(&id));
            hits[s as usize] += 1;
        }
        assert!(hits.iter().all(|&h| h > 0), "distribution: {hits:?}");

        writers.shutdown().await;
    }

    #[tokio::test]
    async fn admission_bytes_bound_is_respected() {
        let dir = tempfile::tempdir().unwrap();
        let spool = Spool::open(dir.path().join("spool"), 2).unwrap();
        let mut cfg = config();
        cfg.pending_append_bytes = 8192;
        let writers = LogWriters::start(&spool, cfg).unwrap();
        let handle = writers.handle();

        // Many concurrent small appends must all land even though their
        // combined size vastly exceeds the admission budget: the semaphore
        // throttles concurrency, it never drops or deadlocks a request.
        let mut tasks = Vec::new();
        for i in 0..50u64 {
            let handle = handle.clone();
            tasks.push(tokio::spawn(async move {
                let body = vec![b'q'; 1024];
                handle.append(message(i, &body)).await
            }));
        }
        for t in tasks {
            t.await.unwrap().unwrap();
        }

        // A single record whose encoded size exceeds the whole admission
        // budget must still succeed via the permit clamp.
        let big_body = vec![b'r'; 16 * 1024];
        handle.append(message(1000, &big_body)).await.unwrap();

        writers.shutdown().await;
    }

    #[tokio::test]
    async fn appends_after_shutdown_fail_with_writer_closed() {
        let dir = tempfile::tempdir().unwrap();
        let spool = Spool::open(dir.path().join("spool"), 1).unwrap();
        let writers = LogWriters::start(&spool, config()).unwrap();
        let handle = writers.handle();
        let surviving_handle = handle.clone();

        writers.shutdown().await;

        let err = surviving_handle
            .append(message(1, b"too late"))
            .await
            .unwrap_err();
        assert!(matches!(err, QueueError::WriterClosed(0)));
    }

    #[tokio::test]
    async fn multi_shard_exclusive_ownership() {
        let dir = tempfile::tempdir().unwrap();
        let spool = Spool::open(dir.path().join("spool"), 4).unwrap();
        let writers = LogWriters::start(&spool, config()).unwrap();
        let handle = writers.handle();

        let mut tasks = Vec::new();
        for i in 0..100u64 {
            let handle = handle.clone();
            tasks.push(tokio::spawn(async move {
                let msg = message(i, b"payload");
                let message_id = msg.message_id;
                let loc = handle.append(msg).await.unwrap();
                (message_id, loc)
            }));
        }
        let mut results = Vec::new();
        for t in tasks {
            results.push(t.await.unwrap());
        }

        let mut expected_counts = vec![0u32; handle.shard_count() as usize];
        for (message_id, loc) in &results {
            let expected_shard = handle.shard_for(message_id);
            assert_eq!(
                loc.shard, expected_shard,
                "returned location's shard must match shard_for"
            );
            expected_counts[expected_shard as usize] += 1;
        }

        writers.shutdown().await;

        // Each shard directory holds only its own shard's segments, and the
        // record count found there matches the messages routed to it.
        for shard in 0..spool.shard_count() {
            let shard_dir = spool.shard(shard);
            let segs = shard_dir.list_segments().unwrap();
            let mut total = 0u32;
            for (_, path) in &segs.sealed {
                let len = std::fs::metadata(path).unwrap().len();
                let reader = SegmentReader::open(path).unwrap();
                crate::logqueue::segment::scan_headers(&reader, 0, len, MAX_RECORD_LEN, |_, _| {
                    total += 1;
                    true
                })
                .unwrap();
            }
            if let Some((_, path)) = &segs.active {
                let len = std::fs::metadata(path).unwrap().len();
                let reader = SegmentReader::open(path).unwrap();
                crate::logqueue::segment::scan_headers(&reader, 0, len, MAX_RECORD_LEN, |_, _| {
                    total += 1;
                    true
                })
                .unwrap();
            }
            assert_eq!(
                total, expected_counts[shard as usize],
                "shard {shard} record count mismatch"
            );
        }
    }

    #[tokio::test]
    async fn restart_reuses_active_segment() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("spool");
        {
            let spool = Spool::open(&root, 1).unwrap();
            let writers = LogWriters::start(&spool, config()).unwrap();
            let handle = writers.handle();
            for i in 0..3u64 {
                handle.append(message(i, b"first-run")).await.unwrap();
            }
            writers.shutdown().await;
        }

        let spool = Spool::open(&root, 1).unwrap();
        let writers = LogWriters::start(&spool, config()).unwrap();
        let handle = writers.handle();
        for i in 3..5u64 {
            handle.append(message(i, b"second-run")).await.unwrap();
        }

        let chain = handle.shard_shared(0).chain();
        assert_eq!(
            chain.len(),
            1,
            "expected the active segment to be reused across restart, chain: {chain:?}"
        );
        let head = chain[0];
        assert!(!head.sealed);

        let path = spool
            .shard(0)
            .path()
            .join(crate::logqueue::segment::active_file_name(head.segment));
        let reader = SegmentReader::open(&path).unwrap();
        let mut ordinals = Vec::new();
        crate::logqueue::segment::scan_headers(&reader, 0, head.committed, MAX_RECORD_LEN, |_, h| {
            ordinals.push(h.ordinal);
            true
        })
        .unwrap();
        assert_eq!(ordinals.len(), 5);
        ordinals.sort_unstable();
        assert_eq!(ordinals, (0..=4).collect::<Vec<_>>());

        writers.shutdown().await;
    }
}
