//! Append writers: one per shard, each exclusively owning its shard's
//! active segment.
//!
//! Admission is bounded by pending bytes (not request count): a permit for
//! the encoded record size is acquired before the request is queued and
//! released once the bytes have been handed to the kernel page cache. SMTP
//! acceptance awaits only this append completion.
//!
//! Publish ordering (PLAN §9.5): write the complete records, then advance
//! the shard's committed head under the state lock, then notify the
//! dispatcher, then complete the requests. The committed head never exposes
//! a partial record — records already queued when the writer wakes are
//! coalesced into one vectored append and published together, and a write
//! that tears is rolled back to the last record boundary before the head
//! moves.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use tokio::sync::{mpsc, oneshot, Notify, Semaphore};

use super::record::{self, RecordParams};
use super::segment::{validate_active_tail, ActiveSegment, PendingRecord};
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

/// Most records coalesced into one vectored append. Two iovecs per record
/// keeps the array well under IOV_MAX (1024 on Linux), past which writev
/// would short-write and cost extra syscalls anyway. Admission bounds the
/// bytes; this bounds the syscall.
const MAX_BATCH_RECORDS: usize = 64;

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
        let head = chain.last_mut().expect("advance_committed on empty chain");
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
    /// Computed by the concurrent admission task so the single shard writer
    /// does not serially checksum every large body before writing it.
    payload_crc: u32,
    /// Measured at admission and reused by the writer: computing the header
    /// length walks the recipient list, and nothing about the record changes
    /// between the two (the writer only stamps the ordinal, which is fixed
    /// width).
    sizes: record::RecordSizes,
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
        let sizes = record::encoded_sizes(&params)?;
        if sizes.record_len > self.max_record_len {
            return Err(QueueError::RecordTooLarge {
                len: sizes.record_len as u64,
                limit: self.max_record_len as u64,
            });
        }
        // The envelope must fit the fixed allowance regardless of body
        // size: segment sizing is validated against it, and every derived
        // state-journal entry (which persists remaining recipients) must
        // stay below the journal replay limit. The SMTP recipient cap keeps
        // real mail far under this; the check makes the queue safe on its
        // own.
        let envelope_len = sizes.header_len as u64 - record::FIXED_HEADER_LEN as u64;
        if envelope_len > super::spool::ENVELOPE_ALLOWANCE {
            return Err(QueueError::InvalidRecord(format!(
                "envelope is {envelope_len} bytes, exceeds the {} byte allowance",
                super::spool::ENVELOPE_ALLOWANCE
            )));
        }

        // Acquire admission permits for the encoded size, clamped so one
        // huge record cannot exceed the whole semaphore (it then simply
        // occupies all admission capacity while queued).
        let permits = (sizes.record_len as u64).min(self.pending_limit) as u32;
        let permit = Arc::clone(&self.pending_bytes)
            .acquire_many_owned(permits)
            .await
            .expect("admission semaphore is never closed");
        crate::metrics::logqueue_pending_append_bytes_set(
            self.pending_limit - self.pending_bytes.available_permits() as u64,
        );

        // Do the body-sized CPU work on the concurrent admission tasks,
        // rather than serializing it on the shard's single writer. The body
        // is immutable Bytes, so the checksum remains valid after queueing.
        let payload_crc = crc32fast::hash(&msg.body);

        let (tx, rx) = oneshot::channel();
        self.shards[shard as usize]
            .tx
            .send(WriterMsg::Append(AppendRequest {
                msg,
                payload_crc,
                sizes,
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
            let first = match msg {
                WriterMsg::Append(req) => req,
                // Dropping the receiver fails any requests queued after the
                // sentinel with WriterClosed (their completions drop).
                WriterMsg::Shutdown => break,
            };
            let (batch, shutdown) = Self::collect_batch(first, &mut rx);
            self.write_batch(batch, &shared, &config);
            if shutdown {
                break;
            }
        }
        tracing::debug!(shard = shared.shard(), "append writer drained and stopped");
    }

    /// Take `first` plus whatever admission has already queued behind it, up
    /// to the batch cap. Nothing is ever waited for, so a lone append is as
    /// prompt as before; a backlog costs one vectored write and one published
    /// head instead of one each.
    ///
    /// The returned flag means the shutdown sentinel was reached: everything
    /// queued ahead of it is still written, then the writer exits.
    fn collect_batch(
        first: AppendRequest,
        rx: &mut mpsc::UnboundedReceiver<WriterMsg>,
    ) -> (VecDeque<AppendRequest>, bool) {
        let mut batch = VecDeque::with_capacity(MAX_BATCH_RECORDS);
        batch.push_back(first);
        while batch.len() < MAX_BATCH_RECORDS {
            match rx.try_recv() {
                Ok(WriterMsg::Append(req)) => batch.push_back(req),
                Ok(WriterMsg::Shutdown) => return (batch, true),
                // Empty or disconnected: write what we have. A disconnect
                // ends the outer loop on the next blocking_recv.
                Err(_) => break,
            }
        }
        (batch, false)
    }

    /// Write a whole batch and complete every request in it. One batch may
    /// take several appends: a chunk ends where the active segment has to
    /// rotate, or where a write failed.
    fn write_batch(
        &mut self,
        mut batch: VecDeque<AppendRequest>,
        shared: &ShardShared,
        config: &WriterConfig,
    ) {
        while !batch.is_empty() {
            let results = self.write_chunk(batch.make_contiguous(), shared, config);
            debug_assert!(!results.is_empty() && results.len() <= batch.len());
            for result in results {
                let req = batch
                    .pop_front()
                    .expect("write_chunk returns at most one result per request");
                if let Err(e) = &result {
                    crate::metrics::logqueue_append_error();
                    tracing::error!(
                        shard = shared.shard(),
                        message_id = %req.msg.message_id,
                        error = %e,
                        "append failed"
                    );
                }
                // Publish ordering: head advanced and dispatcher notified
                // inside write_chunk BEFORE this completion is sent.
                let _ = req.completion.send(result);
            }
        }
    }

    /// Append as much of `reqs` as the active segment can take in one
    /// vectored write, publish the new committed head, and return one result
    /// per request resolved — always at least one, so the caller makes
    /// progress. Requests beyond the returned results are left untouched for
    /// the next chunk.
    fn write_chunk(
        &mut self,
        reqs: &[AppendRequest],
        shared: &ShardShared,
        config: &WriterConfig,
    ) -> Vec<Result<JobLocation, QueueError>> {
        // Recreate the active segment if the previous rotation sealed the
        // old one but failed to create its replacement.
        if self.active.is_none() {
            match ActiveSegment::create(self.dir.path(), self.next_segment) {
                Ok(seg) => {
                    self.next_segment += 1;
                    shared.open_segment(seg.segment());
                    self.active = Some(seg);
                }
                // An error belongs to one request (it cannot be cloned, and
                // reporting it once is honest); the next chunk retries the
                // create for the rest.
                Err(e) => return vec![Err(e)],
            }
        }
        // Rotate if the first record would overflow the target size (never
        // on an empty segment: sizing validation guarantees any legal record
        // fits within a full segment).
        let active = self.active.as_ref().expect("just ensured");
        if active.len() > 0
            && active.len() + reqs[0].sizes.record_len as u64 > config.segment_target_bytes
        {
            if let Err(e) = self.rotate(shared) {
                return vec![Err(e)];
            }
        }

        let active = self
            .active
            .as_mut()
            .expect("rotate keeps an active segment");
        // Records never span segments, so the chunk stops at the segment
        // target and the remainder rotates in the next one. The first record
        // always goes in, whatever its size, or the batch could not drain.
        let room = config.segment_target_bytes.saturating_sub(active.len());
        let mut count = 0;
        let mut chunk_bytes = 0u64;
        for req in reqs {
            let len = req.sizes.record_len as u64;
            if count > 0 && chunk_bytes + len > room {
                break;
            }
            chunk_bytes += len;
            count += 1;
        }

        // Ordinals are consecutive from the segment's next ordinal, which is
        // what append_batch and the tail validator both require.
        let base_ordinal = active.next_ordinal();
        let mut headers = Vec::with_capacity(count);
        for (i, req) in reqs[..count].iter().enumerate() {
            let params = RecordParams {
                message_id: req.msg.message_id,
                enqueue_ms: req.msg.enqueue_ms,
                generation: req.msg.generation,
                ordinal: base_ordinal + i as u32,
                sender: &req.msg.sender,
                recipients: &req.msg.recipients,
                body: &req.msg.body,
            };
            // Header only: the kernel gathers it with the body, so a
            // multi-megabyte message is never copied to make the record
            // contiguous.
            match record::encode_header_with_payload_crc(&params, req.sizes, req.payload_crc) {
                Ok(header) => headers.push(header),
                // Admission measured these sizes, so this is unreachable.
                // Were it not, the offending record must not take the rest
                // of the chunk down with it.
                Err(e) if i == 0 => return vec![Err(e)],
                Err(_) => break,
            }
        }
        let count = headers.len();
        let records: Vec<PendingRecord<'_>> = headers
            .iter()
            .zip(reqs)
            .map(|(header, req)| PendingRecord {
                header,
                body: &req.msg.body,
            })
            .collect();

        let write_started = std::time::Instant::now();
        let batch = active.append_batch(&records);
        // One observation per vectored write: that is the latency every
        // record in the chunk shared.
        crate::metrics::logqueue_append_duration_observe(shared.shard(), write_started.elapsed());

        let committed = batch.offsets.len();
        debug_assert!(committed <= count);
        if committed > 0 {
            let bytes: u64 = reqs[..committed]
                .iter()
                .map(|r| r.sizes.record_len as u64)
                .sum();
            crate::metrics::logqueue_records_appended(shared.shard(), committed as u64);
            crate::metrics::logqueue_bytes_appended(shared.shard(), bytes);
            crate::metrics::logqueue_active_segment_bytes_set(shared.shard(), active.len());
            // Publish once for the chunk: the head moves straight from the
            // old tail to the end of the last record that fully landed, so
            // it never exposes a record the write tore.
            shared.advance_committed(active.segment(), active.len());
            shared.notify.notify_one();
        }

        let mut results = Vec::with_capacity(committed + 1);
        for (i, offset) in batch.offsets.iter().enumerate() {
            results.push(Ok(JobLocation {
                shard: shared.shard(),
                segment: active.segment(),
                offset: *offset,
                length: reqs[i].sizes.record_len,
                ordinal: base_ordinal + i as u32,
                generation: reqs[i].msg.generation,
            }));
        }
        if let Some(e) = batch.error {
            // The record the write stopped on takes the error; anything
            // after it never reached the file and is retried by the next
            // chunk. append_batch only errors with a record left unwritten,
            // so this stays within one result per request.
            debug_assert!(committed < reqs.len());
            results.push(Err(e));
        }
        results
    }

    fn rotate(&mut self, shared: &ShardShared) -> Result<(), QueueError> {
        let old = self
            .active
            .as_ref()
            .expect("rotate requires an active segment");
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
            let mut per_seg: Vec<_> = locations.iter().filter(|l| l.shard == shard).collect();
            per_seg.sort_by_key(|l| (l.segment, l.offset));
            let mut expected_offset = std::collections::HashMap::new();
            for loc in per_seg {
                let e = expected_offset.entry(loc.segment).or_insert(0u64);
                assert_eq!(
                    loc.offset, *e,
                    "hole in shard {shard} segment {}",
                    loc.segment
                );
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
    async fn oversized_envelope_is_rejected_up_front() {
        let dir = tempfile::tempdir().unwrap();
        let spool = Spool::open(dir.path().join("spool"), 1).unwrap();
        let writers = LogWriters::start(&spool, config()).unwrap();
        let handle = writers.handle();

        // ~1.2 MiB of recipient addresses with a tiny body: over the
        // envelope allowance even though the record easily fits a segment.
        let mut msg = message(1, b"small body");
        msg.recipients = (0..6000)
            .map(|i| format!("r{i:05}-{}@example.com", "x".repeat(180)))
            .collect();
        let err = handle.append(msg).await.unwrap_err();
        assert!(matches!(err, QueueError::InvalidRecord(_)), "got {err}");

        // A large BODY with a normal envelope is still fine (the envelope
        // cap must not constrain message size).
        handle
            .append(message(2, &vec![b'b'; 2 * 1024 * 1024]))
            .await
            .unwrap();

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

    /// One queued request, for the batch-collection tests.
    fn request(
        seq: u64,
    ) -> (
        AppendRequest,
        oneshot::Receiver<Result<JobLocation, QueueError>>,
    ) {
        let msg = message(seq, b"body");
        let params = RecordParams {
            message_id: msg.message_id,
            enqueue_ms: msg.enqueue_ms,
            generation: msg.generation,
            ordinal: 0,
            sender: &msg.sender,
            recipients: &msg.recipients,
            body: &msg.body,
        };
        let sizes = record::encoded_sizes(&params).unwrap();
        let payload_crc = crc32fast::hash(&msg.body);
        let (tx, rx) = oneshot::channel();
        (
            AppendRequest {
                msg,
                payload_crc,
                sizes,
                completion: tx,
            },
            rx,
        )
    }

    #[test]
    fn batch_collection_drains_the_backlog_up_to_the_cap() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let queued = MAX_BATCH_RECORDS + 5;
        let mut keep_alive = Vec::new();
        for i in 0..queued as u64 {
            let (req, completion) = request(i);
            keep_alive.push(completion);
            tx.send(WriterMsg::Append(req)).unwrap();
        }
        tx.send(WriterMsg::Shutdown).unwrap();

        // First batch fills to the cap and does not see the sentinel yet.
        let first = match rx.try_recv().unwrap() {
            WriterMsg::Append(req) => req,
            WriterMsg::Shutdown => panic!("sentinel arrived first"),
        };
        let (batch, shutdown) = ShardWriter::collect_batch(first, &mut rx);
        assert_eq!(batch.len(), MAX_BATCH_RECORDS);
        assert!(!shutdown);

        // The rest come out in one batch, and the sentinel is reported
        // rather than swallowed.
        let first = match rx.try_recv().unwrap() {
            WriterMsg::Append(req) => req,
            WriterMsg::Shutdown => panic!("sentinel arrived before the backlog"),
        };
        let (batch, shutdown) = ShardWriter::collect_batch(first, &mut rx);
        assert_eq!(batch.len(), queued - MAX_BATCH_RECORDS - 1 + 1);
        assert!(shutdown);
    }

    #[test]
    fn batch_collection_of_a_lone_request_does_not_wait() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let (req, _completion) = request(1);
        tx.send(WriterMsg::Append(req)).unwrap();
        let first = match rx.try_recv().unwrap() {
            WriterMsg::Append(req) => req,
            WriterMsg::Shutdown => panic!("unexpected sentinel"),
        };
        let (batch, shutdown) = ShardWriter::collect_batch(first, &mut rx);
        assert_eq!(batch.len(), 1);
        assert!(!shutdown);
    }

    /// A burst large enough that the writer coalesces records must produce
    /// exactly the same spool as one-at-a-time appends: dense offsets, one
    /// ordinal per record, every body intact and a tail that validates.
    #[tokio::test]
    async fn coalesced_burst_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let spool = Spool::open(dir.path().join("spool"), 1).unwrap();
        let writers = LogWriters::start(&spool, config()).unwrap();
        let handle = writers.handle();

        let count = 300u64;
        let mut tasks = Vec::new();
        for i in 0..count {
            let handle = handle.clone();
            tasks.push(tokio::spawn(async move {
                let body = vec![b'x'; (i % 97 + 1) as usize];
                let msg = message(i, &body);
                let id = msg.message_id;
                (id, body, handle.append_to_shard(0, msg).await.unwrap())
            }));
        }
        let mut landed = Vec::new();
        for t in tasks {
            landed.push(t.await.unwrap());
        }

        let chain = handle.shard_shared(0).chain();
        assert_eq!(chain.len(), 1, "one segment expected: {chain:?}");
        let head = chain[0];
        writers.shutdown().await;

        landed.sort_by_key(|(_, _, loc)| loc.offset);
        let mut expected_offset = 0u64;
        let path = spool
            .shard(0)
            .path()
            .join(crate::logqueue::segment::active_file_name(head.segment));
        let reader = SegmentReader::open(&path).unwrap();
        for (ordinal, (id, body, loc)) in landed.iter().enumerate() {
            assert_eq!(loc.offset, expected_offset, "hole at ordinal {ordinal}");
            assert_eq!(loc.ordinal, ordinal as u32);
            expected_offset += loc.length as u64;
            let (header, record) = reader
                .read_record_exact(loc.offset, loc.length, MAX_RECORD_LEN)
                .unwrap();
            assert_eq!(header.message_id, *id);
            assert_eq!(&record[header.header_len as usize..], &body[..]);
        }
        assert_eq!(head.committed, expected_offset);

        let v = validate_active_tail(&path, MAX_RECORD_LEN).unwrap();
        assert_eq!(v.records, count as u32);
        assert_eq!(v.truncated_bytes, 0);
        assert_eq!(v.committed_len, expected_offset);
    }

    /// A batch that outgrows the active segment must split at the rotation
    /// boundary: records never span segments, and each segment's ordinals
    /// restart at zero.
    #[tokio::test]
    async fn coalesced_burst_splits_across_rotations() {
        let dir = tempfile::tempdir().unwrap();
        let spool = Spool::open(dir.path().join("spool"), 1).unwrap();
        let mut cfg = config();
        cfg.segment_target_bytes = 8192;
        let writers = LogWriters::start(&spool, cfg).unwrap();
        let handle = writers.handle();

        let count = 200u64;
        let mut tasks = Vec::new();
        for i in 0..count {
            let handle = handle.clone();
            tasks.push(tokio::spawn(async move {
                let body = vec![b'w'; 700];
                handle.append_to_shard(0, message(i, &body)).await.unwrap()
            }));
        }
        let mut landed = Vec::new();
        for t in tasks {
            landed.push(t.await.unwrap());
        }

        let chain = handle.shard_shared(0).chain();
        assert!(chain.len() > 1, "expected rotations, chain: {chain:?}");
        writers.shutdown().await;

        // Per segment: offsets dense from zero, ordinals dense from zero,
        // and nothing past the published committed head.
        let mut by_segment: std::collections::BTreeMap<u64, Vec<&JobLocation>> = Default::default();
        for loc in &landed {
            by_segment.entry(loc.segment).or_default().push(loc);
        }
        assert_eq!(by_segment.len(), chain.len());
        let mut total = 0;
        for (segment, mut locs) in by_segment {
            locs.sort_by_key(|l| l.offset);
            let head = chain.iter().find(|h| h.segment == segment).unwrap();
            let mut expected_offset = 0u64;
            for (i, loc) in locs.iter().enumerate() {
                assert_eq!(loc.offset, expected_offset, "hole in segment {segment}");
                assert_eq!(loc.ordinal, i as u32, "ordinal gap in segment {segment}");
                expected_offset += loc.length as u64;
                total += 1;
            }
            assert_eq!(head.committed, expected_offset);
            let name = if head.sealed {
                crate::logqueue::segment::sealed_file_name(segment)
            } else {
                crate::logqueue::segment::active_file_name(segment)
            };
            let path = spool.shard(0).path().join(name);
            assert_eq!(std::fs::metadata(&path).unwrap().len(), head.committed);
            if !head.sealed {
                let v = validate_active_tail(&path, MAX_RECORD_LEN).unwrap();
                assert_eq!(v.truncated_bytes, 0);
                assert_eq!(v.records as usize, locs.len());
            }
        }
        assert_eq!(total, count);
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
        crate::logqueue::segment::scan_headers(
            &reader,
            0,
            head.committed,
            MAX_RECORD_LEN,
            |_, h| {
                ordinals.push(h.ordinal);
                true
            },
        )
        .unwrap();
        assert_eq!(ordinals.len(), 5);
        ordinals.sort_unstable();
        assert_eq!(ordinals, (0..=4).collect::<Vec<_>>());

        writers.shutdown().await;
    }
}
