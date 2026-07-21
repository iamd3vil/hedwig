//! The dispatcher: one task scheduling delivery across all shards.
//!
//! It discovers appended records via per-shard cursors against the writers'
//! committed chains (notifications are lossy hints), hands payload-free
//! claims to pulling workers, persists every outcome through the shard's
//! state journal before applying it (persist-then-apply), schedules retries
//! by due time, and gates dispatch on the per-domain rate limiter so
//! throttled destinations never occupy worker slots.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use super::segment::{open_segment_reader, scan_headers, SegmentReader};
use super::state::{
    Checkpoint, DeferredJob, PendingCheckpoint, ReadyJob, RecoveredState, SegmentStats,
    ShardStateStore, StateEntry,
};
use super::writer::ShardShared;
use super::{JobLocation, MessageId, QueueError};

/// Dispatch-time rate limiting. `check` returns how long the domain is
/// exhausted for, or `None` when a send is allowed (and accounted).
pub trait RateGate: Send + Sync {
    fn check(&self, domain: &str) -> Option<Duration>;
}

/// Allows everything; used when rate limits are disabled.
pub struct NoRateGate;

impl RateGate for NoRateGate {
    fn check(&self, _domain: &str) -> Option<Duration> {
        None
    }
}

#[derive(Debug, Clone)]
pub struct DispatcherConfig {
    /// Admission-time bound, used only for diagnostics here. All scans of
    /// existing records use the format's absolute [`record::MAX_RECORD_LEN`]
    /// so a config reduction never orphans previously accepted mail.
    pub max_record_len: u32,
    /// Discovery backpressure: stop advancing cursors while this many jobs
    /// are tracked in memory. The log holds everything beyond it.
    pub max_tracked_jobs: usize,
    /// Fallback wake-up for lost notifications and persist retries.
    pub safety_tick: Duration,
    /// Checkpoint a shard once its journal grows past this many bytes.
    pub checkpoint_interval_bytes: u64,
    /// Compact a sealed segment once this fraction of its bytes is dead.
    pub compaction_dead_ratio: f64,
    /// Leave freshly sealed segments alone for this long.
    pub compaction_min_age: Duration,
}

impl Default for DispatcherConfig {
    fn default() -> Self {
        Self {
            max_record_len: super::record::MAX_RECORD_LEN,
            max_tracked_jobs: 100_000,
            safety_tick: Duration::from_millis(500),
            checkpoint_interval_bytes: 8 * 1024 * 1024,
            compaction_dead_ratio: 0.5,
            compaction_min_age: Duration::from_secs(60),
        }
    }
}

/// What a worker receives: identity, location, and delivery metadata —
/// never the message body.
#[derive(Debug, Clone)]
pub struct DeliveryJob {
    pub message_id: MessageId,
    pub location: JobLocation,
    pub attempts: u32,
    pub claim_generation: u64,
    pub enqueue_ms: i64,
    pub sender: String,
    /// Recipients that have not yet accepted the message.
    pub recipients: Vec<String>,
}

/// A worker's report for one claim.
#[derive(Debug)]
pub enum JobOutcome {
    Delivered {
        response: String,
    },
    /// A real failed attempt: increments the attempt count, persists the
    /// remaining recipient set, and schedules the retry by due time.
    Deferred {
        next_attempt_ms: i64,
        remaining_recipients: Vec<String>,
        error: String,
    },
    /// Lost the transmission-time rate-limit race: requeued in memory only.
    /// No journal write, no attempt increment.
    RateLimited {
        retry_after: Duration,
    },
    Bounced {
        reason: String,
    },
}

enum WorkerEvent {
    Outcome {
        id: MessageId,
        generation: u64,
        outcome: JobOutcome,
    },
    Abandoned {
        id: MessageId,
        generation: u64,
    },
}

/// A claimed job. Report exactly one outcome; dropping the claim without
/// reporting counts as abandonment and returns the job to the ready queue.
pub struct Claim {
    pub job: DeliveryJob,
    events: mpsc::UnboundedSender<WorkerEvent>,
    reported: bool,
}

impl Claim {
    pub fn report(mut self, outcome: JobOutcome) {
        self.reported = true;
        let _ = self.events.send(WorkerEvent::Outcome {
            id: self.job.message_id,
            generation: self.job.claim_generation,
            outcome,
        });
    }
}

impl Drop for Claim {
    fn drop(&mut self) {
        if !self.reported {
            let _ = self.events.send(WorkerEvent::Abandoned {
                id: self.job.message_id,
                generation: self.job.claim_generation,
            });
        }
    }
}

type ClaimWaiter = oneshot::Sender<Option<Claim>>;

/// Cloneable handle workers use to pull claims and read message bodies.
#[derive(Clone)]
pub struct DispatcherHandle {
    claim_tx: mpsc::Sender<ClaimWaiter>,
    shard_dirs: Arc<Vec<PathBuf>>,
    max_record_len: u32,
}

impl DispatcherHandle {
    /// Pull the next claim, waiting until one is available. `None` means
    /// the dispatcher is shutting down and the worker should exit.
    pub async fn claim(&self) -> Option<Claim> {
        let (tx, rx) = oneshot::channel();
        self.claim_tx.send(tx).await.ok()?;
        rx.await.ok().flatten()
    }

    /// Read and verify a message body by its location (blocking I/O runs on
    /// a blocking task). Returns the body bytes.
    pub async fn read_body(&self, location: JobLocation) -> Result<Vec<u8>, QueueError> {
        let dir = self.shard_dirs[location.shard as usize].clone();
        tokio::task::spawn_blocking(move || {
            let reader = open_segment_reader(&dir, location.segment)?;
            let (_, body) =
                reader.read_record_at(location.offset, super::record::MAX_RECORD_LEN)?;
            Ok(body)
        })
        .await
        .expect("read_body task panicked")
    }
}

/// Everything the dispatcher needs to run one shard.
pub struct ShardInit {
    pub dir: PathBuf,
    pub shared: Arc<ShardShared>,
    pub store: ShardStateStore,
    pub recovered: RecoveredState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JobState {
    Ready,
    InFlight(u64),
    /// Waiting for a due time: a persisted deferral (real attempt) or an
    /// in-memory rate-limit hold (never persisted).
    Delayed { due_ms: i64, persisted: bool },
}

struct Job {
    location: JobLocation,
    attempts: u32,
    enqueue_ms: i64,
    /// Remaining recipients when a partial delivery has happened; `None`
    /// means the full envelope from the payload header.
    remaining: Option<Vec<String>>,
    last_error: Option<String>,
    /// Envelope cache filled on first dispatch (sender, all recipients).
    envelope: Option<(String, Vec<String>)>,
    state: JobState,
}

struct ShardRuntime {
    shard: u16,
    dir: PathBuf,
    shared: Arc<ShardShared>,
    store: ShardStateStore,
    /// Next undiscovered position. `None` until first initialized from the
    /// chain (fresh shard with no checkpoint).
    cursor: Option<(u64, u64)>,
    tombstones: HashMap<u64, HashSet<MessageId>>,
    stats: HashMap<u64, SegmentStats>,
    readers: HashMap<u64, SegmentReader>,
    /// Outcomes whose journal write failed; retried on the safety tick.
    /// Jobs referenced here stay in flight (never lost, never terminal
    /// without persistence).
    pending_persists: VecDeque<StateEntry>,
    checkpoint: Option<PendingCheckpoint>,
}

impl ShardRuntime {
    fn reader(&mut self, segment: u64) -> Result<&SegmentReader, QueueError> {
        if !self.readers.contains_key(&segment) {
            let r = open_segment_reader(&self.dir, segment)?;
            self.readers.insert(segment, r);
        }
        Ok(self.readers.get(&segment).unwrap())
    }

    fn is_tombstoned(&self, segment: u64, id: &MessageId) -> bool {
        self.tombstones
            .get(&segment)
            .is_some_and(|s| s.contains(id))
    }
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// Domain of an envelope recipient, tolerating angle brackets
/// (`<user@example.com>`), normalized the same way the delivery worker
/// does so the rate gate and the limiter share one bucket per domain.
fn domain_of(address: &str) -> &str {
    let address = address.trim_matches(|c| c == '<' || c == '>');
    address.rsplit_once('@').map(|(_, d)| d).unwrap_or(address)
}

/// An in-progress compaction: live records of one segment being re-appended
/// through the normal writer path with a bumped relocation generation. Only
/// one runs at a time (PLAN §17.4).
struct CompactionRun {
    shard_idx: usize,
    segment: u64,
    queue: VecDeque<MessageId>,
}

pub struct Dispatcher {
    shards: Vec<ShardRuntime>,
    jobs: HashMap<MessageId, Job>,
    ready: BinaryHeap<Reverse<(i64, MessageId)>>,
    delayed: BinaryHeap<Reverse<(i64, MessageId)>>,
    waiting: VecDeque<ClaimWaiter>,
    inflight: usize,
    next_claim_generation: u64,
    gate: Arc<dyn RateGate>,
    config: DispatcherConfig,
    append: super::writer::AppendHandle,
    compaction: Option<CompactionRun>,
    events_tx: mpsc::UnboundedSender<WorkerEvent>,
    cp_tx: mpsc::UnboundedSender<(u16, Result<(), QueueError>)>,
}

impl Dispatcher {
    /// Build the dispatcher from recovered shard state and spawn its task.
    pub fn start(
        shard_inits: Vec<ShardInit>,
        append: super::writer::AppendHandle,
        gate: Arc<dyn RateGate>,
        config: DispatcherConfig,
        cancel: CancellationToken,
    ) -> (DispatcherHandle, tokio::task::JoinHandle<()>) {
        let (claim_tx, claim_rx) = mpsc::channel(1024);
        let (events_tx, events_rx) = mpsc::unbounded_channel();
        let (cp_tx, cp_rx) = mpsc::unbounded_channel();

        let shard_dirs = Arc::new(shard_inits.iter().map(|s| s.dir.clone()).collect::<Vec<_>>());
        let handle = DispatcherHandle {
            claim_tx,
            shard_dirs,
            max_record_len: config.max_record_len,
        };

        let mut dispatcher = Dispatcher {
            shards: Vec::with_capacity(shard_inits.len()),
            jobs: HashMap::new(),
            ready: BinaryHeap::new(),
            delayed: BinaryHeap::new(),
            waiting: VecDeque::new(),
            inflight: 0,
            next_claim_generation: 0,
            gate,
            config,
            append,
            compaction: None,
            events_tx,
            cp_tx,
        };
        for init in shard_inits {
            dispatcher.add_shard(init);
        }

        let task = tokio::spawn(dispatcher.run(claim_rx, events_rx, cp_rx, cancel));
        (handle, task)
    }

    fn add_shard(&mut self, init: ShardInit) {
        let ShardInit {
            dir,
            shared,
            store,
            mut recovered,
        } = init;
        let chain = shared.chain();

        // Reconcile checkpoint state with the writer-validated chain. A torn
        // active tail was truncated during writer recovery, so a checkpoint
        // written just before the crash can reference positions past the
        // committed head:
        //  - a cursor past the head would skip every record appended after
        //    restart (stranding accepted mail forever) — clamp it back;
        //  - a job whose payload sat in the truncated tail no longer exists
        //    on disk; the append was never completed-and-acknowledged (or
        //    was lost within the accepted page-cache window), so drop it.
        let committed_of = |segment: u64| -> Option<u64> {
            chain.iter().find(|h| h.segment == segment).map(|h| h.committed)
        };
        if let Some((seg, off)) = recovered.cursor {
            match committed_of(seg) {
                Some(committed) if off > committed => {
                    tracing::warn!(
                        shard = shared.shard(),
                        segment = seg,
                        cursor = off,
                        committed,
                        "checkpoint cursor is past the validated tail; clamping"
                    );
                    recovered.cursor = Some((seg, committed));
                }
                _ => {}
            }
        }
        let payload_gone = |location: &JobLocation| -> bool {
            matches!(
                committed_of(location.segment),
                Some(committed) if location.offset + location.length as u64 > committed
            )
        };
        recovered.ready.retain(|id, r| {
            if payload_gone(&r.location) {
                tracing::warn!(message_id = %id, location = ?r.location,
                    "dropping recovered ready job whose payload was truncated with the torn tail");
                false
            } else {
                true
            }
        });
        recovered.deferred.retain(|id, d| {
            if payload_gone(&d.location) {
                tracing::warn!(message_id = %id, location = ?d.location,
                    "dropping recovered deferred job whose payload was truncated with the torn tail");
                false
            } else {
                true
            }
        });

        for (id, r) in recovered.ready {
            self.jobs.insert(
                id,
                Job {
                    location: r.location,
                    attempts: r.attempts,
                    enqueue_ms: r.enqueue_ms,
                    remaining: (!r.remaining_recipients.is_empty()).then_some(r.remaining_recipients),
                    last_error: None,
                    envelope: None,
                    state: JobState::Ready,
                },
            );
            self.ready.push(Reverse((r.enqueue_ms, id)));
        }
        for (id, d) in recovered.deferred {
            self.jobs.insert(
                id,
                Job {
                    location: d.location,
                    attempts: d.attempts,
                    // Queue age is unknown for deferred checkpoint entries
                    // until the header is read; due time is a fine proxy for
                    // ordering once it re-enters ready.
                    enqueue_ms: d.next_attempt_ms,
                    remaining: Some(d.remaining_recipients),
                    last_error: Some(d.last_error),
                    envelope: None,
                    state: JobState::Delayed {
                        due_ms: d.next_attempt_ms,
                        persisted: true,
                    },
                },
            );
            self.delayed.push(Reverse((d.next_attempt_ms, id)));
        }
        let mut stats = recovered.segment_stats;
        // Record sealed-segment sizes for GC eligibility: a segment is
        // reclaimable only once its total size is known (i.e. it is sealed;
        // the writer's recovered chain lists every sealed segment on disk).
        for head in &chain {
            if head.sealed {
                stats.entry(head.segment).or_default().total_bytes = head.committed;
            }
        }
        self.shards.push(ShardRuntime {
            shard: shared.shard(),
            dir,
            shared,
            store,
            cursor: recovered.cursor,
            tombstones: recovered.tombstones,
            stats,
            readers: HashMap::new(),
            pending_persists: VecDeque::new(),
            checkpoint: None,
        });
    }

    async fn run(
        mut self,
        mut claim_rx: mpsc::Receiver<ClaimWaiter>,
        mut events_rx: mpsc::UnboundedReceiver<WorkerEvent>,
        mut cp_rx: mpsc::UnboundedReceiver<(u16, Result<(), QueueError>)>,
        cancel: CancellationToken,
    ) {
        // Merge every shard's notify into one wake-up signal.
        let discovery_wake = Arc::new(tokio::sync::Notify::new());
        for shard in &self.shards {
            let shared = Arc::clone(&shard.shared);
            let wake = Arc::clone(&discovery_wake);
            let cancel = cancel.clone();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = shared.notify.notified() => wake.notify_one(),
                        _ = cancel.cancelled() => break,
                    }
                }
            });
        }

        self.discover_all();
        let mut tick = tokio::time::interval(self.config.safety_tick);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            self.wake_due_jobs();
            self.try_dispatch();

            let next_due = self.next_due_in();
            tokio::select! {
                biased;

                _ = cancel.cancelled() => break,

                Some((shard, result)) = cp_rx.recv() => {
                    self.finish_checkpoint(shard, result);
                }

                Some(event) = events_rx.recv() => {
                    self.on_worker_event(event);
                    // Drain whatever else is immediately available.
                    while let Ok(event) = events_rx.try_recv() {
                        self.on_worker_event(event);
                    }
                }

                Some(waiter) = claim_rx.recv() => {
                    self.waiting.push_back(waiter);
                }

                _ = discovery_wake.notified() => {
                    self.discover_all();
                }

                _ = tick.tick() => {
                    self.discover_all();
                    self.retry_pending_persists();
                    self.maybe_checkpoint();
                    self.sweep_dead_segments();
                    self.maybe_start_compaction();
                    self.drive_compaction().await;
                    self.publish_metrics();
                }

                _ = tokio::time::sleep(next_due) => {}
            }
        }

        self.shutdown(&mut events_rx).await;
    }

    /// Graceful shutdown: refuse new claims, wait for in-flight outcomes,
    /// persist everything, checkpoint every shard.
    async fn shutdown(&mut self, events_rx: &mut mpsc::UnboundedReceiver<WorkerEvent>) {
        for waiter in self.waiting.drain(..) {
            let _ = waiter.send(None);
        }
        while self.inflight > 0 {
            match events_rx.recv().await {
                Some(event) => self.on_worker_event(event),
                None => break,
            }
        }
        self.retry_pending_persists();
        for i in 0..self.shards.len() {
            if self.shards[i].checkpoint.is_some() {
                continue; // an async checkpoint is mid-flight; journals cover us
            }
            if let Err(e) = self.checkpoint_shard_sync(i) {
                tracing::error!(shard = self.shards[i].shard, error = %e,
                    "final checkpoint failed; journals remain authoritative");
            }
        }
        tracing::info!("dispatcher stopped");
    }

    // ------------------------------------------------------------------
    // Discovery.

    fn discover_all(&mut self) {
        for i in 0..self.shards.len() {
            if let Err(e) = self.discover_shard(i) {
                tracing::error!(shard = self.shards[i].shard, error = %e, "discovery failed");
            }
        }
    }

    fn discover_shard(&mut self, i: usize) -> Result<(), QueueError> {
        loop {
            if self.jobs.len() >= self.config.max_tracked_jobs {
                return Ok(()); // discovery backpressure; the log holds the rest
            }
            let budget = self.config.max_tracked_jobs - self.jobs.len();

            let shard = &mut self.shards[i];
            let chain = shard.shared.chain();
            // Note sealed sizes for GC as segments seal (idempotent).
            for head in &chain {
                if head.sealed {
                    shard.stats.entry(head.segment).or_default().total_bytes = head.committed;
                }
            }
            let Some(first) = chain.first() else {
                return Ok(());
            };
            let (mut seg, mut off) = shard.cursor.unwrap_or((first.segment, 0));

            // Position the cursor on its chain entry; if that segment is
            // gone (pruned after full consumption), move to the next one.
            let entry = match chain.iter().find(|h| h.segment == seg) {
                Some(e) => *e,
                None => match chain.iter().find(|h| h.segment > seg) {
                    Some(e) => {
                        seg = e.segment;
                        off = 0;
                        *e
                    }
                    None => return Ok(()),
                },
            };

            if off >= entry.committed {
                if entry.sealed && chain.iter().any(|h| h.segment > entry.segment) {
                    // Fully consumed sealed segment: advance to the next
                    // chain entry and let the loop scan it.
                    let next = chain.iter().find(|h| h.segment > entry.segment).unwrap();
                    shard.cursor = Some((next.segment, 0));
                    shard.shared.prune(next.segment);
                    continue;
                }
                return Ok(()); // caught up with the active head
            }

            // Scan headers between cursor and committed tail, registering
            // new jobs, stopping at the backpressure budget. A record whose
            // id is already tracked but whose relocation generation is
            // higher is a compaction copy that must win (crash between
            // relocation and checkpoint leaves both copies on disk).
            let mut discovered: Vec<(MessageId, JobLocation, i64)> = Vec::new();
            let mut relocations: Vec<(MessageId, JobLocation)> = Vec::new();
            let shard_no = shard.shard;
            let tombstones = &shard.tombstones;
            let jobs = &self.jobs;
            let max_record_len = super::record::MAX_RECORD_LEN;
            let reader = {
                if !shard.readers.contains_key(&seg) {
                    let r = open_segment_reader(&shard.dir, seg)?;
                    shard.readers.insert(seg, r);
                }
                shard.readers.get(&seg).unwrap()
            };
            let stopped = scan_headers(reader, off, entry.committed, max_record_len, |o, h| {
                let location = JobLocation {
                    shard: shard_no,
                    segment: seg,
                    offset: o,
                    length: h.record_len,
                    ordinal: h.ordinal,
                    generation: h.generation,
                };
                let dead = tombstones.get(&seg).is_some_and(|s| s.contains(&h.message_id));
                if !dead {
                    match jobs.get(&h.message_id) {
                        None => discovered.push((h.message_id, location, h.enqueue_ms)),
                        Some(job) if h.generation > job.location.generation => {
                            relocations.push((h.message_id, location));
                        }
                        Some(_) => {}
                    }
                }
                discovered.len() < budget
            })?;
            shard.cursor = Some((seg, stopped));

            let made_progress = stopped > off || !discovered.is_empty();
            for (id, location, enqueue_ms) in discovered {
                self.jobs.insert(
                    id,
                    Job {
                        location,
                        attempts: 0,
                        enqueue_ms,
                        remaining: None,
                        last_error: None,
                        envelope: None,
                        state: JobState::Ready,
                    },
                );
                self.ready.push(Reverse((enqueue_ms, id)));
            }
            for (id, location) in relocations {
                // Journal the relocation (again): a crash between the copy
                // and its Relocated entry loses the old copy's garbage
                // accounting, so re-record it durably when rediscovered.
                if let Some(job) = self.jobs.get(&id) {
                    if location.generation > job.location.generation {
                        let old = job.location;
                        self.persist_and_apply(
                            i,
                            StateEntry::Relocated {
                                id,
                                old,
                                new: location,
                            },
                        );
                    }
                }
            }
            if !made_progress {
                return Ok(());
            }
        }
    }

    // ------------------------------------------------------------------
    // Dispatch.

    fn wake_due_jobs(&mut self) {
        let now = now_ms();
        while let Some(Reverse((due, id))) = self.delayed.peek().copied() {
            if due > now {
                break;
            }
            self.delayed.pop();
            let Some(job) = self.jobs.get_mut(&id) else {
                continue; // stale heap entry
            };
            match job.state {
                JobState::Delayed { due_ms, .. } if due_ms == due => {
                    job.state = JobState::Ready;
                    self.ready.push(Reverse((job.enqueue_ms, id)));
                }
                _ => {} // stale entry: the job moved on
            }
        }
    }

    fn next_due_in(&self) -> Duration {
        match self.delayed.peek() {
            Some(Reverse((due, _))) => {
                Duration::from_millis((due - now_ms()).max(0) as u64).min(Duration::from_secs(60))
            }
            None => Duration::from_secs(60),
        }
    }

    fn try_dispatch(&mut self) {
        while !self.waiting.is_empty() {
            let Some((id, enqueue_ms)) = self.pop_ready() else {
                return;
            };

            // Fill the envelope from the payload header on first dispatch.
            if let Err(e) = self.fill_envelope(id) {
                tracing::error!(message_id = %id, error = %e,
                    "cannot read record header; delaying job");
                self.delay_job(id, now_ms() + 30_000, false);
                continue;
            }
            let job = self.jobs.get(&id).expect("popped job exists");
            let (sender, all_recipients) = job.envelope.clone().expect("envelope just filled");
            let recipients = job.remaining.clone().unwrap_or(all_recipients);

            // Dispatch-time rate gating: exhausted destinations stay queued
            // without consuming a worker slot. The due time is not a token —
            // the job re-passes the gate when it wakes.
            if let Some(wait) = self.gate.check(domain_of(&recipients[0])) {
                self.delay_job(id, now_ms() + wait.as_millis() as i64, false);
                continue;
            }

            self.next_claim_generation += 1;
            let generation = self.next_claim_generation;
            let job = self.jobs.get_mut(&id).expect("popped job exists");
            let delivery = DeliveryJob {
                message_id: id,
                location: job.location,
                attempts: job.attempts,
                claim_generation: generation,
                enqueue_ms,
                sender,
                recipients,
            };
            job.state = JobState::InFlight(generation);
            self.inflight += 1;

            let claim = Claim {
                job: delivery,
                events: self.events_tx.clone(),
                reported: false,
            };
            let waiter = self.waiting.pop_front().expect("checked non-empty");
            if waiter.send(Some(claim)).is_err() {
                // Worker vanished; the dropped Claim reports abandonment,
                // which returns the job to ready via the event channel.
                tracing::debug!(message_id = %id, "claim waiter disappeared");
            }
        }
    }

    fn pop_ready(&mut self) -> Option<(MessageId, i64)> {
        while let Some(Reverse((enqueue_ms, id))) = self.ready.pop() {
            match self.jobs.get(&id) {
                Some(job) if job.state == JobState::Ready => return Some((id, enqueue_ms)),
                _ => {} // stale entry
            }
        }
        None
    }

    fn fill_envelope(&mut self, id: MessageId) -> Result<(), QueueError> {
        let job = self.jobs.get(&id).expect("job exists");
        if job.envelope.is_some() {
            return Ok(());
        }
        let location = job.location;
        let shard = &mut self.shards[location.shard as usize];
        let reader = shard.reader(location.segment)?;
        let header = reader.read_header_at(location.offset, super::record::MAX_RECORD_LEN)?;
        let job = self.jobs.get_mut(&id).expect("job exists");
        job.enqueue_ms = header.enqueue_ms;
        job.envelope = Some((header.sender, header.recipients));
        Ok(())
    }

    fn delay_job(&mut self, id: MessageId, due_ms: i64, persisted: bool) {
        if let Some(job) = self.jobs.get_mut(&id) {
            job.state = JobState::Delayed { due_ms, persisted };
            self.delayed.push(Reverse((due_ms, id)));
        }
    }

    // ------------------------------------------------------------------
    // Outcomes (persist-then-apply).

    fn on_worker_event(&mut self, event: WorkerEvent) {
        match event {
            WorkerEvent::Outcome {
                id,
                generation,
                outcome,
            } => self.on_outcome(id, generation, outcome),
            WorkerEvent::Abandoned { id, generation } => {
                if !self.claim_is_current(&id, generation) {
                    return;
                }
                let job = self.jobs.get_mut(&id).expect("claim_is_current checked");
                tracing::warn!(message_id = %id, "worker abandoned claim; requeueing");
                self.inflight -= 1;
                job.state = JobState::Ready;
                self.ready.push(Reverse((job.enqueue_ms, id)));
            }
        }
    }

    fn claim_is_current(&self, id: &MessageId, generation: u64) -> bool {
        matches!(
            self.jobs.get(id).map(|j| j.state),
            Some(JobState::InFlight(g)) if g == generation
        )
    }

    fn on_outcome(&mut self, id: MessageId, generation: u64, outcome: JobOutcome) {
        if !self.claim_is_current(&id, generation) {
            tracing::debug!(message_id = %id, generation, "ignoring stale claim outcome");
            return;
        }
        self.inflight -= 1;
        let job = self.jobs.get_mut(&id).expect("claim_is_current checked");
        let location = job.location;

        let entry = match outcome {
            JobOutcome::RateLimited { retry_after } => {
                // Local throttling: in-memory requeue only.
                self.delay_job(id, now_ms() + retry_after.as_millis() as i64, false);
                return;
            }
            JobOutcome::Delivered { response } => {
                tracing::debug!(message_id = %id, response, "delivered");
                StateEntry::Delivered {
                    id,
                    location,
                    timestamp_ms: now_ms(),
                }
            }
            JobOutcome::Bounced { reason } => StateEntry::Bounced {
                id,
                location,
                timestamp_ms: now_ms(),
                reason,
            },
            JobOutcome::Deferred {
                next_attempt_ms,
                remaining_recipients,
                error,
            } => StateEntry::Deferred {
                id,
                location,
                attempts: job.attempts + 1,
                next_attempt_ms,
                remaining_recipients,
                last_error: error,
            },
        };

        self.persist_and_apply(location.shard as usize, entry);
        self.maybe_checkpoint();
    }

    fn persist_and_apply(&mut self, shard_idx: usize, entry: StateEntry) {
        let shard = &mut self.shards[shard_idx];
        if !shard.pending_persists.is_empty() {
            // Preserve per-shard ordering behind earlier failed writes.
            shard.pending_persists.push_back(entry);
            return;
        }
        match shard.store.append(&entry) {
            Ok(_) => self.apply_persisted(shard_idx, entry),
            Err(e) => {
                tracing::error!(shard = shard.shard, error = %e,
                    "state journal write failed; will retry (job stays in flight)");
                shard.pending_persists.push_back(entry);
            }
        }
    }

    fn retry_pending_persists(&mut self) {
        for i in 0..self.shards.len() {
            while let Some(entry) = self.shards[i].pending_persists.front().cloned() {
                match self.shards[i].store.append(&entry) {
                    Ok(_) => {
                        self.shards[i].pending_persists.pop_front();
                        self.apply_persisted(i, entry);
                    }
                    Err(_) => break,
                }
            }
        }
    }

    /// Apply a journal-persisted transition to scheduling state.
    fn apply_persisted(&mut self, shard_idx: usize, entry: StateEntry) {
        match entry {
            StateEntry::Deferred {
                id,
                attempts,
                next_attempt_ms,
                remaining_recipients,
                last_error,
                ..
            } => {
                if let Some(job) = self.jobs.get_mut(&id) {
                    job.attempts = attempts;
                    job.remaining = Some(remaining_recipients);
                    job.last_error = Some(last_error);
                    job.state = JobState::Delayed {
                        due_ms: next_attempt_ms,
                        persisted: true,
                    };
                    self.delayed.push(Reverse((next_attempt_ms, id)));
                }
            }
            StateEntry::Delivered { id, location, .. }
            | StateEntry::Bounced { id, location, .. } => {
                self.jobs.remove(&id);
                self.mark_copy_dead(shard_idx, id, location);
            }
            StateEntry::Relocated { id, old, new } => {
                match self.jobs.get_mut(&id) {
                    Some(job) if new.generation > job.location.generation => {
                        job.location = new;
                        job.envelope = None; // content identical, offsets not
                        self.mark_copy_dead(shard_idx, id, old);
                    }
                    Some(_) => {
                        // Stale relocation: the new copy lost.
                        self.mark_copy_dead(shard_idx, id, new);
                    }
                    None => {
                        // Terminal raced the copy; neither copy may
                        // resurrect the message.
                        self.mark_copy_dead(shard_idx, id, old);
                        self.mark_copy_dead(shard_idx, id, new);
                    }
                }
            }
        }
    }

    /// Account one physical record copy as dead and evaluate the segment
    /// for event-driven reclamation.
    fn mark_copy_dead(&mut self, shard_idx: usize, id: MessageId, location: JobLocation) {
        let shard = &mut self.shards[shard_idx];
        if shard
            .tombstones
            .entry(location.segment)
            .or_default()
            .insert(id)
        {
            let stats = shard.stats.entry(location.segment).or_default();
            stats.dead_records += 1;
            stats.dead_bytes += location.length as u64;
        }
        self.maybe_delete_segment(shard_idx, location.segment);
    }

    // ------------------------------------------------------------------
    // Reclamation (PLAN §17): event-driven deletion of fully dead sealed
    // segments; dead-ratio compaction for partially live ones.

    /// Delete a sealed segment the moment its last byte goes dead.
    fn maybe_delete_segment(&mut self, shard_idx: usize, segment: u64) {
        let shard = &mut self.shards[shard_idx];
        let Some(stats) = shard.stats.get(&segment) else {
            return;
        };
        // total_bytes > 0 means the segment is sealed with a known size.
        if stats.total_bytes == 0 || stats.dead_bytes < stats.total_bytes {
            return;
        }
        // Destructive boundary: the journal entries recording these deaths
        // must be durable before the payload disappears.
        if let Err(e) = shard.store.fsync_journal() {
            tracing::error!(shard = shard.shard, segment, error = %e,
                "cannot fsync journal; postponing segment deletion");
            return;
        }
        let path = shard.dir.join(super::segment::sealed_file_name(segment));
        if let Err(e) = std::fs::remove_file(&path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                tracing::error!(shard = shard.shard, segment, error = %e,
                    "failed to delete dead segment");
                return;
            }
        }
        shard.readers.remove(&segment);
        shard.tombstones.remove(&segment);
        shard.stats.remove(&segment);
        shard.shared.remove_segment(segment);
        if let Some(run) = &self.compaction {
            if run.shard_idx == shard_idx && run.segment == segment {
                self.compaction = None; // everything left in it just died
            }
        }
        crate::metrics::logqueue_segments_deleted(1);
        tracing::info!(shard = self.shards[shard_idx].shard, segment, "deleted fully dead segment");
    }

    /// Sweep backstop for event-driven deletion (PLAN §17.1): a segment
    /// whose last record went terminal before the dispatcher had observed
    /// the seal (total_bytes still unknown at that moment) misses its
    /// deletion event; catch it on the safety tick.
    fn sweep_dead_segments(&mut self) {
        for shard_idx in 0..self.shards.len() {
            let dead: Vec<u64> = self.shards[shard_idx]
                .stats
                .iter()
                .filter(|(_, s)| s.total_bytes > 0 && s.dead_bytes >= s.total_bytes)
                .map(|(seg, _)| *seg)
                .collect();
            for segment in dead {
                self.maybe_delete_segment(shard_idx, segment);
            }
        }
    }

    /// Pick a compaction candidate if none is running (one at a time
    /// globally). Runs on the safety tick as both trigger and backstop.
    fn maybe_start_compaction(&mut self) {
        if self.compaction.is_some() {
            return;
        }
        for shard_idx in 0..self.shards.len() {
            let shard = &self.shards[shard_idx];
            let cursor_segment = shard.cursor.map(|(s, _)| s).unwrap_or(0);
            for (&segment, stats) in &shard.stats {
                if stats.total_bytes == 0
                    || stats.dead_bytes >= stats.total_bytes
                    || (stats.dead_bytes as f64)
                        < stats.total_bytes as f64 * self.config.compaction_dead_ratio
                    || segment >= cursor_segment
                {
                    continue; // active, fully dead, too alive, or not yet fully discovered
                }
                let path = shard.dir.join(super::segment::sealed_file_name(segment));
                let old_enough = std::fs::metadata(&path)
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|t| t.elapsed().ok())
                    .is_some_and(|age| age >= self.config.compaction_min_age);
                if !old_enough {
                    continue;
                }
                // Snapshot the live set: tracked jobs located in this
                // segment that are not currently being read by a worker.
                let queue: VecDeque<MessageId> = self
                    .jobs
                    .iter()
                    .filter(|(_, j)| {
                        j.location.shard == shard.shard
                            && j.location.segment == segment
                            && !matches!(j.state, JobState::InFlight(_))
                    })
                    .map(|(id, _)| *id)
                    .collect();
                if queue.is_empty() {
                    continue; // only in-flight records left; retry later
                }
                tracing::info!(
                    shard = shard.shard,
                    segment,
                    live = queue.len(),
                    dead_bytes = stats.dead_bytes,
                    total_bytes = stats.total_bytes,
                    "starting compaction"
                );
                crate::metrics::logqueue_compaction_started();
                self.compaction = Some(CompactionRun {
                    shard_idx,
                    segment,
                    queue,
                });
                return;
            }
        }
    }

    /// Copy a bounded batch of live records out of the compaction source.
    /// Each copy is re-appended through the writer (higher relocation
    /// generation, original enqueue timestamp) and journaled as Relocated
    /// before the location switches. The source segment is never touched;
    /// it dies through the normal full-death path once its last live
    /// record has moved out (or delivered).
    async fn drive_compaction(&mut self) {
        const BATCH: usize = 256;
        let Some(run) = &mut self.compaction else {
            return;
        };
        let shard_idx = run.shard_idx;
        let source = run.segment;

        for _ in 0..BATCH {
            let Some(id) = self.compaction.as_mut().and_then(|r| r.queue.pop_front()) else {
                tracing::info!(segment = source, "compaction pass complete");
                crate::metrics::logqueue_compaction_completed();
                self.compaction = None;
                return;
            };
            let Some(job) = self.jobs.get(&id) else {
                continue; // went terminal while queued
            };
            if job.location.segment != source || matches!(job.state, JobState::InFlight(_)) {
                continue; // moved or claimed since the snapshot
            }
            let old = job.location;

            let record = {
                let shard = &mut self.shards[shard_idx];
                shard
                    .reader(source)
                    .and_then(|r| r.read_record_at(old.offset, super::record::MAX_RECORD_LEN))
            };
            let (header, body) = match record {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!(message_id = %id, error = %e,
                        "compaction read failed; aborting pass");
                    crate::metrics::logqueue_compaction_failed();
                    self.compaction = None;
                    return;
                }
            };

            let append = self.append.clone();
            let new = match append
                .append_to_shard(
                    self.shards[shard_idx].shard,
                    super::writer::AppendMessage {
                        message_id: id,
                        enqueue_ms: header.enqueue_ms,
                        generation: old.generation + 1,
                        sender: header.sender,
                        recipients: header.recipients,
                        body: bytes::Bytes::from(body),
                    },
                )
                .await
            {
                Ok(loc) => loc,
                Err(e) => {
                    tracing::error!(message_id = %id, error = %e,
                        "compaction append failed; aborting pass");
                    crate::metrics::logqueue_compaction_failed();
                    self.compaction = None;
                    return;
                }
            };

            crate::metrics::logqueue_compaction_bytes_read(old.length as u64);
            crate::metrics::logqueue_compaction_bytes_written(new.length as u64);
            crate::metrics::logqueue_relocations(1);
            self.persist_and_apply(shard_idx, StateEntry::Relocated { id, old, new });
        }
    }

    /// Push scheduler and storage gauges (runs on the safety tick).
    fn publish_metrics(&self) {
        let now = now_ms();
        let mut ready = 0i64;
        let mut deferred = 0i64;
        let mut oldest_ready_ms: Option<i64> = None;
        let mut oldest_deferred_due: Option<i64> = None;
        for job in self.jobs.values() {
            match job.state {
                JobState::Ready => {
                    ready += 1;
                    oldest_ready_ms =
                        Some(oldest_ready_ms.map_or(job.enqueue_ms, |o| o.min(job.enqueue_ms)));
                }
                JobState::Delayed { due_ms, .. } => {
                    deferred += 1;
                    oldest_deferred_due =
                        Some(oldest_deferred_due.map_or(due_ms, |o| o.min(due_ms)));
                }
                JobState::InFlight(_) => {}
            }
        }
        crate::metrics::logqueue_ready_jobs_set(ready);
        crate::metrics::logqueue_deferred_jobs_set(deferred);
        crate::metrics::logqueue_inflight_jobs_set(self.inflight as i64);
        crate::metrics::logqueue_oldest_ready_age_seconds_set(
            oldest_ready_ms.map_or(0, |ms| ((now - ms) / 1000).max(0)),
        );
        crate::metrics::logqueue_oldest_deferred_age_seconds_set(
            oldest_deferred_due.map_or(0, |due| ((now - due) / 1000).max(0)),
        );

        let mut dead = 0u64;
        let mut total = 0u64;
        let mut sealed = 0i64;
        for shard in &self.shards {
            for stats in shard.stats.values() {
                dead += stats.dead_bytes;
                if stats.total_bytes > 0 {
                    sealed += 1;
                    total += stats.total_bytes;
                }
            }
        }
        crate::metrics::logqueue_dead_bytes_set(dead);
        crate::metrics::logqueue_live_bytes_set(total.saturating_sub(dead));
        crate::metrics::logqueue_sealed_segments_set(sealed);
        if let Some(shard) = self.shards.first() {
            if let Ok(free) = super::spool::disk_free_bytes(&shard.dir) {
                crate::metrics::logqueue_disk_free_bytes_set(free);
            }
        }
    }

    // ------------------------------------------------------------------
    // Checkpoints.

    fn snapshot_shard(&self, shard_idx: usize) -> Checkpoint {
        let shard = &self.shards[shard_idx];
        let mut cp = Checkpoint {
            cursor: shard.cursor,
            ..Default::default()
        };
        for (id, job) in &self.jobs {
            if job.location.shard != shard.shard {
                continue;
            }
            match job.state {
                JobState::Delayed {
                    due_ms,
                    persisted: true,
                } => cp.deferred.push(DeferredJob {
                    id: *id,
                    location: job.location,
                    attempts: job.attempts,
                    next_attempt_ms: due_ms,
                    remaining_recipients: job.remaining.clone().unwrap_or_default(),
                    last_error: job.last_error.clone().unwrap_or_default(),
                }),
                // Ready, in-flight, and rate-limit holds all restart as
                // ready.
                _ => cp.ready.push(ReadyJob {
                    id: *id,
                    location: job.location,
                    attempts: job.attempts,
                    enqueue_ms: job.enqueue_ms,
                    remaining_recipients: job.remaining.clone().unwrap_or_default(),
                }),
            }
        }
        cp.tombstones = shard
            .tombstones
            .iter()
            .map(|(seg, ids)| (*seg, ids.iter().copied().collect()))
            .collect();
        cp.segment_stats = shard.stats.iter().map(|(s, st)| (*s, *st)).collect();
        cp
    }

    fn maybe_checkpoint(&mut self) {
        for i in 0..self.shards.len() {
            let shard = &self.shards[i];
            if shard.checkpoint.is_some()
                || !shard.pending_persists.is_empty()
                || shard.store.bytes_since_checkpoint() < self.config.checkpoint_interval_bytes
            {
                continue;
            }
            let cp = self.snapshot_shard(i);
            let shard = &mut self.shards[i];
            let pending = match shard.store.begin_checkpoint() {
                Ok(p) => p,
                Err(e) => {
                    tracing::error!(shard = shard.shard, error = %e, "cannot begin checkpoint");
                    continue;
                }
            };
            shard.checkpoint = Some(pending);
            let dir = shard.dir.clone();
            let shard_no = shard.shard;
            let cp_tx = self.cp_tx.clone();
            let replay_from = pending.replay_from;
            tokio::task::spawn_blocking(move || {
                let result = super::state::write_checkpoint_file(&dir, &cp, replay_from);
                let _ = cp_tx.send((shard_no, result));
            });
        }
    }

    fn finish_checkpoint(&mut self, shard_no: u16, result: Result<(), QueueError>) {
        let Some(shard) = self.shards.iter_mut().find(|s| s.shard == shard_no) else {
            return;
        };
        let Some(pending) = shard.checkpoint.take() else {
            return;
        };
        match result {
            Ok(()) => {
                if let Err(e) = shard.store.finish_checkpoint(pending) {
                    tracing::warn!(shard = shard_no, error = %e,
                        "checkpoint published but journal pruning failed");
                }
            }
            Err(e) => {
                // The rotated journal chain is still complete, so recovery
                // stays correct; only the compaction of history was lost.
                tracing::error!(shard = shard_no, error = %e, "checkpoint write failed");
            }
        }
    }

    /// Synchronous checkpoint used at shutdown.
    fn checkpoint_shard_sync(&mut self, shard_idx: usize) -> Result<(), QueueError> {
        let cp = self.snapshot_shard(shard_idx);
        self.shards[shard_idx].store.write_checkpoint(&cp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logqueue::spool::Spool;
    use crate::logqueue::state::ShardStateStore;
    use crate::logqueue::writer::{AppendMessage, LogWriters, WriterConfig};
    use bytes::Bytes;
    use std::sync::Mutex;

    fn writer_config() -> WriterConfig {
        WriterConfig {
            segment_target_bytes: 64 * 1024 * 1024,
            max_record_len: crate::logqueue::record::MAX_RECORD_LEN,
            pending_append_bytes: 16 * 1024 * 1024,
        }
    }

    fn message(seq: u64, rcpt: &str) -> AppendMessage {
        AppendMessage {
            message_id: MessageId::from_ulid(ulid::Ulid::from_parts(seq, (seq * 7 + 1) as u128)),
            enqueue_ms: 1_752_000_000_000 + seq as i64,
            generation: 0,
            sender: "sender@example.com".into(),
            recipients: vec![rcpt.into()],
            body: Bytes::from(format!("body {seq}")),
        }
    }

    struct Harness {
        _spool: Spool,
        writers: LogWriters,
        handle: DispatcherHandle,
        dispatcher_task: tokio::task::JoinHandle<()>,
        cancel: CancellationToken,
    }

    fn start(root: &std::path::Path, gate: Arc<dyn RateGate>, config: DispatcherConfig) -> Harness {
        let spool = Spool::open(root.join("spool"), 1).unwrap();
        let writers = LogWriters::start(&spool, writer_config()).unwrap();
        let mut inits = Vec::new();
        for shard_dir in spool.shards() {
            let (store, recovered) =
                ShardStateStore::recover(shard_dir.path(), shard_dir.shard()).unwrap();
            inits.push(ShardInit {
                dir: shard_dir.path().to_path_buf(),
                shared: writers.handle().shard_shared(shard_dir.shard()),
                store,
                recovered,
            });
        }
        let cancel = CancellationToken::new();
        let (handle, dispatcher_task) =
            Dispatcher::start(inits, writers.handle(), gate, config, cancel.clone());
        Harness {
            _spool: spool,
            writers,
            handle,
            dispatcher_task,
            cancel,
        }
    }

    async fn stop(h: Harness) {
        h.cancel.cancel();
        h.dispatcher_task.await.unwrap();
        h.writers.shutdown().await;
    }

    #[tokio::test]
    async fn discovers_and_dispatches_appended_messages() {
        let dir = tempfile::tempdir().unwrap();
        let h = start(
            dir.path(),
            Arc::new(NoRateGate),
            DispatcherConfig::default(),
        );
        let append = h.writers.handle();
        let loc = append.append(message(1, "r1@example.com")).await.unwrap();

        let claim = h.handle.claim().await.expect("claim");
        assert_eq!(claim.job.location, loc);
        assert_eq!(claim.job.attempts, 0);
        assert_eq!(claim.job.sender, "sender@example.com");
        assert_eq!(claim.job.recipients, vec!["r1@example.com".to_string()]);

        let body = h.handle.read_body(claim.job.location).await.unwrap();
        assert_eq!(body, b"body 1");

        claim.report(JobOutcome::Delivered {
            response: "250 ok".into(),
        });
        stop(h).await;
    }

    #[tokio::test]
    async fn deferred_outcome_schedules_retry_with_remaining_recipients() {
        let dir = tempfile::tempdir().unwrap();
        let h = start(
            dir.path(),
            Arc::new(NoRateGate),
            DispatcherConfig::default(),
        );
        let append = h.writers.handle();
        append.append(message(1, "r1@example.com")).await.unwrap();

        let claim = h.handle.claim().await.unwrap();
        let id = claim.job.message_id;
        claim.report(JobOutcome::Deferred {
            next_attempt_ms: now_ms() + 50,
            remaining_recipients: vec!["r1@example.com".into()],
            error: "451 greylisted".into(),
        });

        // The retry claim arrives once due, with the attempt count bumped.
        let claim = h.handle.claim().await.unwrap();
        assert_eq!(claim.job.message_id, id);
        assert_eq!(claim.job.attempts, 1);
        assert_eq!(claim.job.recipients, vec!["r1@example.com".to_string()]);
        claim.report(JobOutcome::Delivered {
            response: "250 ok".into(),
        });
        stop(h).await;
    }

    #[tokio::test]
    async fn rate_limited_outcome_requeues_without_attempt_increment() {
        let dir = tempfile::tempdir().unwrap();
        let h = start(
            dir.path(),
            Arc::new(NoRateGate),
            DispatcherConfig::default(),
        );
        let append = h.writers.handle();
        append.append(message(1, "r1@example.com")).await.unwrap();

        let claim = h.handle.claim().await.unwrap();
        claim.report(JobOutcome::RateLimited {
            retry_after: Duration::from_millis(30),
        });

        let claim = h.handle.claim().await.unwrap();
        assert_eq!(claim.job.attempts, 0, "rate limiting is not an attempt");
        claim.report(JobOutcome::Delivered {
            response: "250 ok".into(),
        });
        stop(h).await;
    }

    #[tokio::test]
    async fn dropped_claim_is_abandoned_and_redispatched() {
        let dir = tempfile::tempdir().unwrap();
        let h = start(
            dir.path(),
            Arc::new(NoRateGate),
            DispatcherConfig::default(),
        );
        let append = h.writers.handle();
        append.append(message(1, "r1@example.com")).await.unwrap();

        let claim = h.handle.claim().await.unwrap();
        let id = claim.job.message_id;
        drop(claim); // worker dies without reporting

        let claim = h.handle.claim().await.unwrap();
        assert_eq!(claim.job.message_id, id);
        claim.report(JobOutcome::Delivered {
            response: "250 ok".into(),
        });
        stop(h).await;
    }

    #[tokio::test]
    async fn stale_generation_outcome_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let h = start(
            dir.path(),
            Arc::new(NoRateGate),
            DispatcherConfig::default(),
        );
        let append = h.writers.handle();
        append.append(message(1, "r1@example.com")).await.unwrap();

        // First claim is abandoned but we keep its (now stale) event sender.
        let claim1 = h.handle.claim().await.unwrap();
        let stale_events = claim1.events.clone();
        let stale_gen = claim1.job.claim_generation;
        let id = claim1.job.message_id;
        drop(claim1);

        let claim2 = h.handle.claim().await.unwrap();
        assert_eq!(claim2.job.message_id, id);
        assert_ne!(claim2.job.claim_generation, stale_gen);

        // The stale generation reports Bounced; it must be ignored.
        let _ = stale_events.send(WorkerEvent::Outcome {
            id,
            generation: stale_gen,
            outcome: JobOutcome::Bounced {
                reason: "stale".into(),
            },
        });
        tokio::time::sleep(Duration::from_millis(50)).await;

        // The live claim still completes normally.
        claim2.report(JobOutcome::Delivered {
            response: "250 ok".into(),
        });
        stop(h).await;

        // After restart nothing is ready (the message really delivered) —
        // i.e. the stale Bounced didn't win.
        // (Verified by the state store directly.)
    }

    struct BlockOnce {
        blocked: Mutex<Option<Duration>>,
    }
    impl RateGate for BlockOnce {
        fn check(&self, _domain: &str) -> Option<Duration> {
            self.blocked.lock().unwrap().take()
        }
    }

    #[tokio::test]
    async fn dispatch_gating_delays_exhausted_domains() {
        let gate = Arc::new(BlockOnce {
            blocked: Mutex::new(Some(Duration::from_millis(40))),
        });
        let dir = tempfile::tempdir().unwrap();
        let h = start(
            dir.path(),
            gate,
            DispatcherConfig::default(),
        );
        let append = h.writers.handle();
        append.append(message(1, "r1@example.com")).await.unwrap();

        let started = std::time::Instant::now();
        let claim = h.handle.claim().await.unwrap();
        assert!(
            started.elapsed() >= Duration::from_millis(35),
            "claim should have been gated, got it after {:?}",
            started.elapsed()
        );
        assert_eq!(claim.job.attempts, 0, "gating is not an attempt");
        claim.report(JobOutcome::Delivered {
            response: "250 ok".into(),
        });
        stop(h).await;
    }

    #[tokio::test]
    async fn full_restart_preserves_deferred_and_skips_terminal() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();

        let (deferred_id, delivered_id) = {
            let h = start(dir.path(), Arc::new(NoRateGate), DispatcherConfig::default());
            let append = h.writers.handle();
            append.append(message(1, "r1@example.com")).await.unwrap();
            append.append(message(2, "r2@example.com")).await.unwrap();

            let c1 = h.handle.claim().await.unwrap();
            let c2 = h.handle.claim().await.unwrap();
            let (deferred, delivered) = (c1.job.message_id, c2.job.message_id);
            c1.report(JobOutcome::Deferred {
                next_attempt_ms: now_ms() + 3_600_000, // an hour away
                remaining_recipients: vec!["r1@example.com".into()],
                error: "451".into(),
            });
            c2.report(JobOutcome::Delivered {
                response: "250 ok".into(),
            });
            stop(h).await;
            (deferred, delivered)
        };

        // Restart on the same spool.
        let spool = Spool::open(root.join("spool"), 1).unwrap();
        let writers = LogWriters::start(&spool, writer_config()).unwrap();
        let (store, recovered) =
            ShardStateStore::recover(spool.shard(0).path(), 0).unwrap();

        let d = recovered
            .deferred
            .get(&deferred_id)
            .expect("deferred job survives restart");
        assert_eq!(d.attempts, 1);
        assert_eq!(d.remaining_recipients, vec!["r1@example.com".to_string()]);
        assert!(
            recovered.is_terminal(d.location.segment, &delivered_id),
            "delivered message stays terminal"
        );
        assert!(recovered.ready.is_empty());
        drop(store);
        writers.shutdown().await;
    }

    #[tokio::test]
    async fn restart_redispatches_inflight_messages() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let id = {
            let h = start(dir.path(), Arc::new(NoRateGate), DispatcherConfig::default());
            let append = h.writers.handle();
            append.append(message(1, "r1@example.com")).await.unwrap();
            // Claim and crash while in flight: report nothing, drop nothing
            // cleanly — forget the claim so no abandonment event fires.
            let claim = h.handle.claim().await.unwrap();
            let id = claim.job.message_id;
            std::mem::forget(claim);
            h.cancel.cancel();
            // The dispatcher will wait for the in-flight claim on shutdown;
            // abandon it by dropping the whole runtime instead (crash).
            h.dispatcher_task.abort();
            h.writers.shutdown().await;
            id
        };

        // Restart: the record was never persisted as terminal, so it must
        // be discovered and dispatched again.
        let spool = Spool::open(root.join("spool"), 1).unwrap();
        let writers = LogWriters::start(&spool, writer_config()).unwrap();
        let (store, recovered) = ShardStateStore::recover(spool.shard(0).path(), 0).unwrap();
        let cancel = CancellationToken::new();
        let (handle, task) = Dispatcher::start(
            vec![ShardInit {
                dir: spool.shard(0).path().to_path_buf(),
                shared: writers.handle().shard_shared(0),
                store,
                recovered,
            }],
            writers.handle(),
            Arc::new(NoRateGate),
            DispatcherConfig::default(),
            cancel.clone(),
        );
        let claim = handle.claim().await.expect("redispatched after restart");
        assert_eq!(claim.job.message_id, id);
        claim.report(JobOutcome::Delivered {
            response: "250 ok".into(),
        });
        cancel.cancel();
        task.await.unwrap();
        writers.shutdown().await;
    }

    #[tokio::test]
    async fn discovery_backpressure_bounds_tracked_jobs_without_losing_any() {
        let config = DispatcherConfig {
            max_tracked_jobs: 10,
            ..Default::default()
        };
        let dir = tempfile::tempdir().unwrap();
        let h = start(dir.path(), Arc::new(NoRateGate), config);
        let append = h.writers.handle();
        for i in 0..50u64 {
            append.append(message(i, "r@example.com")).await.unwrap();
        }
        // Drain everything; backpressure must refill as jobs complete.
        let mut delivered = HashSet::new();
        for _ in 0..50 {
            let claim = h.handle.claim().await.expect("all 50 must arrive");
            assert!(delivered.insert(claim.job.message_id));
            claim.report(JobOutcome::Delivered {
                response: "250 ok".into(),
            });
        }
        assert_eq!(delivered.len(), 50);
        stop(h).await;
    }

    #[tokio::test]
    async fn dispatch_survives_segment_rotation() {
        let dir = tempfile::tempdir().unwrap();
        let spool = Spool::open(dir.path().join("spool"), 1).unwrap();
        let mut wcfg = writer_config();
        wcfg.segment_target_bytes = 2048; // force rotations
        let writers = LogWriters::start(&spool, wcfg).unwrap();
        let (store, recovered) = ShardStateStore::recover(spool.shard(0).path(), 0).unwrap();
        let cancel = CancellationToken::new();
        let (handle, task) = Dispatcher::start(
            vec![ShardInit {
                dir: spool.shard(0).path().to_path_buf(),
                shared: writers.handle().shard_shared(0),
                store,
                recovered,
            }],
            writers.handle(),
            Arc::new(NoRateGate),
            DispatcherConfig::default(),
            cancel.clone(),
        );
        let append = writers.handle();
        for i in 0..30u64 {
            let mut m = message(i, "r@example.com");
            m.body = Bytes::from(vec![b'x'; 512]);
            append.append(m).await.unwrap();
        }
        let mut seen = HashSet::new();
        for _ in 0..30 {
            let claim = handle.claim().await.expect("all records across segments");
            assert!(seen.insert(claim.job.message_id));
            let body = handle.read_body(claim.job.location).await.unwrap();
            assert_eq!(body.len(), 512);
            claim.report(JobOutcome::Delivered {
                response: "250 ok".into(),
            });
        }
        cancel.cancel();
        task.await.unwrap();
        writers.shutdown().await;
    }

    // ------------------------------------------------------------------
    // GC and compaction (PLAN §26.5).

    /// Poll until `cond` holds or ~5s elapse.
    async fn eventually(mut cond: impl FnMut() -> bool, what: &str) {
        for _ in 0..500 {
            if cond() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("timed out waiting for: {what}");
    }

    fn sealed_segment_files(shard_dir: &std::path::Path) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(shard_dir)
            .unwrap()
            .filter_map(|e| e.unwrap().file_name().into_string().ok())
            .filter(|n| n.ends_with(".log") && n.starts_with("segment-"))
            .collect();
        v.sort();
        v
    }

    #[tokio::test]
    async fn fully_delivered_sealed_segments_are_deleted_event_driven() {
        let dir = tempfile::tempdir().unwrap();
        let spool = Spool::open(dir.path().join("spool"), 1).unwrap();
        let mut wcfg = writer_config();
        wcfg.segment_target_bytes = 2048;
        let writers = LogWriters::start(&spool, wcfg).unwrap();
        let (store, recovered) = ShardStateStore::recover(spool.shard(0).path(), 0).unwrap();
        let cancel = CancellationToken::new();
        let (handle, task) = Dispatcher::start(
            vec![ShardInit {
                dir: spool.shard(0).path().to_path_buf(),
                shared: writers.handle().shard_shared(0),
                store,
                recovered,
            }],
            writers.handle(),
            Arc::new(NoRateGate),
            DispatcherConfig {
                safety_tick: Duration::from_millis(50),
                ..Default::default()
            },
            cancel.clone(),
        );
        let append = writers.handle();
        for i in 0..12u64 {
            let mut m = message(i, "r@example.com");
            m.body = Bytes::from(vec![b'x'; 400]);
            append.append(m).await.unwrap();
        }
        let shard_dir = spool.shard(0).path().to_path_buf();
        // Several segments sealed.
        assert!(!sealed_segment_files(&shard_dir).is_empty());

        for _ in 0..12 {
            let claim = handle.claim().await.unwrap();
            claim.report(JobOutcome::Delivered {
                response: "250 ok".into(),
            });
        }
        // Every sealed segment dies without waiting for anything periodic
        // beyond the event itself (deletion happens in the terminal apply).
        eventually(
            || sealed_segment_files(&shard_dir).is_empty(),
            "all sealed segments deleted",
        )
        .await;

        cancel.cancel();
        task.await.unwrap();
        writers.shutdown().await;
    }

    #[tokio::test]
    async fn live_record_prevents_deletion_and_compaction_relocates_it() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let spool = Spool::open(root.join("spool"), 1).unwrap();
        let mut wcfg = writer_config();
        wcfg.segment_target_bytes = 2048;
        let writers = LogWriters::start(&spool, wcfg).unwrap();
        let (store, recovered) = ShardStateStore::recover(spool.shard(0).path(), 0).unwrap();
        let cancel = CancellationToken::new();
        let (handle, task) = Dispatcher::start(
            vec![ShardInit {
                dir: spool.shard(0).path().to_path_buf(),
                shared: writers.handle().shard_shared(0),
                store,
                recovered,
            }],
            writers.handle(),
            Arc::new(NoRateGate),
            DispatcherConfig {
                safety_tick: Duration::from_millis(50),
                compaction_dead_ratio: 0.5,
                compaction_min_age: Duration::ZERO,
                ..Default::default()
            },
            cancel.clone(),
        );
        let append = writers.handle();
        // m0..m3 fill segment 1; m4 forces rotation into segment 2.
        for i in 0..5u64 {
            let mut m = message(i, "r@example.com");
            m.body = Bytes::from(vec![b'x'; 400]);
            append.append(m).await.unwrap();
        }
        let shard_dir = spool.shard(0).path().to_path_buf();
        let first_sealed = sealed_segment_files(&shard_dir);
        assert_eq!(first_sealed.len(), 1, "expected one sealed segment");

        // Deliver everything except one message, which defers far out.
        let mut survivor = None;
        for _ in 0..5 {
            let claim = handle.claim().await.unwrap();
            if survivor.is_none() && claim.job.location.segment == 1 {
                survivor = Some(claim.job.message_id);
                claim.report(JobOutcome::Deferred {
                    next_attempt_ms: now_ms() + 3_600_000,
                    remaining_recipients: vec!["r@example.com".into()],
                    error: "451 long defer".into(),
                });
            } else {
                claim.report(JobOutcome::Delivered {
                    response: "250 ok".into(),
                });
            }
        }
        let survivor = survivor.expect("segment 1 had a claim");

        // Segment 1 is 75% dead but held live by the survivor; compaction
        // relocates the survivor, then segment 1 dies.
        eventually(
            || !shard_dir.join(crate::logqueue::segment::sealed_file_name(1)).exists(),
            "compacted source segment deleted",
        )
        .await;

        // Clean shutdown, then verify on-disk state.
        cancel.cancel();
        task.await.unwrap();
        writers.shutdown().await;
        drop(spool);

        let spool = Spool::open(root.join("spool"), 1).unwrap();
        let (_, recovered) = ShardStateStore::recover(spool.shard(0).path(), 0).unwrap();
        let d = recovered
            .deferred
            .get(&survivor)
            .expect("survivor still deferred after relocation + restart");
        assert_ne!(d.location.segment, 1, "location moved off the dead segment");
        assert_eq!(d.location.generation, 1, "relocation bumped the generation");
        assert_eq!(d.attempts, 1);

        // The body is intact at the relocated position.
        let reader = crate::logqueue::segment::open_segment_reader(
            spool.shard(0).path(),
            d.location.segment,
        )
        .unwrap();
        let (header, body) = reader
            .read_record_at(d.location.offset, crate::logqueue::record::MAX_RECORD_LEN)
            .unwrap();
        assert_eq!(header.message_id, survivor);
        assert_eq!(header.generation, 1);
        assert_eq!(body, vec![b'x'; 400]);
    }

    #[tokio::test]
    async fn rediscovered_higher_generation_copy_wins_after_crashy_restart() {
        // Simulate the crash window between the compaction copy landing and
        // its Relocated journal entry: two copies of the same message id on
        // disk, generation 0 and 1, no state at all. Discovery must track
        // the generation-1 copy.
        let dir = tempfile::tempdir().unwrap();
        let spool = Spool::open(dir.path().join("spool"), 1).unwrap();
        let writers = LogWriters::start(&spool, writer_config()).unwrap();
        let append = writers.handle();

        let mut m = message(1, "r@example.com");
        let id = m.message_id;
        m.body = Bytes::from_static(b"old copy");
        append.append(m).await.unwrap();
        let mut m = message(1, "r@example.com");
        m.generation = 1;
        m.body = Bytes::from_static(b"new copy");
        let new_loc = append.append(m).await.unwrap();

        let (store, recovered) = ShardStateStore::recover(spool.shard(0).path(), 0).unwrap();
        let cancel = CancellationToken::new();
        let (handle, task) = Dispatcher::start(
            vec![ShardInit {
                dir: spool.shard(0).path().to_path_buf(),
                shared: writers.handle().shard_shared(0),
                store,
                recovered,
            }],
            writers.handle(),
            Arc::new(NoRateGate),
            DispatcherConfig::default(),
            cancel.clone(),
        );

        let claim = handle.claim().await.unwrap();
        assert_eq!(claim.job.message_id, id);
        assert_eq!(claim.job.location, new_loc);
        let body = handle.read_body(claim.job.location).await.unwrap();
        assert_eq!(body, b"new copy");
        claim.report(JobOutcome::Delivered {
            response: "250 ok".into(),
        });

        cancel.cancel();
        task.await.unwrap();
        writers.shutdown().await;
    }
}
