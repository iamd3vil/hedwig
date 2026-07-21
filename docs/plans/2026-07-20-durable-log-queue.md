# Hedwig Durable Log Queue Plan

> Status: design captured for future implementation; revised 2026-07-20 after pair review
>
> Date: 2026-07-20
>
> Scope: replace the filesystem spool plus worker-coupled in-memory job queue with a single-process dispatcher backed by segmented append-only message logs. One append writer by default; the on-disk format is shard-capable so more writers can be enabled if benchmarks justify them.

## 1. Executive summary

Hedwig currently persists an incoming message and then awaits capacity in the bounded in-memory worker channel before returning SMTP `250 OK`. When outbound workers are slow, sleeping for rate limits, or otherwise occupied, the channel eventually fills and inbound acceptance becomes limited by outbound drain speed.

The intended architecture is:

- Hedwig remains a **single process**.
- There is **one dispatcher** responsible for scheduling all delivery work.
- There is **one append writer** by default. The record format, job locations, and dispatcher are shard-aware, so `N` writers can be enabled later without a format change; multiple writers ship only if benchmarks justify them.
- Each append writer exclusively owns its shard and writes to that shard's segmented log files. Logs are segmented: the active file is sealed at a target size and a new one is started, so no single file grows without bound regardless of total throughput.
- The complete message is stored in the log record, eliminating one spool file per message and avoiding large flat-directory scans.
- SMTP acceptance waits only for the append write to complete into the kernel page cache. It does **not** wait for `fsync`, the dispatcher, a worker, or outbound delivery capacity.
- The dispatcher discovers appended records using per-shard committed-tail positions and maintains ready, deferred, and in-flight state.
- Workers pull jobs from the dispatcher and report outcomes.
- Delivered records become garbage. Segment reclamation is event-driven: a segment whose live count reaches zero is deleted immediately, and a sealed segment is queued for compaction as soon as its garbage ratio crosses the threshold. Periodic sweeps exist only as a safety-net backstop.
- A small amount of temporary disk amplification is accepted; delivered payloads do not remain indefinitely.
- Multiple processes, shared queues, leader election, distributed claims, and exactly-once delivery are explicitly out of scope.

The main result is that inbound SMTP acceptance is bounded by disk append throughput rather than outbound worker drain throughput.

## 2. Context and current problem

### 2.1 Current acceptance path

The current path is effectively:

```text
SMTP DATA
  -> persist message as Queued
  -> await sender_channel.send(job)
  -> return 250 OK
```

Relevant current code:

- `smtp-server/src/callbacks.rs:248-280` persists the queued message and then awaits sending its `Job` to the worker channel.
- `smtp/src/lib.rs:465-469` waits for the DATA callback before returning `250 OK`.
- `smtp-server/src/main.rs:108-112` creates a bounded job channel using `queue_buffer`.

The body has already been written to the filesystem at this point — with page-cache durability only: no `fsync` and no atomic rename — but the SMTP client is not acknowledged until an in-memory worker slot becomes available. Once the channel fills, inbound acceptance proceeds only as quickly as workers remove jobs from the channel.

### 2.2 Why workers may not drain promptly

A worker occupies its slot while performing the complete delivery lifecycle, including:

- loading and parsing the message;
- signing it;
- waiting for rate limits;
- DNS and MX work;
- connecting to remote MTAs;
- attempting SMTP delivery.

In particular, a rate-limited job currently sleeps in the worker in `smtp-server/src/worker/mod.rs:610-617`. Enough sleeping jobs can consume every worker slot even when unrelated destinations could proceed.

### 2.3 Current scanning costs

The current filesystem backend uses status directories containing one file per message. Existing operations include:

- flat directory enumeration for queued messages;
- startup replay of the entire queued set before accepting new connections;
- periodic deferred metadata scans;
- per-message path, inode, open, and file creation work.

The SQLite backend avoids directory scans but still performs whole-status queries. The new architecture must avoid relying on full per-message scans during normal startup and scheduling.

## 3. Goals

### 3.1 Primary goals

1. Decouple inbound acceptance from outbound worker drain speed.
2. Keep disk as the source of truth; message bodies must not remain in memory while waiting for outbound delivery.
3. Replace one-file-per-message storage with sequential append-oriented storage.
4. Avoid large queued/deferred directory scans.
5. Preserve at-least-once delivery and retry-attempt recovery across process restarts.
6. Keep the design optimized for a single Hedwig process.
7. Keep the on-disk format and dispatcher shard-capable so append throughput can later scale across multiple independently owned log shards.
8. Reclaim delivered-message disk space through segment deletion and compaction.
9. Move delayed retry waiting out of worker slots and into dispatcher scheduling.
10. Maintain or improve observability of queue depth, age, retries, and delivery outcomes.

### 3.2 Secondary goals

- Bound in-memory admission buffering by bytes rather than message count.
- Permit tuning the append-writer count without changing dispatcher semantics.
- Make startup recovery sequential and deterministic.
- Keep the on-disk format versioned and independently testable.
- Preserve the existing filesystem backend's accepted page-cache durability tradeoff.

## 4. Non-goals

The initial implementation will not provide:

- multiple processes sharing one queue;
- active-active dispatchers;
- leader election or fencing;
- distributed leases;
- online resharding of an existing non-empty queue;
- exactly-once delivery to remote SMTP servers;
- strict global FIFO delivery order;
- an `fsync` per message or group-commit durability;
- a general-purpose external message broker;
- removal of all disk-capacity safeguards.

Operators who need multiple Hedwig instances can run independent processes with independent queues and load-balance or round-robin inbound traffic themselves.

## 5. Decisions captured

### 5.1 Process model

- Hedwig is always single-process for this queue design.
- There is one dispatcher.
- There is one append writer (one shard) by default. The design supports `N` writers, each owning exactly one shard; enabling more than one is a benchmark-driven decision, not the v1 default.
- Workers remain ordinary tasks inside the same process.

### 5.2 Storage model

- The full message body and delivery envelope are stored in segmented append-only payload logs.
- Each shard owns one active segment and zero or more sealed segments.
- No two append writers write to the same active file.
- Each record is identified by a stable message ID and a physical location.
- Delivered records are marked terminal and later reclaimed through segment deletion or compaction.

### 5.3 Durability model

- SMTP `250 OK` may be returned after the complete record has been accepted by the kernel via successful write calls.
- Hedwig will not require `fsync` before acknowledging the message.
- A process crash should recover page-cache-backed data normally.
- A machine crash or power loss may lose recently acknowledged messages. This is an explicit and accepted performance tradeoff.
- State updates use the same page-cache durability policy.
- Destructive operations are the exception: before deleting or truncating anything that holds live data, the replacement must be durable. Compaction fsyncs its output segment and the location manifest before unlinking the source; checkpoints are fsynced before covered journal history is truncated. Without these barriers a power loss could destroy arbitrarily old queued mail, not just recently accepted mail.

### 5.4 Scheduling model

- The append log is the authoritative admission queue.
- Dispatcher wake-up notifications are hints, not authoritative job storage.
- The dispatcher tracks one discovery cursor per shard.
- Workers pull or are assigned one claim at a time from the dispatcher.
- Worker ownership is in-memory only.
- On restart, every non-terminal, non-deferred record is eligible for redispatch.
- Deferred jobs are scheduled by due time rather than occupying sleeping worker slots.

### 5.5 Delivery semantics

- Delivery remains at-least-once.
- The delivery unit is one message. A job carries the whole message even when its recipients span multiple domains; per-domain delivery units are future work.
- A deferred-state record persists the remaining (not-yet-accepted) recipient set, so a retry re-sends only to recipients that have not accepted the message. This removes the current behavior where a partial failure re-delivers to recipients that already accepted it.
- If a remote MTA accepts a message and Hedwig crashes before recording terminal success, the message may be delivered again after restart.
- Exactly-once SMTP delivery is not achievable and will not be claimed.

### 5.6 Sharding model

- New messages are assigned to a shard using a stable hash of the message ID.
- The initial implementation will require the queue to be empty before changing the configured shard count.
- Existing records retain their explicit physical shard and segment location; runtime lookup must not depend only on the current shard count.
- Recipient domain is not used as the payload-sharding key because large domains could create hot writer shards.

## 6. High-level architecture

```text
                         +------------------+
SMTP connections ------>| shard selection  |
                         +--+----+----+------+
                            |    |    |
                   +--------+    |    +--------+
                   v             v             v
               writer 0       writer 1       writer N
               shard 0        shard 1        shard N
                   |             |             |
                   +------ committed heads ----+
                                 |
                                 v
                         one dispatcher
                 +---------------+---------------+
                 | ready scheduling              |
                 | deferred due-time heap        |
                 | in-flight jobs                |
                 | message locations             |
                 | per-segment live/dead counts  |
                 +---------------+---------------+
                                 |
                            worker pulls
                                 |
                                 v
                            worker pool
                                 |
                         delivery outcomes
                                 |
                                 v
                  dispatcher -> owning shard state
                                 |
                         segment GC/compaction
```

## 7. On-disk layout

A possible initial layout is:

```text
spool/
  format-version
  shard-0000/
    segment-000000000001.log
    segment-000000000001.state
    segment-000000000002.open
    state-journal.log
    checkpoint

  shard-0001/
    segment-000000000001.log
    segment-000000000001.state
    segment-000000000002.open
    state-journal.log
    checkpoint
```

Properties:

- The number of shard directories is small and configured.
- The number of segment files is proportional to live data and temporary garbage, not total historical message count.
- `.open` identifies the shard's current append target.
- Sealing a segment renames it to `.log`.
- Payload segments are immutable after sealing.
- State transitions are maintained separately from immutable payload data.

The exact state sidecar and journal division should be finalized during the format implementation. The intended behavior is:

- append-only state transitions for crash-tolerant replay;
- compact state checkpoints for fast startup;
- per-segment live/dead accounting for GC;
- no requirement to rewrite payload segments for ordinary state changes.

## 8. Payload record format

The record format must be versioned and self-framing. A conceptual record is:

```text
+-------------------------+
| magic                   |
| format version          |
| header length           |
| total record length     |
| header checksum         |
| payload checksum        |
| message ID              |
| enqueue timestamp       |
| relocation generation   |
| envelope metadata       |
| message body length     |
| message body            |
+-------------------------+
```

The fixed portion must contain enough information for the dispatcher to discover jobs without reading or decoding the body:

- total record length;
- message ID;
- enqueue time;
- sender/domain routing information needed by scheduling;
- recipient information needed to construct a job;
- body offset and length;
- format and relocation generation.

The dispatcher should be able to read the fixed header and skip directly to the next record.

Checksums serve two different purposes:

- detect a partial or corrupt active tail;
- detect unexpected corruption in sealed segments.

On startup:

- an incomplete final record in an active segment may be truncated;
- corruption in the middle of a sealed segment must be reported and handled explicitly rather than silently skipped.

## 9. Append writers

### 9.1 Ownership

Each append writer owns:

- one shard directory;
- the active payload file;
- active segment offsets and ordinals;
- segment rotation;
- shard state persistence commands;
- shard-local live/dead accounting;
- deletion eligibility;
- coordination with compaction.

No mutex is required around a shared append offset because there is no shared append file.

### 9.2 Append request

A conceptual request is:

```rust
struct AppendRequest {
    message_id: MessageId,
    envelope: Envelope,
    body: Bytes,
    completion: oneshot::Sender<Result<JobLocation>>,
}
```

The writer returns:

```rust
struct JobLocation {
    shard: u16,
    segment: u64,
    offset: u64,
    length: u32,
    ordinal: u32,
    generation: u32,
}
```

The SMTP callback awaits only this append completion before returning `250 OK`.

### 9.3 Admission queue

The append request queue must be bounded by pending bytes, not only pending record count.

This prevents a large number of messages waiting for disk admission from consuming unbounded RAM. Backpressure at this boundary is valid because it represents actual storage throughput rather than outbound delivery throughput.

The bound applies only until records are copied into the page cache. Message bodies are never retained in this queue while waiting for workers or remote MTAs.

The append bound alone does not cap inbound memory: each SMTP session buffers its full DATA payload before the callback runs. Total inbound memory is governed by the composition of `max_connections`, `max_message_size`, and the pending-append byte bound, and the chosen defaults must be documented together as one memory budget.

### 9.4 Write batching

The writer may batch adjacent pending requests into fewer write operations. Since no `fsync` is required, the batching policy can prioritize throughput without introducing a durability timer.

Initial implementation may use straightforward buffered `write_all` operations. More advanced `writev` batching should be justified by benchmarks.

### 9.5 Publish ordering

For each record, the writer must:

1. encode the complete record;
2. write the complete record successfully;
3. update the shard's published committed tail with release ordering;
4. notify the dispatcher;
5. complete the SMTP append request.

The committed tail must never expose a partial record.

## 10. Shard selection

Initial selection:

```text
shard = stable_hash(message_id) % append_writer_count
```

ULID randomness should distribute messages sufficiently over time.

If short-term size imbalance becomes measurable, a later optimization may use power-of-two choices:

1. derive two candidate shards from the message ID;
2. inspect each writer's pending-byte count;
3. choose the less-loaded writer.

This is an optimization, not part of the initial correctness model.

## 11. Dispatcher discovery

### 11.1 Per-shard committed heads

Each writer publishes:

```rust
struct ShardHead {
    segment: u64,
    committed_offset: u64,
}
```

The dispatcher owns one discovery cursor per shard:

```rust
struct ShardCursor {
    segment: u64,
    offset: u64,
}
```

When notified, the dispatcher reads headers between its cursor and the committed head and adds newly discovered messages to its scheduler.

### 11.2 Notifications are hints

The dispatcher notification mechanism must not become another authoritative bounded work queue.

A `Notify`-style wake-up is sufficient because:

- notifications may be coalesced or lost;
- the committed head remains authoritative;
- the dispatcher always compares its cursor against the current head;
- a low-frequency safety tick can discover work even if no notification is observed.

A descriptor fast-path channel (writer `try_send(JobDescriptor)` with cursor catch-up on overflow) was considered and cut from v1: the cursor plus notification path is the only discovery mechanism. Reintroduce the fast path only if header rereads measurably matter.

### 11.3 Segment rotation

When a writer rotates its active segment:

1. finish the current record;
2. seal the current segment;
3. publish its final committed length;
4. create the next active segment;
5. publish the new active segment identity;
6. notify the dispatcher.

The dispatcher must be able to advance from the end of one segment to the start of the next without requiring per-message directory enumeration.

## 12. Dispatcher state

A conceptual in-memory dispatcher is:

```rust
struct Dispatcher {
    shard_cursors: Vec<ShardCursor>,
    ready: ReadyScheduler,
    deferred: BinaryHeap<Reverse<DeferredJob>>,
    inflight: HashMap<MessageId, InFlightJob>,
    locations: HashMap<MessageId, JobLocation>,
    segment_stats: HashMap<SegmentKey, SegmentStats>,
}
```

Dispatcher memory must be bounded from the start, not as a deferred optimization, because a disk-sized backlog otherwise becomes an OOM that repeats on every restart. The baseline mechanism is discovery backpressure: the dispatcher stops advancing shard cursors while its in-memory tables hold a configured maximum of undispatched entries. The log itself preserves everything beyond that window, so nothing is lost; discovery resumes as entries drain. Memory per million queued and per million deferred records is a required benchmark, and a paged deferred index is added only if those measurements demand it.

### 12.1 Job states

Conceptual states are:

```text
Ready
InFlight
Deferred(next_attempt, attempts)
TerminalDelivered
TerminalBounced
```

`InFlight` is process-local and does not need to be persisted.

### 12.2 Worker claims

When a worker asks for work:

```text
Ready -> InFlight
```

Claims carry a mandatory in-memory generation so a late result from a cancelled or stalled worker cannot complete a later reassignment of the same message. Worker panic, cancellation, or closure of the outcome channel must surface to the dispatcher as an abandonment event that returns the job to `Ready`; a claim must never leak. Reassignment of a timed-out claim should still be conservative — the generation makes a duplicate result safe to ignore, but it cannot prevent a duplicate outbound delivery already in progress.

Because all workers and the dispatcher are in one process, no durable lease expiry or cross-process fencing is required.

### 12.3 Restart behavior

After restart:

- terminal records remain terminal based on persisted state;
- deferred records return to the due-time scheduler with their attempt counts;
- all other live records become ready;
- records that were in flight before the crash are redispatched.

## 13. Worker interaction

Workers should receive a lightweight job containing identity, location, and delivery metadata, not the message body.

```rust
struct DeliveryJob {
    message_id: MessageId,
    location: JobLocation,
    attempts: u32,
    claim_generation: u64,
}
```

The worker reads the body directly from the segment using positioned reads. Workers may read sealed and active segments concurrently with the owning append writer because they only access committed record ranges. If a positioned read fails because compaction relocated the record and removed the source segment, the worker re-fetches the current location from the dispatcher and retries before treating the failure as an error.

The worker reports one of:

```rust
enum JobOutcome {
    Delivered {
        response: DeliveryResponse,
    },
    Deferred {
        attempts: u32,
        next_attempt: SystemTime,
        remaining_recipients: Vec<String>,
        error: String,
    },
    RateLimited {
        domain: String,
        retry_after: Duration,
    },
    Bounced {
        reason: String,
    },
}
```

`Deferred` is a real delivery failure: it increments the attempt count and is persisted together with the remaining recipient set. `RateLimited` is local throttling: it does not increment attempts and is requeued in memory only (section 14).

The dispatcher validates the claim generation, applies the persistent state transition through the owning shard, and only then updates scheduling state (section 16).

## 14. Retry scheduling

Rate-limited and retryable jobs must not sleep inside worker slots, and the two cases are distinct.

Delivery retry (a real failed attempt):

```text
worker attempt fails temporarily
  -> reports Deferred(next_attempt, remaining_recipients)
  -> dispatcher persists deferred state (attempts incremented)
  -> dispatcher inserts job into due-time heap
  -> worker immediately asks for another job
```

Rate limiting (local throttling, not an attempt):

```text
dispatcher checks the shared per-domain rate limiter before dispatching a claim
  -> jobs for exhausted domains stay queued; other domains dispatch
worker re-acquires the limit immediately before transmission
  -> if it loses that race it reports RateLimited(retry_after)
  -> dispatcher requeues in memory only: no journal write, no attempt increment
```

A due timestamp is not a token reservation: jobs waking at the same due time must re-pass the limiter at dispatch, which prevents a thundering herd against one domain. Rate-limit deferrals are never persisted — after a restart the job simply becomes ready and is gated by the limiter again.

When a deferred job becomes due:

```text
Deferred -> Ready
```

This eliminates the current periodic full deferred scan and prevents delayed jobs from occupying the delivery worker pool.

The initial scheduler can use a min-heap keyed by `next_attempt`. A timing wheel or paged on-disk due-time index is unnecessary until measurements show the heap is too large.

## 15. Fair scheduling

Durable append order does not have to equal delivery order, and strict global FIFO is not a goal.

Because the v1 delivery unit is a whole message — which may span domains — true per-domain fair scheduling is not implementable yet and is deferred until per-domain delivery units exist. What v1 provides instead:

- rate-limit gating at dispatch time (section 14), so exhausted domains do not consume worker slots;
- no sleeping in workers, so a slow domain ties up at most the claims actively being attempted against it;
- enqueue-age ordering, so old messages do not starve.

When per-domain delivery units are introduced later, deficit round-robin over per-domain ready queues is the intended fairness mechanism. Payload sharding stays keyed by message ID either way.

## 16. Persistent state

Payload records remain immutable after append. Delivery state is stored separately.

The intended model is:

- per-shard append-only state journal for transitions;
- periodic compact checkpoint containing the latest state of live records;
- optional small per-segment state summary for GC accounting.

Conceptual state entries include:

```text
DEFER(message_id, attempts, next_attempt, remaining_recipients, last_error)
DELIVERED(message_id, timestamp, remote_response_summary)
BOUNCED(message_id, timestamp, reason)
```

Persistence is the state boundary. The dispatcher applies an outcome to its in-memory state only after the journal write succeeds:

```text
DEFER persisted     -> remove InFlight -> insert into deferred heap
DELIVERED persisted -> remove InFlight -> decrement segment live count -> GC eligible
state write failure -> job stays InFlight and the write is retried; a job is
                       never marked terminal or dropped from scheduling on a
                       failed write
```

An enqueue transition does not need a separate state record because the payload record itself implies `Ready` unless superseded by later state.

State-journal writes follow the same page-cache durability policy as payload writes. A lost terminal transition may cause duplicate delivery after an exceptional system failure, which is permitted by at-least-once semantics.

A checkpoint must be self-sufficient for every segment that still exists on disk. Because a payload record implies `Ready` unless superseded, truncating the journal entry that recorded a delivery — while that payload still sits in a partially dead segment — would resurrect delivered mail on the next restart. Every checkpoint therefore contains:

- terminal tombstones (or a per-segment bitmap) for every terminal record in every still-present segment;
- the deferred set with attempts, due times, and remaining recipients;
- the per-shard discovery cursor;
- the state-journal position (LSN) it covers;
- the segment topology and current location generation;
- a checksum and format version.

Checkpointing must use copy-before-replace ordering:

1. write a new checkpoint;
2. `fsync` it (destructive-boundary rule, section 5.3);
3. rename it into place;
4. truncate only journal history at or below the checkpoint's recorded LSN.

The exact binary format, checkpoint cadence, and journal rotation thresholds will be specified and tested as part of the storage-format phase.

## 17. Segment deletion and compaction

### 17.1 Fully terminal segments

Each sealed segment tracks:

- total records and bytes;
- live records and bytes;
- terminal records and bytes;
- oldest and newest enqueue time.

Reclamation is event-driven, not scan-based. The terminal transition that drops a sealed segment's live count to zero immediately schedules that segment for deletion; the transition that pushes its dead ratio over the compaction threshold immediately queues it as a compaction candidate. A low-frequency periodic sweep exists only as a backstop for missed events.

When:

```text
live_records == 0
```

its payload, sidecar, and obsolete state data are deleted.

At high delivery rates this is the dominant reclamation path: a segment written during a burst has essentially all of its records delivered within the retry horizon, dies completely, and is unlinked without any copying. Compaction is reserved for the minority of segments pinned by long-deferred stragglers.

### 17.2 Partially live segments

A segment with a small number of long-lived messages may otherwise retain a large amount of delivered garbage.

Initial compaction policy:

```text
compact when:
  segment is sealed
  AND dead_bytes / total_bytes >= 0.50
  AND segment is older than a short grace period
```

A 50% threshold limits uncompacted sealed-segment amplification to roughly 2x live bytes. A higher threshold such as 75% reduces copying but allows roughly 4x amplification. The threshold must be configurable and tuned through benchmarks.

### 17.3 Compaction flow

1. Select a sealed source segment.
2. Snapshot its live record set.
3. Copy each still-live record into an unpublished compaction output segment. Compaction output is never discovered as new admissions: it is excluded from the dispatcher's discovery cursors and enters the system only through the location switch below.
4. Give relocated records a higher relocation generation.
5. Recheck that copied records are still live; a record that went terminal during the copy is dropped from the relocation set. Terminal races must not resurrect messages.
6. Seal and `fsync` the compaction output.
7. Atomically publish the new location generation (manifest update, then `fsync`) and update dispatcher locations.
8. Wait for in-flight readers of the source segment to drain; a worker holding a stale location that loses this race re-fetches the current location and retries (section 13).
9. Unlink the source segment only after steps 6-8 are durable and complete.

If both old and relocated records are observed during recovery, the record with the highest valid relocation generation wins.

### 17.4 Compaction concurrency

Append writers may be sharded, but their files commonly share one physical disk. Initial policy:

```text
maximum concurrent compactions = 1
```

A global semaphore prevents multiple shards from creating avoidable read/write interference. Append operations continue while a sealed segment is compacted.

### 17.5 Long-deferred records

A long-deferred message may be repeatedly moved as surrounding segments become garbage. Initial mitigations:

- do not immediately recompact a newly produced compaction segment;
- use a minimum segment age before eligibility;
- track per-record relocation count for diagnostics.

If repeated movement becomes significant, introduce deferred segments bucketed by due-time range. This is a future optimization, not required initially.

## 18. Active segment sizing

More shards create more partially filled active segments. Segment sizing should account for total active slack.

A possible initial policy is:

```text
target total active segment capacity = 64-128 MiB
per-shard segment size = max(8 MiB, target / shard_count)
```

Example:

| Append writers | Segment size | Total active capacity |
|---:|---:|---:|
| 1 | 64 MiB | 64 MiB |
| 2 | 32 MiB | 64 MiB |
| 4 | 16 MiB | 64 MiB |
| 8 | 8 MiB | 64 MiB |

These are benchmark starting points, not final defaults. With the default single writer, a larger segment (128-256 MiB) may be preferable to keep file counts low at high volume.

Two invariants and one observation:

- A record never spans segments. Per-shard segment size must therefore be at least the configured maximum message size plus record overhead; configurations violating this are rejected at startup.
- Sustained high throughput does not create huge files — it creates more sealed segments. At 3 million messages per hour averaging 10 KiB, one writer appends roughly 30 GiB/hour: about 470 sealed segments per hour at 64 MiB, or 120 at 256 MiB. Segment count, not file size, tracks throughput.
- Steady-state disk use and file count are proportional to live backlog plus not-yet-reclaimed garbage, not to total historical volume, because fully dead segments are unlinked as soon as they die (section 17.1).

## 19. Bounced-message retention

A delivered message can be discarded immediately from the logical queue. A bounced message may need to remain available according to existing Hedwig behavior or future retention policy.

Bounced retention must not pin active queue segments indefinitely. If the message body must be retained:

1. copy or append it to separate bounce/archive storage;
2. persist the bounce outcome;
3. mark the original queue record terminal;
4. allow normal queue-segment GC.

Bounce/archive storage should have an explicit retention policy independent of the active delivery queue.

## 20. Disk growth and safety

The log design creates two categories of disk use:

- live queued/deferred messages;
- temporary garbage awaiting segment deletion or compaction.

GC and compaction bound the second category. They cannot bound the first category when incoming mail continuously exceeds outgoing delivery capacity. The existing spool has the same fundamental behavior.

The initial implementation should therefore retain a simple disk reserve check:

```text
if available disk space < configured reserve:
    temporarily reject new SMTP DATA
```

This is an operational safety boundary, not a mechanism required specifically by append logs. An elaborate quota system is not required for the first implementation.

Useful configuration may include:

```toml
[queue]
append_writers = 1
pending_append_bytes = 134217728
segment_target_bytes = 67108864
compaction_dead_ratio = 0.50
compaction_min_age = "60s"
max_concurrent_compactions = 1
disk_reserve_bytes = 1073741824
durability = "page-cache"
```

Exact names and defaults must follow the existing configuration style.

## 21. Shard-count changes

For the initial version:

> Changing `append_writers` requires an empty queue.

This avoids implementing online resharding before it is needed.

The on-disk location stored for every job must still include its explicit shard, segment, and offset. Code must not attempt to locate an existing record by recalculating `hash(id) % current_writer_count`.

A future extension could use generations:

```text
spool/generation-0001/  # old shard count
spool/generation-0002/  # current shard count
```

The dispatcher could drain old generations while new appends use only the current one. This is not part of the initial implementation.

## 22. Startup and recovery

Startup should not await replaying every job through a bounded worker channel before binding the SMTP listener.

Proposed startup sequence:

1. Read and validate the spool format version.
2. Discover the small set of configured shard directories and segment files.
3. Validate each active tail and truncate any incomplete final record.
4. Load each shard checkpoint.
5. Replay state-journal entries newer than the checkpoint.
6. Reconcile payload records newer than the checkpoint/discovery position.
7. Rebuild ready, deferred, location, and segment-stat indexes.
8. Start append writers and the dispatcher.
9. Start workers.
10. Bind the SMTP listener without first feeding the entire backlog through a bounded channel.
11. Let workers begin pulling from the reconstructed dispatcher state.

For a very large backlog, recovery may later be changed to open the listener after minimum metadata initialization and continue indexing in the background. The first implementation should prioritize correctness and deterministic recovery, then measure startup time. Discovery backpressure (section 12) applies during recovery as well, so index rebuild memory stays bounded.

### 22.1 Shutdown ordering

Shutdown must drain the ownership graph deterministically:

1. stop accepting new SMTP connections;
2. drain or cancel in-progress DATA sessions;
3. close append admission and drain pending append requests;
4. stop issuing new worker claims;
5. wait for in-flight deliveries to finish, or abandon them explicitly (they redispatch on restart);
6. persist all accepted outcomes through the state journal;
7. stop compaction at a recoverable step boundary;
8. flush and close state writers;
9. exit.

A claim owned by a worker that has not returned is abandoned, never silently reassigned during shutdown.

## 23. Migration from the current filesystem spool

The new format requires an explicit migration strategy.

A one-time migration may:

1. stop ordinary queue mutation;
2. enumerate existing `Queued` and `Deferred` files;
3. preserve message IDs, attempt counts, and next-attempt timestamps;
4. append each live message to its selected new shard;
5. write equivalent deferred state where needed;
6. verify that every legacy live record has a new record;
7. rename the legacy spool to a migration backup;
8. activate the new format;
9. delete the backup only after operator confirmation or a defined grace period.

Migration must be restart-safe and exclusive:

- a root manifest records the format version, shard topology, migration epoch, and activation state, and the switch to the new format is a single atomic manifest update;
- migration is idempotent: re-running after a crash detects already-migrated message IDs instead of appending duplicates;
- retry metadata is honored for queued bodies as well as deferred ones — a message that was mid-retry sits in `queued/` with its metadata still attached;
- an exclusive OS-level lock on the spool root is held before migration, recovery, tail truncation, or writer startup, and independent Hedwig processes must use distinct spool roots.

This migration is allowed to scan the old directories once. The new steady-state architecture must not depend on those scans.

Alternative rollout approaches to evaluate during implementation:

- introduce the log queue as a new storage backend and require operators to drain before switching;
- provide an offline migration command;
- auto-migrate on startup only when explicitly enabled.

Automatic destructive migration without an explicit backup or operator opt-in is not acceptable.

## 24. SQLite backend impact

Decision: the log queue ships as a new selectable storage backend alongside the existing filesystem and SQLite backends. The existing backends keep their current scheduling path (bounded channel, deferred worker) unchanged while the log backend proves out. Deprecating the legacy backends is a separate later decision. The migration tooling in section 23 covers the filesystem spool first; SQLite-to-log migration is deferred.

The append-log format must not be forced into the existing `Storage` trait if that makes the log hot path slower or more complicated; the log backend may use its own internal interfaces.

## 25. Metrics and observability

Add or adapt metrics for:

### Admission

- append latency by shard;
- pending append requests;
- pending append bytes;
- bytes appended;
- records appended;
- append errors;
- active segment size;
- segment rotations.

### Dispatcher

- per-shard committed head;
- per-shard discovery cursor;
- dispatcher lag in records and bytes;
- ready jobs;
- deferred jobs;
- in-flight jobs;
- oldest ready age;
- oldest deferred age;
- jobs scheduled by destination domain.

### Storage and GC

- live bytes;
- dead bytes;
- active-segment bytes;
- sealed segment count;
- segments deleted;
- compactions started/completed/failed;
- bytes read and written by compaction;
- relocation count;
- disk free bytes and configured reserve.

### Delivery

Existing delivery, retry, bounce, and latency metrics should remain meaningful. Queue time should continue to use the original enqueue timestamp even after compaction relocation.

### Operator tooling

The one-file-per-message spool is inspectable with `ls` and repairable with `rm`; binary segments are not. A minimal queue CLI is therefore in scope, not an afterthought:

- list queued/deferred messages with age, attempts, and next-attempt time;
- show one message's envelope, state history, and current location;
- remove a message from the queue (recorded as an operator-cancelled terminal state);
- show per-segment and per-shard statistics (live/dead counts, garbage ratio).

Read-only inspection must work against a live spool without stopping the server.

## 26. Testing strategy

### 26.1 Record format tests

- encode/decode round trip;
- variable metadata and body sizes;
- maximum configured message size;
- checksum failures;
- unknown format version;
- truncated fixed header;
- truncated body;
- partial final record recovery;
- corruption in a sealed segment.

### 26.2 Append writer tests

- concurrent SMTP-side append requests;
- exclusive shard ownership;
- monotonic offsets and ordinals;
- committed tail never exposes partial records;
- rotation at target size;
- byte-bounded admission;
- append error propagation;
- notification loss does not lose work.

### 26.3 Dispatcher tests

- discovers all records from multiple shard heads;
- independent shard cursors;
- merges records without requiring global order;
- worker claim and completion transitions;
- stale claim generation is ignored;
- worker cancellation returns work to ready state;
- deferred jobs become ready at the correct time;
- rate-limited jobs do not occupy sleeping workers;
- rate-limited jobs are requeued without incrementing attempts and without journal writes;
- rate-limit gating at dispatch prevents one exhausted destination from monopolizing workers;
- discovery backpressure bounds dispatcher memory without losing records.

### 26.4 Recovery tests

- restart with ready jobs;
- restart with deferred jobs and preserved attempt counts;
- restart with in-flight jobs causes redispatch;
- restart after terminal state update;
- terminal state loss may duplicate but does not lose a live message;
- partial state-journal tail;
- checkpoint plus journal replay;
- journal truncation after checkpoint cannot resurrect a terminal record whose segment still exists;
- restart mid-retry preserves the remaining-recipient set;
- active-segment partial tail truncation;
- duplicate old/new relocation records choose the latest valid generation.

### 26.5 GC and compaction tests

- fully terminal segment is deleted;
- live record prevents deletion;
- dead-ratio threshold triggers compaction;
- live records survive compaction;
- terminal race during compaction does not resurrect a message;
- process interruption at each compaction step remains recoverable;
- simulated power loss between compaction copy and source unlink loses no live records (fsync barriers);
- a worker holding a stale location re-fetches and reads the relocated record;
- a segment whose last live record goes terminal is deleted without waiting for a periodic sweep;
- only one compaction runs initially;
- long-deferred record does not permanently pin mostly dead storage;
- dispatcher locations update after relocation.

### 26.6 End-to-end tests

- inbound acceptance continues when all workers are busy;
- inbound acceptance continues when workers are rate-limited;
- append backpressure occurs only when disk admission buffering is full;
- outbound delivery reads the correct body from a segment;
- successful delivery eventually reclaims disk;
- deferred delivery survives restart;
- retry after a partial multi-recipient failure re-sends only to remaining recipients;
- graceful shutdown drains outcomes and restarts cleanly;
- bounced-message retention does not pin active segments;
- the existing dev DNS and fake-MTA verification harness passes.

## 27. Benchmark plan

Benchmark before and after each major stage.

### 27.1 Admission benchmarks

Measure at several message sizes, including at least:

- 1 KiB;
- 16 KiB;
- 64 KiB;
- 1 MiB where practical.

Test:

- append writers: `1`, `2`, `4`, `8`;
- suitable segment sizes for each writer count;
- outbound disabled;
- outbound intentionally stalled;
- tmpfs and a real local filesystem;
- steady-state append plus background compaction.

Metrics:

- messages per second;
- bytes per second;
- median and tail SMTP DATA latency;
- CPU usage;
- write syscall count;
- context switches;
- pending append bytes;
- dispatcher lag;
- disk amplification.

### 27.2 Recovery benchmarks

Measure startup with:

- 10 thousand queued messages;
- 100 thousand queued messages;
- 1 million queued messages if practical;
- mixtures of ready, deferred, and terminal records;
- many small segments versus fewer large segments.

### 27.3 GC benchmarks

Measure:

- cost of deleting fully dead segments;
- compaction throughput;
- impact of compaction on SMTP acceptance latency;
- repeated long-deferred-message relocation;
- storage amplification at 50% and 75% thresholds.

### 27.4 Expected writer count

Do not assume more writers are always faster. A single batched writer may already saturate the disk or memory-copy path. Multiple writers are expected to help most on NVMe and tmpfs and may hurt on rotational disks.

The implementation supports configurable sharding, but the default is a single writer; changing that default requires benchmark evidence.

## 28. Implementation phases

This work is intentionally deferred and should be implemented incrementally.

Phases 1-7 are internal milestones: the log backend must not be the active backend of a deployed build until they are all complete. Making it selectable comes last because deploying it without recovery (phase 3) or reclamation (phase 6) would redeliver mail after every restart and grow disk without bound. Until then the new code lands alongside the untouched legacy path.

### Phase 0: preserve baselines and invariants

- Record current acceptance, delivery, startup, retry, and disk-use behavior.
- Preserve existing benchmark tooling.
- Document current at-least-once and durability semantics.
- Add tests demonstrating that worker-channel saturation currently blocks SMTP acceptance.

### Phase 1: on-disk format and shard primitives

- Define versioned record and state formats and the root manifest.
- Implement record encoding, decoding, checksums, and active-tail validation.
- Implement shard directory and segment lifecycle, plus the exclusive spool lock.
- Implement positioned message reads.
- Enforce the record-never-spans-segments sizing invariant.
- Add exhaustive format and corruption tests.

### Phase 2: append writer

- Implement one append writer with byte-bounded admission.
- Return physical `JobLocation` after page-cache write completion.
- Implement committed-head publication and segment rotation.
- Keep the writer interface shard-capable; `N` writers stay configurable but default to 1.
- Benchmark `1`, `2`, `4`, and `8` writers before revisiting the default.

### Phase 3: persistent state and recovery

- Implement per-shard state journals with the persist-then-apply ordering.
- Implement checkpoints (terminal tombstones, LSN, cursors, topology) and journal replay.
- Implement startup recovery: tail truncation, checkpoint load, journal replay, payload reconciliation.
- Preserve retry attempts, next-attempt times, and remaining-recipient sets.
- Validate restart behavior for ready, deferred, in-flight, and terminal messages.

### Phase 4: dispatcher discovery

- Implement per-shard discovery cursors.
- Discover work from committed heads without an authoritative job channel.
- Make notifications lossy hints with cursor-based recovery.
- Reconstruct jobs from record headers without reading message bodies.
- Implement discovery backpressure as the dispatcher memory bound.

### Phase 5: worker pull protocol and retries

- Replace the current shared job-channel lifecycle with dispatcher claims.
- Keep job payloads out of the scheduling path; read bodies by `JobLocation` with stale-location refetch.
- Add mandatory claim generations and abandonment recovery.
- Add the deferred due-time heap; move delayed retry waiting out of workers.
- Add dispatcher-side rate-limit gating and the in-memory `RateLimited` requeue path.
- Ensure global per-domain rate limits remain correct across all workers.
- Preserve delivery logging and metrics.

### Phase 6: deletion and compaction

- Delete fully terminal sealed segments, triggered by the terminal transition (event-driven).
- Implement dead-ratio selection and the compaction candidate queue.
- Implement copy-before-delete compaction with unpublished output, relocation generations, manifest publication, and fsync barriers at destructive boundaries.
- Add one global compaction permit.
- Add GC metrics and failure recovery.
- Implement the disk reserve check.

### Phase 7: bounce retention, migration, and backend selection

- Separate bounce retention from active queue segments.
- Implement the restart-safe legacy-spool migration (idempotent, manifest-gated, locked).
- Make the log backend selectable alongside the filesystem and SQLite backends.
- Add the queue inspection CLI.
- Add explicit format/version and rollback handling.

### Phase 8: SMTP acknowledgement cutover

- Change the DATA callback to await only append completion when the log backend is active.
- Return `250 OK` without waiting for dispatcher or worker capacity.
- Remove startup replay through the bounded worker channel.
- Verify that stalled outbound delivery does not block acceptance until disk-admission buffering or disk reserve is reached.

### Phase 9: production hardening and tuning

- Run end-to-end fake-MTA verification.
- Run large-backlog startup tests.
- Run append and compaction benchmarks on representative filesystems.
- Confirm default writer count, segment size, pending-byte bound, and compaction threshold from benchmarks.
- Update production-hardening documentation and operator guidance.

## 29. Risks and tradeoffs

### 29.1 Implementation size

This is a large architectural change crossing SMTP acceptance, storage, scheduling, retry handling, workers, startup recovery, metrics, and migration. It should not be attempted as a single unreviewable patch.

### 29.2 Compaction correctness

Compaction is the most correctness-sensitive component because it rewrites live queued data. Copy-before-delete ordering, relocation generations, race handling, and interruption tests are mandatory.

### 29.3 Memory use

A dispatcher entry for every live message may become large at very high queue depths. Discovery backpressure (section 12) bounds this from the start; memory-per-million-record benchmarks validate the bound, and a paged deferred index is added only if measurements demand it.

### 29.4 Disk write amplification

Compaction rewrites long-lived records. Thresholds and minimum ages must balance disk utilization against copy cost.

### 29.5 More writers are not automatically faster

Multiple active files may reduce append contention but increase active-segment slack and randomize physical writes. Benchmarking determines the useful writer count.

### 29.6 Page-cache durability

The no-`fsync` decision prioritizes throughput. Documentation must state clearly that a machine crash or power loss can lose recently acknowledged mail. Destructive boundaries (compaction publication, checkpoint truncation, segment deletion) do use `fsync` so power loss can never destroy old queued mail (section 5.3).

### 29.7 Migration

Existing queued and deferred mail must not be silently dropped. Migration needs explicit validation and rollback behavior.

## 30. Definition of done

The architecture is complete when:

- SMTP acknowledgement no longer waits for worker-channel capacity;
- outbound slowdown does not block inbound acceptance except at actual disk-admission or disk-reserve boundaries;
- complete messages are stored in sharded segmented logs;
- one dispatcher schedules across all shards;
- workers pull payload-free job descriptors and read bodies by location;
- retry waits no longer consume worker slots;
- rate-limit throttling neither consumes attempts nor writes journal entries;
- retries re-send only to recipients that have not yet accepted the message;
- attempt counts, deferred times, and remaining-recipient sets survive restart;
- startup does not feed the full backlog through a bounded in-memory channel before listening;
- fully dead segments are deleted as soon as they die, without waiting for a periodic sweep;
- partially dead segments are compacted safely;
- delivered payload garbage remains bounded by the configured GC policy;
- migration or an explicit drain-before-switch path exists;
- a queue inspection CLI covers list, show, remove, and segment statistics;
- graceful shutdown drains state deterministically;
- queue, dispatcher, shard, and GC metrics are available;
- unit, recovery, compaction, integration, and end-to-end tests pass;
- benchmarks establish justified defaults for writer count and segment sizing;
- operator documentation clearly explains durability and disk-capacity behavior.

## 31. Final intended model

```text
Inbound throughput is limited by:
  SMTP parsing + memory copies + append writers + page-cache/disk throughput

Outbound throughput is limited by:
  workers + DNS + remote MTAs + rate limits

The durable log separates these two rates.

One dispatcher provides:
  scheduling + fairness + retries + in-flight ownership

The segmented append log provides:
  admission bounded by disk throughput; one writer by default,
  shard-capable when benchmarks justify parallel writers

Segment GC provides:
  deletion of fully dead data + bounded reclamation of partial garbage
```

This is the architectural direction to resume when Hedwig is ready for the queue rewrite.
