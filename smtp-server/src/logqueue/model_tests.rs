//! Stateright model of the logqueue's crash-recovery protocol.
//!
//! Where the fuzz tests establish per-file guarantees empirically ("journal
//! recovery yields a prefix", "a torn segment tail truncates to a record
//! boundary"), this model takes those guarantees as axioms and exhaustively
//! checks how the *protocol* composes them: page-cache-only payload
//! durability, journal fsync boundaries, checkpoint publication, and the
//! startup reconciliation in `Dispatcher::add_shard`, across every
//! interleaving of appends, outcomes, checkpoints, and OS crashes.
//!
//! The recovery semantics are exercised through the real code where it is
//! pure: journal replay and checkpoint application go through
//! [`RecoveredState::apply`] on real [`StateEntry`] values, so the subtle
//! transition logic (tombstone supersession, deferral replay) is the
//! production code, not a re-implementation. The file-level plumbing
//! (codecs, torn-tail scans) is abstracted to its fuzz-verified contract.
//!
//! # Mapping to the real system (one shard, one active segment)
//!
//! | model                      | real system                                |
//! |----------------------------|--------------------------------------------|
//! | `segment: Vec<Msg>`        | active segment page cache; offset = index, every record length 1; never fsynced |
//! | `journal: Vec<Entry>`      | state journal since the last checkpoint (page cache) |
//! | `synced`                   | journal fsync watermark (`begin_checkpoint`, segment-deletion boundary) |
//! | `checkpoint`               | the checkpoint file (tmp + fsync + rename + dir fsync: atomic, durable) |
//! | `mem`                      | dispatcher in-memory state (jobs, cursor, tombstones) |
//! | `Accept`                   | append + committed-head publish + SMTP 250; discovery folded in (the dispatcher discovers promptly) |
//! | `Deliver`/`Defer`/`Bounce` | worker outcome, persist-then-apply         |
//! | `Checkpoint`               | fsync journal, snapshot in-memory state, publish, prune journal |
//! | `Crash`                    | OS crash + restart: un-fsynced tails truncate to an arbitrary prefix, then `ShardStateStore::recover` + `Dispatcher::add_shard` rebuild `mem`; the reconciled state is re-persisted (checkpoint + journal prune) before admission reopens (`Dispatcher::start`) |
//!
//! Not modeled (candidates for a second iteration): segment rotation and
//! GC/compaction (`Relocated` entries), lagging discovery cursors,
//! non-atomic checkpoint publication (crash between journal rotation and
//! checkpoint rename), journal-write failures (`pending_persists`), and
//! in-flight claims (crash mid-flight only widens the documented
//! at-least-once window, which is not an invariant here).
//!
//! # Checked invariants
//!
//! 1. Accepted mail whose payload survived a crash is never silently lost:
//!    it stays live (will be attempted) or has a terminal tombstone. Loss is
//!    permitted *only* when the payload record itself was torn away — the
//!    documented page-cache acceptance window.
//! 2. No live job ever points at a missing record or at bytes that now
//!    belong to a different message.
//! 3. A message whose terminal outcome reached durable storage (fsynced
//!    journal or checkpoint) never becomes live again.
//! 4. A tear-free restart reproduces the dispatcher's in-memory state
//!    exactly (recovery is a right-inverse of normal operation).

use std::collections::BTreeSet;

use stateright::{Checker, Model, Property};

use super::state::{DeferredJob, ReadyJob, RecoveredState, StateEntry};
use super::{JobLocation, MessageId};

/// Distinct messages in the model. Two is enough for every invariant here
/// (loss, aliasing, resurrection all need at most one witness and one
/// interfering message) while keeping the state space small.
const MSGS: u8 = 2;
/// Deferral cap so attempt counters cannot grow the state space unboundedly.
const MAX_ATTEMPTS: u8 = 2;

type Msg = u8;

fn mid(m: Msg) -> MessageId {
    let mut b = [0u8; 16];
    b[0] = m + 1;
    MessageId(b)
}

fn msg_of(id: &MessageId) -> Msg {
    id.0[0] - 1
}

fn loc(off: u8) -> JobLocation {
    JobLocation {
        shard: 0,
        segment: 0,
        offset: off as u64,
        length: 1,
        ordinal: off as u32,
        generation: 0,
    }
}

/// One journal entry. Offsets are captured at write time, exactly like the
/// `JobLocation` embedded in real entries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Entry {
    Deferred { msg: Msg, off: u8, attempts: u8 },
    Delivered { msg: Msg, off: u8 },
    Bounced { msg: Msg, off: u8 },
}

impl Entry {
    fn to_state_entry(self) -> StateEntry {
        match self {
            Entry::Deferred { msg, off, attempts } => StateEntry::Deferred {
                id: mid(msg),
                location: loc(off),
                attempts: attempts as u32,
                next_attempt_ms: attempts as i64,
                remaining_recipients: vec!["rcpt@example.com".into()],
                last_error: "451 try later".into(),
            },
            Entry::Delivered { msg, off } => StateEntry::Delivered {
                id: mid(msg),
                location: loc(off),
                timestamp_ms: 0,
            },
            Entry::Bounced { msg, off } => StateEntry::Bounced {
                id: mid(msg),
                location: loc(off),
                timestamp_ms: 0,
                reason: "550 no".into(),
            },
        }
    }

    fn msg(self) -> Msg {
        match self {
            Entry::Deferred { msg, .. }
            | Entry::Delivered { msg, .. }
            | Entry::Bounced { msg, .. } => msg,
        }
    }

    fn is_terminal(self) -> bool {
        matches!(self, Entry::Delivered { .. } | Entry::Bounced { .. })
    }
}

/// One live job as the dispatcher tracks it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct Live {
    msg: Msg,
    off: u8,
    attempts: u8,
    deferred: bool,
}

/// The dispatcher's in-memory view (`Dispatcher::{jobs, cursor, tombstones}`).
/// Kept sorted so equal views hash equally.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Default)]
struct Mem {
    cursor: u8,
    live: Vec<Live>,
    tombstones: BTreeSet<Msg>,
}

impl Mem {
    fn find(&self, m: Msg) -> Option<Live> {
        self.live.iter().copied().find(|l| l.msg == m)
    }
}

/// Compact mirror of `state::Checkpoint` for one segment.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Default)]
struct Snapshot {
    cursor: u8,
    ready: Vec<Live>,
    deferred: Vec<Live>,
    tombstones: Vec<Msg>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Default)]
struct QState {
    /// Payload records in the page cache. Never fsynced: any prefix may
    /// survive an OS crash.
    segment: Vec<Msg>,
    /// State-journal entries appended since the last checkpoint.
    journal: Vec<Entry>,
    /// Journal entries below this index are durable.
    synced: u8,
    /// Durably published checkpoint.
    checkpoint: Option<Snapshot>,
    /// Dispatcher in-memory state; rebuilt from durable state on crash.
    mem: Mem,
    /// Ghost: messages the SMTP client received a 250 for.
    acked: BTreeSet<Msg>,
    /// Ghost: messages whose terminal outcome reached durable storage.
    terminal_durable: BTreeSet<Msg>,
}

/// Restart: rebuild the dispatcher view from durable + page-cache state.
/// Mirrors `ShardStateStore::recover` (checkpoint + journal replay, through
/// the real `RecoveredState::apply`) followed by `Dispatcher::add_shard`
/// reconciliation and a full discovery scan.
fn rebuild_mem(segment: &[Msg], journal: &[Entry], checkpoint: &Option<Snapshot>) -> Mem {
    let mut rs = RecoveredState::default();
    if let Some(cp) = checkpoint {
        rs.cursor = Some((0, cp.cursor as u64));
        for l in &cp.ready {
            rs.ready.insert(
                mid(l.msg),
                ReadyJob {
                    id: mid(l.msg),
                    location: loc(l.off),
                    attempts: l.attempts as u32,
                    enqueue_ms: 0,
                    remaining_recipients: Vec::new(),
                },
            );
        }
        for l in &cp.deferred {
            rs.deferred.insert(
                mid(l.msg),
                DeferredJob {
                    id: mid(l.msg),
                    location: loc(l.off),
                    attempts: l.attempts as u32,
                    next_attempt_ms: l.attempts as i64,
                    remaining_recipients: vec!["rcpt@example.com".into()],
                    last_error: "451 try later".into(),
                },
            );
        }
        for &m in &cp.tombstones {
            rs.tombstones.entry(0).or_default().insert(mid(m));
        }
    }
    for e in journal {
        rs.apply(e.to_state_entry());
    }

    // `Dispatcher::add_shard`: reconcile against the writer-validated
    // committed head — clamp a cursor past the tail, drop jobs whose payload
    // was truncated away.
    let committed = segment.len() as u64;
    if let Some((_, off)) = rs.cursor {
        if off > committed {
            rs.cursor = Some((0, committed));
        }
    }
    rs.ready
        .retain(|_, r| r.location.offset + r.location.length as u64 <= committed);
    rs.deferred
        .retain(|_, d| d.location.offset + d.location.length as u64 <= committed);

    // Discovery scan from the cursor: a payload record implies Ready unless
    // already tracked or tombstoned (`Dispatcher::discover_shard`).
    let mut live: Vec<Live> = Vec::new();
    let scan_from = rs.cursor.map(|(_, o)| o).unwrap_or(0) as usize;
    for (i, &m) in segment.iter().enumerate().skip(scan_from) {
        let id = mid(m);
        if rs.is_terminal(0, &id) || rs.ready.contains_key(&id) || rs.deferred.contains_key(&id) {
            continue;
        }
        live.push(Live {
            msg: m,
            off: i as u8,
            attempts: 0,
            deferred: false,
        });
    }
    for r in rs.ready.values() {
        live.push(Live {
            msg: msg_of(&r.id),
            off: r.location.offset as u8,
            attempts: r.attempts as u8,
            deferred: false,
        });
    }
    for d in rs.deferred.values() {
        live.push(Live {
            msg: msg_of(&d.id),
            off: d.location.offset as u8,
            attempts: d.attempts as u8,
            deferred: true,
        });
    }
    live.sort_unstable();

    Mem {
        cursor: segment.len() as u8,
        live,
        tombstones: rs
            .tombstones
            .get(&0)
            .map(|ids| ids.iter().map(msg_of).collect())
            .unwrap_or_default(),
    }
}

/// The checkpoint the dispatcher would publish right now: built from the
/// in-memory view, exactly like `Dispatcher::snapshot_shard`.
fn snapshot(mem: &Mem) -> Snapshot {
    Snapshot {
        cursor: mem.cursor,
        ready: mem.live.iter().copied().filter(|l| !l.deferred).collect(),
        deferred: mem.live.iter().copied().filter(|l| l.deferred).collect(),
        tombstones: mem.tombstones.iter().copied().collect(),
    }
}

/// `ShardStateStore::write_checkpoint`: fsync the journal it covers, publish
/// the snapshot durably, prune the covered journal.
fn publish_checkpoint(s: &mut QState) {
    for e in &s.journal {
        if e.is_terminal() {
            s.terminal_durable.insert(e.msg());
        }
    }
    let snap = snapshot(&s.mem);
    for &m in &snap.tombstones {
        s.terminal_durable.insert(m);
    }
    s.checkpoint = Some(snap);
    s.journal.clear();
    s.synced = 0;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Act {
    /// SMTP acceptance: append the record, publish the head, return 250.
    Accept(Msg),
    /// Worker outcome, journalled then applied (persist-then-apply).
    Deliver(Msg),
    Defer(Msg),
    Bounce(Msg),
    /// Journal fsync (checkpoint begin / segment-deletion boundary).
    FsyncJournal,
    /// Publish a checkpoint and prune the journal it covers.
    Checkpoint,
    /// OS crash + restart: each un-fsynced tail independently truncates to
    /// an arbitrary prefix (the per-file prefix guarantee is established by
    /// the fuzz tests), the fsynced checkpoint survives, and recovery
    /// rebuilds the in-memory view.
    Crash {
        seg_len: u8,
        journal_len: u8,
    },
}

struct LogQueue;

impl Model for LogQueue {
    type State = QState;
    type Action = Act;

    fn init_states(&self) -> Vec<QState> {
        vec![QState::default()]
    }

    fn actions(&self, s: &QState, actions: &mut Vec<Act>) {
        for m in 0..MSGS {
            if !s.acked.contains(&m) {
                actions.push(Act::Accept(m));
            }
        }
        for l in &s.mem.live {
            actions.push(Act::Deliver(l.msg));
            actions.push(Act::Bounce(l.msg));
            if l.attempts < MAX_ATTEMPTS {
                actions.push(Act::Defer(l.msg));
            }
        }
        if (s.synced as usize) < s.journal.len() {
            actions.push(Act::FsyncJournal);
        }
        if s.checkpoint.as_ref() != Some(&snapshot(&s.mem)) {
            actions.push(Act::Checkpoint);
        }
        for seg_len in 0..=s.segment.len() as u8 {
            for journal_len in s.synced..=s.journal.len() as u8 {
                actions.push(Act::Crash {
                    seg_len,
                    journal_len,
                });
            }
        }
    }

    fn next_state(&self, s: &QState, a: Act) -> Option<QState> {
        let mut s = s.clone();
        match a {
            Act::Accept(m) => {
                let off = s.segment.len() as u8;
                s.segment.push(m);
                s.acked.insert(m);
                s.mem.live.push(Live {
                    msg: m,
                    off,
                    attempts: 0,
                    deferred: false,
                });
                s.mem.live.sort_unstable();
                s.mem.cursor = s.segment.len() as u8;
            }
            Act::Deliver(m) | Act::Bounce(m) => {
                let l = s.mem.find(m)?;
                s.journal.push(if matches!(a, Act::Deliver(_)) {
                    Entry::Delivered { msg: m, off: l.off }
                } else {
                    Entry::Bounced { msg: m, off: l.off }
                });
                s.mem.live.retain(|x| x.msg != m);
                s.mem.tombstones.insert(m);
            }
            Act::Defer(m) => {
                let l = s.mem.find(m)?;
                s.journal.push(Entry::Deferred {
                    msg: m,
                    off: l.off,
                    attempts: l.attempts + 1,
                });
                for x in &mut s.mem.live {
                    if x.msg == m {
                        x.attempts += 1;
                        x.deferred = true;
                    }
                }
                s.mem.live.sort_unstable();
            }
            Act::FsyncJournal => {
                s.synced = s.journal.len() as u8;
                for e in &s.journal {
                    if e.is_terminal() {
                        s.terminal_durable.insert(e.msg());
                    }
                }
            }
            Act::Checkpoint => publish_checkpoint(&mut s),
            Act::Crash {
                seg_len,
                journal_len,
            } => {
                s.segment.truncate(seg_len as usize);
                s.journal.truncate(journal_len as usize);
                s.mem = rebuild_mem(&s.segment, &s.journal, &s.checkpoint);
                // `Dispatcher::start`: every shard's reconciled state is
                // re-persisted (checkpoint written, journals pruned) before
                // admission reopens, so no durable artifact keeps referencing
                // offsets past the validated committed head.
                publish_checkpoint(&mut s);
            }
        }
        Some(s)
    }

    fn properties(&self) -> Vec<Property<Self>> {
        vec![
            Property::<Self>::always(
                "accepted mail with a surviving payload is never lost",
                |_, s| {
                    s.acked.iter().all(|&m| {
                        !s.segment.contains(&m)
                            || s.mem.find(m).is_some()
                            || s.mem.tombstones.contains(&m)
                    })
                },
            ),
            Property::<Self>::always(
                "no live job points at a missing or foreign record",
                |_, s| {
                    s.mem
                        .live
                        .iter()
                        .all(|l| s.segment.get(l.off as usize) == Some(&l.msg))
                },
            ),
            Property::<Self>::always("a durably terminal message never resurrects", |_, s| {
                s.terminal_durable.iter().all(|&m| s.mem.find(m).is_none())
            }),
            Property::<Self>::always(
                "a tear-free restart reproduces the in-memory state",
                |_, s| rebuild_mem(&s.segment, &s.journal, &s.checkpoint) == s.mem,
            ),
        ]
    }
}

#[test]
fn crash_recovery_protocol_model() {
    let checker = LogQueue
        .checker()
        .threads(std::thread::available_parallelism().map_or(2, |n| n.get()))
        .spawn_bfs()
        .join();
    println!("explored {} unique states", checker.unique_state_count());
    checker.assert_properties();
}
