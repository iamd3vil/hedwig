//! Per-shard persistent delivery state: append-only journal + checkpoints.
//!
//! Payload records are immutable; everything that changes after acceptance
//! (defer, deliver, bounce) is an entry in the shard's state journal. A
//! payload record implies `Ready` unless superseded by later state, so no
//! enqueue entry exists.
//!
//! Journal files are `journal-NNNNNNNNNNNN.log`; a new one starts at every
//! checkpoint and files fully covered by the checkpoint are deleted. An LSN
//! is (journal ordinal, byte offset). Journal writes use page-cache
//! durability like payload writes; the checkpoint is the destructive
//! boundary and is fsynced before any journal history is removed.

use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

use super::{JobLocation, MessageId, QueueError};

const JOURNAL_PREFIX: &str = "journal-";
const JOURNAL_EXT: &str = "log";
const CHECKPOINT_FILE: &str = "checkpoint";
const CHECKPOINT_TMP: &str = "checkpoint.tmp";

const CHECKPOINT_MAGIC: [u8; 4] = *b"HWCP";
const CHECKPOINT_VERSION: u16 = 1;

/// Framing overhead per journal entry: length + crc.
const ENTRY_FRAME: usize = 8;
/// Sanity cap on one journal entry (a huge recipient list stays far below).
const MAX_ENTRY_LEN: u32 = 16 * 1024 * 1024;

/// Log sequence number: position in the shard's journal stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Lsn {
    pub journal: u64,
    pub offset: u64,
}

/// A persisted delivery-state transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateEntry {
    /// A real failed attempt: attempts incremented, remaining recipients
    /// persisted so a retry only re-sends to those.
    Deferred {
        id: MessageId,
        location: JobLocation,
        attempts: u32,
        next_attempt_ms: i64,
        remaining_recipients: Vec<String>,
        last_error: String,
    },
    Delivered {
        id: MessageId,
        location: JobLocation,
        timestamp_ms: i64,
    },
    Bounced {
        id: MessageId,
        location: JobLocation,
        timestamp_ms: i64,
        reason: String,
    },
    /// Compaction copied this record from `old` to `new` (higher relocation
    /// generation). If the message is live, `new` becomes its location and
    /// the old copy is garbage; if it raced to terminal first, the new copy
    /// is garbage instead.
    Relocated {
        id: MessageId,
        old: JobLocation,
        new: JobLocation,
    },
}

impl StateEntry {
    pub fn id(&self) -> MessageId {
        match self {
            StateEntry::Deferred { id, .. }
            | StateEntry::Delivered { id, .. }
            | StateEntry::Bounced { id, .. }
            | StateEntry::Relocated { id, .. } => *id,
        }
    }

    pub fn location(&self) -> JobLocation {
        match self {
            StateEntry::Deferred { location, .. }
            | StateEntry::Delivered { location, .. }
            | StateEntry::Bounced { location, .. } => *location,
            StateEntry::Relocated { new, .. } => *new,
        }
    }
}

// ---------------------------------------------------------------------------
// Minimal binary codec shared by journal entries and checkpoints.

struct Enc(Vec<u8>);

impl Enc {
    fn new() -> Self {
        Enc(Vec::new())
    }
    fn u8(&mut self, v: u8) {
        self.0.push(v);
    }
    fn u16(&mut self, v: u16) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn i64(&mut self, v: i64) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn id(&mut self, v: &MessageId) {
        self.0.extend_from_slice(&v.0);
    }
    fn str(&mut self, v: &str) {
        self.u32(v.len() as u32);
        self.0.extend_from_slice(v.as_bytes());
    }
    fn location(&mut self, l: &JobLocation) {
        self.u16(l.shard);
        self.u64(l.segment);
        self.u64(l.offset);
        self.u32(l.length);
        self.u32(l.ordinal);
        self.u32(l.generation);
    }
}

struct Dec<'a> {
    buf: &'a [u8],
    at: usize,
}

impl<'a> Dec<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Dec { buf, at: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], QueueError> {
        if self.at + n > self.buf.len() {
            return Err(QueueError::InvalidRecord(
                "state entry truncated mid-field".into(),
            ));
        }
        let s = &self.buf[self.at..self.at + n];
        self.at += n;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, QueueError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, QueueError> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32, QueueError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, QueueError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn i64(&mut self) -> Result<i64, QueueError> {
        Ok(i64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn id(&mut self) -> Result<MessageId, QueueError> {
        Ok(MessageId(self.take(16)?.try_into().unwrap()))
    }
    fn str(&mut self) -> Result<String, QueueError> {
        let len = self.u32()? as usize;
        let bytes = self.take(len)?;
        String::from_utf8(bytes.to_vec())
            .map_err(|_| QueueError::InvalidRecord("state entry string is not UTF-8".into()))
    }
    fn location(&mut self) -> Result<JobLocation, QueueError> {
        Ok(JobLocation {
            shard: self.u16()?,
            segment: self.u64()?,
            offset: self.u64()?,
            length: self.u32()?,
            ordinal: self.u32()?,
            generation: self.u32()?,
        })
    }
    fn finished(&self) -> bool {
        self.at == self.buf.len()
    }
}

const KIND_DEFERRED: u8 = 1;
const KIND_DELIVERED: u8 = 2;
const KIND_BOUNCED: u8 = 3;
const KIND_RELOCATED: u8 = 4;

fn encode_entry(entry: &StateEntry) -> Vec<u8> {
    let mut e = Enc::new();
    match entry {
        StateEntry::Deferred {
            id,
            location,
            attempts,
            next_attempt_ms,
            remaining_recipients,
            last_error,
        } => {
            e.u8(KIND_DEFERRED);
            e.id(id);
            e.location(location);
            e.u32(*attempts);
            e.i64(*next_attempt_ms);
            e.u32(remaining_recipients.len() as u32);
            for r in remaining_recipients {
                e.str(r);
            }
            e.str(last_error);
        }
        StateEntry::Delivered {
            id,
            location,
            timestamp_ms,
        } => {
            e.u8(KIND_DELIVERED);
            e.id(id);
            e.location(location);
            e.i64(*timestamp_ms);
        }
        StateEntry::Bounced {
            id,
            location,
            timestamp_ms,
            reason,
        } => {
            e.u8(KIND_BOUNCED);
            e.id(id);
            e.location(location);
            e.i64(*timestamp_ms);
            e.str(reason);
        }
        StateEntry::Relocated { id, old, new } => {
            e.u8(KIND_RELOCATED);
            e.id(id);
            e.location(old);
            e.location(new);
        }
    }
    e.0
}

fn decode_entry(buf: &[u8]) -> Result<StateEntry, QueueError> {
    let mut d = Dec::new(buf);
    let entry = match d.u8()? {
        KIND_DEFERRED => {
            let id = d.id()?;
            let location = d.location()?;
            let attempts = d.u32()?;
            let next_attempt_ms = d.i64()?;
            let n = d.u32()? as usize;
            let mut remaining_recipients = Vec::with_capacity(n.min(1024));
            for _ in 0..n {
                remaining_recipients.push(d.str()?);
            }
            StateEntry::Deferred {
                id,
                location,
                attempts,
                next_attempt_ms,
                remaining_recipients,
                last_error: d.str()?,
            }
        }
        KIND_DELIVERED => StateEntry::Delivered {
            id: d.id()?,
            location: d.location()?,
            timestamp_ms: d.i64()?,
        },
        KIND_BOUNCED => StateEntry::Bounced {
            id: d.id()?,
            location: d.location()?,
            timestamp_ms: d.i64()?,
            reason: d.str()?,
        },
        KIND_RELOCATED => StateEntry::Relocated {
            id: d.id()?,
            old: d.location()?,
            new: d.location()?,
        },
        k => {
            return Err(QueueError::InvalidRecord(format!(
                "unknown state entry kind {k}"
            )))
        }
    };
    if !d.finished() {
        return Err(QueueError::InvalidRecord(
            "trailing bytes after state entry".into(),
        ));
    }
    Ok(entry)
}

// ---------------------------------------------------------------------------
// Journal files.

fn journal_file_name(ordinal: u64) -> String {
    format!("{JOURNAL_PREFIX}{ordinal:012}.{JOURNAL_EXT}")
}

fn parse_journal_name(name: &str) -> Option<u64> {
    let digits = name
        .strip_prefix(JOURNAL_PREFIX)?
        .strip_suffix(&format!(".{JOURNAL_EXT}"))?;
    if digits.len() != 12 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

struct JournalWriter {
    file: File,
    path: PathBuf,
    ordinal: u64,
    len: u64,
}

impl JournalWriter {
    fn create(dir: &Path, ordinal: u64) -> Result<Self, QueueError> {
        let path = dir.join(journal_file_name(ordinal));
        let file = OpenOptions::new()
            .create_new(true)
            .append(true)
            .open(&path)
            .map_err(|e| QueueError::io(&path, e))?;
        Ok(Self {
            file,
            path,
            ordinal,
            len: 0,
        })
    }

    fn reopen(dir: &Path, ordinal: u64, len: u64) -> Result<Self, QueueError> {
        let path = dir.join(journal_file_name(ordinal));
        let file = OpenOptions::new()
            .append(true)
            .open(&path)
            .map_err(|e| QueueError::io(&path, e))?;
        Ok(Self {
            file,
            path,
            ordinal,
            len,
        })
    }

    /// Append one entry; returns the LSN one past it (replay resumes there).
    fn append(&mut self, payload: &[u8]) -> Result<Lsn, QueueError> {
        let mut framed = Vec::with_capacity(ENTRY_FRAME + payload.len());
        framed.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        framed.extend_from_slice(&crc32fast::hash(payload).to_le_bytes());
        framed.extend_from_slice(payload);
        if let Err(e) = self.file.write_all(&framed) {
            let _ = self.file.set_len(self.len);
            return Err(QueueError::io(&self.path, e));
        }
        self.len += framed.len() as u64;
        Ok(Lsn {
            journal: self.ordinal,
            offset: self.len,
        })
    }

    fn fsync(&self) -> Result<(), QueueError> {
        self.file
            .sync_data()
            .map_err(|e| QueueError::io(&self.path, e))
    }
}

/// How [`replay_journal`] should react to an invalid entry at the position
/// it stops on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TornTail {
    /// Any invalid entry is a hard error: used for older journals fully
    /// covered by a checkpoint, which must never contain garbage.
    HardError,
    /// Cut the file back to the last valid boundary. The write path's policy
    /// for the active journal after a crash.
    Truncate,
    /// Stop replay at the last valid boundary without touching the file.
    /// Used by read-only inspection of a spool a live writer may still own.
    StopReadOnly,
}

/// Read entries from one journal file starting at `offset`.
///
/// `tail` selects the active-journal policy for an invalid entry: hard
/// error, truncate-in-place, or (read-only callers) simply stop replay
/// without mutating the file.
fn replay_journal(
    path: &Path,
    start: u64,
    tail: TornTail,
    mut apply: impl FnMut(StateEntry),
) -> Result<u64, QueueError> {
    let file = File::open(path).map_err(|e| QueueError::io(path, e))?;
    let len = file.metadata().map_err(|e| QueueError::io(path, e))?.len();
    let mut at = start;
    let mut frame = [0u8; ENTRY_FRAME];

    let invalid = loop {
        if at == len {
            break None;
        }
        if len - at < ENTRY_FRAME as u64 {
            break Some(format!("{} trailing bytes", len - at));
        }
        file.read_exact_at(&mut frame, at)
            .map_err(|e| QueueError::io(path, e))?;
        let entry_len = u32::from_le_bytes(frame[0..4].try_into().unwrap());
        let crc = u32::from_le_bytes(frame[4..8].try_into().unwrap());
        if entry_len > MAX_ENTRY_LEN {
            break Some(format!("implausible entry length {entry_len}"));
        }
        if len - at - (ENTRY_FRAME as u64) < entry_len as u64 {
            break Some("entry overruns file".into());
        }
        let mut payload = vec![0u8; entry_len as usize];
        file.read_exact_at(&mut payload, at + ENTRY_FRAME as u64)
            .map_err(|e| QueueError::io(path, e))?;
        if crc32fast::hash(&payload) != crc {
            break Some("entry checksum mismatch".into());
        }
        match decode_entry(&payload) {
            Ok(entry) => apply(entry),
            Err(e) => break Some(format!("undecodable entry: {e}")),
        }
        at += ENTRY_FRAME as u64 + entry_len as u64;
    };

    if let Some(reason) = invalid {
        match tail {
            TornTail::HardError => {
                return Err(QueueError::CorruptSealedSegment {
                    path: path.display().to_string(),
                    offset: at,
                    reason,
                });
            }
            TornTail::Truncate => {
                let f = OpenOptions::new()
                    .write(true)
                    .open(path)
                    .map_err(|e| QueueError::io(path, e))?;
                f.set_len(at).map_err(|e| QueueError::io(path, e))?;
                tracing::warn!(
                    path = %path.display(),
                    valid_len = at,
                    reason,
                    "truncated torn tail of state journal"
                );
            }
            TornTail::StopReadOnly => {
                tracing::debug!(
                    path = %path.display(),
                    valid_len = at,
                    reason,
                    "read-only replay stopped at torn tail"
                );
            }
        }
    }
    Ok(at)
}

// ---------------------------------------------------------------------------
// Checkpoint.

/// A message known to be live and already discovered (its location would
/// not be re-found by a cursor scan).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadyJob {
    pub id: MessageId,
    pub location: JobLocation,
    pub attempts: u32,
    pub enqueue_ms: i64,
    /// Recipients that have not yet accepted the message, when a partial
    /// delivery happened before this snapshot. Empty means the full
    /// envelope from the payload record. Without this, a deferred message
    /// that became due and was then checkpointed as ready would re-send to
    /// recipients that already accepted it.
    pub remaining_recipients: Vec<String>,
}

/// A deferred message with everything needed to retry it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeferredJob {
    pub id: MessageId,
    pub location: JobLocation,
    pub attempts: u32,
    pub next_attempt_ms: i64,
    pub remaining_recipients: Vec<String>,
    pub last_error: String,
}

/// Per-segment reclamation accounting.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SegmentStats {
    pub total_records: u32,
    pub total_bytes: u64,
    pub dead_records: u32,
    pub dead_bytes: u64,
}

/// A self-sufficient snapshot of one shard's scheduling state (PLAN §16).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Checkpoint {
    /// Discovery cursor: records at or past this position have not been
    /// discovered. `None` means nothing was ever discovered (scan from the
    /// start of the append chain).
    pub cursor: Option<(u64, u64)>,
    /// Discovered live messages (ready or in flight at snapshot time).
    pub ready: Vec<ReadyJob>,
    /// Deferred messages with attempts and due times.
    pub deferred: Vec<DeferredJob>,
    /// Terminal tombstones per still-present segment.
    pub tombstones: Vec<(u64, Vec<MessageId>)>,
    /// Reclamation stats per segment.
    pub segment_stats: Vec<(u64, SegmentStats)>,
}

fn encode_checkpoint(cp: &Checkpoint, replay_from: Lsn) -> Vec<u8> {
    let mut e = Enc::new();
    e.u64(replay_from.journal);
    e.u64(replay_from.offset);
    match cp.cursor {
        None => e.u8(0),
        Some((seg, off)) => {
            e.u8(1);
            e.u64(seg);
            e.u64(off);
        }
    }
    e.u64(cp.ready.len() as u64);
    for r in &cp.ready {
        e.id(&r.id);
        e.location(&r.location);
        e.u32(r.attempts);
        e.i64(r.enqueue_ms);
        e.u32(r.remaining_recipients.len() as u32);
        for rcpt in &r.remaining_recipients {
            e.str(rcpt);
        }
    }
    e.u64(cp.deferred.len() as u64);
    for d in &cp.deferred {
        e.id(&d.id);
        e.location(&d.location);
        e.u32(d.attempts);
        e.i64(d.next_attempt_ms);
        e.u32(d.remaining_recipients.len() as u32);
        for r in &d.remaining_recipients {
            e.str(r);
        }
        e.str(&d.last_error);
    }
    e.u64(cp.tombstones.len() as u64);
    for (segment, ids) in &cp.tombstones {
        e.u64(*segment);
        e.u64(ids.len() as u64);
        for id in ids {
            e.id(id);
        }
    }
    e.u64(cp.segment_stats.len() as u64);
    for (segment, s) in &cp.segment_stats {
        e.u64(*segment);
        e.u32(s.total_records);
        e.u64(s.total_bytes);
        e.u32(s.dead_records);
        e.u64(s.dead_bytes);
    }
    e.0
}

fn decode_checkpoint(buf: &[u8]) -> Result<(Checkpoint, Lsn), QueueError> {
    let mut d = Dec::new(buf);
    let replay_from = Lsn {
        journal: d.u64()?,
        offset: d.u64()?,
    };
    let cursor = match d.u8()? {
        0 => None,
        1 => Some((d.u64()?, d.u64()?)),
        v => {
            return Err(QueueError::InvalidRecord(format!(
                "bad cursor discriminant {v}"
            )))
        }
    };
    let mut cp = Checkpoint {
        cursor,
        ..Default::default()
    };
    for _ in 0..d.u64()? {
        let id = d.id()?;
        let location = d.location()?;
        let attempts = d.u32()?;
        let enqueue_ms = d.i64()?;
        let n = d.u32()? as usize;
        let mut remaining_recipients = Vec::with_capacity(n.min(1024));
        for _ in 0..n {
            remaining_recipients.push(d.str()?);
        }
        cp.ready.push(ReadyJob {
            id,
            location,
            attempts,
            enqueue_ms,
            remaining_recipients,
        });
    }
    for _ in 0..d.u64()? {
        let id = d.id()?;
        let location = d.location()?;
        let attempts = d.u32()?;
        let next_attempt_ms = d.i64()?;
        let n = d.u32()? as usize;
        let mut remaining_recipients = Vec::with_capacity(n.min(1024));
        for _ in 0..n {
            remaining_recipients.push(d.str()?);
        }
        cp.deferred.push(DeferredJob {
            id,
            location,
            attempts,
            next_attempt_ms,
            remaining_recipients,
            last_error: d.str()?,
        });
    }
    for _ in 0..d.u64()? {
        let segment = d.u64()?;
        let n = d.u64()? as usize;
        let mut ids = Vec::with_capacity(n.min(1 << 20));
        for _ in 0..n {
            ids.push(d.id()?);
        }
        cp.tombstones.push((segment, ids));
    }
    for _ in 0..d.u64()? {
        cp.segment_stats.push((
            d.u64()?,
            SegmentStats {
                total_records: d.u32()?,
                total_bytes: d.u64()?,
                dead_records: d.u32()?,
                dead_bytes: d.u64()?,
            },
        ));
    }
    if !d.finished() {
        return Err(QueueError::InvalidRecord(
            "trailing bytes after checkpoint".into(),
        ));
    }
    Ok((cp, replay_from))
}

/// A begun-but-not-published checkpoint: the journal has rotated; the
/// snapshot still has to be written and old journals pruned.
#[derive(Debug, Clone, Copy)]
pub struct PendingCheckpoint {
    pub replay_from: Lsn,
    covered: u64,
}

pub fn write_checkpoint_file(dir: &Path, cp: &Checkpoint, replay_from: Lsn) -> Result<(), QueueError> {
    let payload = encode_checkpoint(cp, replay_from);
    let mut buf = Vec::with_capacity(payload.len() + 16);
    buf.extend_from_slice(&CHECKPOINT_MAGIC);
    buf.extend_from_slice(&CHECKPOINT_VERSION.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes()); // reserved
    buf.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    buf.extend_from_slice(&crc32fast::hash(&payload).to_le_bytes());
    buf.extend_from_slice(&payload);

    // Destructive-boundary ordering (PLAN §5.3/§16): write, fsync, rename,
    // fsync the directory. Only after all of that may journal history die.
    let tmp = dir.join(CHECKPOINT_TMP);
    let path = dir.join(CHECKPOINT_FILE);
    let mut f = File::create(&tmp).map_err(|e| QueueError::io(&tmp, e))?;
    f.write_all(&buf).map_err(|e| QueueError::io(&tmp, e))?;
    f.sync_data().map_err(|e| QueueError::io(&tmp, e))?;
    drop(f);
    std::fs::rename(&tmp, &path).map_err(|e| QueueError::io(&path, e))?;
    let dirf = File::open(dir).map_err(|e| QueueError::io(dir, e))?;
    dirf.sync_data().map_err(|e| QueueError::io(dir, e))?;
    Ok(())
}

fn load_checkpoint_file(dir: &Path) -> Result<Option<(Checkpoint, Lsn)>, QueueError> {
    let path = dir.join(CHECKPOINT_FILE);
    let buf = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(QueueError::io(&path, e)),
    };
    let corrupt = |reason: &str| QueueError::CorruptRecord {
        offset: 0,
        reason: format!("checkpoint {}: {reason}", path.display()),
    };
    if buf.len() < 20 || buf[0..4] != CHECKPOINT_MAGIC {
        return Err(corrupt("bad magic or truncated header"));
    }
    let version = u16::from_le_bytes(buf[4..6].try_into().unwrap());
    if version != CHECKPOINT_VERSION {
        return Err(QueueError::UnsupportedVersion {
            found: version,
            supported: CHECKPOINT_VERSION,
        });
    }
    let payload_len = u64::from_le_bytes(buf[8..16].try_into().unwrap()) as usize;
    let crc = u32::from_le_bytes(buf[16..20].try_into().unwrap());
    if buf.len() != 20 + payload_len {
        return Err(corrupt("length mismatch"));
    }
    let payload = &buf[20..];
    if crc32fast::hash(payload) != crc {
        return Err(corrupt("checksum mismatch"));
    }
    decode_checkpoint(payload).map(Some)
}

// ---------------------------------------------------------------------------
// Shard state store.

/// One shard's recovered scheduling state, produced by
/// [`ShardStateStore::recover`]: the checkpoint with all journal entries
/// newer than it applied on top.
#[derive(Debug, Default)]
pub struct RecoveredState {
    pub cursor: Option<(u64, u64)>,
    pub ready: HashMap<MessageId, ReadyJob>,
    pub deferred: HashMap<MessageId, DeferredJob>,
    pub tombstones: HashMap<u64, HashSet<MessageId>>,
    pub segment_stats: HashMap<u64, SegmentStats>,
}

impl RecoveredState {
    fn from_checkpoint(cp: Checkpoint) -> Self {
        Self {
            cursor: cp.cursor,
            ready: cp.ready.into_iter().map(|r| (r.id, r)).collect(),
            deferred: cp.deferred.into_iter().map(|d| (d.id, d)).collect(),
            tombstones: cp
                .tombstones
                .into_iter()
                .map(|(seg, ids)| (seg, ids.into_iter().collect()))
                .collect(),
            segment_stats: cp.segment_stats.into_iter().collect(),
        }
    }

    /// Apply one journal entry on top of the current state; used both for
    /// recovery replay and could be reused by live accounting.
    pub fn apply(&mut self, entry: StateEntry) {
        match entry {
            StateEntry::Deferred {
                id,
                location,
                attempts,
                next_attempt_ms,
                remaining_recipients,
                last_error,
            } => {
                self.ready.remove(&id);
                self.deferred.insert(
                    id,
                    DeferredJob {
                        id,
                        location,
                        attempts,
                        next_attempt_ms,
                        remaining_recipients,
                        last_error,
                    },
                );
            }
            StateEntry::Delivered { id, location, .. }
            | StateEntry::Bounced { id, location, .. } => {
                self.ready.remove(&id);
                self.deferred.remove(&id);
                self.mark_copy_dead(id, location);
            }
            StateEntry::Relocated { id, old, new } => {
                // Ordered replay: if the message is still live here, the
                // relocation won and the old copy is garbage. If a terminal
                // entry preceded this one, the terminal copy accounting
                // already covered `old` (or an earlier location) and the
                // fresh copy at `new` is garbage — a terminal race during
                // compaction must not resurrect the message.
                let terminal =
                    self.is_terminal(old.segment, &id) || self.is_terminal(new.segment, &id);
                let live_ready = self.ready.get_mut(&id).map(|r| &mut r.location);
                let live_deferred = self.deferred.get_mut(&id).map(|d| &mut d.location);
                match live_ready.or(live_deferred) {
                    Some(location) if new.generation > location.generation => {
                        *location = new;
                        self.mark_copy_dead(id, old);
                    }
                    Some(_) => {
                        // Stale relocation (shouldn't happen with ordered
                        // replay): the new copy is the garbage one.
                        self.mark_copy_dead(id, new);
                    }
                    None if terminal => {
                        // Terminal raced the copy; neither copy may
                        // resurrect the message.
                        self.mark_copy_dead(id, old);
                        self.mark_copy_dead(id, new);
                    }
                    None => {
                        // Live message the checkpoint never captured: it was
                        // discovered from the payload log alone (a record
                        // implies Ready unless superseded). Kill only the
                        // old copy — the new one must stay discoverable, or
                        // a crash between relocation and the next checkpoint
                        // would silently drop live mail.
                        self.mark_copy_dead(id, old);
                    }
                }
            }
        }
    }

    /// Account one physical record copy as dead (idempotently) for GC.
    fn mark_copy_dead(&mut self, id: MessageId, location: JobLocation) {
        if self
            .tombstones
            .entry(location.segment)
            .or_default()
            .insert(id)
        {
            let stats = self.segment_stats.entry(location.segment).or_default();
            stats.dead_records += 1;
            stats.dead_bytes += location.length as u64;
        }
    }

    pub fn is_terminal(&self, segment: u64, id: &MessageId) -> bool {
        self.tombstones
            .get(&segment)
            .is_some_and(|ids| ids.contains(id))
    }
}

/// Owns a shard's journal + checkpoint files. Writes are synchronous and
/// meant to run on the shard's writer task.
pub struct ShardStateStore {
    dir: PathBuf,
    shard: u16,
    journal: JournalWriter,
    /// Bytes appended to journals since the last checkpoint (drives the
    /// caller's checkpoint cadence).
    bytes_since_checkpoint: u64,
}

impl ShardStateStore {
    /// Load the checkpoint (if any), replay newer journal entries, truncate
    /// a torn active-journal tail, and open the journal for append.
    pub fn recover(shard_dir: &Path, shard: u16) -> Result<(Self, RecoveredState), QueueError> {
        let (mut state, replay_from) = match load_checkpoint_file(shard_dir)? {
            Some((cp, replay_from)) => (RecoveredState::from_checkpoint(cp), replay_from),
            None => (
                RecoveredState::default(),
                Lsn {
                    journal: 0,
                    offset: 0,
                },
            ),
        };

        // Enumerate journal files at or past the replay position.
        let mut journals: Vec<u64> = Vec::new();
        let entries =
            std::fs::read_dir(shard_dir).map_err(|e| QueueError::io(shard_dir, e))?;
        for entry in entries {
            let entry = entry.map_err(|e| QueueError::io(shard_dir, e))?;
            if let Some(ordinal) = entry.file_name().to_str().and_then(parse_journal_name) {
                if ordinal >= replay_from.journal {
                    journals.push(ordinal);
                } else {
                    // Covered by the checkpoint; a leftover from a crash
                    // between checkpoint publication and deletion.
                    let path = entry.path();
                    tracing::info!(path = %path.display(), "removing journal covered by checkpoint");
                    std::fs::remove_file(&path).map_err(|e| QueueError::io(&path, e))?;
                }
            }
        }
        journals.sort_unstable();
        if let Some(w) = journals.windows(2).find(|w| w[1] != w[0] + 1) {
            return Err(QueueError::Layout(format!(
                "shard {shard} journal sequence has a gap between {} and {}",
                w[0], w[1]
            )));
        }
        if let Some(&first) = journals.first() {
            let expected = if replay_from.journal > 0 {
                replay_from.journal
            } else {
                // No checkpoint: the stream must be complete from its start,
                // or silently lost history would resurrect terminal mail.
                1
            };
            if first != expected {
                return Err(QueueError::Layout(format!(
                    "shard {shard} state journals must start at {expected} but oldest present \
                     is {first}; refusing to recover from an incomplete journal stream"
                )));
            }
        }

        let mut bytes_replayed = 0u64;
        let journal = match journals.last().copied() {
            None => {
                // Fresh shard (or checkpoint with no journal yet): start the
                // stream at the checkpoint's expected ordinal.
                let ordinal = replay_from.journal.max(1);
                JournalWriter::create(shard_dir, ordinal)?
            }
            Some(last) => {
                for &ordinal in &journals {
                    let path = shard_dir.join(journal_file_name(ordinal));
                    let start = if ordinal == replay_from.journal {
                        replay_from.offset
                    } else {
                        0
                    };
                    let tail = if ordinal == last {
                        TornTail::Truncate
                    } else {
                        TornTail::HardError
                    };
                    let end = replay_journal(&path, start, tail, |e| state.apply(e))?;
                    bytes_replayed += end.saturating_sub(start);
                }
                let len = std::fs::metadata(shard_dir.join(journal_file_name(last)))
                    .map_err(|e| QueueError::io(shard_dir, e))?
                    .len();
                JournalWriter::reopen(shard_dir, last, len)?
            }
        };

        Ok((
            Self {
                dir: shard_dir.to_path_buf(),
                shard,
                journal,
                bytes_since_checkpoint: bytes_replayed,
            },
            state,
        ))
    }

    /// Persist one state transition (page-cache durability). The caller
    /// applies the transition to in-memory state only after this returns.
    pub fn append(&mut self, entry: &StateEntry) -> Result<Lsn, QueueError> {
        let payload = encode_entry(entry);
        let lsn = self.journal.append(&payload)?;
        self.bytes_since_checkpoint += (ENTRY_FRAME + payload.len()) as u64;
        Ok(lsn)
    }

    /// Journal bytes written since the last checkpoint; the caller's
    /// checkpoint cadence trigger.
    pub fn bytes_since_checkpoint(&self) -> u64 {
        self.bytes_since_checkpoint
    }

    /// Make the journal durable. Required before destructive boundaries
    /// (segment deletion) so terminal/relocation entries covering the
    /// deleted data can never be lost while the data is already gone.
    pub fn fsync_journal(&self) -> Result<(), QueueError> {
        self.journal.fsync()
    }

    /// Write a checkpoint covering everything appended so far, then start a
    /// fresh journal and delete the ones the checkpoint covers.
    ///
    /// Convenience composition of [`Self::begin_checkpoint`],
    /// [`write_checkpoint_file`], and [`Self::finish_checkpoint`]; callers
    /// that must not block (the dispatcher) run the middle step on a
    /// blocking task instead.
    pub fn write_checkpoint(&mut self, cp: &Checkpoint) -> Result<(), QueueError> {
        let pending = self.begin_checkpoint()?;
        write_checkpoint_file(&self.dir, cp, pending.replay_from)?;
        self.finish_checkpoint(pending)
    }

    /// Start a checkpoint: make the current journal durable, then switch
    /// appends to a fresh journal file. State snapshotted after this call
    /// plus `replay_from` is exactly what the checkpoint must contain;
    /// entries appended meanwhile go to the new journal and replay on top.
    pub fn begin_checkpoint(&mut self) -> Result<PendingCheckpoint, QueueError> {
        // The journal must be durable up to the point the checkpoint claims
        // to cover, otherwise a power loss could leave a checkpoint that
        // skips entries which never reached disk.
        self.journal.fsync()?;
        let covered = self.journal.ordinal;
        let next_ordinal = covered + 1;
        self.journal = JournalWriter::create(&self.dir, next_ordinal)?;
        self.bytes_since_checkpoint = 0;
        Ok(PendingCheckpoint {
            replay_from: Lsn {
                journal: next_ordinal,
                offset: 0,
            },
            covered,
        })
    }

    /// Delete journal history covered by a checkpoint that
    /// [`write_checkpoint_file`] has durably published.
    pub fn finish_checkpoint(&mut self, pending: PendingCheckpoint) -> Result<(), QueueError> {
        for ordinal in (1..=pending.covered).rev() {
            let path = self.dir.join(journal_file_name(ordinal));
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
                Err(e) => return Err(QueueError::io(&path, e)),
            }
        }
        Ok(())
    }

    /// Directory this store writes to (for running the checkpoint-file step
    /// on a blocking task).
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn shard(&self) -> u16 {
        self.shard
    }
}

/// Read-only counterpart to [`ShardStateStore::recover`], for inspection
/// tools that must never mutate a spool a live writer may still own: loads
/// the checkpoint and replays every journal entry newer than it, but never
/// truncates a torn tail, never deletes a stale covered journal, and never
/// creates a journal file.
///
/// A torn tail on the active journal simply ends the replay at the last
/// valid boundary — the same boundary [`ShardStateStore::recover`] would
/// truncate to, just without touching the file. A shard with no checkpoint
/// and no journals yet (fresh, or not present at all) yields the default
/// empty state.
pub fn load_state_readonly(shard_dir: &Path) -> Result<RecoveredState, QueueError> {
    let (mut state, replay_from) = match load_checkpoint_file(shard_dir)? {
        Some((cp, replay_from)) => (RecoveredState::from_checkpoint(cp), replay_from),
        None => (
            RecoveredState::default(),
            Lsn {
                journal: 0,
                offset: 0,
            },
        ),
    };

    let mut journals: Vec<u64> = Vec::new();
    let entries = match std::fs::read_dir(shard_dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(state),
        Err(e) => return Err(QueueError::io(shard_dir, e)),
    };
    for entry in entries {
        let entry = entry.map_err(|e| QueueError::io(shard_dir, e))?;
        if let Some(ordinal) = entry.file_name().to_str().and_then(parse_journal_name) {
            // Read-only: unlike `recover`, never remove a stale journal that
            // the checkpoint already covers; that cleanup is the write
            // path's job.
            if ordinal >= replay_from.journal {
                journals.push(ordinal);
            }
        }
    }
    journals.sort_unstable();
    if let Some(w) = journals.windows(2).find(|w| w[1] != w[0] + 1) {
        return Err(QueueError::Layout(format!(
            "journal sequence has a gap between {} and {}",
            w[0], w[1]
        )));
    }
    if let (Some(&first), true) = (journals.first(), replay_from.journal > 0) {
        if first != replay_from.journal {
            return Err(QueueError::Layout(format!(
                "checkpoint expects journal {} but oldest present is {first}",
                replay_from.journal
            )));
        }
    }

    let last = journals.last().copied();
    for &ordinal in &journals {
        let path = shard_dir.join(journal_file_name(ordinal));
        let start = if ordinal == replay_from.journal {
            replay_from.offset
        } else {
            0
        };
        let tail = if Some(ordinal) == last {
            TornTail::StopReadOnly
        } else {
            TornTail::HardError
        };
        replay_journal(&path, start, tail, |e| state.apply(e))?;
    }

    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u64) -> MessageId {
        MessageId::from_ulid(ulid::Ulid::from_parts(n, (n * 13 + 5) as u128))
    }

    fn loc(segment: u64, offset: u64) -> JobLocation {
        JobLocation {
            shard: 0,
            segment,
            offset,
            length: 512,
            ordinal: (offset / 512) as u32,
            generation: 0,
        }
    }

    fn deferred(n: u64, attempts: u32) -> StateEntry {
        StateEntry::Deferred {
            id: id(n),
            location: loc(1, n * 512),
            attempts,
            next_attempt_ms: 1_752_000_100_000 + n as i64,
            remaining_recipients: vec![format!("r{n}@example.com")],
            last_error: "451 try later".into(),
        }
    }

    fn delivered(n: u64) -> StateEntry {
        StateEntry::Delivered {
            id: id(n),
            location: loc(1, n * 512),
            timestamp_ms: 1_752_000_200_000,
        }
    }

    #[test]
    fn entry_round_trip() {
        for entry in [
            deferred(1, 3),
            delivered(2),
            StateEntry::Bounced {
                id: id(3),
                location: loc(2, 1024),
                timestamp_ms: 5,
                reason: "550 no such user".into(),
            },
        ] {
            let buf = encode_entry(&entry);
            assert_eq!(decode_entry(&buf).unwrap(), entry);
        }
    }

    #[test]
    fn journal_replay_and_state() {
        let dir = tempfile::tempdir().unwrap();
        {
            let (mut store, state) = ShardStateStore::recover(dir.path(), 0).unwrap();
            assert!(state.ready.is_empty() && state.deferred.is_empty());
            store.append(&deferred(1, 1)).unwrap();
            store.append(&deferred(2, 1)).unwrap();
            store.append(&delivered(1)).unwrap();
        }
        let (_, state) = ShardStateStore::recover(dir.path(), 0).unwrap();
        assert!(!state.deferred.contains_key(&id(1)), "delivered wins");
        assert!(state.deferred.contains_key(&id(2)));
        assert!(state.is_terminal(1, &id(1)));
        assert_eq!(state.segment_stats[&1].dead_records, 1);
        assert_eq!(state.segment_stats[&1].dead_bytes, 512);
    }

    #[test]
    fn deferred_attempts_survive_restart() {
        let dir = tempfile::tempdir().unwrap();
        {
            let (mut store, _) = ShardStateStore::recover(dir.path(), 0).unwrap();
            store.append(&deferred(7, 1)).unwrap();
            store.append(&deferred(7, 2)).unwrap();
            store.append(&deferred(7, 3)).unwrap();
        }
        let (_, state) = ShardStateStore::recover(dir.path(), 0).unwrap();
        let d = &state.deferred[&id(7)];
        assert_eq!(d.attempts, 3);
        assert_eq!(d.remaining_recipients, vec!["r7@example.com".to_string()]);
    }

    #[test]
    fn torn_journal_tail_is_truncated() {
        let dir = tempfile::tempdir().unwrap();
        {
            let (mut store, _) = ShardStateStore::recover(dir.path(), 0).unwrap();
            store.append(&deferred(1, 1)).unwrap();
            store.append(&deferred(2, 1)).unwrap();
        }
        // Tear the last entry.
        let path = dir.path().join(journal_file_name(1));
        let len = std::fs::metadata(&path).unwrap().len();
        let f = OpenOptions::new().write(true).open(&path).unwrap();
        f.set_len(len - 5).unwrap();

        let (mut store, state) = ShardStateStore::recover(dir.path(), 0).unwrap();
        assert!(state.deferred.contains_key(&id(1)));
        assert!(!state.deferred.contains_key(&id(2)), "torn entry dropped");

        // The journal must be appendable at the truncated boundary.
        store.append(&deferred(3, 1)).unwrap();
        let (_, state) = ShardStateStore::recover(dir.path(), 0).unwrap();
        assert!(state.deferred.contains_key(&id(3)));
    }

    #[test]
    fn checkpoint_round_trip_and_journal_rotation() {
        let dir = tempfile::tempdir().unwrap();
        let (mut store, _) = ShardStateStore::recover(dir.path(), 0).unwrap();
        store.append(&deferred(1, 1)).unwrap();
        store.append(&delivered(2)).unwrap();
        assert!(store.bytes_since_checkpoint() > 0);

        let cp = Checkpoint {
            cursor: Some((3, 4096)),
            ready: vec![
                ReadyJob {
                    id: id(10),
                    location: loc(2, 0),
                    attempts: 0,
                    enqueue_ms: 42,
                    remaining_recipients: vec![],
                },
                // A formerly-deferred job that became due before the
                // snapshot: its partial-recipient set must survive.
                ReadyJob {
                    id: id(11),
                    location: loc(2, 512),
                    attempts: 2,
                    enqueue_ms: 43,
                    remaining_recipients: vec!["still-waiting@example.com".into()],
                },
            ],
            deferred: vec![DeferredJob {
                id: id(1),
                location: loc(1, 512),
                attempts: 1,
                next_attempt_ms: 99,
                remaining_recipients: vec!["r@example.com".into()],
                last_error: "451".into(),
            }],
            tombstones: vec![(1, vec![id(2)])],
            segment_stats: vec![(1, SegmentStats {
                total_records: 8,
                total_bytes: 4096,
                dead_records: 1,
                dead_bytes: 512,
            })],
        };
        store.write_checkpoint(&cp).unwrap();
        assert_eq!(store.bytes_since_checkpoint(), 0);
        // Old journal deleted, new one active.
        assert!(!dir.path().join(journal_file_name(1)).exists());
        assert!(dir.path().join(journal_file_name(2)).exists());

        // Entries after the checkpoint layer on top of it. The Delivered
        // entry carries the message's actual location (segment 2).
        store
            .append(&StateEntry::Delivered {
                id: id(10),
                location: loc(2, 0),
                timestamp_ms: 1_752_000_300_000,
            })
            .unwrap();
        drop(store);

        let (_, state) = ShardStateStore::recover(dir.path(), 0).unwrap();
        assert_eq!(state.cursor, Some((3, 4096)));
        let r = &state.ready[&id(11)];
        assert_eq!(r.attempts, 2);
        assert_eq!(
            r.remaining_recipients,
            vec!["still-waiting@example.com".to_string()],
            "partial-recipient set survives a ready-state checkpoint"
        );
        assert!(!state.ready.contains_key(&id(10)), "delivered post-checkpoint");
        assert!(state.is_terminal(2, &id(10)));
        assert!(state.is_terminal(1, &id(2)), "checkpoint tombstone kept");
        let d = &state.deferred[&id(1)];
        assert_eq!(d.attempts, 1);
        assert_eq!(state.segment_stats[&1].total_records, 8);
    }

    #[test]
    fn relocation_updates_live_location_and_kills_old_copy() {
        let dir = tempfile::tempdir().unwrap();
        {
            let (mut store, _) = ShardStateStore::recover(dir.path(), 0).unwrap();
            store.append(&deferred(1, 2)).unwrap();
            let mut new = loc(9, 0);
            new.generation = 1;
            store
                .append(&StateEntry::Relocated {
                    id: id(1),
                    old: loc(1, 512),
                    new,
                })
                .unwrap();
        }
        let (_, state) = ShardStateStore::recover(dir.path(), 0).unwrap();
        let d = &state.deferred[&id(1)];
        assert_eq!(d.location.segment, 9);
        assert_eq!(d.location.generation, 1);
        assert_eq!(d.attempts, 2, "relocation preserves retry state");
        // Old copy is dead garbage.
        assert!(state.is_terminal(1, &id(1)));
        assert_eq!(state.segment_stats[&1].dead_bytes, 512);
        // New copy is not dead.
        assert!(!state.is_terminal(9, &id(1)));
    }

    #[test]
    fn relocation_of_uncheckpointed_live_message_keeps_new_copy_alive() {
        // A ready message that exists only as a payload record (discovered,
        // never journaled or checkpointed) gets relocated by compaction and
        // the process crashes before the next checkpoint. Replay must kill
        // only the old copy: tombstoning the new copy too would silently
        // drop live mail.
        let dir = tempfile::tempdir().unwrap();
        {
            let (mut store, _) = ShardStateStore::recover(dir.path(), 0).unwrap();
            let mut new = loc(9, 0);
            new.generation = 1;
            store
                .append(&StateEntry::Relocated {
                    id: id(1),
                    old: loc(1, 512),
                    new,
                })
                .unwrap();
        }
        let (_, state) = ShardStateStore::recover(dir.path(), 0).unwrap();
        assert!(state.is_terminal(1, &id(1)), "old copy is garbage");
        assert!(
            !state.is_terminal(9, &id(1)),
            "new copy must stay discoverable"
        );
    }

    #[test]
    fn terminal_race_during_relocation_does_not_resurrect() {
        let dir = tempfile::tempdir().unwrap();
        {
            let (mut store, _) = ShardStateStore::recover(dir.path(), 0).unwrap();
            store.append(&deferred(1, 1)).unwrap();
            // Terminal lands first (worker delivered while compaction was
            // copying), then the relocation entry arrives.
            store.append(&delivered(1)).unwrap();
            let mut new = loc(9, 0);
            new.generation = 1;
            store
                .append(&StateEntry::Relocated {
                    id: id(1),
                    old: loc(1, 512),
                    new,
                })
                .unwrap();
        }
        let (_, state) = ShardStateStore::recover(dir.path(), 0).unwrap();
        assert!(state.ready.is_empty() && state.deferred.is_empty());
        // Both physical copies are garbage; neither resurrects the message.
        assert!(state.is_terminal(1, &id(1)));
        assert!(state.is_terminal(9, &id(1)));
        assert_eq!(state.segment_stats[&9].dead_records, 1);
    }

    #[test]
    fn checkpoint_corruption_is_a_hard_error() {
        let dir = tempfile::tempdir().unwrap();
        let (mut store, _) = ShardStateStore::recover(dir.path(), 0).unwrap();
        store.append(&deferred(1, 1)).unwrap();
        store.write_checkpoint(&Checkpoint::default()).unwrap();
        drop(store);

        let path = dir.path().join(CHECKPOINT_FILE);
        let mut buf = std::fs::read(&path).unwrap();
        let last = buf.len() - 1;
        buf[last] ^= 0xff;
        std::fs::write(&path, &buf).unwrap();
        assert!(ShardStateStore::recover(dir.path(), 0).is_err());
    }

    #[test]
    fn journal_gap_is_a_hard_error() {
        let dir = tempfile::tempdir().unwrap();
        {
            let (mut store, _) = ShardStateStore::recover(dir.path(), 0).unwrap();
            store.append(&deferred(1, 1)).unwrap();
            store.write_checkpoint(&Checkpoint::default()).unwrap();
            store.append(&deferred(2, 1)).unwrap();
            store.write_checkpoint(&Checkpoint::default()).unwrap();
        }
        // Journals 1,2 deleted; 3 is active. Fabricate a gap: 3 -> 5.
        std::fs::write(dir.path().join(journal_file_name(5)), b"").unwrap();
        assert!(matches!(
            ShardStateStore::recover(dir.path(), 0),
            Err(QueueError::Layout(_))
        ));
    }

    #[test]
    fn crash_between_checkpoint_and_journal_delete_recovers() {
        let dir = tempfile::tempdir().unwrap();
        let (mut store, _) = ShardStateStore::recover(dir.path(), 0).unwrap();
        store.append(&delivered(1)).unwrap();
        store.write_checkpoint(&Checkpoint {
            tombstones: vec![(1, vec![id(1)])],
            ..Default::default()
        })
        .unwrap();
        drop(store);

        // Simulate the crash by resurrecting a stale, covered journal file
        // containing garbage; recovery must delete it, not replay it.
        std::fs::write(dir.path().join(journal_file_name(1)), b"stale garbage").unwrap();
        let (_, state) = ShardStateStore::recover(dir.path(), 0).unwrap();
        assert!(state.is_terminal(1, &id(1)));
        assert!(!dir.path().join(journal_file_name(1)).exists());
    }

    #[test]
    fn read_only_loader_handles_a_fresh_shard() {
        let dir = tempfile::tempdir().unwrap();
        // Directory exists but nothing has ever been written to it.
        std::fs::create_dir_all(dir.path()).unwrap();
        let state = load_state_readonly(dir.path()).unwrap();
        assert!(state.ready.is_empty());
        assert!(state.deferred.is_empty());
        assert_eq!(state.cursor, None);

        // A shard directory that does not exist at all is just as fine.
        let missing = dir.path().join("does-not-exist");
        let state = load_state_readonly(&missing).unwrap();
        assert!(state.ready.is_empty() && state.deferred.is_empty());
    }

    #[test]
    fn read_only_loader_does_not_mutate_a_torn_journal() {
        let dir = tempfile::tempdir().unwrap();
        {
            let (mut store, _) = ShardStateStore::recover(dir.path(), 0).unwrap();
            store.append(&deferred(1, 1)).unwrap();
            store.append(&deferred(2, 1)).unwrap();
        }
        // Tear the last entry, exactly like `torn_journal_tail_is_truncated`.
        let path = dir.path().join(journal_file_name(1));
        let len = std::fs::metadata(&path).unwrap().len();
        let f = OpenOptions::new().write(true).open(&path).unwrap();
        f.set_len(len - 5).unwrap();
        let torn_len = std::fs::metadata(&path).unwrap().len();

        let state = load_state_readonly(dir.path()).unwrap();
        assert!(state.deferred.contains_key(&id(1)));
        assert!(
            !state.deferred.contains_key(&id(2)),
            "torn entry excluded from replay"
        );

        // The critical read-only property: the file must be byte-for-byte
        // unchanged, unlike the write path's truncation.
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            torn_len,
            "read-only loader must never truncate the journal"
        );
        let contents_after = std::fs::read(&path).unwrap();
        assert_eq!(contents_after.len() as u64, torn_len);

        // Calling it again is idempotent and still doesn't touch the file.
        let state2 = load_state_readonly(dir.path()).unwrap();
        assert_eq!(state2.deferred.contains_key(&id(1)), true);
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            torn_len,
            "second read-only call must not touch the file either"
        );

        // The write path can still recover (and truncate) normally
        // afterwards; the read-only loader must not have wedged anything.
        let (mut store, recovered) = ShardStateStore::recover(dir.path(), 0).unwrap();
        assert!(recovered.deferred.contains_key(&id(1)));
        assert!(!recovered.deferred.contains_key(&id(2)));
        store.append(&deferred(3, 1)).unwrap();
        let (_, state3) = ShardStateStore::recover(dir.path(), 0).unwrap();
        assert!(state3.deferred.contains_key(&id(3)));
    }

    #[test]
    fn read_only_loader_matches_recover_across_a_checkpoint() {
        let dir = tempfile::tempdir().unwrap();
        {
            let (mut store, _) = ShardStateStore::recover(dir.path(), 0).unwrap();
            store.append(&deferred(1, 1)).unwrap();
            store
                .write_checkpoint(&Checkpoint {
                    tombstones: vec![(1, vec![id(9)])],
                    ..Default::default()
                })
                .unwrap();
            store.append(&delivered(2)).unwrap();
        }

        let readonly = load_state_readonly(dir.path()).unwrap();
        let (_, recovered) = ShardStateStore::recover(dir.path(), 0).unwrap();
        assert_eq!(readonly.cursor, recovered.cursor);
        assert_eq!(readonly.ready, recovered.ready);
        assert_eq!(readonly.deferred, recovered.deferred);
        assert_eq!(readonly.tombstones, recovered.tombstones);
        assert_eq!(readonly.segment_stats, recovered.segment_stats);
    }
}
