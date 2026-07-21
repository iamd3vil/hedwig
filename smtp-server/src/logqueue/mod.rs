//! Durable segmented append-only log queue.
//!
//! This module implements the storage layer described in PLAN.md: sharded,
//! segmented append-only payload logs holding complete messages, with
//! delivery state tracked separately. It is not yet wired into the serving
//! path; it lands incrementally alongside the legacy spool backends.

// Remove once the log backend is selectable and consumed by the server
// (implementation phases 7-8).
#![allow(dead_code)]

pub mod dispatcher;
pub mod record;
pub mod segment;
pub mod shard;
pub mod spool;
pub mod state;
pub mod writer;

use std::fmt;

use thiserror::Error;

/// Current on-disk format version for payload records and spool layout.
pub const FORMAT_VERSION: u16 = 1;

/// A message's stable identity: the binary form of its ULID.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MessageId(pub [u8; 16]);

impl MessageId {
    pub fn from_ulid(u: ulid::Ulid) -> Self {
        Self(u.to_bytes())
    }

    pub fn parse(s: &str) -> Result<Self, QueueError> {
        let u = ulid::Ulid::from_string(s)
            .map_err(|e| QueueError::InvalidMessageId(format!("{s:?}: {e}")))?;
        Ok(Self::from_ulid(u))
    }

    pub fn to_ulid(self) -> ulid::Ulid {
        ulid::Ulid::from_bytes(self.0)
    }
}

impl fmt::Display for MessageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.to_ulid().fmt(f)
    }
}

impl fmt::Debug for MessageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MessageId({})", self.to_ulid())
    }
}

/// Physical location of a payload record. Stored state must always carry the
/// explicit location; nothing may re-derive a shard from the current
/// configured writer count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct JobLocation {
    pub shard: u16,
    pub segment: u64,
    pub offset: u64,
    pub length: u32,
    pub ordinal: u32,
    pub generation: u32,
}

#[derive(Debug, Error, miette::Diagnostic)]
pub enum QueueError {
    #[error("i/o error on {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("invalid message id {0}")]
    InvalidMessageId(String),

    #[error("record too large: {len} bytes exceeds limit {limit}")]
    RecordTooLarge { len: u64, limit: u64 },

    #[error("invalid record field: {0}")]
    InvalidRecord(String),

    #[error("corrupt record at offset {offset}: {reason}")]
    CorruptRecord { offset: u64, reason: String },

    #[error("unsupported format version {found} (supported: {supported})")]
    UnsupportedVersion { found: u16, supported: u16 },

    #[error("corruption inside sealed segment {path} at offset {offset}: {reason}")]
    CorruptSealedSegment {
        path: String,
        offset: u64,
        reason: String,
    },

    #[error("spool layout error: {0}")]
    Layout(String),

    #[error("spool is locked by another process ({path})")]
    SpoolLocked { path: String },

    #[error("append writer for shard {0} is shut down")]
    WriterClosed(u16),

    #[error(
        "segment size {segment_bytes} cannot hold the maximum message size \
         {max_message_bytes} plus record overhead"
    )]
    SegmentTooSmall {
        segment_bytes: u64,
        max_message_bytes: u64,
    },
}

impl QueueError {
    pub(crate) fn io(path: impl AsRef<std::path::Path>, source: std::io::Error) -> Self {
        QueueError::Io {
            path: path.as_ref().display().to_string(),
            source,
        }
    }
}
