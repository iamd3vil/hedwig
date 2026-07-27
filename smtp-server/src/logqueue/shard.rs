//! Shard directories: each append writer exclusively owns one.

use std::path::{Path, PathBuf};

use super::segment::{self, SegmentKind};
use super::QueueError;

pub fn shard_dir_name(shard: u16) -> String {
    format!("shard-{shard:04}")
}

/// A shard's directory on disk.
#[derive(Debug, Clone)]
pub struct ShardDir {
    path: PathBuf,
    shard: u16,
}

/// The segment files present in a shard directory.
#[derive(Debug, Default)]
pub struct ShardSegments {
    /// Sealed segments, sorted by segment ordinal.
    pub sealed: Vec<(u64, PathBuf)>,
    /// The active segment, if one exists. More than one is a layout error.
    pub active: Option<(u64, PathBuf)>,
    /// The ordinal the next created segment must use (max seen + 1).
    pub next_segment: u64,
}

impl ShardDir {
    pub fn open_or_create(spool_root: &Path, shard: u16) -> Result<Self, QueueError> {
        let path = spool_root.join(shard_dir_name(shard));
        std::fs::create_dir_all(&path).map_err(|e| QueueError::io(&path, e))?;
        Ok(Self { path, shard })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn shard(&self) -> u16 {
        self.shard
    }

    /// Enumerate segment files. This is a small, bounded listing (segments
    /// are proportional to live data, not message history) and runs only at
    /// startup and GC boundaries, never per message.
    pub fn list_segments(&self) -> Result<ShardSegments, QueueError> {
        let mut out = ShardSegments {
            next_segment: 1,
            ..Default::default()
        };
        let entries = std::fs::read_dir(&self.path).map_err(|e| QueueError::io(&self.path, e))?;
        for entry in entries {
            let entry = entry.map_err(|e| QueueError::io(&self.path, e))?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                tracing::warn!(shard = self.shard, ?name, "ignoring non-UTF-8 file in shard dir");
                continue;
            };
            let Some((ordinal, kind)) = segment::parse_file_name(name) else {
                continue; // journal, checkpoint, temp files, …
            };
            out.next_segment = out.next_segment.max(ordinal + 1);
            match kind {
                SegmentKind::Sealed => out.sealed.push((ordinal, entry.path())),
                SegmentKind::Active => {
                    if let Some((existing, _)) = out.active {
                        return Err(QueueError::Layout(format!(
                            "shard {} has two active segments ({} and {}); \
                             rotation must seal before creating the next",
                            self.shard, existing, ordinal
                        )));
                    }
                    out.active = Some((ordinal, entry.path()));
                }
            }
        }
        out.sealed.sort_unstable_by_key(|(ordinal, _)| *ordinal);
        if let Some(w) = out.sealed.windows(2).find(|w| w[0].0 == w[1].0) {
            return Err(QueueError::Layout(format!(
                "shard {} has duplicate segment ordinal {}",
                self.shard, w[0].0
            )));
        }
        if let Some((active, _)) = out.active {
            if out.sealed.iter().any(|(s, _)| *s == active) {
                return Err(QueueError::Layout(format!(
                    "shard {} segment {} exists as both .open and .log",
                    self.shard, active
                )));
            }
        }
        Ok(out)
    }

    /// Whether the shard holds any segment data at all.
    pub fn is_empty(&self) -> Result<bool, QueueError> {
        let segs = self.list_segments()?;
        Ok(segs.sealed.is_empty() && segs.active.is_none())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logqueue::segment::{active_file_name, sealed_file_name};

    #[test]
    fn empty_shard() {
        let dir = tempfile::tempdir().unwrap();
        let shard = ShardDir::open_or_create(dir.path(), 0).unwrap();
        let segs = shard.list_segments().unwrap();
        assert!(segs.sealed.is_empty());
        assert!(segs.active.is_none());
        assert_eq!(segs.next_segment, 1);
        assert!(shard.is_empty().unwrap());
    }

    #[test]
    fn lists_and_sorts_segments() {
        let dir = tempfile::tempdir().unwrap();
        let shard = ShardDir::open_or_create(dir.path(), 3).unwrap();
        for seg in [3u64, 1, 2] {
            std::fs::write(shard.path().join(sealed_file_name(seg)), b"").unwrap();
        }
        std::fs::write(shard.path().join(active_file_name(4)), b"").unwrap();
        // Non-segment files are ignored.
        std::fs::write(shard.path().join("state-journal.log"), b"").unwrap();
        std::fs::write(shard.path().join("checkpoint"), b"").unwrap();

        let segs = shard.list_segments().unwrap();
        assert_eq!(
            segs.sealed.iter().map(|(s, _)| *s).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        assert_eq!(segs.active.as_ref().map(|(s, _)| *s), Some(4));
        assert_eq!(segs.next_segment, 5);
        assert!(!shard.is_empty().unwrap());
    }

    #[test]
    fn two_active_segments_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let shard = ShardDir::open_or_create(dir.path(), 0).unwrap();
        std::fs::write(shard.path().join(active_file_name(1)), b"").unwrap();
        std::fs::write(shard.path().join(active_file_name(2)), b"").unwrap();
        assert!(matches!(
            shard.list_segments(),
            Err(QueueError::Layout(_))
        ));
    }

    #[test]
    fn same_ordinal_open_and_log_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let shard = ShardDir::open_or_create(dir.path(), 0).unwrap();
        std::fs::write(shard.path().join(active_file_name(1)), b"").unwrap();
        std::fs::write(shard.path().join(sealed_file_name(1)), b"").unwrap();
        assert!(matches!(
            shard.list_segments(),
            Err(QueueError::Layout(_))
        ));
    }
}
