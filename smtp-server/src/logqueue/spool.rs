//! Spool root: format version, exclusive process lock, shard layout.

use std::fs::{File, OpenOptions, TryLockError};
use std::path::{Path, PathBuf};

use super::record::FIXED_HEADER_LEN;
use super::shard::ShardDir;
use super::{QueueError, FORMAT_VERSION};

const VERSION_FILE: &str = "format-version";
const LOCK_FILE: &str = ".lock";

/// Fixed allowance for record overhead (header + envelope) on top of the
/// message body when validating segment sizing. Generous relative to real
/// envelopes; a record whose envelope exceeds it is rejected at append time
/// by the writer's fits-in-one-segment check, so the invariant that a record
/// never spans segments holds either way.
pub const ENVELOPE_ALLOWANCE: u64 = 1024 * 1024;

/// An opened spool root. Holds the exclusive OS-level lock for its lifetime:
/// recovery, tail truncation, migration, and append writers must all sit
/// behind this. Independent Hedwig processes must use distinct spool roots.
pub struct Spool {
    root: PathBuf,
    shards: Vec<ShardDir>,
    /// Lock is released when the file handle drops.
    _lock: File,
}

impl Spool {
    /// Open (creating if necessary) a spool root with `shard_count` shards.
    ///
    /// Fails if another process holds the spool lock, if the on-disk format
    /// version is unsupported, or if shrinking `shard_count` would orphan
    /// shard directories that still contain segment data (changing the
    /// writer count requires an empty queue).
    pub fn open(root: impl Into<PathBuf>, shard_count: u16) -> Result<Self, QueueError> {
        assert!(shard_count > 0, "shard_count must be at least 1");
        let root = root.into();
        std::fs::create_dir_all(&root).map_err(|e| QueueError::io(&root, e))?;

        let lock = Self::acquire_lock(&root)?;
        Self::check_format_version(&root)?;

        // Changing the shard count (in either direction) requires an empty
        // queue. Count the contiguous shard directories already present; a
        // mismatch is only legal if every one of them is empty.
        let mut existing = 0u16;
        while root.join(super::shard::shard_dir_name(existing)).is_dir() {
            existing += 1;
        }
        if existing != 0 && existing != shard_count {
            for shard in 0..existing {
                let dir = ShardDir::open_or_create(&root, shard)?;
                if !dir.is_empty()? {
                    return Err(QueueError::Layout(format!(
                        "spool has {existing} shards but {shard_count} are configured, and \
                         shard {shard} still holds data; changing append_writers requires \
                         an empty queue",
                    )));
                }
            }
        }

        let mut shards = Vec::with_capacity(shard_count as usize);
        for shard in 0..shard_count {
            shards.push(ShardDir::open_or_create(&root, shard)?);
        }

        Ok(Self {
            root,
            shards,
            _lock: lock,
        })
    }

    fn acquire_lock(root: &Path) -> Result<File, QueueError> {
        let path = root.join(LOCK_FILE);
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)
            .map_err(|e| QueueError::io(&path, e))?;
        match file.try_lock() {
            Ok(()) => Ok(file),
            Err(TryLockError::WouldBlock) => Err(QueueError::SpoolLocked {
                path: path.display().to_string(),
            }),
            Err(TryLockError::Error(e)) => Err(QueueError::io(&path, e)),
        }
    }

    fn check_format_version(root: &Path) -> Result<(), QueueError> {
        let path = root.join(VERSION_FILE);
        match std::fs::read_to_string(&path) {
            Ok(contents) => {
                let found: u16 = contents.trim().parse().map_err(|_| {
                    QueueError::Layout(format!(
                        "{} does not contain a version number: {contents:?}",
                        path.display()
                    ))
                })?;
                if found != FORMAT_VERSION {
                    return Err(QueueError::UnsupportedVersion {
                        found,
                        supported: FORMAT_VERSION,
                    });
                }
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                std::fs::write(&path, format!("{FORMAT_VERSION}\n"))
                    .map_err(|e| QueueError::io(&path, e))
            }
            Err(e) => Err(QueueError::io(&path, e)),
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn shard_count(&self) -> u16 {
        self.shards.len() as u16
    }

    pub fn shard(&self, shard: u16) -> &ShardDir {
        &self.shards[shard as usize]
    }

    pub fn shards(&self) -> &[ShardDir] {
        &self.shards
    }
}

/// Free bytes available to unprivileged writes on the filesystem holding
/// `path`. Drives the disk-reserve acceptance check (PLAN §20).
pub fn disk_free_bytes(path: &Path) -> std::io::Result<u64> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path contains NUL")
    })?;
    let mut vfs: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c.as_ptr(), &mut vfs) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(vfs.f_bavail as u64 * vfs.f_frsize as u64)
}

/// Reject configurations where a maximum-size message could not fit in one
/// segment. Records never span segments, so the segment target must cover
/// the largest possible record.
pub fn check_segment_sizing(
    segment_target_bytes: u64,
    max_message_bytes: u64,
) -> Result<(), QueueError> {
    let worst_case = max_message_bytes + ENVELOPE_ALLOWANCE + FIXED_HEADER_LEN as u64;
    if segment_target_bytes < worst_case {
        return Err(QueueError::SegmentTooSmall {
            segment_bytes: segment_target_bytes,
            max_message_bytes,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logqueue::segment::sealed_file_name;

    #[test]
    fn open_creates_layout_and_reopens() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("spool");
        {
            let spool = Spool::open(&root, 2).unwrap();
            assert_eq!(spool.shard_count(), 2);
            assert!(root.join("shard-0000").is_dir());
            assert!(root.join("shard-0001").is_dir());
            assert_eq!(
                std::fs::read_to_string(root.join(VERSION_FILE)).unwrap().trim(),
                "1"
            );
        }
        // Lock released on drop; reopening works.
        Spool::open(&root, 2).unwrap();
    }

    #[test]
    fn second_open_is_rejected_while_locked() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("spool");
        let _spool = Spool::open(&root, 1).unwrap();
        match Spool::open(&root, 1).err() {
            Some(QueueError::SpoolLocked { .. }) => {}
            other => panic!("expected SpoolLocked, got {other:?}"),
        }
    }

    #[test]
    fn unsupported_version_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("spool");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join(VERSION_FILE), "99\n").unwrap();
        match Spool::open(&root, 1).err() {
            Some(QueueError::UnsupportedVersion { found: 99, .. }) => {}
            other => panic!("expected UnsupportedVersion, got {other:?}"),
        }
    }

    #[test]
    fn garbage_version_file_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("spool");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join(VERSION_FILE), "not a number").unwrap();
        assert!(matches!(Spool::open(&root, 1), Err(QueueError::Layout(_))));
    }

    #[test]
    fn shrinking_shard_count_requires_empty_orphans() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("spool");
        {
            let spool = Spool::open(&root, 4).unwrap();
            std::fs::write(
                spool.shard(3).path().join(sealed_file_name(1)),
                b"",
            )
            .unwrap();
        }
        // Shard 3 still holds a segment: shrinking to 2 must fail.
        assert!(matches!(Spool::open(&root, 2), Err(QueueError::Layout(_))));
        // Removing the data makes the shrink legal.
        std::fs::remove_file(root.join("shard-0003").join(sealed_file_name(1))).unwrap();
        Spool::open(&root, 2).unwrap();
    }

    #[test]
    fn growing_shard_count_requires_empty_queue() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("spool");
        {
            let spool = Spool::open(&root, 1).unwrap();
            std::fs::write(spool.shard(0).path().join(sealed_file_name(1)), b"").unwrap();
        }
        assert!(matches!(Spool::open(&root, 4), Err(QueueError::Layout(_))));
        std::fs::remove_file(root.join("shard-0000").join(sealed_file_name(1))).unwrap();
        let spool = Spool::open(&root, 4).unwrap();
        assert_eq!(spool.shard_count(), 4);
    }

    #[test]
    fn segment_sizing_invariant() {
        assert!(check_segment_sizing(64 * 1024 * 1024, 25 * 1024 * 1024).is_ok());
        assert!(matches!(
            check_segment_sizing(8 * 1024 * 1024, 25 * 1024 * 1024),
            Err(QueueError::SegmentTooSmall { .. })
        ));
    }
}
