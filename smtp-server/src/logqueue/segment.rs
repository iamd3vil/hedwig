//! Segment files: the unit of payload storage and reclamation.
//!
//! A shard has at most one active segment (`segment-NNNNNNNNNNNN.open`),
//! which is sealed by renaming it to `.log`. Sealed segments are immutable.
//! Records never span segments.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

use super::record::{self, DecodeError, RecordHeader, FIXED_HEADER_LEN};
use super::QueueError;

pub const SEALED_EXT: &str = "log";
pub const ACTIVE_EXT: &str = "open";

/// Read granularity while scanning records; large enough to cover almost
/// every header in one positioned read.
const SCAN_CHUNK: usize = 128 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegmentKind {
    Active,
    Sealed,
}

pub fn sealed_file_name(segment: u64) -> String {
    format!("segment-{segment:012}.{SEALED_EXT}")
}

pub fn active_file_name(segment: u64) -> String {
    format!("segment-{segment:012}.{ACTIVE_EXT}")
}

/// Parse a segment file name into its ordinal and kind. Returns `None` for
/// unrelated files.
pub fn parse_file_name(name: &str) -> Option<(u64, SegmentKind)> {
    let rest = name.strip_prefix("segment-")?;
    let (digits, ext) = rest.split_once('.')?;
    if digits.len() != 12 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let ordinal = digits.parse().ok()?;
    let kind = match ext {
        SEALED_EXT => SegmentKind::Sealed,
        ACTIVE_EXT => SegmentKind::Active,
        _ => return None,
    };
    Some((ordinal, kind))
}

/// The shard's current append target. All methods are synchronous; the
/// append writer owns this on a dedicated task.
pub struct ActiveSegment {
    file: File,
    path: PathBuf,
    segment: u64,
    len: u64,
    next_ordinal: u32,
}

impl ActiveSegment {
    /// Create a brand-new active segment. Fails if the file already exists:
    /// segment ordinals are never reused.
    pub fn create(shard_dir: &Path, segment: u64) -> Result<Self, QueueError> {
        let path = shard_dir.join(active_file_name(segment));
        // O_APPEND, like `recover`: after a partial-write rollback
        // (`set_len` back to the committed tail) the next write must land
        // at the new EOF. A plain write cursor would sit past the
        // truncation point and punch a hole that loses every later record
        // at recovery.
        let file = OpenOptions::new()
            .append(true)
            .create_new(true)
            .open(&path)
            .map_err(|e| QueueError::io(&path, e))?;
        Ok(Self {
            file,
            path,
            segment,
            len: 0,
            next_ordinal: 0,
        })
    }

    /// Reopen an existing active segment for append after its tail has been
    /// validated (and truncated if needed) by [`validate_active_tail`].
    pub fn recover(path: PathBuf, segment: u64, tail: &TailValidation) -> Result<Self, QueueError> {
        // O_APPEND: writes land at end-of-file, which after tail validation
        // is exactly the committed tail (create() starts at 0 and only ever
        // writes sequentially, so it needs no special mode).
        let file = OpenOptions::new()
            .append(true)
            .open(&path)
            .map_err(|e| QueueError::io(&path, e))?;
        Ok(Self {
            file,
            path,
            segment,
            len: tail.committed_len,
            next_ordinal: tail.next_ordinal,
        })
    }

    pub fn segment(&self) -> u64 {
        self.segment
    }

    /// Committed length: every byte below this is a complete record.
    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn next_ordinal(&self) -> u32 {
        self.next_ordinal
    }

    #[cfg(test)]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append one encoded record. Returns the record's offset. The caller
    /// must have encoded with `ordinal == self.next_ordinal()`.
    ///
    /// The write either fully succeeds or the segment is left with the
    /// previous committed length: on a partial failure the file is truncated
    /// back so a retry (or seal) never leaves a torn record below the
    /// committed tail.
    pub fn append(&mut self, encoded: &[u8]) -> Result<u64, QueueError> {
        let offset = self.len;
        if let Err(e) = self.file.write_all(encoded) {
            // Best effort: cut back to the committed tail. If this fails the
            // tail validator will do the same at next startup.
            let _ = self.file.set_len(offset);
            return Err(QueueError::io(&self.path, e));
        }
        self.len += encoded.len() as u64;
        self.next_ordinal += 1;
        Ok(offset)
    }

    /// Seal this segment: rename `.open` to `.log`. Returns the sealed path
    /// and final committed length. The file is immutable afterwards; the
    /// caller must not append through this handle again (the writer swaps
    /// in a fresh segment, or tests drop it).
    pub fn seal_in_place(&self) -> Result<(PathBuf, u64), QueueError> {
        let sealed = self
            .path
            .parent()
            .expect("segment path has a parent")
            .join(sealed_file_name(self.segment));
        std::fs::rename(&self.path, &sealed).map_err(|e| QueueError::io(&self.path, e))?;
        Ok((sealed, self.len))
    }
}

/// Read-only positioned access to a (sealed or active) segment.
///
/// Reading an active segment concurrently with the writer is safe as long as
/// callers stay below the published committed tail.
pub struct SegmentReader {
    file: File,
    path: PathBuf,
}

impl SegmentReader {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, QueueError> {
        let path = path.into();
        let file = File::open(&path).map_err(|e| QueueError::io(&path, e))?;
        Ok(Self { file, path })
    }

    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> Result<(), QueueError> {
        self.file
            .read_exact_at(buf, offset)
            .map_err(|e| QueueError::io(&self.path, e))
    }

    /// Decode the record header at `offset`.
    pub fn read_header_at(
        &self,
        offset: u64,
        max_record_len: u32,
    ) -> Result<RecordHeader, QueueError> {
        let mut buf = vec![0u8; FIXED_HEADER_LEN];
        self.read_exact_at(&mut buf, offset)?;
        loop {
            match record::decode_header(&buf, max_record_len) {
                Ok(h) => return Ok(h),
                Err(DecodeError::Incomplete { needed }) if needed > buf.len() => {
                    let have = buf.len();
                    buf.resize(needed, 0);
                    self.read_exact_at(&mut buf[have..], offset + have as u64)?;
                }
                Err(e) => return Err(e.into_queue_error(offset)),
            }
        }
    }

    /// Read and checksum-verify the body of a record whose header was read
    /// at `offset`.
    pub fn read_body(&self, header: &RecordHeader, offset: u64) -> Result<Vec<u8>, QueueError> {
        let mut body = vec![0u8; header.body_len() as usize];
        self.read_exact_at(&mut body, offset + header.header_len as u64)?;
        record::verify_body(header, &body)?;
        Ok(body)
    }

    /// Read a complete record (header + verified body) at `offset`.
    pub fn read_record_at(
        &self,
        offset: u64,
        max_record_len: u32,
    ) -> Result<(RecordHeader, Vec<u8>), QueueError> {
        let header = self.read_header_at(offset, max_record_len)?;
        let body = self.read_body(&header, offset)?;
        Ok((header, body))
    }

    fn file_len(&self) -> Result<u64, QueueError> {
        Ok(self
            .file
            .metadata()
            .map_err(|e| QueueError::io(&self.path, e))?
            .len())
    }
}

/// One step of a header scan.
enum ScanStep {
    Record { header: RecordHeader, offset: u64 },
    /// Clean end: `end` is the offset one past the last complete record.
    End { end: u64 },
    /// The bytes at `offset` are not a complete valid record.
    Invalid { offset: u64, reason: String },
}

/// Streaming header scanner over a segment file. Reads headers, skips
/// bodies. `verify_bodies` additionally reads and checksums each body (used
/// for active-tail validation).
struct Scanner<'a> {
    reader: &'a SegmentReader,
    end: u64,
    offset: u64,
    max_record_len: u32,
    verify_bodies: bool,
    buf: Vec<u8>,
}

impl<'a> Scanner<'a> {
    fn new(
        reader: &'a SegmentReader,
        start: u64,
        end: u64,
        max_record_len: u32,
        verify_bodies: bool,
    ) -> Self {
        Self {
            reader,
            end,
            offset: start,
            max_record_len,
            verify_bodies,
            buf: Vec::new(),
        }
    }

    fn read_window(&mut self, len: usize) -> Result<(), QueueError> {
        self.buf.resize(len, 0);
        self.reader.read_exact_at(&mut self.buf, self.offset)
    }

    fn next(&mut self) -> Result<ScanStep, QueueError> {
        let remaining = self.end - self.offset;
        if remaining == 0 {
            return Ok(ScanStep::End { end: self.offset });
        }
        if remaining < FIXED_HEADER_LEN as u64 {
            return Ok(ScanStep::Invalid {
                offset: self.offset,
                reason: format!("{remaining} trailing bytes, shorter than a record header"),
            });
        }

        let window = SCAN_CHUNK.min(remaining as usize);
        self.read_window(window)?;
        let header = loop {
            match record::decode_header(&self.buf, self.max_record_len) {
                Ok(h) => break h,
                Err(DecodeError::Incomplete { needed }) => {
                    if needed as u64 > remaining {
                        return Ok(ScanStep::Invalid {
                            offset: self.offset,
                            reason: format!(
                                "record needs {needed} header bytes but only {remaining} remain"
                            ),
                        });
                    }
                    if needed <= self.buf.len() {
                        // decode_header asked for bytes we already have:
                        // internal inconsistency, treat as corrupt.
                        return Ok(ScanStep::Invalid {
                            offset: self.offset,
                            reason: "header decoder made no progress".into(),
                        });
                    }
                    self.read_window(needed)?;
                }
                Err(DecodeError::UnsupportedVersion(v)) => {
                    return Ok(ScanStep::Invalid {
                        offset: self.offset,
                        reason: format!("unsupported record version {v}"),
                    });
                }
                Err(DecodeError::Corrupt(reason)) => {
                    return Ok(ScanStep::Invalid {
                        offset: self.offset,
                        reason,
                    });
                }
            }
        };

        if header.record_len as u64 > remaining {
            return Ok(ScanStep::Invalid {
                offset: self.offset,
                reason: format!(
                    "record length {} overruns segment end by {}",
                    header.record_len,
                    header.record_len as u64 - remaining
                ),
            });
        }

        if self.verify_bodies {
            if let Err(e) = self.reader.read_body(&header, self.offset) {
                return Ok(ScanStep::Invalid {
                    offset: self.offset,
                    reason: format!("body verification failed: {e}"),
                });
            }
        }

        let offset = self.offset;
        self.offset += header.record_len as u64;
        Ok(ScanStep::Record { header, offset })
    }
}

/// Open a segment by ordinal, whether sealed or still active. Rotation can
/// race this (rename .open -> .log), so the sealed name is tried first and
/// the active name second, then once more in case the rename happened in
/// between. An already-open descriptor keeps working across the rename, so
/// callers may cache the reader.
pub fn open_segment_reader(shard_dir: &Path, segment: u64) -> Result<SegmentReader, QueueError> {
    for name in [
        sealed_file_name(segment),
        active_file_name(segment),
        sealed_file_name(segment),
    ] {
        match SegmentReader::open(shard_dir.join(name)) {
            Ok(r) => return Ok(r),
            Err(QueueError::Io { ref source, .. })
                if source.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    Err(QueueError::Layout(format!(
        "segment {segment} not found in {}",
        shard_dir.display()
    )))
}

/// Outcome of validating (and possibly truncating) an active segment tail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailValidation {
    /// Length of the valid record prefix; the file's length after validation.
    pub committed_len: u64,
    /// Number of valid records.
    pub records: u32,
    /// Ordinal the next appended record must use.
    pub next_ordinal: u32,
    /// Bytes discarded from the tail (0 for a clean shutdown).
    pub truncated_bytes: u64,
}

/// Validate an active segment: scan from the start, verify every header and
/// body checksum and the ordinal sequence, and truncate the file at the
/// first invalid position.
///
/// With sequential appends a crash can only tear the tail, so everything
/// past the first invalid byte is unrecoverable garbage. Under the accepted
/// page-cache durability model, a power loss may also punch holes earlier in
/// the file; bytes after such a hole are discarded with the tail and counted
/// in `truncated_bytes` (this falls under "recently accepted mail may be
/// lost", and the truncation is logged loudly by the caller).
pub fn validate_active_tail(path: &Path, max_record_len: u32) -> Result<TailValidation, QueueError> {
    let reader = SegmentReader::open(path)?;
    let file_len = reader.file_len()?;
    let mut scanner = Scanner::new(&reader, 0, file_len, max_record_len, true);

    let mut records = 0u32;
    let mut next_ordinal = 0u32;
    let (committed_len, invalid_reason) = loop {
        match scanner.next()? {
            ScanStep::Record { header, offset } => {
                if header.ordinal != next_ordinal {
                    break (
                        offset,
                        Some(format!(
                            "ordinal {} where {} was expected",
                            header.ordinal, next_ordinal
                        )),
                    );
                }
                records += 1;
                next_ordinal += 1;
            }
            ScanStep::End { end } => break (end, None),
            ScanStep::Invalid { offset, reason } => break (offset, Some(reason)),
        }
    };

    let truncated_bytes = file_len - committed_len;
    if truncated_bytes > 0 {
        let file = OpenOptions::new()
            .write(true)
            .open(path)
            .map_err(|e| QueueError::io(path, e))?;
        file.set_len(committed_len)
            .map_err(|e| QueueError::io(path, e))?;
        tracing::warn!(
            path = %path.display(),
            committed_len,
            truncated_bytes,
            reason = invalid_reason.as_deref().unwrap_or("unknown"),
            "truncated invalid tail of active segment"
        );
    }

    Ok(TailValidation {
        committed_len,
        records,
        next_ordinal,
        truncated_bytes,
    })
}

/// Scan record headers in `[start, end)` of a segment, invoking `f` for each
/// record. `f` returns whether to continue; the scan's return value is the
/// offset one past the last visited record (== `end` when it ran to
/// completion). Any invalid record is an error: sealed segments must be
/// perfect, and callers scanning an active segment must pass the committed
/// tail as `end`, below which the same holds.
pub fn scan_headers(
    reader: &SegmentReader,
    start: u64,
    end: u64,
    max_record_len: u32,
    mut f: impl FnMut(u64, RecordHeader) -> bool,
) -> Result<u64, QueueError> {
    let mut scanner = Scanner::new(reader, start, end, max_record_len, false);
    loop {
        match scanner.next()? {
            ScanStep::Record { header, offset } => {
                let next = offset + header.record_len as u64;
                if !f(offset, header) {
                    return Ok(next);
                }
            }
            ScanStep::End { end } => return Ok(end),
            ScanStep::Invalid { offset, reason } => {
                return Err(QueueError::CorruptSealedSegment {
                    path: reader.path.display().to_string(),
                    offset,
                    reason,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logqueue::record::{encode, RecordParams, MAX_RECORD_LEN};
    use crate::logqueue::MessageId;

    fn record(ordinal: u32, body: &[u8]) -> Vec<u8> {
        let recipients = vec!["rcpt@example.com".to_string()];
        encode(&RecordParams {
            message_id: MessageId::from_ulid(ulid::Ulid::from_parts(ordinal as u64, 42)),
            enqueue_ms: 1_752_000_000_000 + ordinal as i64,
            generation: 0,
            ordinal,
            sender: "sender@example.com",
            recipients: &recipients,
            body,
        })
        .unwrap()
    }

    fn fill_segment(dir: &Path, segment: u64, bodies: &[&[u8]]) -> (ActiveSegment, Vec<u64>) {
        let mut seg = ActiveSegment::create(dir, segment).unwrap();
        let mut offsets = Vec::new();
        for (i, body) in bodies.iter().enumerate() {
            let encoded = record(i as u32, body);
            offsets.push(seg.append(&encoded).unwrap());
        }
        (seg, offsets)
    }

    #[test]
    fn file_name_round_trip() {
        assert_eq!(
            parse_file_name(&sealed_file_name(42)),
            Some((42, SegmentKind::Sealed))
        );
        assert_eq!(
            parse_file_name(&active_file_name(7)),
            Some((7, SegmentKind::Active))
        );
        assert_eq!(parse_file_name("segment-123.log"), None); // wrong width
        assert_eq!(parse_file_name("segment-00000000000x.log"), None);
        assert_eq!(parse_file_name("checkpoint"), None);
        assert_eq!(parse_file_name("segment-000000000001.tmp"), None);
    }

    #[test]
    fn append_read_seal_read() {
        let dir = tempfile::tempdir().unwrap();
        let (seg, offsets) =
            fill_segment(dir.path(), 1, &[b"first body", b"second body", b"third"]);
        let active_path = seg.path().to_path_buf();

        // Read back through the active file.
        let reader = SegmentReader::open(&active_path).unwrap();
        let (h, body) = reader.read_record_at(offsets[1], MAX_RECORD_LEN).unwrap();
        assert_eq!(h.ordinal, 1);
        assert_eq!(body, b"second body");

        // Seal, then read through the sealed file.
        let (sealed_path, len) = seg.seal_in_place().unwrap();
        assert!(!active_path.exists());
        assert_eq!(len, std::fs::metadata(&sealed_path).unwrap().len());
        let reader = SegmentReader::open(&sealed_path).unwrap();
        let (h, body) = reader.read_record_at(offsets[2], MAX_RECORD_LEN).unwrap();
        assert_eq!(h.ordinal, 2);
        assert_eq!(body, b"third");
    }

    #[test]
    fn segment_ordinals_never_reused() {
        let dir = tempfile::tempdir().unwrap();
        let _seg = ActiveSegment::create(dir.path(), 1).unwrap();
        assert!(ActiveSegment::create(dir.path(), 1).is_err());
    }

    #[test]
    fn scan_headers_visits_all_records() {
        let dir = tempfile::tempdir().unwrap();
        let (seg, offsets) = fill_segment(dir.path(), 1, &[b"a", b"bb", b"ccc", b"dddd"]);
        let committed = seg.len();
        let (sealed, _) = seg.seal_in_place().unwrap();

        let reader = SegmentReader::open(&sealed).unwrap();
        let mut seen = Vec::new();
        scan_headers(&reader, 0, committed, MAX_RECORD_LEN, |off, h| {
            seen.push((off, h.ordinal, h.body_len()));
            true
        })
        .unwrap();
        assert_eq!(seen.len(), 4);
        for (i, (off, ordinal, body_len)) in seen.iter().enumerate() {
            assert_eq!(*off, offsets[i]);
            assert_eq!(*ordinal, i as u32);
            assert_eq!(*body_len, (i + 1) as u32);
        }

        // Scan from a mid-segment cursor position.
        let mut seen = Vec::new();
        scan_headers(&reader, offsets[2], committed, MAX_RECORD_LEN, |off, _| {
            seen.push(off);
            true
        })
        .unwrap();
        assert_eq!(seen, vec![offsets[2], offsets[3]]);
    }

    #[test]
    fn clean_tail_validates_without_truncation() {
        let dir = tempfile::tempdir().unwrap();
        let (seg, _) = fill_segment(dir.path(), 1, &[b"a", b"b"]);
        let path = seg.path().to_path_buf();
        let len = seg.len();
        drop(seg);

        let v = validate_active_tail(&path, MAX_RECORD_LEN).unwrap();
        assert_eq!(
            v,
            TailValidation {
                committed_len: len,
                records: 2,
                next_ordinal: 2,
                truncated_bytes: 0,
            }
        );
    }

    #[test]
    fn partial_final_record_is_truncated() {
        let dir = tempfile::tempdir().unwrap();
        let (seg, offsets) = fill_segment(dir.path(), 1, &[b"aaaa", b"bbbb", b"cccc"]);
        let path = seg.path().to_path_buf();
        drop(seg);
        let full_len = std::fs::metadata(&path).unwrap().len();

        // Cut the file mid-way through the last record.
        let cut = offsets[2] + (full_len - offsets[2]) / 2;
        let f = OpenOptions::new().write(true).open(&path).unwrap();
        f.set_len(cut).unwrap();

        let v = validate_active_tail(&path, MAX_RECORD_LEN).unwrap();
        assert_eq!(v.records, 2);
        assert_eq!(v.committed_len, offsets[2]);
        assert_eq!(v.truncated_bytes, cut - offsets[2]);
        assert_eq!(std::fs::metadata(&path).unwrap().len(), offsets[2]);

        // The segment must be appendable again with the right ordinal.
        let mut seg = ActiveSegment::recover(path.clone(), 1, &v).unwrap();
        assert_eq!(seg.next_ordinal(), 2);
        let encoded = record(2, b"replacement");
        let off = seg.append(&encoded).unwrap();
        assert_eq!(off, offsets[2]);
        let v2 = validate_active_tail(&path, MAX_RECORD_LEN).unwrap();
        assert_eq!(v2.records, 3);
        assert_eq!(v2.truncated_bytes, 0);
    }

    #[test]
    fn corrupt_tail_body_is_truncated() {
        let dir = tempfile::tempdir().unwrap();
        let (seg, offsets) = fill_segment(dir.path(), 1, &[b"aaaa", b"bbbbbbbb"]);
        let path = seg.path().to_path_buf();
        let len = seg.len();
        drop(seg);

        // Flip a byte inside the final record's body.
        let f = OpenOptions::new().read(true).write(true).open(&path).unwrap();
        let mut b = [0u8; 1];
        f.read_exact_at(&mut b, len - 2).unwrap();
        f.write_all_at(&[b[0] ^ 0xff], len - 2).unwrap();

        let v = validate_active_tail(&path, MAX_RECORD_LEN).unwrap();
        assert_eq!(v.records, 1);
        assert_eq!(v.committed_len, offsets[1]);
    }

    #[test]
    fn sealed_segment_corruption_is_an_error_not_a_skip() {
        let dir = tempfile::tempdir().unwrap();
        let (seg, offsets) = fill_segment(dir.path(), 1, &[b"aaaa", b"bbbb", b"cccc"]);
        let committed = seg.len();
        let (sealed, _) = seg.seal_in_place().unwrap();

        // Corrupt the middle record's header region.
        let f = OpenOptions::new().write(true).open(&sealed).unwrap();
        f.write_all_at(&[0xff; 8], offsets[1] + 24).unwrap();

        let reader = SegmentReader::open(&sealed).unwrap();
        let err = scan_headers(&reader, 0, committed, MAX_RECORD_LEN, |_, _| true).unwrap_err();
        match err {
            QueueError::CorruptSealedSegment { offset, .. } => assert_eq!(offset, offsets[1]),
            other => panic!("expected CorruptSealedSegment, got {other}"),
        }
    }

    #[test]
    fn ordinal_gap_truncates_active_tail() {
        let dir = tempfile::tempdir().unwrap();
        let mut seg = ActiveSegment::create(dir.path(), 1).unwrap();
        seg.append(&record(0, b"a")).unwrap();
        let gap_offset = seg.append(&record(5, b"skipped ordinal")).unwrap();
        let path = seg.path().to_path_buf();
        drop(seg);

        let v = validate_active_tail(&path, MAX_RECORD_LEN).unwrap();
        assert_eq!(v.records, 1);
        assert_eq!(v.committed_len, gap_offset);
        assert_eq!(v.next_ordinal, 1);
    }

    #[test]
    fn empty_active_segment_validates() {
        let dir = tempfile::tempdir().unwrap();
        let seg = ActiveSegment::create(dir.path(), 1).unwrap();
        let path = seg.path().to_path_buf();
        drop(seg);
        let v = validate_active_tail(&path, MAX_RECORD_LEN).unwrap();
        assert_eq!(v.committed_len, 0);
        assert_eq!(v.records, 0);
        assert_eq!(v.next_ordinal, 0);
    }

    #[test]
    fn garbage_prefix_truncates_to_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(active_file_name(1));
        std::fs::write(&path, b"this is not a record at all, just garbage bytes!!").unwrap();
        let v = validate_active_tail(&path, MAX_RECORD_LEN).unwrap();
        assert_eq!(v.committed_len, 0);
        assert!(v.truncated_bytes > 0);
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
    }
}
