//! Segment files: the unit of payload storage and reclamation.
//!
//! A shard has at most one active segment (`segment-NNNNNNNNNNNN.open`),
//! which is sealed by renaming it to `.log`. Sealed segments are immutable.
//! Records never span segments.

use std::fs::{File, OpenOptions};
use std::io::{IoSlice, Write};
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
    // The file-name formatters pad to a MINIMUM of 12 digits; ordinals past
    // 10^12 produce longer names, which must still parse.
    if digits.len() < 12 || !digits.bytes().all(|b| b.is_ascii_digit()) {
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

/// One record offered to [`ActiveSegment::append_batch`]: its encoded
/// header and the body that header frames, kept apart so the body is never
/// copied just to make the record contiguous.
pub struct PendingRecord<'a> {
    pub header: &'a [u8],
    pub body: &'a [u8],
}

impl PendingRecord<'_> {
    fn len(&self) -> u64 {
        self.header.len() as u64 + self.body.len() as u64
    }
}

/// Outcome of a batched append: the offsets of the leading records that were
/// fully written, plus the error that stopped the batch. Records from
/// `offsets.len()` onwards did not reach the file.
pub struct BatchAppend {
    pub offsets: Vec<u64>,
    pub error: Option<QueueError>,
}

/// `write_all` for iovecs. `write_vectored` may consume only part of what it
/// is offered, so advance and retry until nothing is left. Returns the bytes
/// actually written and the error that stopped the loop, if any — the caller
/// needs the count to know how much of the batch survived.
///
/// (`Write::write_all_vectored` would do this but is still unstable.)
///
/// Generic over the sink so the advance-and-retry arithmetic can be tested
/// against a short-writing one; the only real caller passes `&File`.
fn write_all_vectored<W: Write>(
    mut sink: W,
    slices: &mut [IoSlice<'_>],
) -> (u64, Option<std::io::Error>) {
    let mut written = 0u64;
    let mut rest = &mut slices[..];
    while !rest.is_empty() {
        match sink.write_vectored(rest) {
            // Refusing to make progress on a regular file would spin here.
            Ok(0) => return (written, Some(std::io::ErrorKind::WriteZero.into())),
            Ok(n) => {
                written += n as u64;
                IoSlice::advance_slices(&mut rest, n);
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return (written, Some(e)),
        }
    }
    (written, None)
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
    #[allow(clippy::len_without_is_empty)]
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
        let mut batch = self.append_batch(&[PendingRecord {
            header: encoded,
            body: &[],
        }]);
        match batch.error {
            Some(e) => Err(e),
            None => Ok(batch.offsets.pop().expect("committed record has an offset")),
        }
    }

    /// Append several records in one vectored write. The records must have
    /// been encoded with consecutive ordinals starting at
    /// `self.next_ordinal()`.
    ///
    /// Same all-or-nothing contract as [`Self::append`], applied per record:
    /// the returned offsets are those of the leading records that fully
    /// reached the file, any torn remainder is truncated away, and `error`
    /// says why the batch stopped. The committed length therefore always
    /// lands on a record boundary, so a later append (or seal) can never
    /// leave a partial record below it.
    pub fn append_batch(&mut self, records: &[PendingRecord<'_>]) -> BatchAppend {
        debug_assert!(!records.is_empty());
        let mut slices = Vec::with_capacity(records.len() * 2);
        for record in records {
            slices.push(IoSlice::new(record.header));
            // Skip empty bodies rather than spend an iovec on them.
            if !record.body.is_empty() {
                slices.push(IoSlice::new(record.body));
            }
        }
        let (written, error) = write_all_vectored(&self.file, &mut slices);
        self.commit_batch(records, written, error)
    }

    /// Account for a batch write that put `written` bytes into the file.
    /// Split out from [`Self::append_batch`] so the torn-write path can be
    /// tested without arranging a real short write.
    fn commit_batch(
        &mut self,
        records: &[PendingRecord<'_>],
        written: u64,
        error: Option<std::io::Error>,
    ) -> BatchAppend {
        let start = self.len;
        let mut committed = 0u64;
        let mut offsets = Vec::with_capacity(records.len());
        for record in records {
            let end = committed + record.len();
            if end > written {
                break;
            }
            offsets.push(start + committed);
            committed = end;
        }
        self.len = start + committed;
        self.next_ordinal += offsets.len() as u32;

        if committed < written {
            // The kernel took a fraction of a record. Cut back to the last
            // record boundary; O_APPEND then puts the next write at that
            // new end of file. Best effort — if this fails the tail
            // validator does the same at next startup.
            let _ = self.file.set_len(self.len);
        }
        // A write that reported no error consumed every iovec we offered.
        debug_assert!(error.is_some() || offsets.len() == records.len());
        BatchAppend {
            offsets,
            error: error.map(|e| QueueError::io(&self.path, e)),
        }
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

    /// Read up to `buf.len()` bytes at `offset`, stopping early at EOF.
    /// Returns the number of bytes read.
    fn read_up_to(&self, buf: &mut [u8], offset: u64) -> Result<usize, QueueError> {
        let mut read = 0;
        while read < buf.len() {
            match self.file.read_at(&mut buf[read..], offset + read as u64) {
                Ok(0) => break,
                Ok(n) => read += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(QueueError::io(&self.path, e)),
            }
        }
        Ok(read)
    }

    /// Decode the record header at `offset`.
    pub fn read_header_at(
        &self,
        offset: u64,
        max_record_len: u32,
    ) -> Result<RecordHeader, QueueError> {
        // header_len always exceeds FIXED_HEADER_LEN (the envelope follows),
        // so start with enough room for a typical envelope to decode in one
        // read; short reads at EOF are fine, the decoder reports what it
        // still needs.
        const INITIAL_READ: usize = 1024;
        let mut buf = vec![0u8; INITIAL_READ];
        let n = self.read_up_to(&mut buf, offset)?;
        buf.truncate(n);
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

    /// Read a record whose total length is already known (from a
    /// `JobLocation`) in a single positioned read, then decode and verify
    /// it. Returns the header and the full record buffer; the body is
    /// `buf[header.header_len..]`.
    pub fn read_record_exact(
        &self,
        offset: u64,
        length: u32,
        max_record_len: u32,
    ) -> Result<(RecordHeader, Vec<u8>), QueueError> {
        // `length` reaches us from a JobLocation, i.e. from a header that
        // decode_header already bounded or from a CRC-checked journal entry.
        // Re-check it here anyway so the allocation below cannot be driven
        // by a bad length that arrived some other way.
        if length > max_record_len.min(record::MAX_RECORD_LEN) {
            return Err(QueueError::CorruptRecord {
                offset,
                reason: format!("record length {length} exceeds the maximum"),
            });
        }
        let mut buf = vec![0u8; length as usize];
        self.read_exact_at(&mut buf, offset)?;
        let header =
            record::decode_header(&buf, max_record_len).map_err(|e| e.into_queue_error(offset))?;
        if header.record_len != length {
            return Err(QueueError::CorruptRecord {
                offset,
                reason: format!(
                    "record length {} does not match expected length {length}",
                    header.record_len
                ),
            });
        }
        record::verify_body(&header, &buf[header.header_len as usize..])?;
        Ok((header, buf))
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
    /// File offset of `buf[0]`; the buffer holds `[buf_start, buf_start + buf.len())`.
    buf_start: u64,
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
            buf_start: start,
        }
    }

    /// The buffered window starting at `self.offset`, guaranteed to hold at
    /// least `needed` bytes (clamped to the scan end). Issues a positioned
    /// read only when the current buffer doesn't already cover the range,
    /// reading a full SCAN_CHUNK so successive headers decode from memory.
    fn window(&mut self, needed: usize) -> Result<&[u8], QueueError> {
        let remaining = (self.end - self.offset) as usize;
        let needed = needed.min(remaining);
        // `offset` only moves forward and `buf_start` is always set to a
        // past value of it, so this cannot underflow.
        let rel = (self.offset - self.buf_start) as usize;
        if rel > self.buf.len() || self.buf.len() - rel < needed {
            let len = needed.max(SCAN_CHUNK).min(remaining);
            self.buf.resize(len, 0);
            self.reader.read_exact_at(&mut self.buf, self.offset)?;
            self.buf_start = self.offset;
            return Ok(&self.buf);
        }
        Ok(&self.buf[rel..])
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

        let mut needed = FIXED_HEADER_LEN;
        let max_record_len = self.max_record_len;
        let header = loop {
            let window = self.window(needed)?;
            match record::decode_header(window, max_record_len) {
                Ok(h) => break h,
                Err(DecodeError::Incomplete { needed: more }) => {
                    if more as u64 > remaining {
                        return Ok(ScanStep::Invalid {
                            offset: self.offset,
                            reason: format!(
                                "record needs {more} header bytes but only {remaining} remain"
                            ),
                        });
                    }
                    if more <= window.len() {
                        // decode_header asked for bytes we already have:
                        // internal inconsistency, treat as corrupt.
                        return Ok(ScanStep::Invalid {
                            offset: self.offset,
                            reason: "header decoder made no progress".into(),
                        });
                    }
                    needed = more;
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
    use crate::logqueue::record::{
        encode, encode_header, encoded_sizes, RecordParams, MAX_RECORD_LEN,
    };
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

    /// The two halves the append path deals in: the encoded header and the
    /// body it frames.
    fn header_and_body(ordinal: u32, body: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let recipients = vec!["rcpt@example.com".to_string()];
        let params = RecordParams {
            message_id: MessageId::from_ulid(ulid::Ulid::from_parts(ordinal as u64, 42)),
            enqueue_ms: 1_752_000_000_000 + ordinal as i64,
            generation: 0,
            ordinal,
            sender: "sender@example.com",
            recipients: &recipients,
            body,
        };
        let sizes = encoded_sizes(&params).unwrap();
        (encode_header(&params, sizes).unwrap(), body.to_vec())
    }

    fn pending(parts: &[(Vec<u8>, Vec<u8>)]) -> Vec<PendingRecord<'_>> {
        parts
            .iter()
            .map(|(header, body)| PendingRecord { header, body })
            .collect()
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
    fn batched_append_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let mut seg = ActiveSegment::create(dir.path(), 1).unwrap();
        let bodies: [&[u8]; 4] = [b"first", b"", b"third body", &[b'z'; 9000]];
        let parts: Vec<_> = bodies
            .iter()
            .enumerate()
            .map(|(i, b)| header_and_body(i as u32, b))
            .collect();
        let records = pending(&parts);

        let batch = seg.append_batch(&records);
        assert!(batch.error.is_none());
        assert_eq!(batch.offsets.len(), 4);
        assert_eq!(seg.next_ordinal(), 4);

        // Offsets must be dense and the committed length must be the sum.
        let mut expected = 0u64;
        for (offset, r) in batch.offsets.iter().zip(records.iter()) {
            assert_eq!(*offset, expected);
            expected += r.len();
        }
        assert_eq!(seg.len(), expected);

        let path = seg.path().to_path_buf();
        drop(seg);
        let reader = SegmentReader::open(&path).unwrap();
        for (i, (offset, body)) in batch.offsets.iter().zip(bodies.iter()).enumerate() {
            let (h, read) = reader.read_record_at(*offset, MAX_RECORD_LEN).unwrap();
            assert_eq!(h.ordinal, i as u32);
            assert_eq!(read, *body);
        }
        let v = validate_active_tail(&path, MAX_RECORD_LEN).unwrap();
        assert_eq!(v.records, 4);
        assert_eq!(v.truncated_bytes, 0);
        assert_eq!(v.committed_len, expected);
    }

    #[test]
    fn torn_batch_write_commits_only_whole_records() {
        let dir = tempfile::tempdir().unwrap();
        let mut seg = ActiveSegment::create(dir.path(), 1).unwrap();
        let first = seg.append(&record(0, b"already here")).unwrap();
        assert_eq!(first, 0);
        let committed_before = seg.len();

        let parts: Vec<_> = (1..4u32)
            .map(|i| header_and_body(i, format!("body {i}").as_bytes()))
            .collect();
        let records = pending(&parts);

        // Put two whole records plus a fragment of the third in the file,
        // then account for it as the failed write it stands in for.
        let mut bytes = Vec::new();
        for r in &records[..2] {
            bytes.extend_from_slice(r.header);
            bytes.extend_from_slice(r.body);
        }
        bytes.extend_from_slice(&records[2].header[..3]);
        (&seg.file).write_all(&bytes).unwrap();
        let batch = seg.commit_batch(
            &records,
            bytes.len() as u64,
            Some(std::io::ErrorKind::StorageFull.into()),
        );

        assert!(matches!(batch.error, Some(QueueError::Io { .. })));
        assert_eq!(batch.offsets.len(), 2);
        assert_eq!(batch.offsets[0], committed_before);
        assert_eq!(batch.offsets[1], committed_before + records[0].len());
        let expected_len = committed_before + records[0].len() + records[1].len();
        assert_eq!(seg.len(), expected_len);
        assert_eq!(seg.next_ordinal(), 3);
        // The fragment must be gone from the file, not merely uncommitted.
        let path = seg.path().to_path_buf();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), expected_len);

        // The next append lands exactly at the committed tail, and the
        // segment still validates cleanly end to end.
        let next = seg.append(&record(3, b"after the tear")).unwrap();
        assert_eq!(next, expected_len);
        drop(seg);
        let v = validate_active_tail(&path, MAX_RECORD_LEN).unwrap();
        assert_eq!(v.records, 4);
        assert_eq!(v.truncated_bytes, 0);
    }

    #[test]
    fn failed_batch_write_commits_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let mut seg = ActiveSegment::create(dir.path(), 1).unwrap();
        seg.append(&record(0, b"already here")).unwrap();
        let committed_before = seg.len();

        let parts: Vec<_> = (1..3u32).map(|i| header_and_body(i, b"body")).collect();
        let batch = seg.commit_batch(
            &pending(&parts),
            0,
            Some(std::io::ErrorKind::StorageFull.into()),
        );
        assert!(batch.offsets.is_empty());
        assert!(batch.error.is_some());
        assert_eq!(seg.len(), committed_before);
        assert_eq!(seg.next_ordinal(), 1);
        assert_eq!(
            std::fs::metadata(seg.path()).unwrap().len(),
            committed_before
        );
    }

    /// A sink that takes at most `chunk` bytes per call and refuses more
    /// than `cap` in total, standing in for a short write.
    struct ChokedSink {
        taken: Vec<u8>,
        chunk: usize,
        cap: usize,
    }

    impl Write for ChokedSink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let room = self.cap.saturating_sub(self.taken.len());
            if room == 0 {
                return Err(std::io::ErrorKind::StorageFull.into());
            }
            let n = buf.len().min(self.chunk).min(room);
            self.taken.extend_from_slice(&buf[..n]);
            Ok(n)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn short_writes_are_retried_until_the_batch_lands() {
        let parts: Vec<_> = (0..3u32)
            .map(|i| header_and_body(i, format!("body {i}").as_bytes()))
            .collect();
        let records = pending(&parts);
        let total: u64 = records.iter().map(|r| r.len()).sum();
        let mut expected = Vec::new();
        for r in &records {
            expected.extend_from_slice(r.header);
            expected.extend_from_slice(r.body);
        }

        let mut slices: Vec<IoSlice<'_>> = records
            .iter()
            .flat_map(|r| [IoSlice::new(r.header), IoSlice::new(r.body)])
            .collect();
        let mut sink = ChokedSink {
            taken: Vec::new(),
            chunk: 7,
            cap: usize::MAX,
        };
        let (written, error) = write_all_vectored(&mut sink, &mut slices);
        assert!(error.is_none());
        assert_eq!(written, total);
        assert_eq!(sink.taken, expected);

        // A sink that stops early reports exactly what it took, which is
        // what tells commit_batch how much of the batch survived.
        let mut slices: Vec<IoSlice<'_>> = records
            .iter()
            .flat_map(|r| [IoSlice::new(r.header), IoSlice::new(r.body)])
            .collect();
        let cap = records[0].len() as usize + 5;
        let mut sink = ChokedSink {
            taken: Vec::new(),
            chunk: 7,
            cap,
        };
        let (written, error) = write_all_vectored(&mut sink, &mut slices);
        assert!(error.is_some());
        assert_eq!(written, cap as u64);
        assert_eq!(sink.taken, expected[..cap]);
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
