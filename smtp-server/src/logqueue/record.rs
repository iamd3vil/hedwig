//! Versioned, self-framing payload record encoding.
//!
//! Layout (all integers little-endian):
//!
//! ```text
//! offset  size  field
//!      0     4  magic ("HWLQ")
//!      4     2  format version
//!      6     2  flags (reserved, must be zero)
//!      8     4  record_len   — total record size: header_len + body_len
//!     12     4  header_len   — body starts at this offset within the record
//!     16     4  header_crc   — crc32 over [0..16) ++ [20..header_len)
//!     20     4  payload_crc  — crc32 over the body
//!     24    16  message id (binary ULID)
//!     40     8  enqueue timestamp, unix milliseconds (i64)
//!     48     4  relocation generation
//!     52     4  per-segment record ordinal
//!     56   var  envelope: sender_len u16, sender bytes,
//!                         rcpt_count u16, then per recipient u16 len + bytes
//!            …  body (record_len - header_len bytes)
//! ```
//!
//! The fixed header plus envelope is everything the dispatcher needs to
//! construct a job; it never has to read or decode the body. `record_len`
//! lets a scanner skip directly to the next record.

use super::{MessageId, QueueError, FORMAT_VERSION};

pub const MAGIC: [u8; 4] = *b"HWLQ";
/// Size of the fixed portion of the header, before the envelope.
pub const FIXED_HEADER_LEN: usize = 56;
/// Byte range covered by `header_crc`, part 1 (everything before the crc
/// fields) and the offset where part 2 (message id onward) begins.
const CRC_PART1_END: usize = 16;
const CRC_PART2_START: usize = 20;

/// Upper bound on encoded record size. `record_len` is a u32; keep a margin
/// below `u32::MAX` so arithmetic can never overflow.
pub const MAX_RECORD_LEN: u32 = u32::MAX - 4096;

/// The envelope and identity of a queued message, decoded from a record
/// header without touching the body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordHeader {
    pub message_id: MessageId,
    pub enqueue_ms: i64,
    pub generation: u32,
    pub ordinal: u32,
    pub sender: String,
    pub recipients: Vec<String>,
    pub record_len: u32,
    pub header_len: u32,
    pub payload_crc: u32,
}

impl RecordHeader {
    pub fn body_len(&self) -> u32 {
        self.record_len - self.header_len
    }
}

/// Why a header could not be decoded. `Incomplete` means the buffer ends
/// before the record does — expected at the tail of an active segment.
/// `Corrupt` means the bytes are wrong, not merely missing.
#[derive(Debug)]
pub enum DecodeError {
    /// More bytes are needed; `needed` is the total record prefix length
    /// required to make progress (from the start of the record).
    Incomplete { needed: usize },
    Corrupt(String),
    UnsupportedVersion(u16),
}

impl DecodeError {
    pub fn into_queue_error(self, offset: u64) -> QueueError {
        match self {
            DecodeError::Incomplete { needed } => QueueError::CorruptRecord {
                offset,
                reason: format!("record truncated: needs {needed} bytes"),
            },
            DecodeError::Corrupt(reason) => QueueError::CorruptRecord { offset, reason },
            DecodeError::UnsupportedVersion(found) => QueueError::UnsupportedVersion {
                found,
                supported: FORMAT_VERSION,
            },
        }
    }
}

/// Everything needed to encode a payload record.
pub struct RecordParams<'a> {
    pub message_id: MessageId,
    pub enqueue_ms: i64,
    pub generation: u32,
    pub ordinal: u32,
    pub sender: &'a str,
    pub recipients: &'a [String],
    pub body: &'a [u8],
}

/// Encoded size of a record, or an error if any field exceeds format limits.
pub fn encoded_len(params: &RecordParams<'_>) -> Result<u32, QueueError> {
    let header = header_len(params)?;
    let total = header as u64 + params.body.len() as u64;
    if total > MAX_RECORD_LEN as u64 {
        return Err(QueueError::RecordTooLarge {
            len: total,
            limit: MAX_RECORD_LEN as u64,
        });
    }
    Ok(total as u32)
}

fn header_len(params: &RecordParams<'_>) -> Result<u32, QueueError> {
    if params.sender.len() > u16::MAX as usize {
        return Err(QueueError::InvalidRecord(format!(
            "sender address is {} bytes, exceeds u16",
            params.sender.len()
        )));
    }
    if params.recipients.is_empty() {
        return Err(QueueError::InvalidRecord(
            "record must have at least one recipient".into(),
        ));
    }
    if params.recipients.len() > u16::MAX as usize {
        return Err(QueueError::InvalidRecord(format!(
            "{} recipients exceeds u16",
            params.recipients.len()
        )));
    }
    let mut len = FIXED_HEADER_LEN as u64 + 2 + params.sender.len() as u64 + 2;
    for rcpt in params.recipients {
        if rcpt.len() > u16::MAX as usize {
            return Err(QueueError::InvalidRecord(format!(
                "recipient address is {} bytes, exceeds u16",
                rcpt.len()
            )));
        }
        len += 2 + rcpt.len() as u64;
    }
    if len > MAX_RECORD_LEN as u64 {
        return Err(QueueError::RecordTooLarge {
            len,
            limit: MAX_RECORD_LEN as u64,
        });
    }
    Ok(len as u32)
}

/// Encode a complete record into a fresh buffer.
pub fn encode(params: &RecordParams<'_>) -> Result<Vec<u8>, QueueError> {
    let header_len = header_len(params)?;
    let record_len = encoded_len(params)?;

    let mut buf = Vec::with_capacity(record_len as usize);
    buf.extend_from_slice(&MAGIC);
    buf.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes()); // flags
    buf.extend_from_slice(&record_len.to_le_bytes());
    buf.extend_from_slice(&header_len.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes()); // header_crc placeholder
    buf.extend_from_slice(&crc32fast::hash(params.body).to_le_bytes());
    buf.extend_from_slice(&params.message_id.0);
    buf.extend_from_slice(&params.enqueue_ms.to_le_bytes());
    buf.extend_from_slice(&params.generation.to_le_bytes());
    buf.extend_from_slice(&params.ordinal.to_le_bytes());
    debug_assert_eq!(buf.len(), FIXED_HEADER_LEN);

    buf.extend_from_slice(&(params.sender.len() as u16).to_le_bytes());
    buf.extend_from_slice(params.sender.as_bytes());
    buf.extend_from_slice(&(params.recipients.len() as u16).to_le_bytes());
    for rcpt in params.recipients {
        buf.extend_from_slice(&(rcpt.len() as u16).to_le_bytes());
        buf.extend_from_slice(rcpt.as_bytes());
    }
    debug_assert_eq!(buf.len(), header_len as usize);

    let crc = header_crc(&buf, header_len as usize);
    buf[16..20].copy_from_slice(&crc.to_le_bytes());

    buf.extend_from_slice(params.body);
    debug_assert_eq!(buf.len(), record_len as usize);
    Ok(buf)
}

/// crc32 over the header with the `header_crc` field itself excluded.
fn header_crc(header: &[u8], header_len: usize) -> u32 {
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(&header[..CRC_PART1_END]);
    hasher.update(&header[CRC_PART2_START..header_len]);
    hasher.finalize()
}

fn read_u16(buf: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([buf[at], buf[at + 1]])
}

fn read_u32(buf: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(buf[at..at + 4].try_into().unwrap())
}

/// Decode a record header from `buf`, which starts at a record boundary.
/// `buf` may be shorter than the full record; only the header bytes are
/// required. `max_record_len` bounds `record_len` for sanity (a corrupt
/// length field must not drive huge reads).
pub fn decode_header(buf: &[u8], max_record_len: u32) -> Result<RecordHeader, DecodeError> {
    if buf.len() < FIXED_HEADER_LEN {
        return Err(DecodeError::Incomplete {
            needed: FIXED_HEADER_LEN,
        });
    }
    if buf[0..4] != MAGIC {
        return Err(DecodeError::Corrupt("bad magic".into()));
    }
    let version = read_u16(buf, 4);
    if version != FORMAT_VERSION {
        return Err(DecodeError::UnsupportedVersion(version));
    }
    let flags = read_u16(buf, 6);
    if flags != 0 {
        return Err(DecodeError::Corrupt(format!("unknown flags {flags:#06x}")));
    }
    let record_len = read_u32(buf, 8);
    let header_len = read_u32(buf, 12);
    if header_len < (FIXED_HEADER_LEN as u32 + 4)
        || header_len > record_len
        || record_len > max_record_len.min(MAX_RECORD_LEN)
    {
        return Err(DecodeError::Corrupt(format!(
            "implausible lengths: record_len={record_len} header_len={header_len}"
        )));
    }
    if buf.len() < header_len as usize {
        return Err(DecodeError::Incomplete {
            needed: header_len as usize,
        });
    }

    let stored_crc = read_u32(buf, 16);
    if header_crc(buf, header_len as usize) != stored_crc {
        return Err(DecodeError::Corrupt("header checksum mismatch".into()));
    }

    let payload_crc = read_u32(buf, 20);
    let mut id = [0u8; 16];
    id.copy_from_slice(&buf[24..40]);
    let enqueue_ms = i64::from_le_bytes(buf[40..48].try_into().unwrap());
    let generation = read_u32(buf, 48);
    let ordinal = read_u32(buf, 52);

    // Envelope. The header crc already validated these bytes, so length
    // errors here indicate an encoder bug rather than disk corruption, but
    // they are still reported as corruption instead of panicking.
    let end = header_len as usize;
    let mut at = FIXED_HEADER_LEN;
    let sender = take_str(buf, &mut at, end)?;
    if at + 2 > end {
        return Err(DecodeError::Corrupt("envelope overruns header".into()));
    }
    let rcpt_count = read_u16(buf, at) as usize;
    at += 2;
    if rcpt_count == 0 {
        return Err(DecodeError::Corrupt("record has no recipients".into()));
    }
    let mut recipients = Vec::with_capacity(rcpt_count);
    for _ in 0..rcpt_count {
        recipients.push(take_str(buf, &mut at, end)?);
    }
    if at != end {
        return Err(DecodeError::Corrupt(format!(
            "{} trailing bytes after envelope",
            end - at
        )));
    }

    Ok(RecordHeader {
        message_id: MessageId(id),
        enqueue_ms,
        generation,
        ordinal,
        sender,
        recipients,
        record_len,
        header_len,
        payload_crc,
    })
}

fn take_str(buf: &[u8], at: &mut usize, end: usize) -> Result<String, DecodeError> {
    if *at + 2 > end {
        return Err(DecodeError::Corrupt("envelope overruns header".into()));
    }
    let len = read_u16(buf, *at) as usize;
    *at += 2;
    if *at + len > end {
        return Err(DecodeError::Corrupt("envelope overruns header".into()));
    }
    let s = std::str::from_utf8(&buf[*at..*at + len])
        .map_err(|_| DecodeError::Corrupt("envelope field is not UTF-8".into()))?
        .to_owned();
    *at += len;
    Ok(s)
}

/// Verify a record body against the checksum recorded in its header.
pub fn verify_body(header: &RecordHeader, body: &[u8]) -> Result<(), QueueError> {
    if body.len() != header.body_len() as usize {
        return Err(QueueError::InvalidRecord(format!(
            "body length {} does not match header {}",
            body.len(),
            header.body_len()
        )));
    }
    if crc32fast::hash(body) != header.payload_crc {
        return Err(QueueError::InvalidRecord(
            "payload checksum mismatch".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params<'a>(body: &'a [u8], recipients: &'a [String]) -> RecordParams<'a> {
        RecordParams {
            message_id: MessageId::from_ulid(ulid::Ulid::from_parts(1234, 5678)),
            enqueue_ms: 1_752_000_000_000,
            generation: 0,
            ordinal: 7,
            sender: "sender@example.com",
            recipients,
            body,
        }
    }

    #[test]
    fn round_trip() {
        let rcpts = vec!["a@example.com".to_string(), "b@example.org".to_string()];
        let body = b"Subject: hi\r\n\r\nhello world";
        let p = params(body, &rcpts);
        let buf = encode(&p).unwrap();
        assert_eq!(buf.len() as u32, encoded_len(&p).unwrap());

        let h = decode_header(&buf, MAX_RECORD_LEN).unwrap();
        assert_eq!(h.message_id, p.message_id);
        assert_eq!(h.enqueue_ms, p.enqueue_ms);
        assert_eq!(h.ordinal, 7);
        assert_eq!(h.generation, 0);
        assert_eq!(h.sender, p.sender);
        assert_eq!(h.recipients, rcpts);
        assert_eq!(h.body_len() as usize, body.len());
        verify_body(&h, &buf[h.header_len as usize..]).unwrap();
    }

    #[test]
    fn empty_body_and_single_recipient() {
        let rcpts = vec!["a@example.com".to_string()];
        let p = params(b"", &rcpts);
        let buf = encode(&p).unwrap();
        let h = decode_header(&buf, MAX_RECORD_LEN).unwrap();
        assert_eq!(h.body_len(), 0);
        verify_body(&h, b"").unwrap();
    }

    #[test]
    fn rejects_zero_recipients() {
        let rcpts: Vec<String> = vec![];
        assert!(matches!(
            encode(&params(b"x", &rcpts)),
            Err(QueueError::InvalidRecord(_))
        ));
    }

    #[test]
    fn incomplete_fixed_header() {
        let rcpts = vec!["a@example.com".to_string()];
        let buf = encode(&params(b"body", &rcpts)).unwrap();
        for cut in [0, 1, FIXED_HEADER_LEN - 1] {
            match decode_header(&buf[..cut], MAX_RECORD_LEN) {
                Err(DecodeError::Incomplete { needed }) => {
                    assert_eq!(needed, FIXED_HEADER_LEN)
                }
                other => panic!("expected Incomplete, got {other:?}"),
            }
        }
    }

    #[test]
    fn incomplete_variable_header() {
        let rcpts = vec!["a@example.com".to_string()];
        let buf = encode(&params(b"body", &rcpts)).unwrap();
        let h = decode_header(&buf, MAX_RECORD_LEN).unwrap();
        match decode_header(&buf[..h.header_len as usize - 1], MAX_RECORD_LEN) {
            Err(DecodeError::Incomplete { needed }) => {
                assert_eq!(needed, h.header_len as usize)
            }
            other => panic!("expected Incomplete, got {other:?}"),
        }
    }

    #[test]
    fn corrupt_magic_and_version() {
        let rcpts = vec!["a@example.com".to_string()];
        let mut buf = encode(&params(b"body", &rcpts)).unwrap();
        buf[0] ^= 0xff;
        assert!(matches!(
            decode_header(&buf, MAX_RECORD_LEN),
            Err(DecodeError::Corrupt(_))
        ));
        buf[0] ^= 0xff;
        buf[4] = 0xfe;
        assert!(matches!(
            decode_header(&buf, MAX_RECORD_LEN),
            Err(DecodeError::UnsupportedVersion(_))
        ));
    }

    #[test]
    fn header_bitflips_are_detected() {
        let rcpts = vec!["a@example.com".to_string(), "b@example.com".to_string()];
        let clean = encode(&params(b"body", &rcpts)).unwrap();
        let header_len = decode_header(&clean, MAX_RECORD_LEN).unwrap().header_len as usize;
        // Flip one bit at every header position; every flip must be caught.
        for i in 0..header_len {
            let mut buf = clean.clone();
            buf[i] ^= 0x01;
            assert!(
                decode_header(&buf, MAX_RECORD_LEN).is_err(),
                "bit flip at byte {i} went undetected"
            );
        }
    }

    #[test]
    fn body_corruption_detected() {
        let rcpts = vec!["a@example.com".to_string()];
        let mut buf = encode(&params(b"body", &rcpts)).unwrap();
        let h = decode_header(&buf, MAX_RECORD_LEN).unwrap();
        let last = buf.len() - 1;
        buf[last] ^= 0x01;
        assert!(verify_body(&h, &buf[h.header_len as usize..]).is_err());
    }

    #[test]
    fn record_len_bound_enforced() {
        let rcpts = vec!["a@example.com".to_string()];
        let buf = encode(&params(&[0u8; 4096], &rcpts)).unwrap();
        // A cap below the actual record size must reject the header.
        assert!(matches!(
            decode_header(&buf, 128),
            Err(DecodeError::Corrupt(_))
        ));
    }

    #[test]
    fn large_body_round_trip() {
        let rcpts = vec!["a@example.com".to_string()];
        let body = vec![0xABu8; 25 * 1024 * 1024];
        let p = params(&body, &rcpts);
        let buf = encode(&p).unwrap();
        assert_eq!(buf.len() as u32, encoded_len(&p).unwrap());

        let h = decode_header(&buf, MAX_RECORD_LEN).unwrap();
        assert_eq!(h.body_len() as usize, body.len());
        verify_body(&h, &buf[h.header_len as usize..]).unwrap();
    }

    #[test]
    fn many_recipients_round_trip() {
        let rcpts: Vec<String> = (0..5000).map(|i| format!("user{i}@example.com")).collect();
        let body = b"hello world";
        let p = params(body, &rcpts);
        let buf = encode(&p).unwrap();

        let h = decode_header(&buf, MAX_RECORD_LEN).unwrap();
        assert_eq!(h.recipients.len(), 5000);
        assert_eq!(h.recipients, rcpts);
        verify_body(&h, &buf[h.header_len as usize..]).unwrap();
    }

    #[test]
    fn sender_and_recipient_length_limits() {
        let rcpts = vec!["a@example.com".to_string()];
        let long_sender = "a".repeat(u16::MAX as usize + 1);
        let mut p = params(b"body", &rcpts);
        p.sender = &long_sender;
        assert!(matches!(encode(&p), Err(QueueError::InvalidRecord(_))));

        let long_rcpts = vec!["a".repeat(u16::MAX as usize + 1)];
        let p2 = params(b"body", &long_rcpts);
        assert!(matches!(encode(&p2), Err(QueueError::InvalidRecord(_))));
    }

    #[test]
    fn enqueue_timestamp_and_generation_preserved() {
        let rcpts = vec!["a@example.com".to_string()];
        let mut p = params(b"body", &rcpts);
        p.enqueue_ms = -1_000_000_000_000; // well before the unix epoch
        p.generation = 42;
        let buf = encode(&p).unwrap();

        let h = decode_header(&buf, MAX_RECORD_LEN).unwrap();
        assert_eq!(h.enqueue_ms, p.enqueue_ms);
        assert_eq!(h.generation, 42);
    }
}
