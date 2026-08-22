//! Fuzz active-segment tail validation with an arbitrary file image: it
//! must never panic or error, must be idempotent, and the surviving prefix
//! must scan cleanly with sequential ordinals and verified bodies.

#![no_main]

use hedwig::logqueue::record::MAX_RECORD_LEN;
use hedwig::logqueue::segment::{scan_headers, validate_active_tail, SegmentReader};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("segment-000000000001.open");
    std::fs::write(&path, data).unwrap();

    let v = validate_active_tail(&path, MAX_RECORD_LEN).expect("tail validation must not error");
    assert!(v.committed_len <= data.len() as u64);
    assert_eq!(v.committed_len + v.truncated_bytes, data.len() as u64);
    assert_eq!(std::fs::metadata(&path).unwrap().len(), v.committed_len);
    assert_eq!(v.next_ordinal, v.records);

    // Idempotent: a second pass finds a fully clean file.
    let v2 = validate_active_tail(&path, MAX_RECORD_LEN).unwrap();
    assert_eq!(v2.committed_len, v.committed_len);
    assert_eq!(v2.records, v.records);
    assert_eq!(v2.truncated_bytes, 0);

    // The committed prefix scans as perfect records with dense offsets and
    // sequential ordinals.
    let reader = SegmentReader::open(&path).unwrap();
    let mut next_ordinal = 0u32;
    let mut expected_offset = 0u64;
    let end = scan_headers(&reader, 0, v.committed_len, MAX_RECORD_LEN, |off, h| {
        assert_eq!(off, expected_offset, "hole between records");
        assert_eq!(h.ordinal, next_ordinal, "ordinal gap survived validation");
        reader.read_body(&h, off).expect("committed body must verify");
        expected_offset = off + h.record_len as u64;
        next_ordinal += 1;
        true
    })
    .expect("committed prefix must scan cleanly");
    assert_eq!(end, v.committed_len);
    assert_eq!(next_ordinal, v.records);
});
