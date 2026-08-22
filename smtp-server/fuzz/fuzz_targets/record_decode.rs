//! Coverage-guided fuzzing of the payload-record header decoder: arbitrary
//! bytes must never panic, and any successful decode must satisfy the
//! format's own invariants and be re-encodable to the identical header.

#![no_main]

use hedwig::logqueue::record::{self, RecordParams, FIXED_HEADER_LEN, MAX_RECORD_LEN};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Exercise both the absolute bound and a tight caller-supplied bound.
    for max_len in [MAX_RECORD_LEN, 4096] {
        let Ok(h) = record::decode_header(data, max_len) else {
            continue;
        };
        // Internal consistency of anything the decoder accepts.
        assert!(h.record_len <= max_len);
        assert!(h.header_len <= h.record_len);
        assert!(h.header_len as usize >= FIXED_HEADER_LEN + 4);
        assert!(!h.recipients.is_empty());
        assert_eq!(h.body_len(), h.record_len - h.header_len);

        // Encoder/decoder agreement: the decoded envelope must be
        // re-encodable, and decoding the re-encoding must give back the
        // same fields with the same header length. (The body bytes are not
        // part of the input here, so payload_crc is not compared.)
        let body_len = h.body_len() as usize;
        if body_len <= 4096 {
            let body = vec![0u8; body_len];
            let re = record::encode(&RecordParams {
                message_id: h.message_id,
                enqueue_ms: h.enqueue_ms,
                generation: h.generation,
                ordinal: h.ordinal,
                sender: &h.sender,
                recipients: &h.recipients,
                body: &body,
            })
            .expect("decoded header must be re-encodable");
            let h2 = record::decode_header(&re, MAX_RECORD_LEN)
                .expect("re-encoded record must decode");
            assert_eq!(h2.message_id, h.message_id);
            assert_eq!(h2.enqueue_ms, h.enqueue_ms);
            assert_eq!(h2.generation, h.generation);
            assert_eq!(h2.ordinal, h.ordinal);
            assert_eq!(h2.sender, h.sender);
            assert_eq!(h2.recipients, h.recipients);
            assert_eq!(h2.header_len, h.header_len);
            assert_eq!(h2.record_len, h.record_len);
        }

        // If the full record is present, body verification must not panic.
        if data.len() >= h.record_len as usize {
            let _ = record::verify_body(&h, &data[h.header_len as usize..h.record_len as usize]);
        }
    }
});
