//! Structure-aware round-trip fuzzing of the record encoder: any params the
//! encoder accepts must decode back bit-identically, and any rejection must
//! be for a documented limit.

#![no_main]

use arbitrary::Arbitrary;
use hedwig::logqueue::record::{self, RecordParams, MAX_RECORD_LEN};
use hedwig::logqueue::{MessageId, QueueError};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct Input {
    id: [u8; 16],
    enqueue_ms: i64,
    generation: u32,
    ordinal: u32,
    sender: String,
    recipients: Vec<String>,
    body: Vec<u8>,
}

fuzz_target!(|input: Input| {
    let params = RecordParams {
        message_id: MessageId(input.id),
        enqueue_ms: input.enqueue_ms,
        generation: input.generation,
        ordinal: input.ordinal,
        sender: &input.sender,
        recipients: &input.recipients,
        body: &input.body,
    };
    match record::encode(&params) {
        Ok(buf) => {
            assert_eq!(buf.len() as u32, record::encoded_len(&params).unwrap());
            let h = record::decode_header(&buf, MAX_RECORD_LEN)
                .expect("encoder output must decode");
            assert_eq!(h.message_id, params.message_id);
            assert_eq!(h.enqueue_ms, params.enqueue_ms);
            assert_eq!(h.generation, params.generation);
            assert_eq!(h.ordinal, params.ordinal);
            assert_eq!(h.sender, input.sender);
            assert_eq!(h.recipients, input.recipients);
            assert_eq!(h.body_len() as usize, input.body.len());
            record::verify_body(&h, &buf[h.header_len as usize..])
                .expect("encoder output body must verify");

            // Every strict prefix must decode as Incomplete or the full
            // header — never as corrupt (a scanner mid-write must be able
            // to tell "not yet" from "broken").
            for cut in [0, 1, buf.len().saturating_sub(1)] {
                match record::decode_header(&buf[..cut.min(h.header_len as usize)], MAX_RECORD_LEN)
                {
                    Ok(_) | Err(record::DecodeError::Incomplete { .. }) => {}
                    Err(e) => panic!("prefix of a valid record decoded as corrupt: {e:?}"),
                }
            }
        }
        Err(QueueError::InvalidRecord(_)) => {
            // Legal only for: empty recipients, or a field over u16::MAX.
            let field_too_long = input.sender.len() > u16::MAX as usize
                || input.recipients.len() > u16::MAX as usize
                || input.recipients.iter().any(|r| r.len() > u16::MAX as usize);
            assert!(
                input.recipients.is_empty() || field_too_long,
                "encoder rejected legal params: {input:?}"
            );
        }
        Err(QueueError::RecordTooLarge { .. }) => {}
        Err(e) => panic!("unexpected encoder error: {e}"),
    }
});
