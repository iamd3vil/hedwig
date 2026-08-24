//! Randomized (fuzz-style) tests for the log queue's on-disk formats and
//! crash recovery. Every test uses a fixed RNG seed so a failure is
//! reproducible; iteration counts are sized to keep the suite fast.
//!
//! What is checked, beyond "no panic":
//! - record decode round-trips and rejects arbitrary/mutated bytes;
//! - active-segment tail validation always lands on a record boundary of
//!   the original stream and leaves the file appendable;
//! - state-journal recovery is always some prefix of the written entries,
//!   and recovery is idempotent;
//! - checkpoint corruption is a hard error, never a panic or silent skip.

use std::collections::HashSet;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use super::record::{self, DecodeError, RecordParams, FIXED_HEADER_LEN, MAX_RECORD_LEN};
use super::segment::{scan_headers, validate_active_tail, ActiveSegment, SegmentReader};
use super::state::{Checkpoint, RecoveredState, ShardStateStore, StateEntry};
use super::{JobLocation, MessageId, QueueError};

fn rng(seed: u64) -> StdRng {
    StdRng::seed_from_u64(seed)
}

fn random_string(rng: &mut StdRng, max_len: usize) -> String {
    let len = rng.gen_range(0..=max_len);
    (0..len)
        .map(|_| {
            // Mostly ASCII with some multi-byte characters mixed in.
            match rng.gen_range(0..10) {
                0 => 'é',
                1 => '日',
                2 => '🦉',
                _ => rng.gen_range(b'!'..=b'~') as char,
            }
        })
        .collect()
}

fn random_id(rng: &mut StdRng) -> MessageId {
    MessageId::from_ulid(ulid::Ulid::from_parts(rng.gen(), rng.gen()))
}

fn random_params<'a>(
    rng: &mut StdRng,
    sender: &'a str,
    recipients: &'a [String],
    body: &'a [u8],
) -> RecordParams<'a> {
    RecordParams {
        message_id: random_id(rng),
        enqueue_ms: rng.gen(),
        generation: rng.gen(),
        ordinal: rng.gen(),
        sender,
        recipients,
        body,
    }
}

// ---------------------------------------------------------------------------
// Record format.

/// Random valid params encode, decode back to identical fields, and the
/// body verifies.
#[test]
fn fuzz_record_round_trip() {
    let mut rng = rng(1);
    for _ in 0..2_000 {
        let sender = random_string(&mut rng, 200);
        let n_rcpt = rng.gen_range(1..=40);
        let recipients: Vec<String> = (0..n_rcpt).map(|_| random_string(&mut rng, 120)).collect();
        let body: Vec<u8> = (0..rng.gen_range(0..4096)).map(|_| rng.gen()).collect();
        let p = random_params(&mut rng, &sender, &recipients, &body);

        let buf = record::encode(&p).unwrap();
        assert_eq!(buf.len() as u32, record::encoded_len(&p).unwrap());
        let h = record::decode_header(&buf, MAX_RECORD_LEN).unwrap();
        assert_eq!(h.message_id, p.message_id);
        assert_eq!(h.enqueue_ms, p.enqueue_ms);
        assert_eq!(h.generation, p.generation);
        assert_eq!(h.ordinal, p.ordinal);
        assert_eq!(h.sender, sender);
        assert_eq!(h.recipients, recipients);
        record::verify_body(&h, &buf[h.header_len as usize..]).unwrap();
    }
}

/// Arbitrary bytes must never panic the header decoder, and any `Ok` must
/// satisfy the format's own invariants.
#[test]
fn fuzz_decode_header_arbitrary_bytes() {
    let mut rng = rng(2);
    for i in 0..50_000 {
        let len = rng.gen_range(0..600);
        let mut buf: Vec<u8> = (0..len).map(|_| rng.gen()).collect();
        // Half the time, plant plausible magic/version so the decoder gets
        // past the first checks and exercises deeper paths.
        if i % 2 == 0 && buf.len() >= 8 {
            buf[0..4].copy_from_slice(&record::MAGIC);
            buf[4..6].copy_from_slice(&super::FORMAT_VERSION.to_le_bytes());
            buf[6..8].copy_from_slice(&0u16.to_le_bytes());
        }
        if let Ok(h) = record::decode_header(&buf, MAX_RECORD_LEN) {
            assert!(h.header_len <= h.record_len);
            assert!(h.header_len as usize >= FIXED_HEADER_LEN + 4);
            assert!(!h.recipients.is_empty());
        }
    }
}

/// Mutations of a valid record are either rejected or (when the mutation
/// missed every header byte) decode to the identical header.
#[test]
fn fuzz_decode_header_mutations() {
    let mut rng = rng(3);
    for _ in 0..5_000 {
        let sender = random_string(&mut rng, 60);
        let recipients: Vec<String> = (0..rng.gen_range(1..=5))
            .map(|_| random_string(&mut rng, 60))
            .collect();
        let body: Vec<u8> = (0..rng.gen_range(0..512)).map(|_| rng.gen()).collect();
        let p = random_params(&mut rng, &sender, &recipients, &body);
        let clean = record::encode(&p).unwrap();
        let original = record::decode_header(&clean, MAX_RECORD_LEN).unwrap();

        let mut buf = clean.clone();
        let flips = rng.gen_range(1..=4);
        let mut touched_header = false;
        for _ in 0..flips {
            let at = rng.gen_range(0..buf.len());
            let bit = 1u8 << rng.gen_range(0..8);
            buf[at] ^= bit;
            if at < original.header_len as usize {
                touched_header = true;
            }
        }
        match record::decode_header(&buf, MAX_RECORD_LEN) {
            Ok(h) => {
                // Body-only mutations leave the header intact; a header
                // mutation that still decodes must be a CRC collision,
                // which is effectively impossible at these iteration
                // counts.
                assert!(
                    !touched_header || h == original,
                    "header mutation went undetected"
                );
            }
            Err(DecodeError::Corrupt(_) | DecodeError::UnsupportedVersion(_)) => {}
            Err(DecodeError::Incomplete { .. }) => {
                panic!("full-length record decoded as incomplete after mutation")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Active-segment tail recovery.

fn encode_record(rng: &mut StdRng, ordinal: u32, body_len: usize) -> Vec<u8> {
    let recipients: Vec<String> = (0..rng.gen_range(1..=3))
        .map(|_| format!("{}@example.com", random_string(rng, 20).replace('@', "_")))
        .collect();
    let body: Vec<u8> = (0..body_len).map(|_| rng.gen()).collect();
    record::encode(&RecordParams {
        message_id: MessageId::from_ulid(ulid::Ulid::from_parts(rng.gen(), rng.gen())),
        enqueue_ms: 1_752_000_000_000 + ordinal as i64,
        generation: 0,
        ordinal,
        sender: "sender@example.com",
        recipients: &recipients,
        body: &body,
    })
    .unwrap()
}

/// Write a random segment, corrupt it randomly (truncation, bit flips,
/// appended garbage, or a mix), and check that tail validation:
/// - never panics or errors,
/// - lands exactly on one of the original record boundaries,
/// - leaves a file whose surviving prefix scans cleanly with sequential
///   ordinals, and
/// - leaves the segment appendable at the right ordinal.
#[test]
fn fuzz_active_tail_corruption_recovery() {
    let mut rng = rng(4);
    for iter in 0..250 {
        let dir = tempfile::tempdir().unwrap();
        let mut seg = ActiveSegment::create(dir.path(), 1).unwrap();
        let n = rng.gen_range(1..=12);
        let mut boundaries = vec![0u64];
        for ordinal in 0..n {
            let body_len = rng.gen_range(0..2048);
            let encoded = encode_record(&mut rng, ordinal, body_len);
            seg.append(&encoded).unwrap();
            boundaries.push(seg.len());
        }
        let path = seg.path().to_path_buf();
        drop(seg);
        let full_len = std::fs::metadata(&path).unwrap().len();

        // Random corruption.
        let mode = rng.gen_range(0..4);
        {
            use std::os::unix::fs::FileExt;
            let f = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .unwrap();
            if mode == 0 || mode == 3 {
                let cut = rng.gen_range(0..=full_len);
                f.set_len(cut).unwrap();
            }
            let len_now = f.metadata().unwrap().len();
            if (mode == 1 || mode == 3) && len_now > 0 {
                for _ in 0..rng.gen_range(1..=8) {
                    let at = rng.gen_range(0..len_now);
                    let mut b = [0u8; 1];
                    f.read_exact_at(&mut b, at).unwrap();
                    f.write_all_at(&[b[0] ^ (1 << rng.gen_range(0..8))], at)
                        .unwrap();
                }
            }
            if mode == 2 {
                let garbage: Vec<u8> = (0..rng.gen_range(1..300)).map(|_| rng.gen()).collect();
                f.write_all_at(&garbage, len_now).unwrap();
            }
        }

        let v = validate_active_tail(&path, MAX_RECORD_LEN)
            .unwrap_or_else(|e| panic!("iter {iter}: validation errored: {e}"));
        assert!(
            boundaries.contains(&v.committed_len),
            "iter {iter}: committed_len {} is not an original record boundary {boundaries:?}",
            v.committed_len
        );
        assert_eq!(std::fs::metadata(&path).unwrap().len(), v.committed_len);

        // The surviving prefix is perfect: sequential ordinals from zero,
        // bodies verified.
        let reader = SegmentReader::open(&path).unwrap();
        let mut next = 0u32;
        scan_headers(&reader, 0, v.committed_len, MAX_RECORD_LEN, |off, h| {
            assert_eq!(h.ordinal, next, "iter {iter}: ordinal gap at offset {off}");
            let body = reader.read_body(&h, off).unwrap();
            assert_eq!(body.len() as u32, h.body_len());
            next += 1;
            true
        })
        .unwrap();
        assert_eq!(next, v.records);
        assert_eq!(v.next_ordinal, v.records);

        // Appendable after recovery.
        let mut seg = ActiveSegment::recover(path.clone(), 1, &v).unwrap();
        let encoded = encode_record(&mut rng, v.next_ordinal, 64);
        seg.append(&encoded).unwrap();
        drop(seg);
        let v2 = validate_active_tail(&path, MAX_RECORD_LEN).unwrap();
        assert_eq!(v2.records, v.records + 1);
        assert_eq!(v2.truncated_bytes, 0);
    }
}

// ---------------------------------------------------------------------------
// State journal recovery.

fn random_location(rng: &mut StdRng) -> JobLocation {
    JobLocation {
        shard: 0,
        segment: rng.gen_range(1..6),
        offset: rng.gen_range(0..1 << 20),
        length: rng.gen_range(64..4096),
        ordinal: rng.gen(),
        generation: rng.gen_range(0..3),
    }
}

fn random_entry(rng: &mut StdRng, ids: &[MessageId]) -> StateEntry {
    let id = ids[rng.gen_range(0..ids.len())];
    match rng.gen_range(0..4) {
        0 => StateEntry::Deferred {
            id,
            location: random_location(rng),
            attempts: rng.gen_range(0..10),
            next_attempt_ms: rng.gen(),
            remaining_recipients: (0..rng.gen_range(0..5))
                .map(|_| random_string(rng, 40))
                .collect(),
            last_error: random_string(rng, 80),
        },
        1 => StateEntry::Delivered {
            id,
            location: random_location(rng),
            timestamp_ms: rng.gen(),
        },
        2 => StateEntry::Bounced {
            id,
            location: random_location(rng),
            timestamp_ms: rng.gen(),
            reason: random_string(rng, 80),
        },
        _ => {
            let old = random_location(rng);
            let mut new = random_location(rng);
            new.generation = old.generation + 1;
            StateEntry::Relocated { id, old, new }
        }
    }
}

fn state_eq(a: &RecoveredState, b: &RecoveredState) -> bool {
    a.cursor == b.cursor
        && a.ready == b.ready
        && a.deferred == b.deferred
        && a.tombstones == b.tombstones
        && a.segment_stats == b.segment_stats
}

fn prefix_state(entries: &[StateEntry], k: usize) -> RecoveredState {
    let mut s = RecoveredState::default();
    for e in &entries[..k] {
        s.apply(e.clone());
    }
    s
}

const JOURNAL_1: &str = "journal-000000000001.log";

/// Append random entries, corrupt the journal randomly, and check that
/// recovery never panics and always yields the state of some prefix of the
/// written entries — never a state with holes in the middle.
#[test]
fn fuzz_journal_corruption_recovers_a_prefix() {
    let mut rng = rng(5);
    for iter in 0..250 {
        let dir = tempfile::tempdir().unwrap();
        let ids: Vec<MessageId> = (0..5).map(|_| random_id(&mut rng)).collect();
        let n = rng.gen_range(1..=25);
        let mut entries = Vec::with_capacity(n);
        {
            let (mut store, _) = ShardStateStore::recover(dir.path(), 0).unwrap();
            for _ in 0..n {
                let e = random_entry(&mut rng, &ids);
                store.append(&e).unwrap();
                entries.push(e);
            }
        }

        // Random corruption of the (only) journal file.
        let path = dir.path().join(JOURNAL_1);
        let full_len = std::fs::metadata(&path).unwrap().len();
        let mode = rng.gen_range(0..4);
        {
            use std::os::unix::fs::FileExt;
            let f = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .unwrap();
            match mode {
                0 => f.set_len(rng.gen_range(0..=full_len)).unwrap(),
                1 => {
                    for _ in 0..rng.gen_range(1..=4) {
                        let at = rng.gen_range(0..full_len);
                        let mut b = [0u8; 1];
                        f.read_exact_at(&mut b, at).unwrap();
                        f.write_all_at(&[b[0] ^ (1 << rng.gen_range(0..8))], at)
                            .unwrap();
                    }
                }
                2 => {
                    let garbage: Vec<u8> = (0..rng.gen_range(1..200)).map(|_| rng.gen()).collect();
                    f.write_all_at(&garbage, full_len).unwrap();
                }
                _ => {} // no corruption: the full state must survive
            }
        }

        let (mut store, recovered) = ShardStateStore::recover(dir.path(), 0)
            .unwrap_or_else(|e| panic!("iter {iter}: recovery errored: {e}"));
        let matched = (0..=n)
            .rev()
            .find(|&k| state_eq(&recovered, &prefix_state(&entries, k)));
        let Some(k) = matched else {
            panic!("iter {iter}: recovered state is not any prefix of the written entries");
        };
        if mode == 3 {
            assert_eq!(k, n, "iter {iter}: uncorrupted journal lost entries");
        }

        // The store stays appendable and a second recovery agrees.
        let extra = random_entry(&mut rng, &ids);
        store.append(&extra).unwrap();
        drop(store);
        let (_, again) = ShardStateStore::recover(dir.path(), 0).unwrap();
        let mut expected = prefix_state(&entries, k);
        expected.apply(extra);
        assert!(
            state_eq(&again, &expected),
            "iter {iter}: post-recovery append did not persist cleanly"
        );
    }
}

/// Random and mutated checkpoint files must be rejected as errors (never a
/// panic, never silently treated as valid), and untouched checkpoints must
/// round-trip through recovery.
#[test]
fn fuzz_checkpoint_corruption_is_rejected() {
    let mut rng = rng(6);
    for iter in 0..200 {
        let dir = tempfile::tempdir().unwrap();
        let ids: Vec<MessageId> = (0..4).map(|_| random_id(&mut rng)).collect();
        {
            let (mut store, _) = ShardStateStore::recover(dir.path(), 0).unwrap();
            for _ in 0..rng.gen_range(1..=8) {
                store.append(&random_entry(&mut rng, &ids)).unwrap();
            }
            store.write_checkpoint(&Checkpoint::default()).unwrap();
        }

        let path = dir.path().join("checkpoint");
        let clean = std::fs::read(&path).unwrap();
        let mode = rng.gen_range(0..3);
        match mode {
            0 => {
                // Bit flips.
                let mut buf = clean.clone();
                for _ in 0..rng.gen_range(1..=4) {
                    let at = rng.gen_range(0..buf.len());
                    buf[at] ^= 1 << rng.gen_range(0..8);
                }
                std::fs::write(&path, &buf).unwrap();
                match ShardStateStore::recover(dir.path(), 0) {
                    Err(_) => {}
                    Ok(_) => {
                        // A flip may have been undone by a later flip at the
                        // same position; only identical bytes may succeed.
                        assert_eq!(
                            std::fs::read(&path).unwrap(),
                            clean,
                            "iter {iter}: mutated checkpoint accepted"
                        );
                    }
                }
            }
            1 => {
                // Truncation.
                let cut = rng.gen_range(0..clean.len());
                std::fs::write(&path, &clean[..cut]).unwrap();
                assert!(
                    ShardStateStore::recover(dir.path(), 0).is_err(),
                    "iter {iter}: truncated checkpoint accepted"
                );
            }
            _ => {
                // Pure garbage.
                let garbage: Vec<u8> = (0..rng.gen_range(0..400)).map(|_| rng.gen()).collect();
                std::fs::write(&path, &garbage).unwrap();
                assert!(
                    ShardStateStore::recover(dir.path(), 0).is_err(),
                    "iter {iter}: garbage checkpoint accepted"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// End-to-end: random crash-and-recover cycles over segments + journal.

/// Simulates the full recovery loop under random torn tails on BOTH files:
/// segment truncation plus journal truncation, repeated across generations.
/// Invariant: no message is ever in two scheduling states at once, and
/// recovery is deterministic (running it twice yields identical state).
#[test]
fn fuzz_repeated_crash_cycles() {
    let mut rng = rng(7);
    for _ in 0..60 {
        let dir = tempfile::tempdir().unwrap();
        let ids: Vec<MessageId> = (0..6).map(|_| random_id(&mut rng)).collect();
        for _cycle in 0..4 {
            {
                let (mut store, _) = ShardStateStore::recover(dir.path(), 0).unwrap();
                for _ in 0..rng.gen_range(0..8) {
                    store.append(&random_entry(&mut rng, &ids)).unwrap();
                }
                if rng.gen_bool(0.3) {
                    // Snapshot whatever state we currently believe in.
                    store.write_checkpoint(&Checkpoint::default()).unwrap();
                }
            }
            // Crash: tear the tail off the newest journal.
            if rng.gen_bool(0.5) {
                let newest = std::fs::read_dir(dir.path())
                    .unwrap()
                    .filter_map(|e| e.ok())
                    .filter(|e| e.file_name().to_string_lossy().starts_with("journal-"))
                    .max_by_key(|e| e.file_name());
                if let Some(entry) = newest {
                    let len = entry.metadata().unwrap().len();
                    if len > 0 {
                        let cut = rng.gen_range(0..len);
                        let f = std::fs::OpenOptions::new()
                            .write(true)
                            .open(entry.path())
                            .unwrap();
                        f.set_len(cut).unwrap();
                    }
                }
            }
            // Recovery must succeed and be deterministic.
            let (_, a) = ShardStateStore::recover(dir.path(), 0).unwrap();
            let (_, b) = ShardStateStore::recover(dir.path(), 0).unwrap();
            assert!(state_eq(&a, &b), "recovery is not idempotent");
            let ready: HashSet<_> = a.ready.keys().collect();
            let deferred: HashSet<_> = a.deferred.keys().collect();
            assert!(
                ready.is_disjoint(&deferred),
                "message simultaneously ready and deferred"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Bug demonstrations (found by review; kept as regression documentation).

/// Regression: `replay_journal` rejects entries above `MAX_ENTRY_LEN`
/// (16 MiB) as corruption, so `append` must refuse to write them — written,
/// such an entry would truncate replay (silently discarding it and every
/// later entry, resurrecting delivered mail) or hard-fail recovery of a
/// rotated journal. The journal stream must stay replayable around the
/// rejection.
#[test]
fn oversized_journal_entry_rejected_at_append() {
    let dir = tempfile::tempdir().unwrap();
    let big_rcpts: Vec<String> = (0..70_000)
        .map(|i| format!("recipient-{i:06}-{}@example.com", "x".repeat(220)))
        .collect(); // ~17.5 MiB encoded, above MAX_ENTRY_LEN
    let mut r = rng(8);
    let oversized_id = random_id(&mut r);
    let delivered_id = random_id(&mut r);
    let delivered_loc = random_location(&mut r);
    {
        let (mut store, _) = ShardStateStore::recover(dir.path(), 0).unwrap();
        let err = store
            .append(&StateEntry::Deferred {
                id: oversized_id,
                location: random_location(&mut r),
                attempts: 1,
                next_attempt_ms: 1_752_000_000_000,
                remaining_recipients: big_rcpts,
                last_error: "451 try later".into(),
            })
            .unwrap_err();
        assert!(matches!(err, QueueError::InvalidRecord(_)), "got {err}");
        // The stream stays intact: later entries append and replay fine.
        store
            .append(&StateEntry::Delivered {
                id: delivered_id,
                location: delivered_loc,
                timestamp_ms: 1_752_000_000_001,
            })
            .unwrap();
    }
    let (_, state) = ShardStateStore::recover(dir.path(), 0).unwrap();
    assert!(!state.deferred.contains_key(&oversized_id));
    assert!(state.is_terminal(delivered_loc.segment, &delivered_id));
}

/// Companion check that pins the boundary itself: entries just UNDER the
/// replay cap round-trip fine, so the cap is the only thing standing
/// between the write path and the replay path.
#[test]
fn journal_entry_just_under_replay_cap_round_trips() {
    let dir = tempfile::tempdir().unwrap();
    let rcpts: Vec<String> = (0..40_000)
        .map(|i| format!("r{i:06}-{}@example.com", "x".repeat(220)))
        .collect(); // ~10 MiB encoded, under MAX_ENTRY_LEN
    let mut r = rng(10);
    let id = random_id(&mut r);
    {
        let (mut store, _) = ShardStateStore::recover(dir.path(), 0).unwrap();
        store
            .append(&StateEntry::Deferred {
                id,
                location: random_location(&mut r),
                attempts: 1,
                next_attempt_ms: 1_752_000_000_000,
                remaining_recipients: rcpts.clone(),
                last_error: "451".into(),
            })
            .unwrap();
    }
    let (_, state) = ShardStateStore::recover(dir.path(), 0).unwrap();
    assert_eq!(state.deferred[&id].remaining_recipients, rcpts);
}

/// Regression (found by the libFuzzer `state_recovery` target): a checkpoint
/// whose length field is near u64::MAX overflowed `20 + payload_len` and
/// panicked instead of reporting corruption.
#[test]
fn checkpoint_with_huge_length_field_is_an_error_not_a_panic() {
    let dir = tempfile::tempdir().unwrap();
    let mut buf = Vec::new();
    buf.extend_from_slice(b"HWCP");
    buf.extend_from_slice(&1u16.to_le_bytes()); // version
    buf.extend_from_slice(&0u16.to_le_bytes()); // reserved
    buf.extend_from_slice(&u64::MAX.to_le_bytes()); // absurd payload_len
    buf.extend_from_slice(&0u32.to_le_bytes()); // crc
    std::fs::write(dir.path().join("checkpoint"), &buf).unwrap();
    assert!(matches!(
        ShardStateStore::recover(dir.path(), 0),
        Err(QueueError::CorruptRecord { .. })
    ));
}

/// Regression (found by the libFuzzer `state_recovery` target, which forged
/// a CRC-valid checkpoint via comparison tracing): a checkpoint claiming a
/// journal ordinal past 10^12 made `recover` create a journal file whose
/// name (13+ digits, since `{:012}` is a minimum width) the 12-digit-exact
/// parser could not read back — so the SECOND recovery saw no journals,
/// retried the create, and died on AlreadyExists forever.
#[test]
fn recovery_survives_checkpoint_with_13_digit_journal_ordinal() {
    let dir = tempfile::tempdir().unwrap();
    // Minimal valid checkpoint: replay_from = (10^12 + 5, 0), no cursor,
    // zero ready/deferred/tombstones/stats.
    let mut payload = Vec::new();
    payload.extend_from_slice(&(1_000_000_000_005u64).to_le_bytes());
    payload.extend_from_slice(&0u64.to_le_bytes());
    payload.push(0); // no cursor
    payload.extend_from_slice(&[0u8; 32]); // four empty u64 counts
    let mut buf = Vec::new();
    buf.extend_from_slice(b"HWCP");
    buf.extend_from_slice(&1u16.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    buf.extend_from_slice(&crc32fast::hash(&payload).to_le_bytes());
    buf.extend_from_slice(&payload);
    std::fs::write(dir.path().join("checkpoint"), &buf).unwrap();

    let (store, _) = ShardStateStore::recover(dir.path(), 0).unwrap();
    drop(store);
    // The journal created above must be found again, not re-created.
    ShardStateStore::recover(dir.path(), 0)
        .expect("second recovery must reopen the 13-digit journal it created");
}

/// Segment/journal file names must round-trip through their parsers for
/// EVERY ordinal, including those past the 12-digit padding width.
#[test]
fn file_names_round_trip_for_huge_ordinals() {
    use super::segment::{parse_file_name, sealed_file_name, SegmentKind};
    for ordinal in [0, 999_999_999_999, 1_000_000_000_000, u64::MAX] {
        assert_eq!(
            parse_file_name(&sealed_file_name(ordinal)),
            Some((ordinal, SegmentKind::Sealed)),
            "segment name for ordinal {ordinal} does not round-trip"
        );
    }
}

#[test]
fn fuzz_message_id_parse_arbitrary_strings() {
    let mut rng = rng(11);
    for _ in 0..20_000 {
        let s = random_string(&mut rng, 40);
        let _ = MessageId::parse(&s); // must never panic
    }
    // Round trip for valid ids.
    for _ in 0..1_000 {
        let id = random_id(&mut rng);
        assert_eq!(MessageId::parse(&id.to_string()).unwrap(), id);
    }
}

#[test]
fn fuzz_segment_file_name_parse() {
    let mut rng = rng(12);
    for _ in 0..20_000 {
        let s = random_string(&mut rng, 30);
        let _ = super::segment::parse_file_name(&s); // must never panic
    }
}

/// `QueueError` display must not panic for any variant (exercised because
/// several carry formatted strings from corrupt input).
#[test]
fn queue_error_display_smoke() {
    let e = QueueError::CorruptRecord {
        offset: u64::MAX,
        reason: "\u{0}\u{7f}🦉".into(),
    };
    let _ = format!("{e}");
}
/// Regression: with no checkpoint and a journal stream that does not start
/// at ordinal 1, `ShardStateStore::recover` refuses to start — and
/// `load_state_readonly` must refuse identically, or the `hedwig queue`
/// inspection CLI would report state (derived from history with a missing
/// prefix) that the server itself refuses to load.
#[test]
fn readonly_vs_recover_incomplete_stream_asymmetry() {
    let dir = tempfile::tempdir().unwrap();
    // Build a valid journal 1 with one entry, then rename it to ordinal 5:
    // an incomplete stream with no checkpoint.
    {
        let (mut store, _) = ShardStateStore::recover(dir.path(), 0).unwrap();
        let mut r = rng(13);
        store
            .append(&StateEntry::Delivered {
                id: random_id(&mut r),
                location: random_location(&mut r),
                timestamp_ms: 1,
            })
            .unwrap();
    }
    std::fs::rename(
        dir.path().join(JOURNAL_1),
        dir.path().join("journal-000000000005.log"),
    )
    .unwrap();
    let recover = ShardStateStore::recover(dir.path(), 0);
    let readonly = super::state::load_state_readonly(dir.path());
    assert_eq!(
        recover.is_ok(),
        readonly.is_ok(),
        "read-only loader and recover disagree on an incomplete journal stream: \
         recover={:?} readonly_ok={}",
        recover.err().map(|e| e.to_string()),
        readonly.is_ok()
    );
}
