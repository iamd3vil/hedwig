//! Seed the fuzz corpora with VALID on-disk artifacts (records, segments,
//! journals, checkpoints) built through the real write paths, so the
//! coverage-guided mutator starts from deep inside the formats instead of
//! spending cycles rediscovering magics and checksums.
//!
//! Run from `smtp-server/fuzz/`: `cargo run --bin gen_corpus`

use std::fs;
use std::path::PathBuf;

use hedwig::logqueue::record::{encode, RecordParams};
use hedwig::logqueue::state::{Checkpoint, ShardStateStore, StateEntry};
use hedwig::logqueue::{JobLocation, MessageId};

fn corpus_dir(target: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("corpus")
        .join(target);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn record(ordinal: u32, rcpts: usize, body: &[u8]) -> Vec<u8> {
    let recipients: Vec<String> = (0..rcpts).map(|i| format!("r{i}@example.com")).collect();
    encode(&RecordParams {
        message_id: MessageId::from_ulid(ulid::Ulid::from_parts(ordinal as u64, 42)),
        enqueue_ms: 1_752_000_000_000,
        generation: 0,
        ordinal,
        sender: "sender@example.com",
        recipients: &recipients,
        body,
    })
    .unwrap()
}

fn loc(segment: u64, offset: u64) -> JobLocation {
    JobLocation {
        shard: 0,
        segment,
        offset,
        length: 512,
        ordinal: 0,
        generation: 0,
    }
}

fn build_shard(entries: usize, checkpoint: bool) -> (Vec<u8>, Option<Vec<u8>>) {
    let dir = tempfile::tempdir().unwrap();
    {
        let (mut store, _) = ShardStateStore::recover(dir.path(), 0).unwrap();
        for i in 0..entries as u64 {
            let id = MessageId::from_ulid(ulid::Ulid::from_parts(i, 7));
            let entry = match i % 4 {
                0 => StateEntry::Deferred {
                    id,
                    location: loc(1, i * 512),
                    attempts: 1,
                    next_attempt_ms: 1_752_000_100_000,
                    remaining_recipients: vec![format!("r{i}@example.com")],
                    last_error: "451 try later".into(),
                },
                1 => StateEntry::Delivered {
                    id,
                    location: loc(1, i * 512),
                    timestamp_ms: 1_752_000_200_000,
                },
                2 => StateEntry::Bounced {
                    id,
                    location: loc(1, i * 512),
                    timestamp_ms: 1_752_000_200_000,
                    reason: "550 no such user".into(),
                },
                _ => StateEntry::Relocated {
                    id,
                    old: loc(1, i * 512),
                    new: JobLocation {
                        generation: 1,
                        ..loc(2, 0)
                    },
                },
            };
            store.append(&entry).unwrap();
        }
        if checkpoint {
            store.write_checkpoint(&Checkpoint::default()).unwrap();
            // Add one post-checkpoint entry so replay layers on top.
            store
                .append(&StateEntry::Delivered {
                    id: MessageId::from_ulid(ulid::Ulid::from_parts(99, 7)),
                    location: loc(2, 0),
                    timestamp_ms: 1_752_000_300_000,
                })
                .unwrap();
        }
    }
    let mut journal = Vec::new();
    let mut cp = None;
    for entry in fs::read_dir(dir.path()).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with("journal-") {
            let bytes = fs::read(entry.path()).unwrap();
            if bytes.len() > journal.len() {
                journal = bytes;
            }
        } else if name == "checkpoint" {
            cp = Some(fs::read(entry.path()).unwrap());
        }
    }
    (journal, cp)
}

fn frame(section: &[u8]) -> Vec<u8> {
    let mut out = (section.len() as u16).to_le_bytes().to_vec();
    out.extend_from_slice(&section[..section.len().min(u16::MAX as usize)]);
    out
}

fn main() {
    // record_decode: single encoded records of a few shapes.
    let dir = corpus_dir("record_decode");
    for (name, rec) in [
        ("small", record(0, 1, b"hello")),
        ("empty-body", record(3, 2, b"")),
        ("many-rcpt", record(7, 40, b"body")),
    ] {
        fs::write(dir.join(name), rec).unwrap();
    }

    // tail_validation: whole segment images (clean and torn).
    let dir = corpus_dir("tail_validation");
    let mut image = Vec::new();
    for i in 0..4 {
        image.extend_from_slice(&record(i, 2, format!("body {i}").as_bytes()));
    }
    fs::write(dir.join("clean-4-records"), &image).unwrap();
    fs::write(dir.join("torn-tail"), &image[..image.len() - 9]).unwrap();

    // state_recovery: framed spool images (see the target's header comment).
    let dir = corpus_dir("state_recovery");
    let (journal, _) = build_shard(6, false);
    let mut seed = vec![0b0000_0010u8]; // no checkpoint, 1 journal
    seed.extend(frame(&journal));
    fs::write(dir.join("journal-only"), &seed).unwrap();

    let (journal2, cp) = build_shard(8, true);
    let cp = cp.expect("checkpoint written");
    // After a checkpoint the surviving journal is ordinal 2, so set bit 3
    // (journals start at ordinal 2) to reassemble a consistent spool.
    let mut seed = vec![0b0000_1011u8];
    seed.extend(frame(&cp));
    seed.extend(frame(&journal2));
    fs::write(dir.join("checkpoint-and-journal"), &seed).unwrap();

    let mut seed = vec![0b0000_0001u8]; // checkpoint only
    seed.extend(frame(&cp));
    fs::write(dir.join("checkpoint-only"), &seed).unwrap();

    println!("corpora seeded");
}
