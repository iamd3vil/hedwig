//! Differential fuzzing of shard state recovery: an arbitrary spool
//! directory image (checkpoint file + up to three journal files) is loaded
//! through BOTH the read-only inspector and the real recovery path.
//!
//! Oracle:
//! - neither path may panic;
//! - `load_state_readonly` must never mutate any file;
//! - if `recover` succeeds, the read-only loader must agree exactly;
//! - if the read-only loader rejects the spool, recover must reject it too
//!   (the server must never start from state the inspector calls broken);
//! - recovery is idempotent: recovering twice yields identical state.
//!
//! Input framing (so seeds can embed real on-disk files):
//!   [0]      flags: bit0 = has checkpoint, bits1-2 = journal count (0..=3),
//!            bit3 = journals start at ordinal 2, bit4 = gap after first
//!   then per section: u16 LE length + bytes
//!   sections: checkpoint (if flagged), then each journal in order.

#![no_main]

use std::collections::BTreeMap;
use std::path::Path;

use hedwig::logqueue::state::{load_state_readonly, RecoveredState, ShardStateStore};
use libfuzzer_sys::fuzz_target;

fn take_section<'a>(data: &mut &'a [u8]) -> Option<&'a [u8]> {
    if data.len() < 2 {
        return None;
    }
    let len = u16::from_le_bytes([data[0], data[1]]) as usize;
    let rest = &data[2..];
    if rest.len() < len {
        return None;
    }
    *data = &rest[len..];
    Some(&rest[..len])
}

fn journal_name(ordinal: u64) -> String {
    format!("journal-{ordinal:012}.log")
}

fn dir_snapshot(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|e| {
            let e = e.unwrap();
            (
                e.file_name().to_string_lossy().into_owned(),
                std::fs::read(e.path()).unwrap(),
            )
        })
        .collect()
}

fn state_eq(a: &RecoveredState, b: &RecoveredState) -> bool {
    a.cursor == b.cursor
        && a.ready == b.ready
        && a.deferred == b.deferred
        && a.tombstones == b.tombstones
        && a.segment_stats == b.segment_stats
}

fuzz_target!(|data: &[u8]| {
    let mut data = data;
    let Some(&flags) = data.first() else { return };
    data = &data[1..];

    let dir = tempfile::tempdir().unwrap();
    if flags & 1 != 0 {
        let Some(cp) = take_section(&mut data) else { return };
        std::fs::write(dir.path().join("checkpoint"), cp).unwrap();
    }
    let journal_count = ((flags >> 1) & 0b11) as u64;
    let mut ordinal = if flags & 0b1000 != 0 { 2 } else { 1 };
    for i in 0..journal_count {
        let Some(j) = take_section(&mut data) else { return };
        std::fs::write(dir.path().join(journal_name(ordinal)), j).unwrap();
        ordinal += 1;
        if i == 0 && flags & 0b10000 != 0 {
            ordinal += 1; // fabricate a gap in the stream
        }
    }

    // Read-only first, on the pristine image; it must not touch anything.
    let before = dir_snapshot(dir.path());
    let readonly = load_state_readonly(dir.path());
    assert_eq!(
        dir_snapshot(dir.path()),
        before,
        "read-only loader mutated the spool"
    );

    let recovered = ShardStateStore::recover(dir.path(), 0);
    match (&recovered, &readonly) {
        (Ok((_, state)), Ok(ro)) => {
            assert!(
                state_eq(state, ro),
                "recover and read-only loader disagree on the same spool"
            );
        }
        (Ok(_), Err(e)) => {
            panic!("recover accepted a spool the read-only loader rejects: {e}")
        }
        // Known one-way asymmetry: recover may reject (e.g. incomplete
        // journal stream) where the read-only inspector still shows state.
        (Err(_), Ok(_)) | (Err(_), Err(_)) => {}
    }

    // Recovery is idempotent and deterministic after its own repairs.
    if let Ok((store, state)) = recovered {
        drop(store);
        let (_, again) =
            ShardStateStore::recover(dir.path(), 0).expect("second recovery must succeed");
        assert!(
            state_eq(&state, &again),
            "recovery is not idempotent"
        );
    }
});
