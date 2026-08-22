# Log-queue fuzzing

Coverage-guided (libFuzzer) fuzz targets for the durable log queue's
on-disk formats and recovery paths. Requires the nightly toolchain and
`cargo-fuzz`:

```sh
rustup toolchain install nightly
cargo install cargo-fuzz
```

Seed the corpora with valid artifacts built through the real write paths
(recommended before the first run):

```sh
cd smtp-server/fuzz && cargo +nightly run --bin gen_corpus
```

Run a target (from `smtp-server/`):

```sh
cargo +nightly fuzz run record_decode    -- -dict=fuzz/hwlq.dict
cargo +nightly fuzz run record_roundtrip -- -dict=fuzz/hwlq.dict
cargo +nightly fuzz run tail_validation  -- -dict=fuzz/hwlq.dict
cargo +nightly fuzz run state_recovery   -- -dict=fuzz/hwlq.dict
```

Add `-max_total_time=300` for a bounded session; crashes land in
`fuzz/artifacts/<target>/` and reproduce with
`cargo +nightly fuzz run <target> <artifact-path>`.

## Targets and oracles

- **record_decode** — arbitrary bytes into the payload-record header
  decoder. Any accepted header must satisfy the format invariants and be
  re-encodable to an equivalent record.
- **record_roundtrip** — structure-aware (Arbitrary) encoder round-trip:
  anything the encoder accepts must decode bit-identically; every strict
  prefix must read as `Incomplete`, never `Corrupt`; rejections must match
  a documented limit.
- **tail_validation** — arbitrary bytes as an active segment image.
  Validation must never error, must be idempotent, and the committed
  prefix must scan as perfect, dense, ordinal-sequential records.
- **state_recovery** — differential: an arbitrary spool image (checkpoint
  + up to three journals) loaded through both `load_state_readonly` and
  `ShardStateStore::recover`. The read-only loader must never mutate a
  file; whenever recovery succeeds both must agree exactly; recovery must
  be idempotent.

The deterministic seeded-RNG corruption tests in
`src/logqueue/fuzz_tests.rs` cover the same invariants inside plain
`cargo test` (no nightly needed); the fuzz targets here explore the input
space coverage-guided.
