# SQLite Storage Backend

**Date**: 2026-03-29
**Status**: Approved
**Scope**: Add sharded SQLite storage as a new `Storage` trait implementation alongside `FileSystemStorage`

## Motivation

The current filesystem storage (`fs_storage.rs`) has two compounding problems identified in the production hardening audit:

1. **No durability guarantees** (#5) — `tokio::fs::write()` with no temp-file + rename + fsync. Crash or power loss can corrupt the queue or lose acknowledged emails.
2. **Flat directories don't scale** (#6) — `queued/`, `deferred/`, `bounced/` with millions of files degrades ext4 `readdir()` performance. Startup replay and cleanup become directory-walk bound.

SQLite addresses both in one move: writes are transactional (atomic commit), and indexed queries replace directory walks.

Additionally, the filesystem stores email bodies (`.json`) and retry metadata (`.meta.json`) as separate files. Status transitions (`mv` + `put_meta`) are not atomic — a crash between them leaves inconsistent state. SQLite merges both into a single row, making all state transitions atomic.

## Goals

- Implement `SqliteStorage` as a new `Storage` backend, selectable via `storage_type = "sqlite"` in config.
- Keep `FileSystemStorage` unchanged for A/B benchmarking.
- Handle 50M emails/day (~580/sec sustained, 2,000–3,000/sec peak) on a single server.

## Non-Goals

- Body compression (can layer on later if I/O bound).
- Migration tooling from FS → SQLite (greenfield deployment).
- Turso/libSQL backend (potential future experiment).
- Multi-node / distributed queue.

## Architecture

```
                    ┌──────────────┐
                    │ Storage trait │
                    └──────┬───────┘
                           │
              ┌────────────┴────────────┐
              │                         │
    ┌─────────▼──────────┐   ┌─────────▼──────────┐
    │ FileSystemStorage  │   │   SqliteStorage     │
    │ (existing)         │   │   (new)             │
    └────────────────────┘   └─────────┬───────────┘
                                       │
                          ┌────────────┼────────────┐
                          ▼            ▼            ▼
                    ┌──────────┐ ┌──────────┐ ┌──────────┐
                    │ Shard 0  │ │ Shard 1  │ │ Shard N  │
                    │          │ │          │ │          │
                    │ writer   │ │ writer   │ │ writer   │
                    │ task     │ │ task     │ │ task     │
                    │ (mpsc)   │ │ (mpsc)   │ │ (mpsc)   │
                    │          │ │          │ │          │
                    │ read     │ │ read     │ │ read     │
                    │ pool     │ │ pool     │ │ pool     │
                    │          │ │          │ │          │
                    │ shard.db │ │ shard.db │ │ shard.db │
                    └──────────┘ └──────────┘ └──────────┘
```

### Sharding

- N SQLite databases (configurable, default 16), stored as `base_path/shard_0.db` through `base_path/shard_N.db`.
- Shard selection: `hash(message_id) % num_shards` to determine shard index. Use a fast, non-cryptographic hash (e.g. `std::hash::DefaultHasher` or FxHash). ULIDs distribute uniformly.
- Each shard is fully independent — its own writer task, read pool, and database file.
- 16 shards at 3,000 writes/sec peak = ~188 writes/sec per shard, well within SQLite's capacity.

### Per-Shard Writer Task (blobasaur pattern)

Each shard has a dedicated writer task that serializes all write operations:

1. Receives write operations via `tokio::sync::mpsc::channel`.
2. Collects operations into a batch: up to `batch_size` (default 100) or until `batch_timeout_ms` (default 5ms) fires.
3. Executes the entire batch inside a single SQLite transaction (`BEGIN` → operations → `COMMIT`).
4. Sends results back to callers via `tokio::sync::oneshot` channels.

This pattern:
- Eliminates SQLite write contention (single writer per shard).
- Amortizes transaction overhead across N operations.
- Is proven at scale in the blobasaur codebase.

### Separate Read/Write Pools

Per shard:
- **Write pool**: 1 connection, used exclusively by the writer task.
- **Read pool**: Multiple connections (default 10), used for `get`, `get_meta`, and `list` queries.

Reads bypass the writer channel entirely — they go directly to the read pool.

## Schema

Single `emails` table per shard, merging email body and retry metadata:

```sql
CREATE TABLE emails (
    message_id   TEXT PRIMARY KEY,
    status       INTEGER NOT NULL,   -- 0 = queued, 1 = deferred, 2 = bounced
    from_addr    TEXT NOT NULL,
    to_addrs     TEXT NOT NULL,       -- JSON array of recipient addresses
    body         BLOB NOT NULL,
    queued_at    INTEGER,             -- unix timestamp ms, nullable for backward compat
    attempts     INTEGER NOT NULL DEFAULT 0,
    last_attempt INTEGER,             -- unix timestamp ms
    next_attempt INTEGER,             -- unix timestamp ms
    created_at   INTEGER NOT NULL,    -- unix timestamp ms
    updated_at   INTEGER NOT NULL     -- unix timestamp ms
);

CREATE INDEX idx_status ON emails(status);
CREATE INDEX idx_deferred_next ON emails(next_attempt) WHERE status = 1;
CREATE INDEX idx_bounced_updated ON emails(updated_at) WHERE status = 2;
```

### Design Decisions

- **Merged email + metadata**: `attempts`, `last_attempt`, `next_attempt` live on the email row. No separate `.meta.json`. Status transitions are a single `UPDATE`.
- **Status as integer**: Faster indexing and comparison than text. Mapped as: `0 = queued`, `1 = deferred`, `2 = bounced`.
- **Partial indexes**: `idx_deferred_next` only indexes deferred emails (small subset). `idx_bounced_updated` only indexes bounced emails for cleanup. Keeps indexes small.
- **Body as BLOB**: Raw email bytes. No compression in v1 — keep it simple for benchmarking.
- **Timestamps as unix ms integers**: Efficient storage and comparison. Matches `SystemTime` precision.

## Storage Trait Changes

Two methods change return type from `Result<Utf8PathBuf>` to `Result<()>`:

```rust
// Before
async fn put(&self, email: StoredEmail, status: Status) -> Result<Utf8PathBuf>;
async fn put_meta(&self, key: &str, meta: &EmailMetadata) -> Result<Utf8PathBuf>;

// After
async fn put(&self, email: StoredEmail, status: Status) -> Result<()>;
async fn put_meta(&self, key: &str, meta: &EmailMetadata) -> Result<()>;
```

Callers never use the returned path — they just propagate via `?`. `FileSystemStorage` is updated to match (drops the return value). All existing tests are updated.

## Write Operations → SQL Mapping

| Trait method | SQL | Notes |
|---|---|---|
| `put(email, status)` | `INSERT OR REPLACE INTO emails (message_id, status, from_addr, to_addrs, body, queued_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)` | Full row insert |
| `put_meta(key, meta)` | `UPDATE emails SET attempts=?, last_attempt=?, next_attempt=?, updated_at=? WHERE message_id=?` | Updates retry metadata on existing row |
| `delete(key, status)` | `DELETE FROM emails WHERE message_id=? AND status=?` | Status check prevents accidental cross-status deletes |
| `delete_meta(key)` | `UPDATE emails SET attempts=0, last_attempt=NULL, next_attempt=NULL, updated_at=? WHERE message_id=?` | Resets metadata fields |
| `mv(src, dest, src_s, dest_s)` | `UPDATE emails SET message_id=?, status=?, updated_at=? WHERE message_id=? AND status=?` | Atomic status transition |
| `cleanup(config)` | `DELETE FROM emails WHERE status=? AND updated_at < ?` | Retention-based purge, per-status |

All write operations are sent to the shard writer channel. The writer batches them into a single transaction.

## Read Operations → SQL Mapping

| Trait method | SQL | Pool |
|---|---|---|
| `get(key, status)` | `SELECT * FROM emails WHERE message_id=? AND status=?` | Read pool |
| `get_meta(key)` | `SELECT attempts, last_attempt, next_attempt, message_id FROM emails WHERE message_id=?` | Read pool |
| `list(status)` | `SELECT * FROM emails WHERE status=?` per shard, concatenated into stream | Read pool |
| `list_meta()` | `SELECT attempts, last_attempt, next_attempt, message_id FROM emails WHERE status=1` per shard, concatenated | Read pool |

### List Fan-out

`list(status)` and `list_meta()` query all N shards and concatenate results into a single `Pin<Box<dyn Stream<...>>>`. No ordering guarantees (same as current FS implementation). Simple concatenation — the deferred worker and startup replay iterate all results regardless.

## SQLite Configuration

Per-shard pragmas, applied at connection time:

| Pragma | Value | Rationale |
|---|---|---|
| `journal_mode` | `WAL` | Concurrent reads during writes |
| `synchronous` | `NORMAL` | Durable in WAL mode without full fsync per commit |
| `auto_vacuum` | `INCREMENTAL` | Reclaimable space without full VACUUM |
| `busy_timeout` | `5000` | Wait rather than fail on contention |
| `cache_size` | `-102400` (100MB) | Per-shard page cache. Negative = KB. |
| `temp_store` | `MEMORY` | Temp tables in RAM |
| `foreign_keys` | `true` | Safety default |

These follow blobasaur's proven production tuning.

## Configuration

```toml
[storage]
storage_type = "sqlite"        # "fs" for existing filesystem backend
base_path = "./data/queue"     # directory for shard_N.db files
num_shards = 16                # number of SQLite shards (default: 16)
batch_size = 100               # max writes per batch (default: 100)
batch_timeout_ms = 5           # max wait to fill a batch in ms (default: 5)

[storage.sqlite]
synchronous = "NORMAL"         # OFF | NORMAL | FULL (default: NORMAL)
cache_size_mb = 1600           # total cache across all shards (default: 1600)
busy_timeout_ms = 5000         # SQLite busy timeout (default: 5000)
pool_max_connections = 10      # read connections per shard (default: 10)
```

For filesystem storage, existing config is unchanged:

```toml
[storage]
storage_type = "fs"
base_path = "./data/queue"
```

New fields (`num_shards`, `batch_size`, `batch_timeout_ms`, `[storage.sqlite]`) are ignored when `storage_type = "fs"`.

## Dependency

Added to `smtp-server/Cargo.toml`:

```toml
sqlx = { version = "0.8", features = ["runtime-tokio", "sqlite", "sqlite-bundled"] }
```

`sqlite-bundled` compiles SQLite from source — no system dependency, consistent version across platforms.

## Module Structure

```
smtp-server/src/storage/
├── mod.rs              # Storage trait, StoredEmail, Status, CleanupConfig (existing)
├── fs_storage.rs       # FileSystemStorage (existing, updated return types)
└── sqlite_storage.rs   # SqliteStorage (new)
```

`SqliteStorage` is a single file. Internal helpers (shard routing, writer task, batch processing) are private functions/structs within that module. If it grows too large during implementation, split into a `sqlite/` directory.

## Startup & Shutdown

### Startup

1. Create `base_path` directory if it doesn't exist.
2. For each shard 0..N: open read pool + write pool, run `CREATE TABLE IF NOT EXISTS` and `CREATE INDEX IF NOT EXISTS`.
3. Spawn per-shard writer tasks.
4. `SqliteStorage` is ready — callers use it through the `Storage` trait as before.

### Shutdown

1. Drop all `mpsc::Sender` handles (signals writer tasks to drain and stop).
2. Writer tasks process remaining batched operations, then exit.
3. Close all `SqlitePool` connections.

Integrates with hedwig's existing `CancellationToken` shutdown flow.

## Testing Strategy

- Port all existing `fs_storage.rs` tests to work against `SqliteStorage` (same test logic, different backend).
- Parameterize tests where possible to run against both backends.
- Add SQLite-specific tests: batch write atomicity (crash mid-batch doesn't leave partial state), concurrent read during write, shard distribution uniformity.

## Benchmarking

The primary goal is comparing FS vs SQLite storage under realistic load. Benchmarking methodology is out of scope for this spec but the implementation should expose both backends through the same `storage_type` config toggle, making A/B comparison straightforward.
