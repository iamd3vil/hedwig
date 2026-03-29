# SQLite Storage Backend Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development (recommended) or executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add sharded SQLite storage as a new `Storage` trait implementation alongside `FileSystemStorage`, using the blobasaur-style per-shard writer task pattern with sqlx.

**Architecture:** N SQLite shards (default 16), each with a dedicated writer task (mpsc channel + batch writes in a single transaction) and a separate read pool. Hash `message_id` to pick shard. Email body and retry metadata merged into a single `emails` table row.

**Tech Stack:** `sqlx` (0.8, `runtime-tokio` + `sqlite` + `sqlite-bundled`), `tokio::sync::mpsc` + `oneshot` for writer channels, `async-stream` for list fan-out.

**Spec:** `docs/specs/2026-03-29-sqlite-storage-design.md`

---

### Task 1: Update Storage Trait — Change `put`/`put_meta` Return Types

Change `put` and `put_meta` from returning `Result<Utf8PathBuf>` to `Result<()>`. Update all implementations and callers.

**Files:**
- Modify: `smtp-server/src/storage/mod.rs`
- Modify: `smtp-server/src/storage/fs_storage.rs`
- Modify: `smtp-server/src/callbacks.rs`
- Modify: `smtp-server/src/worker/mod.rs`

- [ ] **Step 1: Update the trait definition in `storage/mod.rs`**

In `smtp-server/src/storage/mod.rs`, change:

```rust
async fn put(&self, email: StoredEmail, status: Status) -> Result<Utf8PathBuf>;
```
to:
```rust
async fn put(&self, email: StoredEmail, status: Status) -> Result<()>;
```

And change:
```rust
async fn put_meta(&self, key: &str, meta: &EmailMetadata) -> Result<Utf8PathBuf>;
```
to:
```rust
async fn put_meta(&self, key: &str, meta: &EmailMetadata) -> Result<()>;
```

Remove the `use camino::Utf8PathBuf;` import from `mod.rs` if it's no longer used there (it's still used by `fs_storage.rs` internally).

- [ ] **Step 2: Update `FileSystemStorage` implementation**

In `smtp-server/src/storage/fs_storage.rs`, change the `put` method:

```rust
async fn put(&self, email: StoredEmail, status: Status) -> Result<()> {
    let path = self.file_path(&email.message_id, &status);
    let serialized = serde_json::to_string(&email).into_diagnostic()?;
    fs::write(&path, &serialized).await.into_diagnostic()?;
    Ok(())
}
```

And the `put_meta` method:

```rust
async fn put_meta(&self, key: &str, meta: &EmailMetadata) -> Result<()> {
    let path = self.meta_file_path(key);
    let json = serde_json::to_string(meta).into_diagnostic()?;
    fs::write(&path, json).await.into_diagnostic()?;
    Ok(())
}
```

- [ ] **Step 3: Update mock storages in `callbacks.rs`**

In `smtp-server/src/callbacks.rs`, update `MockStorage`:

```rust
async fn put(&self, _email: StoredEmail, _status: Status) -> Result<()> {
    Ok(())
}

async fn put_meta(&self, _key: &str, _meta: &EmailMetadata) -> Result<()> {
    Ok(())
}
```

And `MockStorageWithError`:

```rust
async fn put(
    &self,
    _email: StoredEmail,
    _status: Status,
) -> Result<(), miette::Report> {
    Err(miette::Report::msg("Storage error"))
}

async fn put_meta(
    &self,
    _key: &str,
    _meta: &crate::worker::EmailMetadata,
) -> Result<(), miette::Report> {
    Ok(())
}
```

- [ ] **Step 4: Update fs_storage tests that used the returned path**

In `smtp-server/src/storage/fs_storage.rs`, in `test_put_and_get`, change:

```rust
let path = storage.put(email.clone(), Status::Queued).await.unwrap();
assert!(path.exists());
```
to:
```rust
storage.put(email.clone(), Status::Queued).await.unwrap();
```

(The `path.exists()` assertion is no longer possible — the `get` test below already verifies the data was stored.)

- [ ] **Step 5: Verify it compiles**

Run: `cargo check --workspace`

Expected: Compiles with at most the existing `fetched_at` warning. No new errors.

- [ ] **Step 6: Commit**

```bash
jj describe -m "refactor: change Storage::put and put_meta to return Result<()>"
jj new
```

---

### Task 2: Add `sqlx` Dependency and Config Types

**Files:**
- Modify: `smtp-server/Cargo.toml`
- Modify: `smtp-server/src/config.rs`

- [ ] **Step 1: Add sqlx to Cargo.toml**

In `smtp-server/Cargo.toml`, add to `[dependencies]`:

```toml
sqlx = { version = "0.8", features = ["runtime-tokio", "sqlite", "sqlite-bundled"] }
```

- [ ] **Step 2: Add SQLite config types to `config.rs`**

In `smtp-server/src/config.rs`, add the following types:

```rust
#[derive(Debug, Deserialize, Clone, Default)]
pub struct CfgSqlite {
    /// SQLite synchronous mode: OFF | NORMAL | FULL (default: NORMAL)
    pub synchronous: Option<String>,
    /// Total cache size in MB across all shards (default: 1600)
    pub cache_size_mb: Option<i32>,
    /// SQLite busy timeout in ms (default: 5000)
    pub busy_timeout_ms: Option<u64>,
    /// Read connections per shard (default: 10)
    pub pool_max_connections: Option<u32>,
}
```

- [ ] **Step 3: Add new fields to `CfgStorage`**

In `smtp-server/src/config.rs`, update `CfgStorage`:

```rust
#[derive(Debug, Deserialize, Clone)]
pub struct CfgStorage {
    pub storage_type: String,
    pub base_path: String,
    #[serde(default)]
    pub cleanup: Option<CfgCleanup>,
    /// Number of SQLite shards (default: 16). Only used when storage_type = "sqlite".
    pub num_shards: Option<usize>,
    /// Max writes per batch (default: 100). Only used when storage_type = "sqlite".
    pub batch_size: Option<usize>,
    /// Max wait to fill a batch in ms (default: 5). Only used when storage_type = "sqlite".
    pub batch_timeout_ms: Option<u64>,
    /// SQLite-specific tuning. Only used when storage_type = "sqlite".
    pub sqlite: Option<CfgSqlite>,
}
```

- [ ] **Step 4: Verify it compiles**

Run: `cargo check --workspace`

Expected: Compiles cleanly.

- [ ] **Step 5: Commit**

```bash
jj describe -m "feat: add sqlx dependency and SQLite storage config types"
jj new
```

---

### Task 3: Implement `SqliteStorage` — Initialization and Schema

Create the core `SqliteStorage` struct with shard initialization, pool creation, and schema setup. No write/read operations yet.

**Files:**
- Create: `smtp-server/src/storage/sqlite_storage.rs`
- Modify: `smtp-server/src/storage/mod.rs`

- [ ] **Step 1: Create `sqlite_storage.rs` with struct and constructor**

Create `smtp-server/src/storage/sqlite_storage.rs`:

```rust
use crate::config::CfgSqlite;
use crate::storage::{CleanupConfig, Status, Storage, StoredEmail};
use crate::worker::EmailMetadata;
use async_trait::async_trait;
use futures::Stream;
use miette::{Context, IntoDiagnostic, Result};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::SqlitePool;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::pin::Pin;
use std::str::FromStr;
use tokio::sync::{mpsc, oneshot};
use tokio::time::Duration;

/// Maps a `Status` enum to its integer representation in the database.
fn status_to_int(status: &Status) -> i32 {
    match status {
        Status::Queued => 0,
        Status::Deferred => 1,
        Status::Bounced => 2,
    }
}

/// A sharded SQLite storage backend.
///
/// Distributes emails across N SQLite databases by hashing the message ID.
/// Each shard has a dedicated writer task for batched writes and a read pool
/// for concurrent reads.
pub struct SqliteStorage {
    /// Read pools, one per shard. Used for get/list operations.
    read_pools: Vec<SqlitePool>,
    /// Write pools, one per shard. Used exclusively by the writer tasks.
    write_pools: Vec<SqlitePool>,
    /// Senders to per-shard writer tasks.
    shard_senders: Vec<mpsc::Sender<ShardWriteOp>>,
    /// Number of shards.
    num_shards: usize,
}

/// A write operation sent to a shard's writer task.
enum ShardWriteOp {
    Put {
        email: StoredEmail,
        status: i32,
        responder: oneshot::Sender<Result<()>>,
    },
    PutMeta {
        key: String,
        meta: EmailMetadata,
        responder: oneshot::Sender<Result<()>>,
    },
    Delete {
        key: String,
        status: i32,
        responder: oneshot::Sender<Result<()>>,
    },
    DeleteMeta {
        key: String,
        responder: oneshot::Sender<Result<()>>,
    },
    Mv {
        src_key: String,
        dest_key: String,
        src_status: i32,
        dest_status: i32,
        responder: oneshot::Sender<Result<()>>,
    },
    Cleanup {
        config: CleanupConfig,
        responder: oneshot::Sender<Result<()>>,
    },
}

impl SqliteStorage {
    /// Determines which shard a message ID belongs to.
    fn shard_for(&self, key: &str) -> usize {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        (hasher.finish() as usize) % self.num_shards
    }

    /// Creates a new `SqliteStorage` with the given configuration.
    ///
    /// This will:
    /// 1. Create the base_path directory if needed.
    /// 2. Open read and write pools for each shard.
    /// 3. Create the `emails` table and indexes on each shard.
    /// 4. Spawn a writer task for each shard.
    pub async fn new(
        base_path: &str,
        num_shards: usize,
        batch_size: usize,
        batch_timeout_ms: u64,
        sqlite_cfg: &CfgSqlite,
    ) -> Result<Self> {
        tokio::fs::create_dir_all(base_path)
            .await
            .into_diagnostic()
            .wrap_err("creating sqlite base_path")?;

        let synchronous = sqlite_cfg
            .synchronous
            .as_deref()
            .unwrap_or("NORMAL");
        let cache_size_mb = sqlite_cfg.cache_size_mb.unwrap_or(1600);
        let busy_timeout_ms = sqlite_cfg.busy_timeout_ms.unwrap_or(5000);
        let pool_max_connections = sqlite_cfg.pool_max_connections.unwrap_or(10);

        // Per-shard cache in KB (negative value = KB for SQLite pragma).
        let cache_per_shard_kb = (cache_size_mb as i64 * 1024) / num_shards.max(1) as i64;

        let mut read_pools = Vec::with_capacity(num_shards);
        let mut write_pools = Vec::with_capacity(num_shards);
        let mut shard_senders = Vec::with_capacity(num_shards);

        for i in 0..num_shards {
            let db_path = format!("{}/shard_{}.db", base_path, i);

            let connect_opts = SqliteConnectOptions::from_str(&format!("sqlite:{}", db_path))
                .into_diagnostic()
                .wrap_err_with(|| format!("parsing sqlite path for shard {}", i))?
                .create_if_missing(true)
                .journal_mode(SqliteJournalMode::Wal)
                .busy_timeout(Duration::from_millis(busy_timeout_ms))
                .pragma("synchronous", synchronous)
                .pragma("auto_vacuum", "INCREMENTAL")
                .pragma("cache_size", format!("-{}", cache_per_shard_kb))
                .pragma("temp_store", "MEMORY")
                .pragma("foreign_keys", "true");

            let read_pool = SqlitePoolOptions::new()
                .max_connections(pool_max_connections)
                .connect_with(connect_opts.clone())
                .await
                .into_diagnostic()
                .wrap_err_with(|| format!("opening read pool for shard {}", i))?;

            let write_pool = SqlitePoolOptions::new()
                .max_connections(1)
                .connect_with(connect_opts)
                .await
                .into_diagnostic()
                .wrap_err_with(|| format!("opening write pool for shard {}", i))?;

            // Create schema on the read pool (any pool works, schema is per-db).
            sqlx::query(
                "CREATE TABLE IF NOT EXISTS emails (
                    message_id   TEXT PRIMARY KEY,
                    status       INTEGER NOT NULL,
                    from_addr    TEXT NOT NULL,
                    to_addrs     TEXT NOT NULL,
                    body         BLOB NOT NULL,
                    queued_at    INTEGER,
                    attempts     INTEGER NOT NULL DEFAULT 0,
                    last_attempt INTEGER,
                    next_attempt INTEGER,
                    created_at   INTEGER NOT NULL,
                    updated_at   INTEGER NOT NULL
                )",
            )
            .execute(&read_pool)
            .await
            .into_diagnostic()
            .wrap_err_with(|| format!("creating emails table on shard {}", i))?;

            sqlx::query("CREATE INDEX IF NOT EXISTS idx_status ON emails(status)")
                .execute(&read_pool)
                .await
                .into_diagnostic()
                .wrap_err_with(|| format!("creating idx_status on shard {}", i))?;

            sqlx::query(
                "CREATE INDEX IF NOT EXISTS idx_deferred_next ON emails(next_attempt) WHERE status = 1",
            )
            .execute(&read_pool)
            .await
            .into_diagnostic()
            .wrap_err_with(|| format!("creating idx_deferred_next on shard {}", i))?;

            sqlx::query(
                "CREATE INDEX IF NOT EXISTS idx_bounced_updated ON emails(updated_at) WHERE status = 2",
            )
            .execute(&read_pool)
            .await
            .into_diagnostic()
            .wrap_err_with(|| format!("creating idx_bounced_updated on shard {}", i))?;

            // Spawn the writer task.
            let (sender, receiver) = mpsc::channel::<ShardWriteOp>(batch_size);
            let pool_for_writer = write_pool.clone();
            tokio::spawn(shard_writer_task(
                i,
                pool_for_writer,
                receiver,
                batch_size,
                batch_timeout_ms,
            ));

            read_pools.push(read_pool);
            write_pools.push(write_pool);
            shard_senders.push(sender);
        }

        Ok(SqliteStorage {
            read_pools,
            write_pools,
            shard_senders,
            num_shards,
        })
    }
}
```

Don't add the `shard_writer_task` function yet — that's Task 4. Add a placeholder:

```rust
/// Per-shard writer task. Receives write operations, batches them, and executes
/// in a single transaction. See Task 4 for full implementation.
async fn shard_writer_task(
    _shard_id: usize,
    _pool: SqlitePool,
    mut receiver: mpsc::Receiver<ShardWriteOp>,
    _batch_size: usize,
    _batch_timeout_ms: u64,
) {
    // Drain the channel so senders don't block during compilation.
    while let Some(_op) = receiver.recv().await {}
}
```

- [ ] **Step 2: Register the module in `storage/mod.rs`**

In `smtp-server/src/storage/mod.rs`, add after the `fs_storage` line:

```rust
pub mod sqlite_storage;
```

- [ ] **Step 3: Verify it compiles**

Run: `cargo check --workspace`

Expected: Compiles cleanly.

- [ ] **Step 4: Write a test for initialization and schema creation**

At the bottom of `smtp-server/src/storage/sqlite_storage.rs`, add:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn default_sqlite_cfg() -> CfgSqlite {
        CfgSqlite {
            synchronous: None,
            cache_size_mb: None,
            busy_timeout_ms: None,
            pool_max_connections: Some(2),
        }
    }

    #[tokio::test]
    async fn test_new_creates_shard_databases() {
        let temp_dir = tempdir().unwrap();
        let base_path = temp_dir.path().to_str().unwrap();
        let cfg = default_sqlite_cfg();

        let storage = SqliteStorage::new(base_path, 4, 10, 5, &cfg).await.unwrap();

        assert_eq!(storage.num_shards, 4);
        assert_eq!(storage.read_pools.len(), 4);
        assert_eq!(storage.write_pools.len(), 4);
        assert_eq!(storage.shard_senders.len(), 4);

        // Verify each shard DB file exists.
        for i in 0..4 {
            let db_path = temp_dir.path().join(format!("shard_{}.db", i));
            assert!(db_path.exists(), "shard_{}.db should exist", i);
        }

        // Verify schema by querying the emails table on each shard.
        for (i, pool) in storage.read_pools.iter().enumerate() {
            let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM emails")
                .fetch_one(pool)
                .await
                .unwrap_or_else(|e| panic!("shard {} emails table query failed: {}", i, e));
            assert_eq!(row.0, 0);
        }
    }

    #[tokio::test]
    async fn test_shard_distribution() {
        let temp_dir = tempdir().unwrap();
        let base_path = temp_dir.path().to_str().unwrap();
        let cfg = default_sqlite_cfg();

        let storage = SqliteStorage::new(base_path, 4, 10, 5, &cfg).await.unwrap();

        // Different keys should map to shards deterministically.
        let shard_a = storage.shard_for("msg_aaa");
        let shard_b = storage.shard_for("msg_aaa");
        assert_eq!(shard_a, shard_b, "same key should always map to same shard");

        // Check all shards are within range.
        for i in 0..100 {
            let key = format!("msg_{}", i);
            let shard = storage.shard_for(&key);
            assert!(shard < 4, "shard {} out of range for key {}", shard, key);
        }
    }
}
```

- [ ] **Step 5: Run the tests**

Run: `cargo test -p hedwig sqlite_storage --lib -- --nocapture`

Expected: Both tests pass.

- [ ] **Step 6: Commit**

```bash
jj describe -m "feat: add SqliteStorage struct with initialization, schema, and shard routing"
jj new
```

---

### Task 4: Implement the Shard Writer Task (Batched Writes)

Replace the placeholder writer task with the full batching implementation, following the blobasaur pattern.

**Files:**
- Modify: `smtp-server/src/storage/sqlite_storage.rs`

- [ ] **Step 1: Implement `shard_writer_task`**

Replace the placeholder `shard_writer_task` function in `sqlite_storage.rs` with:

```rust
/// Per-shard writer task. Collects write operations into batches and executes
/// them inside a single SQLite transaction for throughput.
async fn shard_writer_task(
    shard_id: usize,
    pool: SqlitePool,
    mut receiver: mpsc::Receiver<ShardWriteOp>,
    batch_size: usize,
    batch_timeout_ms: u64,
) {
    use std::collections::VecDeque;

    let batch_timeout = Duration::from_millis(batch_timeout_ms);
    tracing::info!(
        shard_id,
        batch_size,
        batch_timeout_ms,
        "shard writer task started"
    );

    let mut batch: VecDeque<ShardWriteOp> = VecDeque::with_capacity(batch_size);

    loop {
        // Wait for the first operation (blocking).
        if batch.is_empty() {
            match receiver.recv().await {
                Some(op) => batch.push_back(op),
                None => break, // Channel closed — shutdown.
            }
        }

        // Try to fill the batch up to batch_size or until timeout.
        while batch.len() < batch_size {
            match tokio::time::timeout(batch_timeout, receiver.recv()).await {
                Ok(Some(op)) => batch.push_back(op),
                Ok(None) => break,   // Channel closed.
                Err(_) => break,     // Timeout — process current batch.
            }
        }

        // Drain any remaining immediately-available operations.
        while batch.len() < batch_size {
            match receiver.try_recv() {
                Ok(op) => batch.push_back(op),
                Err(_) => break,
            }
        }

        if !batch.is_empty() {
            process_write_batch(shard_id, &pool, &mut batch).await;
        }
    }

    // Drain remaining operations on shutdown.
    if !batch.is_empty() {
        process_write_batch(shard_id, &pool, &mut batch).await;
    }

    tracing::info!(shard_id, "shard writer task stopped");
}

/// Executes a batch of write operations inside a single transaction.
async fn process_write_batch(
    shard_id: usize,
    pool: &SqlitePool,
    batch: &mut VecDeque<ShardWriteOp>,
) {
    let batch_len = batch.len();
    tracing::debug!(shard_id, batch_len, "processing write batch");

    let tx_result = pool.begin().await;
    let mut tx = match tx_result {
        Ok(tx) => tx,
        Err(e) => {
            let err_msg = format!("shard {}: failed to begin transaction: {}", shard_id, e);
            tracing::error!("{}", err_msg);
            // Respond with error to all operations.
            for op in batch.drain(..) {
                if let Some(resp) = extract_responder(op) {
                    let _ = resp.send(Err(miette::miette!("{}", err_msg)));
                }
            }
            return;
        }
    };

    let mut responders: Vec<oneshot::Sender<Result<()>>> = Vec::with_capacity(batch_len);

    for op in batch.drain(..) {
        match op {
            ShardWriteOp::Put {
                email,
                status,
                responder,
            } => {
                let now = now_ms();
                let queued_at_ms = email.queued_at.map(|dt| dt.timestamp_millis());
                let to_json = serde_json::to_string(&email.to).unwrap_or_default();
                let result = sqlx::query(
                    "INSERT OR REPLACE INTO emails
                     (message_id, status, from_addr, to_addrs, body, queued_at, attempts, last_attempt, next_attempt, created_at, updated_at)
                     VALUES (?, ?, ?, ?, ?, ?, 0, NULL, NULL, ?, ?)",
                )
                .bind(&email.message_id)
                .bind(status)
                .bind(&email.from)
                .bind(&to_json)
                .bind(email.body.as_bytes())
                .bind(queued_at_ms)
                .bind(now)
                .bind(now)
                .execute(&mut *tx)
                .await;

                if let Err(e) = result {
                    tracing::error!(shard_id, msg_id = %email.message_id, "INSERT failed: {}", e);
                }
                responders.push(responder);
            }
            ShardWriteOp::PutMeta {
                key,
                meta,
                responder,
            } => {
                let now = now_ms();
                let last_attempt_ms = meta
                    .last_attempt
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as i64)
                    .unwrap_or(0);
                let next_attempt_ms = meta
                    .next_attempt
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as i64)
                    .unwrap_or(0);

                let result = sqlx::query(
                    "UPDATE emails SET attempts = ?, last_attempt = ?, next_attempt = ?, updated_at = ? WHERE message_id = ?",
                )
                .bind(meta.attempts as i64)
                .bind(last_attempt_ms)
                .bind(next_attempt_ms)
                .bind(now)
                .bind(&key)
                .execute(&mut *tx)
                .await;

                if let Err(e) = result {
                    tracing::error!(shard_id, msg_id = %key, "UPDATE meta failed: {}", e);
                }
                responders.push(responder);
            }
            ShardWriteOp::Delete {
                key,
                status,
                responder,
            } => {
                let result =
                    sqlx::query("DELETE FROM emails WHERE message_id = ? AND status = ?")
                        .bind(&key)
                        .bind(status)
                        .execute(&mut *tx)
                        .await;

                if let Err(e) = result {
                    tracing::error!(shard_id, msg_id = %key, "DELETE failed: {}", e);
                }
                responders.push(responder);
            }
            ShardWriteOp::DeleteMeta { key, responder } => {
                let now = now_ms();
                let result = sqlx::query(
                    "UPDATE emails SET attempts = 0, last_attempt = NULL, next_attempt = NULL, updated_at = ? WHERE message_id = ?",
                )
                .bind(now)
                .bind(&key)
                .execute(&mut *tx)
                .await;

                if let Err(e) = result {
                    tracing::error!(shard_id, msg_id = %key, "DELETE META failed: {}", e);
                }
                responders.push(responder);
            }
            ShardWriteOp::Mv {
                src_key,
                dest_key,
                src_status,
                dest_status,
                responder,
            } => {
                let now = now_ms();
                let result = sqlx::query(
                    "UPDATE emails SET message_id = ?, status = ?, updated_at = ? WHERE message_id = ? AND status = ?",
                )
                .bind(&dest_key)
                .bind(dest_status)
                .bind(now)
                .bind(&src_key)
                .bind(src_status)
                .execute(&mut *tx)
                .await;

                if let Err(e) = result {
                    tracing::error!(shard_id, src = %src_key, dest = %dest_key, "MV failed: {}", e);
                }
                responders.push(responder);
            }
            ShardWriteOp::Cleanup { config, responder } => {
                let now = now_ms();

                if let Some(retention) = config.bounced_retention {
                    let cutoff = now - retention.as_millis() as i64;
                    let _ = sqlx::query(
                        "DELETE FROM emails WHERE status = 2 AND updated_at < ?",
                    )
                    .bind(cutoff)
                    .execute(&mut *tx)
                    .await;
                }

                if let Some(retention) = config.deferred_retention {
                    let cutoff = now - retention.as_millis() as i64;
                    let _ = sqlx::query(
                        "DELETE FROM emails WHERE status = 1 AND updated_at < ?",
                    )
                    .bind(cutoff)
                    .execute(&mut *tx)
                    .await;
                }

                responders.push(responder);
            }
        }
    }

    // Commit the transaction.
    match tx.commit().await {
        Ok(_) => {
            for resp in responders {
                let _ = resp.send(Ok(()));
            }
        }
        Err(e) => {
            let err_msg = format!("shard {}: commit failed: {}", shard_id, e);
            tracing::error!("{}", err_msg);
            for resp in responders {
                let _ = resp.send(Err(miette::miette!("{}", err_msg)));
            }
        }
    }
}

/// Extracts the responder from a write operation (for error reporting on tx begin failure).
fn extract_responder(op: ShardWriteOp) -> Option<oneshot::Sender<Result<()>>> {
    match op {
        ShardWriteOp::Put { responder, .. }
        | ShardWriteOp::PutMeta { responder, .. }
        | ShardWriteOp::Delete { responder, .. }
        | ShardWriteOp::DeleteMeta { responder, .. }
        | ShardWriteOp::Mv { responder, .. }
        | ShardWriteOp::Cleanup { responder, .. } => Some(responder),
    }
}

/// Returns the current time as milliseconds since UNIX epoch.
fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}
```

Also add the required imports at the top of the file (merge with existing):

```rust
use std::collections::VecDeque;
use tracing;
```

- [ ] **Step 2: Verify it compiles**

Run: `cargo check --workspace`

Expected: Compiles cleanly.

- [ ] **Step 3: Commit**

```bash
jj describe -m "feat: implement shard writer task with batched transactions"
jj new
```

---

### Task 5: Implement the `Storage` Trait for `SqliteStorage`

Wire up all trait methods: writes go through the shard channel, reads go to the read pool.

**Files:**
- Modify: `smtp-server/src/storage/sqlite_storage.rs`

- [ ] **Step 1: Implement the `Storage` trait**

Add the following impl block to `sqlite_storage.rs`:

```rust
#[async_trait]
impl Storage for SqliteStorage {
    async fn get(&self, key: &str, status: Status) -> Result<Option<StoredEmail>> {
        let shard = self.shard_for(key);
        let status_int = status_to_int(&status);

        let row = sqlx::query_as::<_, (String, String, String, Vec<u8>, Option<i64>)>(
            "SELECT message_id, from_addr, to_addrs, body, queued_at FROM emails WHERE message_id = ? AND status = ?",
        )
        .bind(key)
        .bind(status_int)
        .fetch_optional(&self.read_pools[shard])
        .await
        .into_diagnostic()
        .wrap_err("sqlite get")?;

        match row {
            Some((message_id, from, to_json, body, queued_at_ms)) => {
                let to: Vec<String> = serde_json::from_str(&to_json).into_diagnostic()?;
                let body_str = String::from_utf8(body).into_diagnostic()?;
                let queued_at = queued_at_ms.map(|ms| {
                    chrono::DateTime::from_timestamp_millis(ms)
                        .unwrap_or_default()
                });
                Ok(Some(StoredEmail {
                    message_id,
                    from,
                    to,
                    body: body_str,
                    queued_at,
                }))
            }
            None => Ok(None),
        }
    }

    async fn put(&self, email: StoredEmail, status: Status) -> Result<()> {
        let shard = self.shard_for(&email.message_id);
        let (resp_tx, resp_rx) = oneshot::channel();

        self.shard_senders[shard]
            .send(ShardWriteOp::Put {
                email,
                status: status_to_int(&status),
                responder: resp_tx,
            })
            .await
            .map_err(|_| miette::miette!("shard writer channel closed"))?;

        resp_rx
            .await
            .map_err(|_| miette::miette!("shard writer dropped responder"))?
    }

    async fn get_meta(&self, key: &str) -> Result<Option<EmailMetadata>> {
        let shard = self.shard_for(key);

        let row = sqlx::query_as::<_, (String, i64, Option<i64>, Option<i64>)>(
            "SELECT message_id, attempts, last_attempt, next_attempt FROM emails WHERE message_id = ?",
        )
        .bind(key)
        .fetch_optional(&self.read_pools[shard])
        .await
        .into_diagnostic()
        .wrap_err("sqlite get_meta")?;

        match row {
            Some((msg_id, attempts, last_attempt_ms, next_attempt_ms)) => {
                let last_attempt = last_attempt_ms
                    .map(|ms| std::time::UNIX_EPOCH + Duration::from_millis(ms as u64))
                    .unwrap_or(std::time::UNIX_EPOCH);
                let next_attempt = next_attempt_ms
                    .map(|ms| std::time::UNIX_EPOCH + Duration::from_millis(ms as u64))
                    .unwrap_or(std::time::UNIX_EPOCH);

                Ok(Some(EmailMetadata {
                    msg_id,
                    attempts: attempts as u32,
                    last_attempt,
                    next_attempt,
                }))
            }
            None => Ok(None),
        }
    }

    async fn put_meta(&self, key: &str, meta: &EmailMetadata) -> Result<()> {
        let shard = self.shard_for(key);
        let (resp_tx, resp_rx) = oneshot::channel();

        self.shard_senders[shard]
            .send(ShardWriteOp::PutMeta {
                key: key.to_string(),
                meta: EmailMetadata {
                    msg_id: meta.msg_id.clone(),
                    attempts: meta.attempts,
                    last_attempt: meta.last_attempt,
                    next_attempt: meta.next_attempt,
                },
                responder: resp_tx,
            })
            .await
            .map_err(|_| miette::miette!("shard writer channel closed"))?;

        resp_rx
            .await
            .map_err(|_| miette::miette!("shard writer dropped responder"))?
    }

    async fn delete_meta(&self, key: &str) -> Result<()> {
        let shard = self.shard_for(key);
        let (resp_tx, resp_rx) = oneshot::channel();

        self.shard_senders[shard]
            .send(ShardWriteOp::DeleteMeta {
                key: key.to_string(),
                responder: resp_tx,
            })
            .await
            .map_err(|_| miette::miette!("shard writer channel closed"))?;

        resp_rx
            .await
            .map_err(|_| miette::miette!("shard writer dropped responder"))?
    }

    async fn delete(&self, key: &str, status: Status) -> Result<()> {
        let shard = self.shard_for(key);
        let (resp_tx, resp_rx) = oneshot::channel();

        self.shard_senders[shard]
            .send(ShardWriteOp::Delete {
                key: key.to_string(),
                status: status_to_int(&status),
                responder: resp_tx,
            })
            .await
            .map_err(|_| miette::miette!("shard writer channel closed"))?;

        resp_rx
            .await
            .map_err(|_| miette::miette!("shard writer dropped responder"))?
    }

    async fn mv(
        &self,
        src_key: &str,
        dest_key: &str,
        src_status: Status,
        dest_status: Status,
    ) -> Result<()> {
        let shard = self.shard_for(src_key);
        let (resp_tx, resp_rx) = oneshot::channel();

        self.shard_senders[shard]
            .send(ShardWriteOp::Mv {
                src_key: src_key.to_string(),
                dest_key: dest_key.to_string(),
                src_status: status_to_int(&src_status),
                dest_status: status_to_int(&dest_status),
                responder: resp_tx,
            })
            .await
            .map_err(|_| miette::miette!("shard writer channel closed"))?;

        resp_rx
            .await
            .map_err(|_| miette::miette!("shard writer dropped responder"))?
    }

    fn list(&self, status: Status) -> Pin<Box<dyn Stream<Item = Result<StoredEmail>> + Send>> {
        let status_int = status_to_int(&status);
        let pools: Vec<SqlitePool> = self.read_pools.clone();

        Box::pin(async_stream::try_stream! {
            for pool in pools {
                let mut rows = sqlx::query_as::<_, (String, String, String, Vec<u8>, Option<i64>)>(
                    "SELECT message_id, from_addr, to_addrs, body, queued_at FROM emails WHERE status = ?",
                )
                .bind(status_int)
                .fetch_all(&pool)
                .await
                .into_diagnostic()?;

                for (message_id, from, to_json, body, queued_at_ms) in rows {
                    let to: Vec<String> = serde_json::from_str(&to_json).into_diagnostic()?;
                    let body_str = String::from_utf8(body).into_diagnostic()?;
                    let queued_at = queued_at_ms.map(|ms| {
                        chrono::DateTime::from_timestamp_millis(ms)
                            .unwrap_or_default()
                    });
                    yield StoredEmail {
                        message_id,
                        from,
                        to,
                        body: body_str,
                        queued_at,
                    };
                }
            }
        })
    }

    fn list_meta(&self) -> Pin<Box<dyn Stream<Item = Result<EmailMetadata>> + Send>> {
        let pools: Vec<SqlitePool> = self.read_pools.clone();

        Box::pin(async_stream::try_stream! {
            for pool in pools {
                let rows = sqlx::query_as::<_, (String, i64, Option<i64>, Option<i64>)>(
                    "SELECT message_id, attempts, last_attempt, next_attempt FROM emails WHERE status = 1",
                )
                .fetch_all(&pool)
                .await
                .into_diagnostic()?;

                for (msg_id, attempts, last_attempt_ms, next_attempt_ms) in rows {
                    let last_attempt = last_attempt_ms
                        .map(|ms| std::time::UNIX_EPOCH + Duration::from_millis(ms as u64))
                        .unwrap_or(std::time::UNIX_EPOCH);
                    let next_attempt = next_attempt_ms
                        .map(|ms| std::time::UNIX_EPOCH + Duration::from_millis(ms as u64))
                        .unwrap_or(std::time::UNIX_EPOCH);

                    yield EmailMetadata {
                        msg_id,
                        attempts: attempts as u32,
                        last_attempt,
                        next_attempt,
                    };
                }
            }
        })
    }

    async fn cleanup(&self, config: &CleanupConfig) -> Result<()> {
        // Send cleanup to every shard and wait for all to complete.
        let mut receivers = Vec::with_capacity(self.num_shards);

        for sender in &self.shard_senders {
            let (resp_tx, resp_rx) = oneshot::channel();
            sender
                .send(ShardWriteOp::Cleanup {
                    config: config.clone(),
                    responder: resp_tx,
                })
                .await
                .map_err(|_| miette::miette!("shard writer channel closed"))?;
            receivers.push(resp_rx);
        }

        for resp_rx in receivers {
            resp_rx
                .await
                .map_err(|_| miette::miette!("shard writer dropped responder"))??;
        }

        Ok(())
    }
}
```

- [ ] **Step 2: Verify it compiles**

Run: `cargo check --workspace`

Expected: Compiles cleanly.

- [ ] **Step 3: Commit**

```bash
jj describe -m "feat: implement Storage trait for SqliteStorage"
jj new
```

---

### Task 6: Tests for `SqliteStorage` — Core CRUD Operations

Port the existing fs_storage test patterns to exercise `SqliteStorage`.

**Files:**
- Modify: `smtp-server/src/storage/sqlite_storage.rs` (tests module)

- [ ] **Step 1: Add test helper**

In the `#[cfg(test)] mod tests` block in `sqlite_storage.rs`, add:

```rust
    use futures::StreamExt;
    use std::time::{Duration, SystemTime};

    async fn create_test_storage() -> SqliteStorage {
        let temp_dir = tempdir().unwrap();
        let base_path = temp_dir.path().to_str().unwrap().to_string();
        let cfg = default_sqlite_cfg();
        // Use 2 shards for tests — enough to verify sharding without being slow.
        let storage = SqliteStorage::new(&base_path, 2, 10, 5, &cfg).await.unwrap();
        // Leak temp_dir so it doesn't get dropped (and deleted) while storage is alive.
        std::mem::forget(temp_dir);
        storage
    }

    fn create_test_email(id: &str) -> StoredEmail {
        StoredEmail {
            message_id: id.to_string(),
            from: "sender@example.com".to_string(),
            to: vec!["recipient@example.com".to_string()],
            body: "Test email body".to_string(),
            queued_at: None,
        }
    }
```

- [ ] **Step 2: Add put and get test**

```rust
    #[tokio::test]
    async fn test_put_and_get() {
        let storage = create_test_storage().await;
        let email = create_test_email("test1");

        storage.put(email.clone(), Status::Queued).await.unwrap();

        let retrieved = storage.get("test1", Status::Queued).await.unwrap();
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.message_id, "test1");
        assert_eq!(retrieved.from, "sender@example.com");
        assert_eq!(retrieved.to, vec!["recipient@example.com".to_string()]);
        assert_eq!(retrieved.body, "Test email body");

        // Wrong status returns None.
        let not_found = storage.get("test1", Status::Deferred).await.unwrap();
        assert!(not_found.is_none());

        // Non-existent key returns None.
        let not_found = storage.get("nonexistent", Status::Queued).await.unwrap();
        assert!(not_found.is_none());
    }
```

- [ ] **Step 3: Add delete test**

```rust
    #[tokio::test]
    async fn test_delete() {
        let storage = create_test_storage().await;
        let email = create_test_email("test2");

        storage.put(email, Status::Queued).await.unwrap();
        storage.delete("test2", Status::Queued).await.unwrap();

        let not_found = storage.get("test2", Status::Queued).await.unwrap();
        assert!(not_found.is_none());
    }
```

- [ ] **Step 4: Add mv test**

```rust
    #[tokio::test]
    async fn test_mv() {
        let storage = create_test_storage().await;
        let email = create_test_email("test3");

        storage.put(email, Status::Queued).await.unwrap();
        storage
            .mv("test3", "test3", Status::Queued, Status::Bounced)
            .await
            .unwrap();

        let not_found = storage.get("test3", Status::Queued).await.unwrap();
        assert!(not_found.is_none());

        let found = storage.get("test3", Status::Bounced).await.unwrap();
        assert!(found.is_some());
    }
```

- [ ] **Step 5: Add metadata tests**

```rust
    #[tokio::test]
    async fn test_put_and_get_meta() {
        let storage = create_test_storage().await;
        let email = create_test_email("test_meta");

        // Must insert the email first — put_meta updates an existing row.
        storage.put(email, Status::Deferred).await.unwrap();

        let meta = EmailMetadata {
            msg_id: "test_meta".to_string(),
            attempts: 3,
            last_attempt: SystemTime::now(),
            next_attempt: SystemTime::now() + Duration::from_secs(300),
        };
        storage.put_meta("test_meta", &meta).await.unwrap();

        let retrieved = storage.get_meta("test_meta").await.unwrap();
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.msg_id, "test_meta");
        assert_eq!(retrieved.attempts, 3);

        // Non-existent key returns None.
        let not_found = storage.get_meta("nonexistent").await.unwrap();
        assert!(not_found.is_none());
    }

    #[tokio::test]
    async fn test_delete_meta() {
        let storage = create_test_storage().await;
        let email = create_test_email("test_meta_del");
        storage.put(email, Status::Deferred).await.unwrap();

        let meta = EmailMetadata {
            msg_id: "test_meta_del".to_string(),
            attempts: 2,
            last_attempt: SystemTime::now(),
            next_attempt: SystemTime::now() + Duration::from_secs(60),
        };
        storage.put_meta("test_meta_del", &meta).await.unwrap();
        storage.delete_meta("test_meta_del").await.unwrap();

        let retrieved = storage.get_meta("test_meta_del").await.unwrap();
        assert!(retrieved.is_some());
        // After delete_meta, attempts should be reset to 0.
        assert_eq!(retrieved.unwrap().attempts, 0);
    }
```

- [ ] **Step 6: Add list tests**

```rust
    #[tokio::test]
    async fn test_list() {
        let storage = create_test_storage().await;

        let email1 = create_test_email("list1");
        let email2 = create_test_email("list2");
        let email3 = create_test_email("list3");

        storage.put(email1, Status::Queued).await.unwrap();
        storage.put(email2, Status::Queued).await.unwrap();
        storage.put(email3, Status::Deferred).await.unwrap();

        let mut queued = Vec::new();
        let mut stream = storage.list(Status::Queued);
        while let Some(email) = stream.next().await {
            queued.push(email.unwrap());
        }
        assert_eq!(queued.len(), 2);

        let mut deferred = Vec::new();
        let mut stream = storage.list(Status::Deferred);
        while let Some(email) = stream.next().await {
            deferred.push(email.unwrap());
        }
        assert_eq!(deferred.len(), 1);

        let mut bounced = Vec::new();
        let mut stream = storage.list(Status::Bounced);
        while let Some(email) = stream.next().await {
            bounced.push(email.unwrap());
        }
        assert_eq!(bounced.len(), 0);
    }

    #[tokio::test]
    async fn test_list_meta() {
        let storage = create_test_storage().await;

        let email1 = create_test_email("lm1");
        let email2 = create_test_email("lm2");
        storage.put(email1, Status::Deferred).await.unwrap();
        storage.put(email2, Status::Deferred).await.unwrap();

        let meta1 = EmailMetadata {
            msg_id: "lm1".to_string(),
            attempts: 1,
            last_attempt: SystemTime::now(),
            next_attempt: SystemTime::now() + Duration::from_secs(60),
        };
        let meta2 = EmailMetadata {
            msg_id: "lm2".to_string(),
            attempts: 2,
            last_attempt: SystemTime::now(),
            next_attempt: SystemTime::now() + Duration::from_secs(120),
        };
        storage.put_meta("lm1", &meta1).await.unwrap();
        storage.put_meta("lm2", &meta2).await.unwrap();

        let mut metas = Vec::new();
        let mut stream = storage.list_meta();
        while let Some(meta) = stream.next().await {
            metas.push(meta.unwrap());
        }
        assert_eq!(metas.len(), 2);

        let ids: Vec<String> = metas.iter().map(|m| m.msg_id.clone()).collect();
        assert!(ids.contains(&"lm1".to_string()));
        assert!(ids.contains(&"lm2".to_string()));
    }
```

- [ ] **Step 7: Run all sqlite_storage tests**

Run: `cargo test -p hedwig sqlite_storage --lib -- --nocapture`

Expected: All tests pass.

- [ ] **Step 8: Commit**

```bash
jj describe -m "test: add core CRUD tests for SqliteStorage"
jj new
```

---

### Task 7: Wire Up `SqliteStorage` in `main.rs` and Config

Make `storage_type = "sqlite"` work end-to-end.

**Files:**
- Modify: `smtp-server/src/main.rs`

- [ ] **Step 1: Update `get_storage_type` to handle `"sqlite"`**

In `smtp-server/src/main.rs`, update the `get_storage_type` function:

```rust
use crate::storage::sqlite_storage::SqliteStorage;
```

And update the function body:

```rust
async fn get_storage_type(cfg: &CfgStorage) -> Result<Arc<dyn Storage>> {
    match cfg.storage_type.as_ref() {
        "fs" => {
            let st = FileSystemStorage::new(cfg.base_path.clone()).await?;
            Ok(Arc::new(st))
        }
        "sqlite" => {
            let num_shards = cfg.num_shards.unwrap_or(16);
            let batch_size = cfg.batch_size.unwrap_or(100);
            let batch_timeout_ms = cfg.batch_timeout_ms.unwrap_or(5);
            let sqlite_cfg = cfg.sqlite.clone().unwrap_or_default();
            let st = SqliteStorage::new(
                &cfg.base_path,
                num_shards,
                batch_size,
                batch_timeout_ms,
                &sqlite_cfg,
            )
            .await?;
            Ok(Arc::new(st))
        }
        _ => bail!("Unknown storage type: {}", cfg.storage_type),
    }
}
```

- [ ] **Step 2: Add `Default` derive to `CfgSqlite`**

Verify `CfgSqlite` in `config.rs` has `#[derive(Debug, Deserialize, Clone, Default)]` — it was added in Task 2 with `Default`.

- [ ] **Step 3: Verify it compiles**

Run: `cargo check --workspace`

Expected: Compiles cleanly.

- [ ] **Step 4: Update `config.example.toml` with SQLite example**

Check if `config.example.toml` exists and add a commented-out SQLite section:

```toml
# SQLite storage (alternative to filesystem):
# [storage]
# storage_type = "sqlite"
# base_path = "./data/queue"
# num_shards = 16
# batch_size = 100
# batch_timeout_ms = 5
#
# [storage.sqlite]
# synchronous = "NORMAL"
# cache_size_mb = 1600
# busy_timeout_ms = 5000
# pool_max_connections = 10
```

- [ ] **Step 5: Commit**

```bash
jj describe -m "feat: wire up SqliteStorage in main.rs, selectable via storage_type = sqlite"
jj new
```

---

### Task 8: Cleanup Test for SqliteStorage

Verify retention-based cleanup works correctly.

**Files:**
- Modify: `smtp-server/src/storage/sqlite_storage.rs` (tests module)

- [ ] **Step 1: Add cleanup tests**

In the tests module of `sqlite_storage.rs`:

```rust
    #[tokio::test]
    async fn test_cleanup_bounced_removes_old_messages() {
        let storage = create_test_storage().await;
        let email = create_test_email("bounced_old");
        storage.put(email, Status::Bounced).await.unwrap();

        // Small sleep so updated_at is in the past relative to a tiny retention.
        tokio::time::sleep(Duration::from_millis(20)).await;

        let cleanup_config = CleanupConfig {
            bounced_retention: Some(Duration::from_millis(1)),
            ..Default::default()
        };
        storage.cleanup(&cleanup_config).await.unwrap();

        let retrieved = storage.get("bounced_old", Status::Bounced).await.unwrap();
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_cleanup_deferred_removes_old_messages() {
        let storage = create_test_storage().await;
        let email = create_test_email("deferred_old");
        storage.put(email, Status::Deferred).await.unwrap();

        tokio::time::sleep(Duration::from_millis(20)).await;

        let cleanup_config = CleanupConfig {
            deferred_retention: Some(Duration::from_millis(1)),
            ..Default::default()
        };
        storage.cleanup(&cleanup_config).await.unwrap();

        let retrieved = storage.get("deferred_old", Status::Deferred).await.unwrap();
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_cleanup_does_not_remove_recent_messages() {
        let storage = create_test_storage().await;
        let email = create_test_email("bounced_recent");
        storage.put(email, Status::Bounced).await.unwrap();

        // Retention is 1 hour — message was just created, should survive.
        let cleanup_config = CleanupConfig {
            bounced_retention: Some(Duration::from_secs(3600)),
            ..Default::default()
        };
        storage.cleanup(&cleanup_config).await.unwrap();

        let retrieved = storage.get("bounced_recent", Status::Bounced).await.unwrap();
        assert!(retrieved.is_some());
    }
```

- [ ] **Step 2: Run the tests**

Run: `cargo test -p hedwig sqlite_storage --lib -- --nocapture`

Expected: All tests pass, including cleanup tests.

- [ ] **Step 3: Commit**

```bash
jj describe -m "test: add cleanup tests for SqliteStorage"
jj new
```

---

### Task 9: Update Production Hardening Doc

Mark items #5 and #6 as addressed by the SQLite storage option.

**Files:**
- Modify: `docs/PRODUCTION_HARDENING.md`

- [ ] **Step 1: Update items #5 and #6**

In `docs/PRODUCTION_HARDENING.md`, update item 5's heading to:

```markdown
### 5. ~~Filesystem storage lacks durability guarantees~~ → Addressed (SQLite backend)
```

Add a status line:

```markdown
**Status:** Addressed via `SqliteStorage` backend (`storage_type = "sqlite"`). SQLite transactions provide atomic writes — no partial writes, no fsync gaps. See `docs/specs/2026-03-29-sqlite-storage-design.md`.
```

Similarly for item 6:

```markdown
### 6. ~~Filesystem storage doesn't scale to millions of files~~ → Addressed (SQLite backend)
```

Add:

```markdown
**Status:** Addressed via `SqliteStorage` backend. Sharded SQLite databases with indexed queries replace flat directory walks. See `docs/specs/2026-03-29-sqlite-storage-design.md`.
```

- [ ] **Step 2: Commit**

```bash
jj describe -m "docs: mark hardening items #5 and #6 as addressed by SQLite backend"
jj new
```
