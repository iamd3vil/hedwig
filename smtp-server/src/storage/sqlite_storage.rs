use crate::config::CfgSqlite;
use crate::storage::{CleanupConfig, Status, StoredEmail};
use crate::worker::EmailMetadata;
use miette::{Context, IntoDiagnostic, Result};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::SqlitePool;
use std::collections::{hash_map::DefaultHasher, VecDeque};
use std::hash::{Hash, Hasher};
use tokio::sync::{mpsc, oneshot};
use tokio::time::Duration;

pub struct SqliteStorage {
    pub read_pools: Vec<SqlitePool>,
    pub write_pools: Vec<SqlitePool>,
    pub shard_senders: Vec<mpsc::Sender<ShardWriteOp>>,
    pub num_shards: usize,
}

pub enum ShardWriteOp {
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

pub fn status_to_int(status: &Status) -> i32 {
    match status {
        Status::Queued => 0,
        Status::Deferred => 1,
        Status::Bounced => 2,
    }
}

impl SqliteStorage {
    pub fn shard_for(&self, key: &str) -> usize {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        (hasher.finish() as usize) % self.num_shards
    }

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
            .wrap_err("Failed to create storage base path")?;

        let pool_max_connections = sqlite_cfg.pool_max_connections.unwrap_or(10);
        let busy_timeout_ms = sqlite_cfg.busy_timeout_ms.unwrap_or(5000);
        let cache_size_mb = sqlite_cfg.cache_size_mb.unwrap_or(1600);
        let synchronous = sqlite_cfg
            .synchronous
            .as_deref()
            .unwrap_or("NORMAL")
            .to_owned();

        // Distribute cache evenly across shards; negative value = kilobytes.
        let cache_kb_per_shard = (cache_size_mb as i64 * 1024) / (num_shards as i64);

        let mut read_pools = Vec::with_capacity(num_shards);
        let mut write_pools = Vec::with_capacity(num_shards);
        let mut shard_senders = Vec::with_capacity(num_shards);

        for i in 0..num_shards {
            let db_path = format!("{}/shard_{}.db", base_path, i);

            let base_opts = SqliteConnectOptions::new()
                .filename(&db_path)
                .create_if_missing(true)
                .journal_mode(SqliteJournalMode::Wal)
                .pragma("synchronous", synchronous.clone())
                .pragma("auto_vacuum", "INCREMENTAL")
                .pragma("cache_size", format!("-{}", cache_kb_per_shard))
                .pragma("temp_store", "MEMORY")
                .foreign_keys(true)
                .busy_timeout(Duration::from_millis(busy_timeout_ms));

            let read_pool = SqlitePoolOptions::new()
                .max_connections(pool_max_connections)
                .connect_with(base_opts.clone())
                .await
                .into_diagnostic()
                .wrap_err(format!("Failed to open read pool for shard {}", i))?;

            // Single writer per shard — max_connections(1) serialises writes.
            let write_pool = SqlitePoolOptions::new()
                .max_connections(1)
                .connect_with(base_opts)
                .await
                .into_diagnostic()
                .wrap_err(format!("Failed to open write pool for shard {}", i))?;

            Self::create_schema(&write_pool)
                .await
                .wrap_err(format!("Failed to create schema for shard {}", i))?;

            let (tx, rx) = mpsc::channel::<ShardWriteOp>(1024);
            tokio::spawn(shard_writer_task(
                i,
                write_pool.clone(),
                rx,
                batch_size,
                batch_timeout_ms,
            ));

            read_pools.push(read_pool);
            write_pools.push(write_pool);
            shard_senders.push(tx);
        }

        Ok(SqliteStorage {
            read_pools,
            write_pools,
            shard_senders,
            num_shards,
        })
    }

    async fn create_schema(pool: &SqlitePool) -> Result<()> {
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
        .execute(pool)
        .await
        .into_diagnostic()
        .wrap_err("Failed to create emails table")?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_status ON emails(status)")
            .execute(pool)
            .await
            .into_diagnostic()
            .wrap_err("Failed to create idx_status")?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_deferred_next ON emails(next_attempt) WHERE status = 1",
        )
        .execute(pool)
        .await
        .into_diagnostic()
        .wrap_err("Failed to create idx_deferred_next")?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_bounced_updated ON emails(updated_at) WHERE status = 2",
        )
        .execute(pool)
        .await
        .into_diagnostic()
        .wrap_err("Failed to create idx_bounced_updated")?;

        Ok(())
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

fn extract_responder(op: ShardWriteOp) -> oneshot::Sender<Result<()>> {
    match op {
        ShardWriteOp::Put { responder, .. }
        | ShardWriteOp::PutMeta { responder, .. }
        | ShardWriteOp::Delete { responder, .. }
        | ShardWriteOp::DeleteMeta { responder, .. }
        | ShardWriteOp::Mv { responder, .. }
        | ShardWriteOp::Cleanup { responder, .. } => responder,
    }
}

async fn process_write_batch(
    shard_id: usize,
    pool: &SqlitePool,
    batch: &mut VecDeque<ShardWriteOp>,
) {
    use std::time::UNIX_EPOCH;

    let now = now_ms();
    let ops: Vec<ShardWriteOp> = batch.drain(..).collect();
    let mut responders: Vec<oneshot::Sender<Result<()>>> = Vec::with_capacity(ops.len());

    let mut tx = match pool.begin().await.into_diagnostic() {
        Ok(tx) => tx,
        Err(e) => {
            let err_msg = e.to_string();
            for op in ops {
                let resp = extract_responder(op);
                let _ = resp.send(Err(miette::miette!("{}", err_msg)));
            }
            return;
        }
    };

    let mut batch_failed = false;
    let mut batch_error: Option<String> = None;

    for op in ops {
        match op {
            ShardWriteOp::Put { email, status, responder } => {
                let to_addrs = match serde_json::to_string(&email.to) {
                    Ok(s) => s,
                    Err(e) => {
                        let _ = responder.send(Err(miette::miette!("failed to serialize to_addrs: {}", e)));
                        continue;
                    }
                };
                responders.push(responder);
                let queued_at = email.queued_at.map(|dt| dt.timestamp_millis());
                if let Err(e) = sqlx::query(
                    "INSERT OR REPLACE INTO emails \
                    (message_id, status, from_addr, to_addrs, body, queued_at, attempts, last_attempt, next_attempt, created_at, updated_at) \
                    VALUES (?, ?, ?, ?, ?, ?, 0, NULL, NULL, ?, ?)",
                )
                .bind(&email.message_id)
                .bind(status)
                .bind(&email.from)
                .bind(&to_addrs)
                .bind(email.body.as_bytes())
                .bind(queued_at)
                .bind(now)
                .bind(now)
                .execute(&mut *tx)
                .await
                {
                    tracing::error!(shard_id, error = %e, message_id = %email.message_id, "Put failed");
                    if !batch_failed {
                        batch_failed = true;
                        batch_error = Some(format!("Put failed: {}", e));
                    }
                }
            }
            ShardWriteOp::PutMeta { key, meta, responder } => {
                responders.push(responder);
                let last_attempt = meta
                    .last_attempt
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as i64;
                let next_attempt = meta
                    .next_attempt
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as i64;
                if let Err(e) = sqlx::query(
                    "UPDATE emails SET attempts = ?, last_attempt = ?, next_attempt = ?, updated_at = ? WHERE message_id = ?",
                )
                .bind(meta.attempts as i64)
                .bind(last_attempt)
                .bind(next_attempt)
                .bind(now)
                .bind(&key)
                .execute(&mut *tx)
                .await
                {
                    tracing::error!(shard_id, error = %e, key = %key, "PutMeta failed");
                    if !batch_failed {
                        batch_failed = true;
                        batch_error = Some(format!("PutMeta failed: {}", e));
                    }
                }
            }
            ShardWriteOp::Delete { key, status, responder } => {
                responders.push(responder);
                if let Err(e) = sqlx::query(
                    "DELETE FROM emails WHERE message_id = ? AND status = ?",
                )
                .bind(&key)
                .bind(status)
                .execute(&mut *tx)
                .await
                {
                    tracing::error!(shard_id, error = %e, key = %key, "Delete failed");
                    if !batch_failed {
                        batch_failed = true;
                        batch_error = Some(format!("Delete failed: {}", e));
                    }
                }
            }
            ShardWriteOp::DeleteMeta { key, responder } => {
                responders.push(responder);
                if let Err(e) = sqlx::query(
                    "UPDATE emails SET attempts = 0, last_attempt = NULL, next_attempt = NULL, updated_at = ? WHERE message_id = ?",
                )
                .bind(now)
                .bind(&key)
                .execute(&mut *tx)
                .await
                {
                    tracing::error!(shard_id, error = %e, key = %key, "DeleteMeta failed");
                    if !batch_failed {
                        batch_failed = true;
                        batch_error = Some(format!("DeleteMeta failed: {}", e));
                    }
                }
            }
            ShardWriteOp::Mv { src_key, dest_key, src_status, dest_status, responder } => {
                responders.push(responder);
                if let Err(e) = sqlx::query(
                    "UPDATE emails SET message_id = ?, status = ?, updated_at = ? WHERE message_id = ? AND status = ?",
                )
                .bind(&dest_key)
                .bind(dest_status)
                .bind(now)
                .bind(&src_key)
                .bind(src_status)
                .execute(&mut *tx)
                .await
                {
                    tracing::error!(shard_id, error = %e, src_key = %src_key, "Mv failed");
                    if !batch_failed {
                        batch_failed = true;
                        batch_error = Some(format!("Mv failed: {}", e));
                    }
                }
            }
            ShardWriteOp::Cleanup { config, responder } => {
                responders.push(responder);
                if let Some(bounced_retention) = config.bounced_retention {
                    let cutoff = now - bounced_retention.as_millis() as i64;
                    if let Err(e) = sqlx::query(
                        "DELETE FROM emails WHERE status = ? AND updated_at < ?",
                    )
                    .bind(status_to_int(&Status::Bounced))
                    .bind(cutoff)
                    .execute(&mut *tx)
                    .await
                    {
                        tracing::error!(shard_id, error = %e, "Cleanup bounced failed");
                        if !batch_failed {
                            batch_failed = true;
                            batch_error = Some(format!("Cleanup bounced failed: {}", e));
                        }
                    }
                }
                if let Some(deferred_retention) = config.deferred_retention {
                    let cutoff = now - deferred_retention.as_millis() as i64;
                    if let Err(e) = sqlx::query(
                        "DELETE FROM emails WHERE status = ? AND updated_at < ?",
                    )
                    .bind(status_to_int(&Status::Deferred))
                    .bind(cutoff)
                    .execute(&mut *tx)
                    .await
                    {
                        tracing::error!(shard_id, error = %e, "Cleanup deferred failed");
                        if !batch_failed {
                            batch_failed = true;
                            batch_error = Some(format!("Cleanup deferred failed: {}", e));
                        }
                    }
                }
            }
        }
    }

    if batch_failed {
        drop(tx); // implicit rollback
        let err_msg = batch_error.unwrap_or_else(|| "batch failed".to_string());
        for resp in responders {
            let _ = resp.send(Err(miette::miette!("{}", err_msg)));
        }
        return;
    }

    match tx.commit().await.into_diagnostic() {
        Ok(()) => {
            for resp in responders {
                let _ = resp.send(Ok(()));
            }
        }
        Err(e) => {
            let err_msg = e.to_string();
            for resp in responders {
                let _ = resp.send(Err(miette::miette!("{}", err_msg)));
            }
        }
    }
}

async fn shard_writer_task(
    shard_id: usize,
    pool: SqlitePool,
    mut receiver: mpsc::Receiver<ShardWriteOp>,
    batch_size: usize,
    batch_timeout_ms: u64,
) {
    let batch_timeout = Duration::from_millis(batch_timeout_ms);
    tracing::info!(shard_id, batch_size, batch_timeout_ms, "shard writer task started");

    let mut batch: VecDeque<ShardWriteOp> = VecDeque::with_capacity(batch_size);

    loop {
        // Wait for first op (blocking)
        if batch.is_empty() {
            match receiver.recv().await {
                Some(op) => batch.push_back(op),
                None => break,
            }
        }

        // Fill batch up to size or timeout
        while batch.len() < batch_size {
            match tokio::time::timeout(batch_timeout, receiver.recv()).await {
                Ok(Some(op)) => batch.push_back(op),
                Ok(None) => break,
                Err(_) => break, // timeout
            }
        }

        // Drain any immediately available
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

    // Drain remaining on shutdown
    if !batch.is_empty() {
        process_write_batch(shard_id, &pool, &mut batch).await;
    }

    tracing::info!(shard_id, "shard writer task stopped");
}

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

        for i in 0..4 {
            let db_path = temp_dir.path().join(format!("shard_{}.db", i));
            assert!(db_path.exists(), "shard_{}.db should exist", i);
        }

        // Verify schema exists
        for (i, pool) in storage.read_pools.iter().enumerate() {
            let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM emails")
                .fetch_one(pool)
                .await
                .unwrap_or_else(|e| panic!("shard {} query failed: {}", i, e));
            assert_eq!(row.0, 0);
        }
    }

    #[tokio::test]
    async fn test_shard_distribution() {
        let temp_dir = tempdir().unwrap();
        let base_path = temp_dir.path().to_str().unwrap();
        let cfg = default_sqlite_cfg();
        let storage = SqliteStorage::new(base_path, 4, 10, 5, &cfg).await.unwrap();

        let shard_a = storage.shard_for("msg_aaa");
        let shard_b = storage.shard_for("msg_aaa");
        assert_eq!(shard_a, shard_b, "same key should map to same shard");

        for i in 0..100 {
            let key = format!("msg_{}", i);
            let shard = storage.shard_for(&key);
            assert!(shard < 4, "shard {} out of range for key {}", shard, key);
        }
    }
}
