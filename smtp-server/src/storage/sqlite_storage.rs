use crate::config::CfgSqlite;
use crate::storage::{CleanupConfig, Status, StoredEmail};
use crate::worker::EmailMetadata;
use miette::{Context, IntoDiagnostic, Result};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::SqlitePool;
use std::collections::hash_map::DefaultHasher;
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

async fn shard_writer_task(
    _shard_id: usize,
    _pool: SqlitePool,
    mut receiver: mpsc::Receiver<ShardWriteOp>,
    _batch_size: usize,
    _batch_timeout_ms: u64,
) {
    while let Some(_op) = receiver.recv().await {}
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
