use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};

use async_channel::Sender;
use futures::StreamExt;
use miette::{Context, IntoDiagnostic, Result};
use tokio::time::MissedTickBehavior;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use crate::{
    metrics,
    storage::{Status, Storage},
};

use super::{EmailMetadata, Job};

const DEFAULT_MAX_RETRIES: u32 = 5;

/// How often the deferred worker scans for jobs ready to retry.
const SCAN_INTERVAL: Duration = Duration::from_secs(30);

pub struct DeferredWorker {
    storage: Arc<dyn Storage>,

    max_attempts: u32,

    /// Channel to send jobs to.
    channel: Sender<Job>,
}

impl DeferredWorker {
    pub fn new(storage: Arc<dyn Storage>, channel: Sender<Job>, max_retries: Option<u32>) -> Self {
        Self {
            storage,
            channel,
            max_attempts: max_retries.unwrap_or(DEFAULT_MAX_RETRIES),
        }
    }

    /// Run the deferred worker loop, scanning for retryable jobs every 30 seconds.
    ///
    /// Runs until the `shutdown` token is cancelled.
    pub async fn run(&self, shutdown: CancellationToken) {
        info!(
            "deferred worker started (scan interval: {}s)",
            SCAN_INTERVAL.as_secs()
        );

        // Run an initial scan immediately on startup.
        if let Err(e) = self.process_deferred_jobs().await {
            error!("error during initial deferred job scan: {:#}", e);
        }

        let mut interval = tokio::time::interval(SCAN_INTERVAL);
        interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        // Skip the first immediate tick since we already did an initial scan.
        interval.tick().await;

        loop {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    info!("deferred worker shutting down");
                    break;
                }
                _ = interval.tick() => {
                    if let Err(e) = self.process_deferred_jobs().await {
                        error!("error scanning deferred jobs: {:#}", e);
                    }
                }
            }
        }

        info!("deferred worker stopped");
    }

    async fn process_deferred_jobs(&self) -> Result<()> {
        let mut stream = self.storage.list_meta();

        while let Some(entry) = stream.next().await {
            let entry = match entry {
                Ok(entry) => entry,
                Err(_) => continue,
            };

            let metadata = match self.storage.get_meta(&entry.msg_id).await {
                Ok(Some(metadata)) => metadata,
                Ok(None) => continue,
                Err(e) => {
                    error!(msg_id = %entry.msg_id, "error reading deferred metadata: {:#}", e);
                    continue;
                }
            };

            // Skip if it's not time to retry yet
            if SystemTime::now() < metadata.next_attempt {
                continue;
            }

            let msg_id = metadata.msg_id.clone();

            // An interrupted retry, a crash, or a lowered `max_retries` can
            // leave metadata behind after the body is gone from `deferred/`.
            // Such an orphan would make both the retry `mv` (Deferred->Queued)
            // and the permanent-failure `mv` (Deferred->Bounced) fail with
            // ENOENT on every scan. Detect it once, up front, and just drop the
            // stray meta so neither branch keeps logging.
            match self.storage.get(&msg_id, Status::Deferred).await {
                Ok(Some(_)) => {}
                Ok(None) => {
                    if let Err(e) = self.storage.delete_meta(&msg_id).await {
                        error!(msg_id = %msg_id, "error removing orphaned deferred metadata: {:#}", e);
                    }
                    continue;
                }
                Err(e) => {
                    error!(msg_id = %msg_id, "error checking deferred body: {:#}", e);
                    continue;
                }
            }

            // A failure on a single entry must not abort the rest of the scan,
            // otherwise one bad message blocks every later deferred job.
            let result = if metadata.attempts >= self.max_attempts {
                // Handle permanent failure if max attempts reached
                self.handle_permanent_failure(&msg_id).await
            } else {
                self.process_retry(metadata).await
            };

            if let Err(e) = result {
                error!(msg_id = %msg_id, "error processing deferred job: {:#}", e);
            }
        }
        Ok(())
    }

    // Helper methods
    async fn handle_permanent_failure(&self, msg_id: &str) -> Result<()> {
        self.storage
            .mv(msg_id, msg_id, Status::Deferred, Status::Bounced)
            .await
            .wrap_err("moving from deferred to error")?;

        // Drop metadata so the cleanup job doesn't repeatedly inspect a terminal message.
        self.storage
            .delete_meta(msg_id)
            .await
            .wrap_err("removing deferred metadata")?;

        metrics::email_bounced();

        Ok(())
    }

    async fn process_retry(&self, metadata: EmailMetadata) -> Result<()> {
        // Caller (`process_deferred_jobs`) has already verified the deferred
        // body exists, so the `mv` below won't hit an orphaned-metadata ENOENT.
        self.storage
            .mv(
                &metadata.msg_id,
                &metadata.msg_id,
                Status::Deferred,
                Status::Queued,
            )
            .await
            .wrap_err("moving from deferred to queued")?;

        // Drop the metadata now that the body is back in the queue. The attempt
        // count is carried forward on the Job; `defer_email` recreates the meta
        // if delivery fails again. Done before enqueueing so a fast worker can't
        // re-defer with fresh metadata that we'd then delete out from under it.
        self.storage
            .delete_meta(&metadata.msg_id)
            .await
            .wrap_err("removing deferred metadata after requeue")?;

        metrics::queue_depth_inc();
        metrics::retry_scheduled();

        let job = Job::new(metadata.msg_id, metadata.attempts);
        self.channel.send(job).await.into_diagnostic()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        storage::{fs_storage::FileSystemStorage, StoredEmail},
        worker::EmailMetadata,
    };
    use async_channel::{bounded, Receiver};
    use std::time::{Duration, SystemTime};
    use tempfile::tempdir;

    async fn setup_test_env() -> (DeferredWorker, Receiver<Job>, tempfile::TempDir) {
        let temp_dir = tempdir().unwrap();
        let storage = FileSystemStorage::new(
            camino::Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf()).unwrap(),
        )
        .await
        .unwrap();
        let storage = Arc::new(storage);
        let (sender, receiver) = bounded(100);
        let worker = DeferredWorker::new(storage, sender, None);
        (worker, receiver, temp_dir)
    }

    #[tokio::test]
    async fn test_process_expired_deferred_job() {
        let (worker, receiver, _temp) = setup_test_env().await;

        // Create a metadata entry for a deferred job that should be retried
        let meta = EmailMetadata {
            msg_id: "test1".to_string(),
            attempts: 1,
            last_attempt: SystemTime::now() - Duration::from_secs(3600),
            next_attempt: SystemTime::now() - Duration::from_secs(1800), // Time to retry (in the past)
        };

        // Store the metadata and a corresponding email
        worker.storage.put_meta("test1", &meta).await.unwrap();
        let email = StoredEmail {
            message_id: "test1".to_string(),
            from: "test@example.com".to_string(),
            to: vec!["recipient@example.com".to_string()],
            body: "Test email".to_string(),
            queued_at: None,
        };
        worker.storage.put(email, Status::Deferred).await.unwrap();

        // Process deferred jobs
        worker.process_deferred_jobs().await.unwrap();

        // Check if a job was queued
        let received_job = receiver.recv().await.unwrap();
        assert_eq!(received_job.job_id, "test1");
        assert_eq!(received_job.attempts, 1);
    }

    #[tokio::test]
    async fn test_process_max_attempts_exceeded() {
        let (worker, _receiver, _temp) = setup_test_env().await;

        // Create a metadata entry for a deferred job that has exceeded max attempts
        let meta = EmailMetadata {
            msg_id: "test2".to_string(),
            attempts: 5, // Max attempts
            last_attempt: SystemTime::now() - Duration::from_secs(3600),
            next_attempt: SystemTime::now() - Duration::from_secs(1800),
        };

        // Store the metadata and a corresponding email
        worker.storage.put_meta("test2", &meta).await.unwrap();
        let email = StoredEmail {
            message_id: "test2".to_string(),
            from: "test@example.com".to_string(),
            to: vec!["recipient@example.com".to_string()],
            body: "Test email".to_string(),
            queued_at: None,
        };
        worker.storage.put(email, Status::Deferred).await.unwrap();

        // Process deferred jobs
        worker.process_deferred_jobs().await.unwrap();

        // Verify the email was moved to error status
        let deferred_email = worker.storage.get("test2", Status::Deferred).await.unwrap();
        let error_email = worker.storage.get("test2", Status::Bounced).await.unwrap();

        assert!(deferred_email.is_none());
        assert!(error_email.is_some());
    }

    #[tokio::test]
    async fn test_process_not_ready_for_retry() {
        let (worker, _receiver, _temp) = setup_test_env().await;

        // Create a metadata entry for a deferred job that's not ready for retry
        let meta = EmailMetadata {
            msg_id: "test3".to_string(),
            attempts: 1,
            last_attempt: SystemTime::now(),
            next_attempt: SystemTime::now() + Duration::from_secs(3600), // Future time
        };

        // Store the metadata and a corresponding email
        worker.storage.put_meta("test3", &meta).await.unwrap();
        let email = StoredEmail {
            message_id: "test3".to_string(),
            from: "test@example.com".to_string(),
            to: vec!["recipient@example.com".to_string()],
            body: "Test email".to_string(),
            queued_at: None,
        };
        worker.storage.put(email, Status::Deferred).await.unwrap();

        // Process deferred jobs
        worker.process_deferred_jobs().await.unwrap();

        // Verify the email is still in deferred status and not in queued
        let deferred_email = worker.storage.get("test3", Status::Deferred).await.unwrap();
        let queued_email = worker.storage.get("test3", Status::Queued).await.unwrap();

        assert!(deferred_email.is_some());
        assert!(queued_email.is_none());
    }

    #[tokio::test]
    async fn test_process_orphaned_metadata() {
        let (worker, receiver, _temp) = setup_test_env().await;

        // Metadata that is ready to retry, but with NO corresponding deferred
        // body — simulating an earlier retry that moved the body to queued
        // (or a crash) without removing the meta.
        let meta = EmailMetadata {
            msg_id: "orphan".to_string(),
            attempts: 1,
            last_attempt: SystemTime::now() - Duration::from_secs(3600),
            next_attempt: SystemTime::now() - Duration::from_secs(1800),
        };
        worker.storage.put_meta("orphan", &meta).await.unwrap();

        // Should not error, should not enqueue a job, and should clear the meta.
        worker.process_deferred_jobs().await.unwrap();

        assert!(receiver.try_recv().is_err());
        assert!(worker.storage.get_meta("orphan").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_orphaned_metadata_at_max_attempts() {
        let (worker, _receiver, _temp) = setup_test_env().await;

        // Orphaned meta (no deferred body) that is also at max attempts. Must be
        // dropped by the up-front orphan check, not routed to permanent failure
        // where the Deferred->Bounced mv would fail with ENOENT forever.
        let meta = EmailMetadata {
            msg_id: "orphan_max".to_string(),
            attempts: 5,
            last_attempt: SystemTime::now() - Duration::from_secs(3600),
            next_attempt: SystemTime::now() - Duration::from_secs(1800),
        };
        worker.storage.put_meta("orphan_max", &meta).await.unwrap();

        worker.process_deferred_jobs().await.unwrap();

        assert!(worker.storage.get_meta("orphan_max").await.unwrap().is_none());
        assert!(worker
            .storage
            .get("orphan_max", Status::Bounced)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn test_retry_removes_metadata() {
        let (worker, receiver, _temp) = setup_test_env().await;

        let meta = EmailMetadata {
            msg_id: "retry_meta".to_string(),
            attempts: 1,
            last_attempt: SystemTime::now() - Duration::from_secs(3600),
            next_attempt: SystemTime::now() - Duration::from_secs(1800),
        };
        worker.storage.put_meta("retry_meta", &meta).await.unwrap();
        let email = StoredEmail {
            message_id: "retry_meta".to_string(),
            from: "test@example.com".to_string(),
            to: vec!["recipient@example.com".to_string()],
            body: "Test email".to_string(),
            queued_at: None,
        };
        worker.storage.put(email, Status::Deferred).await.unwrap();

        worker.process_deferred_jobs().await.unwrap();

        // Job enqueued and body moved to queued.
        assert_eq!(receiver.recv().await.unwrap().job_id, "retry_meta");
        // Metadata removed so the next scan won't re-process the moved body.
        assert!(worker.storage.get_meta("retry_meta").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_process_no_metadata() {
        let (worker, receiver, _temp) = setup_test_env().await;

        // Store only the email without metadata
        let email = StoredEmail {
            message_id: "test4".to_string(),
            from: "test@example.com".to_string(),
            to: vec!["recipient@example.com".to_string()],
            body: "Test email".to_string(),
            queued_at: None,
        };
        worker.storage.put(email, Status::Deferred).await.unwrap();

        // Process deferred jobs
        worker.process_deferred_jobs().await.unwrap();

        // Verify no job was queued
        assert!(receiver.try_recv().is_err());
    }
}
