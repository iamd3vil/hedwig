use std::{sync::Arc, time::SystemTime};

use async_channel::Sender;
use futures::StreamExt;
use miette::{Context, IntoDiagnostic, Result};

use crate::storage::{Status, Storage};

use super::{EmailMetadata, Job};

pub struct DeferredWorker {
    storage: Arc<dyn Storage>,

    max_attempts: u32,

    /// Channel to send jobs to.
    channel: Sender<Job>,
}

impl DeferredWorker {
    pub fn new(storage: Arc<dyn Storage>, channel: Sender<Job>) -> Self {
        Self {
            storage,
            channel,
            max_attempts: 5,
        }
    }

    pub async fn process_deferred_jobs(&self) -> Result<()> {
        println!("[*] Processing deferred jobs...");
        let mut stream = self.storage.list_meta();

        while let Some(entry) = stream.next().await {
            let entry = match entry {
                Ok(entry) => entry,
                Err(_) => continue,
            };

            let metadata = match self.storage.get_meta(&entry.msg_id).await? {
                Some(metadata) => metadata,
                None => continue,
            };

            // Skip if it's not time to retry yet
            if SystemTime::now() < metadata.next_attempt {
                continue;
            }

            // Handle permanent failure if max attempts reached
            if metadata.attempts >= self.max_attempts {
                self.handle_permanent_failure(&metadata.msg_id).await?;
                continue;
            }

            // Process retry
            self.process_retry(metadata).await?;
        }
        Ok(())
    }

    // Helper methods
    async fn handle_permanent_failure(&self, msg_id: &str) -> Result<()> {
        self.storage
            .mv(msg_id, msg_id, Status::Deferred, Status::Bounced)
            .await
            .wrap_err("moving from deferred to error")
    }

    async fn process_retry(&self, metadata: EmailMetadata) -> Result<()> {
        self.storage
            .mv(
                &metadata.msg_id,
                &metadata.msg_id,
                Status::Deferred,
                Status::Queued,
            )
            .await
            .wrap_err("moving from deferred to queued")?;

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
        let worker = DeferredWorker::new(storage, sender);
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
    async fn test_process_no_metadata() {
        let (worker, receiver, _temp) = setup_test_env().await;

        // Store only the email without metadata
        let email = StoredEmail {
            message_id: "test4".to_string(),
            from: "test@example.com".to_string(),
            to: vec!["recipient@example.com".to_string()],
            body: "Test email".to_string(),
        };
        worker.storage.put(email, Status::Deferred).await.unwrap();

        // Process deferred jobs
        worker.process_deferred_jobs().await.unwrap();

        // Verify no job was queued
        assert!(receiver.try_recv().is_err());
    }
}
