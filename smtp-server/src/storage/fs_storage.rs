use crate::{
    storage::{Status, Storage, StoredEmail},
    worker::EmailMetadata,
};
use async_trait::async_trait;
use camino::{Utf8Path, Utf8PathBuf};
use futures::Stream;
use miette::{Context, IntoDiagnostic, Result};
use serde_json;
use std::pin::Pin;
use tokio::fs;

pub struct FileSystemStorage {
    base_path: Utf8PathBuf,
}

impl FileSystemStorage {
    pub async fn new<P: AsRef<Utf8Path>>(base_path: P) -> Result<Self> {
        // Create the base path if it doesn't exist.
        fs::create_dir_all(base_path.as_ref())
            .await
            .into_diagnostic()
            .wrap_err("creating base path")?;

        // Create instance to use dir method
        let storage = FileSystemStorage {
            base_path: base_path.as_ref().to_owned(),
        };

        // Create queued, deferred, and error directories.
        let status = [Status::QUEUED, Status::DEFERRED, Status::BOUNCED];
        for s in status.iter() {
            fs::create_dir_all(storage.dir(s))
                .await
                .into_diagnostic()
                .wrap_err("creating status directory")?;
        }

        Ok(storage)
    }

    fn dir(&self, status: &Status) -> Utf8PathBuf {
        match status {
            Status::QUEUED => self.base_path.join("queued"),
            Status::DEFERRED => self.base_path.join("deferred"),
            Status::BOUNCED => self.base_path.join("bounced"),
        }
    }

    fn file_path(&self, key: &str, status: &Status) -> Utf8PathBuf {
        let base_path = self.dir(status);
        base_path.join(format!("{}.json", key))
    }

    fn meta_file_path(&self, key: &str) -> Utf8PathBuf {
        let base_path = self.dir(&Status::DEFERRED);
        base_path.join(format!("{}.meta.json", key))
    }

    fn create_meta_list_stream(
        base_path: Utf8PathBuf,
    ) -> Pin<Box<dyn Stream<Item = Result<EmailMetadata>> + Send>> {
        Box::pin(async_stream::try_stream! {
            let base_path = base_path.join("deferred").clone();
            let mut entries = fs::read_dir(&base_path).await.into_diagnostic()?;
            while let Some(entry) = entries.next_entry().await.into_diagnostic()? {
                let path = entry.path();
                // Check for the ".meta.json" suffix instead of just the extension
                if let Some(file_name) = path.file_name().and_then(|f| f.to_str()) {
                    if file_name.ends_with(".meta.json") {
                        let contents = fs::read_to_string(&path).await.into_diagnostic()?;
                        let meta: EmailMetadata = serde_json::from_str(&contents).into_diagnostic()?;
                        yield meta;
                    }
                }
            }
        })
    }

    fn create_list_stream(
        &self,
        status: Status,
    ) -> Pin<Box<dyn Stream<Item = Result<StoredEmail>> + Send>> {
        let dir = self.dir(&status).clone();
        Box::pin(async_stream::try_stream! {
            let mut entries = fs::read_dir(&dir).await.into_diagnostic()?;
            while let Some(entry) = entries.next_entry().await.into_diagnostic()? {
                let path = entry.path();
                if let Some(file_name) = path.file_name().and_then(|f| f.to_str()) {
                    if file_name.ends_with(".json") {
                        let contents = fs::read_to_string(&path).await.into_diagnostic()?;
                        let email: StoredEmail = serde_json::from_str(&contents).into_diagnostic()?;
                        yield email;
                    }
                }
            }
        })
    }
}

#[async_trait]
impl Storage for FileSystemStorage {
    async fn get(&self, key: &str, status: Status) -> Result<Option<StoredEmail>> {
        let path = self.file_path(key, &status);
        if path.exists() {
            let contents = fs::read_to_string(&path).await.into_diagnostic()?;
            let email: StoredEmail = serde_json::from_str(&contents).into_diagnostic()?;
            Ok(Some(email))
        } else {
            Ok(None)
        }
    }

    async fn put(&self, email: StoredEmail, status: Status) -> Result<Utf8PathBuf> {
        let path = self.file_path(&email.message_id, &status);
        let json = serde_json::to_string(&email).into_diagnostic()?;
        fs::write(&path, json).await.into_diagnostic()?;
        Ok(path)
    }

    async fn delete(&self, key: &str, status: Status) -> Result<()> {
        let path = self.file_path(key, &status);
        if fs::metadata(&path).await.is_ok() {
            fs::remove_file(path).await.into_diagnostic()?;
        }
        Ok(())
    }

    async fn get_meta(&self, key: &str) -> Result<Option<EmailMetadata>> {
        let path = self.meta_file_path(key);
        if fs::metadata(&path).await.is_ok() {
            let contents = fs::read_to_string(&path).await.into_diagnostic()?;
            let meta: EmailMetadata = serde_json::from_str(&contents).into_diagnostic()?;
            Ok(Some(meta))
        } else {
            Ok(None)
        }
    }

    async fn put_meta(&self, key: &str, meta: &EmailMetadata) -> Result<Utf8PathBuf> {
        let path = self.meta_file_path(key);
        let json = serde_json::to_string(meta).into_diagnostic()?;
        fs::write(&path, json).await.into_diagnostic()?;
        Ok(path)
    }

    async fn delete_meta(&self, key: &str) -> Result<()> {
        let path = self.meta_file_path(key);
        if path.exists() {
            fs::remove_file(path).await.into_diagnostic()?;
        }
        Ok(())
    }

    async fn mv(
        &self,
        src_key: &str,
        dest_key: &str,
        src_status: Status,
        dest_status: Status,
    ) -> Result<()> {
        let src_path = self.file_path(src_key, &src_status);
        let dest_path = self.file_path(dest_key, &dest_status);
        fs::rename(src_path, dest_path).await.into_diagnostic()?;
        Ok(())
    }

    fn list(&self, status: Status) -> Pin<Box<dyn Stream<Item = Result<StoredEmail>> + Send>> {
        self.create_list_stream(status)
    }

    fn list_meta(&self) -> Pin<Box<dyn Stream<Item = Result<EmailMetadata>> + Send>> {
        Self::create_meta_list_stream(self.base_path.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;
    use std::time::{Duration, SystemTime};
    use tempfile::tempdir;
    use tokio::test;

    async fn create_test_storage() -> (FileSystemStorage, tempfile::TempDir) {
        let temp_dir = tempdir().into_diagnostic().unwrap();
        let storage = FileSystemStorage::new(
            Utf8PathBuf::from_path_buf(temp_dir.path().to_path_buf()).unwrap(),
        )
        .await
        .unwrap();
        (storage, temp_dir)
    }

    fn create_test_email(id: &str) -> StoredEmail {
        StoredEmail {
            message_id: id.to_string(),
            from: "sender@example.com".to_string(),
            to: vec!["recipient@example.com".to_string()],
            body: "Test email body".to_string(),
        }
    }

    #[test]
    async fn test_put_and_get() {
        let (storage, _temp) = create_test_storage().await;
        let email = create_test_email("test1");

        // Test put
        let path = storage.put(email.clone(), Status::QUEUED).await.unwrap();
        assert!(path.exists());

        // Test get
        let retrieved = storage.get("test1", Status::QUEUED).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().message_id, "test1");

        // Test get non-existent
        let not_found = storage.get("nonexistent", Status::QUEUED).await.unwrap();
        assert!(not_found.is_none());
    }

    #[test]
    async fn test_delete() {
        let (storage, _temp) = create_test_storage().await;
        let email = create_test_email("test2");

        storage.put(email, Status::QUEUED).await.unwrap();
        storage.delete("test2", Status::QUEUED).await.unwrap();

        let not_found = storage.get("test2", Status::QUEUED).await.unwrap();
        assert!(not_found.is_none());
    }

    #[test]
    async fn test_mv() {
        let (storage, _temp) = create_test_storage().await;
        let email = create_test_email("test3");

        storage.put(email, Status::QUEUED).await.unwrap();
        storage
            .mv("test3", "test3", Status::QUEUED, Status::BOUNCED)
            .await
            .unwrap();

        let not_found = storage.get("test3", Status::QUEUED).await.unwrap();
        assert!(not_found.is_none());

        let found = storage.get("test3", Status::BOUNCED).await.unwrap();
        assert!(found.is_some());
    }

    fn create_test_metadata(id: &str) -> EmailMetadata {
        EmailMetadata {
            msg_id: id.to_string(),
            attempts: 1,
            last_attempt: SystemTime::now(),
            next_attempt: SystemTime::now() + Duration::from_secs(300), // 5 minutes in the future
        }
    }

    #[test]
    async fn test_put_and_get_meta() {
        let (storage, _temp) = create_test_storage().await;
        let meta = create_test_metadata("test_meta");

        // Test put_meta
        let path = storage.put_meta("test_meta", &meta).await.unwrap();
        assert!(path.exists());

        // Test get_meta
        let retrieved = storage.get_meta("test_meta").await.unwrap();
        assert!(retrieved.is_some());
        let retrieved_meta = retrieved.unwrap();
        assert_eq!(retrieved_meta.msg_id, meta.msg_id);
        assert_eq!(retrieved_meta.attempts, meta.attempts);

        // Test get_meta for non-existent key
        let not_found = storage.get_meta("nonexistent").await.unwrap();
        assert!(not_found.is_none());
    }

    #[test]
    async fn test_delete_meta() {
        let (storage, _temp) = create_test_storage().await;
        let meta = create_test_metadata("test_meta_delete");

        // Put and then delete metadata
        storage.put_meta("test_meta_delete", &meta).await.unwrap();
        storage.delete_meta("test_meta_delete").await.unwrap();

        // Verify it's gone
        let not_found = storage.get_meta("test_meta_delete").await.unwrap();
        assert!(not_found.is_none());
    }

    #[test]
    async fn test_list_meta() {
        let (storage, _temp) = create_test_storage().await;

        // Create several metadata entries
        let meta1 = create_test_metadata("test_meta_1");
        let meta2 = create_test_metadata("test_meta_2");

        storage.put_meta("test_meta_1", &meta1).await.unwrap();
        storage.put_meta("test_meta_2", &meta2).await.unwrap();

        // List and collect all metadata
        let mut count = 0;
        let mut collected_ids = Vec::new();
        let mut meta_stream = storage.list_meta();
        while let Some(meta_result) = meta_stream.next().await {
            dbg!(&meta_result);
            let meta = meta_result.unwrap();
            collected_ids.push(meta.msg_id.clone());
            count += 1;
        }

        assert_eq!(count, 2);
        assert!(collected_ids.contains(&"test_meta_1".to_string()));
        assert!(collected_ids.contains(&"test_meta_2".to_string()));
    }

    #[test]
    async fn test_meta_operations_with_email() {
        let (storage, _temp) = create_test_storage().await;
        let email = create_test_email("test_combined");
        let meta = create_test_metadata("test_combined");

        // Store both email and metadata
        storage.put(email.clone(), Status::DEFERRED).await.unwrap();
        storage.put_meta("test_combined", &meta).await.unwrap();

        // Verify both exist
        let retrieved_email = storage
            .get("test_combined", Status::DEFERRED)
            .await
            .unwrap();
        let retrieved_meta = storage.get_meta("test_combined").await.unwrap();

        assert!(retrieved_email.is_some());
        assert!(retrieved_meta.is_some());
        assert_eq!(retrieved_meta.unwrap().msg_id, "test_combined");

        // Delete both
        storage
            .delete("test_combined", Status::DEFERRED)
            .await
            .unwrap();
        storage.delete_meta("test_combined").await.unwrap();

        // Verify both are gone
        let email_not_found = storage
            .get("test_combined", Status::DEFERRED)
            .await
            .unwrap();
        let meta_not_found = storage.get_meta("test_combined").await.unwrap();

        assert!(email_not_found.is_none());
        assert!(meta_not_found.is_none());
    }

    #[test]
    async fn test_meta_timing() {
        let (storage, _temp) = create_test_storage().await;

        // Create metadata with specific timing
        let now = SystemTime::now();
        let mut meta = create_test_metadata("test_timing");
        meta.last_attempt = now - Duration::from_secs(3600); // 1 hour ago
        meta.next_attempt = now + Duration::from_secs(3600); // 1 hour in future

        storage.put_meta("test_timing", &meta).await.unwrap();

        let retrieved = storage.get_meta("test_timing").await.unwrap().unwrap();
        assert!(retrieved.last_attempt <= now);
        assert!(retrieved.next_attempt > now);
    }
}
