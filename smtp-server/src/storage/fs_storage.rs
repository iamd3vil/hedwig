use crate::storage::{Status, Storage, StoredEmail};
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

        // Create queued, deferred, and error directories.
        let status = [Status::QUEUED, Status::DEFERRED, Status::ERROR];
        for s in status.iter() {
            fs::create_dir_all(base_path.as_ref().join(match s {
                Status::QUEUED => "queued",
                Status::DEFERRED => "deferred",
                Status::ERROR => "error",
            }))
            .await
            .into_diagnostic()
            .wrap_err("creating status directory")?;
        }

        Ok(FileSystemStorage {
            base_path: base_path.as_ref().to_owned(),
        })
    }

    fn dir(&self, status: Status) -> Utf8PathBuf {
        match status {
            Status::QUEUED => self.base_path.join("queued"),
            Status::DEFERRED => self.base_path.join("deferred"),
            Status::ERROR => self.base_path.join("error"),
        }
    }

    fn file_path(&self, key: &str, status: Status) -> Utf8PathBuf {
        let base_path = self.dir(status);
        base_path.join(format!("{}.json", key))
    }

    fn create_list_stream(
        base_path: Utf8PathBuf,
        status: Status,
    ) -> Pin<Box<dyn Stream<Item = Result<StoredEmail>> + Send>> {
        Box::pin(async_stream::try_stream! {
            let base_path = base_path.join(match status {
                Status::QUEUED => "queued",
                Status::DEFERRED => "deferred",
                Status::ERROR => "error",
            }).clone();
            let mut entries = fs::read_dir(&base_path).await.into_diagnostic()?;
            while let Some(entry) = entries.next_entry().await.into_diagnostic()? {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("json") {
                    let contents = fs::read_to_string(&path).await.into_diagnostic()?;
                    let email: StoredEmail = serde_json::from_str(&contents).into_diagnostic()?;
                    yield email;
                }
            }
        })
    }
}

#[async_trait]
impl Storage for FileSystemStorage {
    async fn get(&self, key: &str, status: Status) -> Result<Option<StoredEmail>> {
        let path = self.file_path(key, status);
        if path.exists() {
            let contents = fs::read_to_string(&path).await.into_diagnostic()?;
            let email: StoredEmail = serde_json::from_str(&contents).into_diagnostic()?;
            Ok(Some(email))
        } else {
            Ok(None)
        }
    }

    async fn put(&self, email: StoredEmail, status: Status) -> Result<Utf8PathBuf> {
        let path = self.file_path(&email.message_id, status);
        let json = serde_json::to_string(&email).into_diagnostic()?;
        fs::write(&path, json).await.into_diagnostic()?;
        Ok(path)
    }

    async fn delete(&self, key: &str, status: Status) -> Result<()> {
        let path = self.file_path(key, status);
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
        let src_path = self.file_path(src_key, src_status);
        let dest_path = self.file_path(dest_key, dest_status);
        fs::rename(src_path, dest_path).await.into_diagnostic()?;
        Ok(())
    }

    fn list(&self, status: Status) -> Pin<Box<dyn Stream<Item = Result<StoredEmail>> + Send>> {
        Self::create_list_stream(self.base_path.clone(), status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;
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
            .mv("test3", "test3", Status::QUEUED, Status::ERROR)
            .await
            .unwrap();

        let not_found = storage.get("test3", Status::QUEUED).await.unwrap();
        assert!(not_found.is_none());

        let found = storage.get("test3", Status::ERROR).await.unwrap();
        assert!(found.is_some());
    }

    #[test]
    async fn test_list() {
        let (storage, _temp) = create_test_storage().await;

        // Add multiple emails
        for i in 1..=3 {
            let email = create_test_email(&format!("test{}", i));
            storage.put(email, Status::QUEUED).await.unwrap();
        }

        let mut count = 0;
        let mut list_stream = storage.list(Status::QUEUED);
        while let Some(result) = list_stream.next().await {
            let email = result.unwrap();
            assert!(email.message_id.starts_with("test"));
            count += 1;
        }
        assert_eq!(count, 3);
    }
}
