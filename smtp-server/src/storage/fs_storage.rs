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
