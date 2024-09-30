use crate::storage::{Storage, StoredEmail};
use async_trait::async_trait;
use camino::{Utf8Path, Utf8PathBuf};
use miette::{IntoDiagnostic, Result};
use serde_json;
use tokio::fs;

pub struct FileSystemStorage {
    base_path: Utf8PathBuf,
}

impl FileSystemStorage {
    pub fn new<P: AsRef<Utf8Path>>(base_path: P) -> Self {
        FileSystemStorage {
            base_path: base_path.as_ref().to_owned(),
        }
    }

    fn file_path(&self, key: &str) -> Utf8PathBuf {
        self.base_path.join(format!("{}.json", key))
    }
}

#[async_trait]
impl Storage for FileSystemStorage {
    async fn get(&self, key: &str) -> Result<Option<StoredEmail>> {
        let path = self.file_path(key);
        if path.exists() {
            let contents = fs::read_to_string(&path).await.into_diagnostic()?;
            let email: StoredEmail = serde_json::from_str(&contents).into_diagnostic()?;
            Ok(Some(email))
        } else {
            Ok(None)
        }
    }

    async fn put(&self, email: StoredEmail) -> Result<()> {
        let path = self.file_path(&email.message_id);
        let json = serde_json::to_string(&email).into_diagnostic()?;
        fs::write(path, json).await.into_diagnostic()?;
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let path = self.file_path(key);
        if path.exists() {
            fs::remove_file(path).await.into_diagnostic()?;
        }
        Ok(())
    }
}
