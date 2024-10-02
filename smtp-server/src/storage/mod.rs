use async_trait::async_trait;
use camino::Utf8PathBuf;
use futures::Stream;
use miette::Result;
use serde::{Deserialize, Serialize};
use std::pin::Pin;

pub mod fs_storage;

#[derive(Serialize, Deserialize)]
pub struct StoredEmail {
    pub message_id: String,
    pub from: String,
    pub to: Vec<String>,
    pub body: String,
}

#[async_trait]
pub trait Storage: Send + Sync {
    async fn get(&self, key: &str) -> Result<Option<StoredEmail>>;
    async fn put(&self, email: StoredEmail) -> Result<Utf8PathBuf>;
    async fn delete(&self, key: &str) -> Result<()>;
    fn list(&self) -> Pin<Box<dyn Stream<Item = Result<StoredEmail>> + Send>>;
}
