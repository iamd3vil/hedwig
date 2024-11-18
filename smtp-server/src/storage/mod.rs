use async_trait::async_trait;
use camino::Utf8PathBuf;
use futures::Stream;
use miette::Result;
use serde::{Deserialize, Serialize};
use std::pin::Pin;

use crate::worker::EmailMetadata;

pub mod fs_storage;

#[derive(Serialize, Deserialize, Clone)]
pub struct StoredEmail {
    pub message_id: String,
    pub from: String,
    pub to: Vec<String>,
    pub body: String,
}

pub enum Status {
    QUEUED,
    DEFERRED,
    ERROR,
}

#[async_trait]
pub trait Storage: Send + Sync {
    async fn get(&self, key: &str, status: Status) -> Result<Option<StoredEmail>>;
    async fn put(&self, email: StoredEmail, status: Status) -> Result<Utf8PathBuf>;
    async fn get_meta(&self, key: &str) -> Result<Option<EmailMetadata>>;
    async fn put_meta(&self, key: &str, meta: &EmailMetadata) -> Result<Utf8PathBuf>;
    async fn delete_meta(&self, key: &str) -> Result<()>;
    async fn delete(&self, key: &str, status: Status) -> Result<()>;
    async fn mv(
        &self,
        src_key: &str,
        dest_key: &str,
        src_status: Status,
        dest_status: Status,
    ) -> Result<()>;
    // fn list(&self, status: Status) -> Pin<Box<dyn Stream<Item = Result<StoredEmail>> + Send>>;
    fn list_meta(&self) -> Pin<Box<dyn Stream<Item = Result<EmailMetadata>> + Send>>;
}
