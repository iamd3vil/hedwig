use async_trait::async_trait;
use miette::Result;
use serde::{Deserialize, Serialize};

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
    async fn put(&self, email: StoredEmail) -> Result<()>;
    async fn delete(&self, key: &str) -> Result<()>;
}
