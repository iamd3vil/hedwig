use async_trait::async_trait;
use camino::Utf8PathBuf;
use futures::Stream;
use miette::Result;
use serde::{Deserialize, Serialize};
use std::{pin::Pin, time::Duration};

use crate::worker::EmailMetadata;

pub mod fs_storage;

#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct StoredEmail {
    pub message_id: String,
    pub from: String,
    pub to: Vec<String>,
    pub body: String,
}

pub enum Status {
    Queued,
    Deferred,
    Bounced,
}

/// Runtime configuration controlling storage cleanup behaviour.
#[derive(Debug, Clone)]
pub struct CleanupConfig {
    pub deferred_retention: Option<Duration>,
    pub bounced_retention: Option<Duration>,
    pub interval: Duration,
}

impl CleanupConfig {
    pub fn is_enabled(&self) -> bool {
        self.deferred_retention.is_some() || self.bounced_retention.is_some()
    }
}

impl Default for CleanupConfig {
    fn default() -> Self {
        Self {
            deferred_retention: None,
            bounced_retention: None,
            interval: Duration::from_secs(60 * 60),
        }
    }
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
    fn list(&self, status: Status) -> Pin<Box<dyn Stream<Item = Result<StoredEmail>> + Send>>;
    fn list_meta(&self) -> Pin<Box<dyn Stream<Item = Result<EmailMetadata>> + Send>>;
    /// Performs backend-specific cleanup according to the provided retention policy.
    ///
    /// Default implementation is a no-op so alternative storage backends can opt in
    /// to cleanup by overriding this method.
    async fn cleanup(&self, _config: &CleanupConfig) -> Result<()> {
        Ok(())
    }
}
