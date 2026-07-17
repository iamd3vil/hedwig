/// File system based storage implementation for email handling.
///
/// This module provides a file system based implementation of the `Storage` trait.
/// Each email is stored as a single-line JSON envelope header followed by the raw
/// message bytes (see `encode_email`), so the message body is written and read
/// verbatim instead of being JSON-escaped. Emails are organized into different
/// directories based on their status (queued, deferred, or bounced).
use crate::{
    storage::{CleanupConfig, Status, Storage, StoredEmail},
    worker::EmailMetadata,
};
use async_trait::async_trait;
use camino::{Utf8Path, Utf8PathBuf};
use chrono::{DateTime, Utc};
use futures::{Stream, StreamExt};
use miette::{miette, Context, IntoDiagnostic, Result};
use serde::{Deserialize, Serialize};
use std::pin::Pin;
use std::time::{Duration, SystemTime};
use tokio::fs;

/// Magic prefix identifying the envelope-header + raw-body file format.
const FORMAT_MAGIC: &[u8] = b"HEDWIG1 ";

/// Envelope fields stored on the first line of an email file. This is
/// `StoredEmail` without the body, which follows as raw bytes.
#[derive(Serialize)]
struct EnvelopeRef<'a> {
    message_id: &'a str,
    from: &'a str,
    to: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    queued_at: Option<DateTime<Utc>>,
}

#[derive(Deserialize)]
struct Envelope {
    message_id: String,
    from: String,
    to: Vec<String>,
    #[serde(default)]
    queued_at: Option<DateTime<Utc>>,
}

/// Serializes an email as a one-line JSON envelope followed by the raw body.
///
/// JSON-encoding the whole email would escape (and later unescape) every body
/// byte, which dominates storage CPU at high message rates.
fn encode_email(email: &StoredEmail) -> Result<Vec<u8>> {
    let envelope = serde_json::to_string(&EnvelopeRef {
        message_id: &email.message_id,
        from: &email.from,
        to: &email.to,
        queued_at: email.queued_at,
    })
    .into_diagnostic()?;

    let mut buf = Vec::with_capacity(FORMAT_MAGIC.len() + envelope.len() + 1 + email.body.len());
    buf.extend_from_slice(FORMAT_MAGIC);
    buf.extend_from_slice(envelope.as_bytes());
    buf.push(b'\n');
    buf.extend_from_slice(email.body.as_bytes());
    Ok(buf)
}

/// Parses an email file in either the current envelope + raw-body format or
/// the legacy whole-file JSON format, so spools written by older versions
/// still replay after an upgrade.
fn decode_email(mut bytes: Vec<u8>) -> Result<StoredEmail> {
    if bytes.starts_with(FORMAT_MAGIC) {
        let newline = memchr::memchr(b'\n', &bytes)
            .ok_or_else(|| miette!("email file has no envelope terminator"))?;
        let body_bytes = bytes.split_off(newline + 1);
        let envelope: Envelope =
            serde_json::from_slice(&bytes[FORMAT_MAGIC.len()..newline]).into_diagnostic()?;
        let body = String::from_utf8(body_bytes)
            .into_diagnostic()
            .wrap_err("email body is not valid UTF-8")?;
        Ok(StoredEmail {
            message_id: envelope.message_id,
            from: envelope.from,
            to: envelope.to,
            body,
            queued_at: envelope.queued_at,
        })
    } else {
        serde_json::from_slice(&bytes).into_diagnostic()
    }
}

/// A storage implementation that uses the file system to store emails and metadata.
///
/// Each email is stored as a JSON file, organized in directories based on their status
/// (queued, deferred, or bounced). The base path contains these status-specific directories.
pub struct FileSystemStorage {
    /// Root directory for all email storage
    base_path: Utf8PathBuf,
}

impl FileSystemStorage {
    /// Creates a new FileSystemStorage instance with the specified base path.
    ///
    /// This will create the necessary directory structure if it doesn't exist:
    /// - base_path/queued/   - for queued emails
    /// - base_path/deferred/ - for deferred emails
    /// - base_path/bounced/  - for bounced emails
    ///
    /// # Arguments
    /// * `base_path` - The root directory path for email storage
    ///
    /// # Returns
    /// * `Result<Self>` - A new FileSystemStorage instance or an error if directory creation fails
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
        let status = [Status::Queued, Status::Deferred, Status::Bounced];
        for s in status.iter() {
            fs::create_dir_all(storage.dir(s))
                .await
                .into_diagnostic()
                .wrap_err("creating status directory")?;
        }

        Ok(storage)
    }

    /// Returns the directory path for a given email status.
    ///
    /// # Arguments
    /// * `status` - The status (QUEUED, DEFERRED, or BOUNCED) to get the directory for
    fn dir(&self, status: &Status) -> Utf8PathBuf {
        match status {
            Status::Queued => self.base_path.join("queued"),
            Status::Deferred => self.base_path.join("deferred"),
            Status::Bounced => self.base_path.join("bounced"),
        }
    }

    /// Constructs the full file path for an email with the given key and status.
    ///
    /// # Arguments
    /// * `key` - The email message ID
    /// * `status` - The status of the email
    fn file_path(&self, key: &str, status: &Status) -> Utf8PathBuf {
        let base_path = self.dir(status);
        base_path.join(format!("{}.json", key))
    }

    /// Constructs the full file path for email metadata with the given key.
    ///
    /// # Arguments
    /// * `key` - The email message ID
    fn meta_file_path(&self, key: &str) -> Utf8PathBuf {
        let base_path = self.dir(&Status::Deferred);
        base_path.join(format!("{}.meta.json", key))
    }

    /// Creates a stream that yields email metadata from the deferred directory.
    ///
    /// This function reads all .meta.json files from the deferred directory and
    /// yields their contents as EmailMetadata objects.
    ///
    /// # Arguments
    /// * `base_path` - The root directory containing the deferred subdirectory
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

    /// Creates a stream that yields stored emails from a specific status directory.
    ///
    /// This function reads all .json files from the specified status directory and
    /// yields their contents as StoredEmail objects.
    ///
    /// # Arguments
    /// * `status` - The status directory to read emails from
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
                    if file_name.ends_with(".json") && !file_name.ends_with(".meta.json") {
                        let contents = fs::read(&path).await.into_diagnostic()?;
                        yield decode_email(contents)?;
                    }
                }
            }
        })
    }

    /// Returns the earliest timestamp considered valid for a given retention duration.
    fn cutoff_time(retention: Duration) -> SystemTime {
        SystemTime::now()
            .checked_sub(retention)
            .unwrap_or(SystemTime::UNIX_EPOCH)
    }

    /// Purges files for the provided status that are older than the retention period.
    async fn cleanup_status_dir(&self, status: Status, retention: Duration) -> Result<()> {
        let dir = self.dir(&status);
        let cutoff = Self::cutoff_time(retention);
        let mut entries = fs::read_dir(&dir).await.into_diagnostic()?;

        while let Some(entry) = entries.next_entry().await.into_diagnostic()? {
            let path = entry.path();
            let file_name = match path.file_name().and_then(|f| f.to_str()) {
                Some(name) => name,
                None => continue,
            };

            if !file_name.ends_with(".json") || file_name.ends_with(".meta.json") {
                continue;
            }

            let metadata = entry.metadata().await.into_diagnostic()?;
            let modified = metadata.modified().into_diagnostic()?;
            if modified < cutoff {
                fs::remove_file(&path).await.into_diagnostic()?;
            }
        }

        Ok(())
    }

    /// Removes deferred messages that exceeded retention, including orphaned JSON bodies.
    async fn cleanup_deferred(&self, retention: Duration) -> Result<()> {
        let now = SystemTime::now();
        let mut meta_stream = self.list_meta();

        while let Some(meta_result) = meta_stream.next().await {
            let metadata = meta_result?;
            let age = now
                .duration_since(metadata.last_attempt)
                .unwrap_or_default();
            if age < retention {
                continue;
            }

            let msg_id = &metadata.msg_id;

            // A body in queued/ means the message is mid-retry and the
            // meta is its only durable attempt count — leave both alone.
            if fs::metadata(self.file_path(msg_id, &Status::Queued))
                .await
                .is_ok()
            {
                continue;
            }

            // Workers run concurrently with cleanup: the message can be
            // requeued or re-deferred (fresh meta) between the snapshot
            // above and the deletes below. Re-read the meta and only act if
            // it is unchanged — a differing or missing meta means the retry
            // machinery touched the message and it is no longer expired.
            match self.get_meta(msg_id).await? {
                Some(current) if current.last_attempt == metadata.last_attempt => {}
                _ => continue,
            }

            // Delete the body first and let its prior existence decide the
            // meta's fate: if the body was already gone, the message either
            // just moved to queued/ (mid-retry — keep the counter) or the
            // meta is a stray from a crash (drop it).
            let body_path = self.file_path(msg_id, &Status::Deferred);
            match fs::remove_file(&body_path).await {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    if fs::metadata(self.file_path(msg_id, &Status::Queued))
                        .await
                        .is_ok()
                    {
                        continue;
                    }
                }
                Err(e) => return Err(e).into_diagnostic(),
            }
            self.delete_meta(msg_id).await?;
        }

        let cutoff = Self::cutoff_time(retention);
        let deferred_dir = self.dir(&Status::Deferred);
        let mut entries = fs::read_dir(&deferred_dir).await.into_diagnostic()?;
        while let Some(entry) = entries.next_entry().await.into_diagnostic()? {
            let path = entry.path();
            let file_name = match path.file_name().and_then(|f| f.to_str()) {
                Some(name) => name,
                None => continue,
            };

            if !file_name.ends_with(".json") || file_name.ends_with(".meta.json") {
                continue;
            }

            let metadata = entry.metadata().await.into_diagnostic()?;
            let modified = metadata.modified().into_diagnostic()?;
            if modified >= cutoff {
                continue;
            }

            let key = file_name.trim_end_matches(".json");
            if fs::metadata(self.meta_file_path(key)).await.is_ok() {
                continue;
            }

            fs::remove_file(&path).await.into_diagnostic()?;
        }

        Ok(())
    }
}

#[async_trait]
impl Storage for FileSystemStorage {
    /// Retrieves an email by its key and status.
    ///
    /// # Arguments
    /// * `key` - The email message ID
    /// * `status` - The status of the email to retrieve
    ///
    /// # Returns
    /// * `Result<Option<StoredEmail>>` - The email if found, None if not found
    async fn get(&self, key: &str, status: Status) -> Result<Option<StoredEmail>> {
        let path = self.file_path(key, &status);
        let contents = match fs::read(&path).await {
            Ok(contents) => contents,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e).into_diagnostic(),
        };
        Ok(Some(decode_email(contents)?))
    }

    /// Stores an email with the specified status.
    ///
    /// # Arguments
    /// * `email` - The email to store
    /// * `status` - The status to store the email under
    ///
    /// # Returns
    /// * `Result<Utf8PathBuf>` - The path where the email was stored
    async fn put(&self, email: StoredEmail, status: Status) -> Result<()> {
        let path = self.file_path(&email.message_id, &status);
        let serialized = encode_email(&email)?;
        fs::write(&path, &serialized).await.into_diagnostic()?;
        Ok(())
    }

    /// Deletes an email by its key and status.
    ///
    /// # Arguments
    /// * `key` - The email message ID
    /// * `status` - The status of the email to delete
    async fn delete(&self, key: &str, status: Status) -> Result<()> {
        let path = self.file_path(key, &status);
        match fs::remove_file(path).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e).into_diagnostic(),
        }
    }

    /// Retrieves metadata for an email by its key.
    ///
    /// # Arguments
    /// * `key` - The email message ID
    ///
    /// # Returns
    /// * `Result<Option<EmailMetadata>>` - The metadata if found, None if not found
    async fn get_meta(&self, key: &str) -> Result<Option<EmailMetadata>> {
        let path = self.meta_file_path(key);
        let contents = match fs::read_to_string(&path).await {
            Ok(contents) => contents,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e).into_diagnostic(),
        };
        let meta: EmailMetadata = serde_json::from_str(&contents).into_diagnostic()?;
        Ok(Some(meta))
    }

    /// Stores metadata for an email.
    ///
    /// # Arguments
    /// * `key` - The email message ID
    /// * `meta` - The metadata to store
    ///
    /// # Returns
    /// * `Result<Utf8PathBuf>` - The path where the metadata was stored
    async fn put_meta(&self, key: &str, meta: &EmailMetadata) -> Result<()> {
        let path = self.meta_file_path(key);
        let json = serde_json::to_string(meta).into_diagnostic()?;
        // The meta is the durable retry counter; an in-place `fs::write`
        // truncates first, so a crash mid-write would corrupt it and reset
        // the attempt count on restart. Write-then-rename keeps the update
        // atomic on the same filesystem.
        let tmp_path = path.with_extension("json.tmp");
        fs::write(&tmp_path, json).await.into_diagnostic()?;
        fs::rename(&tmp_path, &path).await.into_diagnostic()?;
        Ok(())
    }

    /// Deletes metadata for an email.
    ///
    /// # Arguments
    /// * `key` - The email message ID
    async fn delete_meta(&self, key: &str) -> Result<()> {
        let path = self.meta_file_path(key);
        match fs::remove_file(path).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e).into_diagnostic(),
        }
    }

    /// Moves an email from one status to another, potentially with a new key.
    ///
    /// # Arguments
    /// * `src_key` - The source email message ID
    /// * `dest_key` - The destination email message ID
    /// * `src_status` - The source status
    /// * `dest_status` - The destination status
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

    /// Lists all emails with a specific status.
    ///
    /// # Arguments
    /// * `status` - The status of emails to list
    ///
    /// # Returns
    /// * Stream of StoredEmail results
    fn list(&self, status: Status) -> Pin<Box<dyn Stream<Item = Result<StoredEmail>> + Send>> {
        self.create_list_stream(status)
    }

    /// Lists metadata for all emails in the deferred state.
    ///
    /// # Returns
    /// * Stream of EmailMetadata results
    fn list_meta(&self) -> Pin<Box<dyn Stream<Item = Result<EmailMetadata>> + Send>> {
        Self::create_meta_list_stream(self.base_path.clone())
    }

    async fn cleanup(&self, config: &CleanupConfig) -> Result<()> {
        if let Some(retention) = config.bounced_retention {
            self.cleanup_status_dir(Status::Bounced, retention).await?;
        }

        if let Some(retention) = config.deferred_retention {
            self.cleanup_deferred(retention).await?;
        }

        Ok(())
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
            queued_at: None,
        }
    }

    #[test]
    async fn test_put_and_get() {
        let (storage, _temp) = create_test_storage().await;
        let email = create_test_email("test1");

        // Test put
        storage.put(email.clone(), Status::Queued).await.unwrap();

        // Test get
        let retrieved = storage.get("test1", Status::Queued).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().message_id, "test1");

        // Test get non-existent
        let not_found = storage.get("nonexistent", Status::Queued).await.unwrap();
        assert!(not_found.is_none());
    }

    #[test]
    async fn test_put_get_roundtrip_preserves_raw_body() {
        let (storage, _temp) = create_test_storage().await;
        let mut email = create_test_email("raw1");
        // Bytes that JSON escaping used to mangle-and-restore: quotes,
        // backslashes, CRLF line endings, and multibyte UTF-8.
        email.body =
            "Subject: \"quoted\"\r\n\r\nline one\\ two\r\nnaïve 日本語\r\n{\"not\":\"json\"}"
                .to_string();
        email.queued_at = Some(Utc::now());

        storage.put(email.clone(), Status::Queued).await.unwrap();
        let retrieved = storage.get("raw1", Status::Queued).await.unwrap().unwrap();

        assert_eq!(retrieved.message_id, email.message_id);
        assert_eq!(retrieved.from, email.from);
        assert_eq!(retrieved.to, email.to);
        assert_eq!(retrieved.body, email.body);
        assert_eq!(retrieved.queued_at, email.queued_at);
    }

    #[test]
    async fn test_get_reads_legacy_whole_file_json_format() {
        let (storage, _temp) = create_test_storage().await;
        let email = create_test_email("legacy1");

        // Simulate a spool file written by an older version.
        let legacy = serde_json::to_string(&email).unwrap();
        let path = storage.file_path("legacy1", &Status::Queued);
        fs::write(&path, legacy).await.unwrap();

        let retrieved = storage
            .get("legacy1", Status::Queued)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(retrieved.message_id, email.message_id);
        assert_eq!(retrieved.body, email.body);
    }

    #[test]
    async fn test_delete() {
        let (storage, _temp) = create_test_storage().await;
        let email = create_test_email("test2");

        storage.put(email, Status::Queued).await.unwrap();
        storage.delete("test2", Status::Queued).await.unwrap();

        let not_found = storage.get("test2", Status::Queued).await.unwrap();
        assert!(not_found.is_none());
    }

    #[test]
    async fn test_mv() {
        let (storage, _temp) = create_test_storage().await;
        let email = create_test_email("test3");

        storage.put(email, Status::Queued).await.unwrap();
        storage
            .mv("test3", "test3", Status::Queued, Status::Bounced)
            .await
            .unwrap();

        let not_found = storage.get("test3", Status::Queued).await.unwrap();
        assert!(not_found.is_none());

        let found = storage.get("test3", Status::Bounced).await.unwrap();
        assert!(found.is_some());
    }

    fn create_test_metadata(id: &str) -> EmailMetadata {
        EmailMetadata {
            msg_id: id.to_string(),
            attempts: 1,
            last_attempt: SystemTime::now(),
            next_attempt: SystemTime::now() + Duration::from_secs(300), // 5 minutes in the future
            last_error: None,
        }
    }

    #[test]
    async fn test_put_and_get_meta() {
        let (storage, _temp) = create_test_storage().await;
        let meta = create_test_metadata("test_meta");

        // Test put_meta
        storage.put_meta("test_meta", &meta).await.unwrap();

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
        storage.put(email.clone(), Status::Deferred).await.unwrap();
        storage.put_meta("test_combined", &meta).await.unwrap();

        // Verify both exist
        let retrieved_email = storage
            .get("test_combined", Status::Deferred)
            .await
            .unwrap();
        let retrieved_meta = storage.get_meta("test_combined").await.unwrap();

        assert!(retrieved_email.is_some());
        assert!(retrieved_meta.is_some());
        assert_eq!(retrieved_meta.unwrap().msg_id, "test_combined");

        // Delete both
        storage
            .delete("test_combined", Status::Deferred)
            .await
            .unwrap();
        storage.delete_meta("test_combined").await.unwrap();

        // Verify both are gone
        let email_not_found = storage
            .get("test_combined", Status::Deferred)
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

    #[tokio::test]
    async fn test_list() -> Result<()> {
        let (storage, _temp_dir) = create_test_storage().await;

        // Create and store test emails with different statuses
        let email1 = create_test_email("test1");
        let email2 = create_test_email("test2");
        let email3 = create_test_email("test3");

        storage.put(email1.clone(), Status::Queued).await?;
        storage.put(email2.clone(), Status::Queued).await?;
        storage.put(email3.clone(), Status::Deferred).await?;

        // Test listing queued emails
        let mut queued_emails = Vec::new();
        let mut stream = storage.list(Status::Queued);
        while let Some(email) = stream.next().await {
            queued_emails.push(email?);
        }
        assert_eq!(queued_emails.len(), 2);
        assert!(queued_emails.contains(&email1));
        assert!(queued_emails.contains(&email2));

        // Test listing deferred emails
        let mut deferred_emails = Vec::new();
        let mut stream = storage.list(Status::Deferred);
        while let Some(email) = stream.next().await {
            deferred_emails.push(email?);
        }
        assert_eq!(deferred_emails.len(), 1);
        assert!(deferred_emails.contains(&email3));

        // Test listing bounced emails (should be empty)
        let mut bounced_emails = Vec::new();
        let mut stream = storage.list(Status::Bounced);
        while let Some(email) = stream.next().await {
            bounced_emails.push(email?);
        }
        assert_eq!(bounced_emails.len(), 0);

        Ok(())
    }

    #[tokio::test]
    async fn test_cleanup_bounced_removes_old_messages() {
        let (storage, _temp) = create_test_storage().await;
        let email = create_test_email("bounced_old");
        storage.put(email, Status::Bounced).await.unwrap();

        tokio::time::sleep(Duration::from_millis(10)).await;

        let cleanup_config = CleanupConfig {
            bounced_retention: Some(Duration::from_millis(1)),
            ..Default::default()
        };

        storage.cleanup(&cleanup_config).await.unwrap();

        let retrieved = storage.get("bounced_old", Status::Bounced).await.unwrap();
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_cleanup_deferred_removes_old_entries() {
        let (storage, _temp) = create_test_storage().await;
        let email = create_test_email("deferred_old");
        storage.put(email, Status::Deferred).await.unwrap();

        let meta = EmailMetadata {
            msg_id: "deferred_old".to_string(),
            attempts: 3,
            last_attempt: SystemTime::now() - Duration::from_secs(3600),
            next_attempt: SystemTime::now() - Duration::from_secs(300),
            last_error: None,
        };
        storage.put_meta("deferred_old", &meta).await.unwrap();

        let cleanup_config = CleanupConfig {
            deferred_retention: Some(Duration::from_secs(60)),
            ..Default::default()
        };

        storage.cleanup(&cleanup_config).await.unwrap();

        assert!(storage
            .get("deferred_old", Status::Deferred)
            .await
            .unwrap()
            .is_none());
        assert!(storage.get_meta("deferred_old").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_cleanup_deferred_keeps_inflight_retry() {
        let (storage, _temp) = create_test_storage().await;

        // Body is mid-retry in queued/, meta (the durable attempt count) is
        // past retention. Cleanup must not touch either.
        let email = create_test_email("inflight");
        storage.put(email, Status::Queued).await.unwrap();
        let meta = EmailMetadata {
            msg_id: "inflight".to_string(),
            attempts: 4,
            last_attempt: SystemTime::now() - Duration::from_secs(3600),
            next_attempt: SystemTime::now() - Duration::from_secs(300),
            last_error: None,
        };
        storage.put_meta("inflight", &meta).await.unwrap();

        let cleanup_config = CleanupConfig {
            deferred_retention: Some(Duration::from_secs(60)),
            ..Default::default()
        };
        storage.cleanup(&cleanup_config).await.unwrap();

        assert!(storage
            .get("inflight", Status::Queued)
            .await
            .unwrap()
            .is_some());
        let kept = storage.get_meta("inflight").await.unwrap();
        assert_eq!(kept.unwrap().attempts, 4);
    }

    #[tokio::test]
    async fn test_cleanup_deferred_removes_stray_meta() {
        let (storage, _temp) = create_test_storage().await;

        // Meta past retention with a body in neither deferred/ nor queued/ —
        // a stray left by a crash. Cleanup must remove it.
        let meta = EmailMetadata {
            msg_id: "stray".to_string(),
            attempts: 2,
            last_attempt: SystemTime::now() - Duration::from_secs(3600),
            next_attempt: SystemTime::now() - Duration::from_secs(300),
            last_error: None,
        };
        storage.put_meta("stray", &meta).await.unwrap();

        let cleanup_config = CleanupConfig {
            deferred_retention: Some(Duration::from_secs(60)),
            ..Default::default()
        };
        storage.cleanup(&cleanup_config).await.unwrap();

        assert!(storage.get_meta("stray").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_cleanup_deferred_orphaned_email() {
        let (storage, _temp) = create_test_storage().await;
        let email = create_test_email("deferred_orphan");
        storage.put(email, Status::Deferred).await.unwrap();

        tokio::time::sleep(Duration::from_millis(10)).await;

        let cleanup_config = CleanupConfig {
            deferred_retention: Some(Duration::from_millis(1)),
            ..Default::default()
        };

        storage.cleanup(&cleanup_config).await.unwrap();

        assert!(storage
            .get("deferred_orphan", Status::Deferred)
            .await
            .unwrap()
            .is_none());
    }
}
