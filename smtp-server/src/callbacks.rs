use email_address_parser::EmailAddress;
use mailparse::MailAddr;
/// This file defines the callbacks for the SMTP server.
///
/// This module implements the `SmtpCallbacks` trait, providing the logic for
/// handling SMTP commands such as `EHLO`, `AUTH`, `MAIL FROM`, `RCPT TO`, and `DATA`.
use std::{collections::HashMap, sync::Arc};
use tracing;

use async_trait::async_trait;
use hickory_resolver::lookup::MxLookup;
use moka::{future::Cache, Expiry};
use smtp::{Email, SmtpCallbacks, SmtpError};
use tokio::sync::Mutex;
use ulid::Ulid;

use crate::{
    config::{Cfg, FilterAction, FilterType},
    constant_time_eq,
    storage::{Status, Storage, StoredEmail},
    worker::{self, Job, Worker},
};

/// The Callbacks struct holds the configuration, storage, and sender channel.
pub struct Callbacks {
    cfg: Cfg,
    auth_mapping: Mutex<HashMap<String, String>>,
    storage: Arc<dyn Storage>,
    sender_channel: async_channel::Sender<worker::Job>,
}

fn extract_domain_from_path(path: &str) -> Option<String> {
    mailparse::addrparse(path).ok().and_then(|addr| {
        if let Some(email) = addr.get(0) {
            match email {
                MailAddr::Single(info) => {
                    return EmailAddress::parse(info.addr.as_ref(), None)
                        .map(|e| e.domain().to_lowercase())
                }
                _ => return None,
            }
        }
        None
    })
}

pub struct MXExpiry;

impl Expiry<String, MxLookup> for MXExpiry {
    fn expire_after_create(
        &self,
        _key: &String,
        value: &MxLookup,
        _created_at: std::time::Instant,
    ) -> Option<std::time::Duration> {
        let valid_until = value.valid_until();
        // Return time from now until the valid_until time.
        let now = std::time::Instant::now();
        if valid_until > now {
            Some(valid_until - now)
        } else {
            None
        }
    }
}

/// The Callbacks struct implements the SmtpCallbacks trait.
impl Callbacks {
    /// Creates a new Callbacks instance.
    pub fn new(
        storage: Arc<dyn Storage>,
        sender_channel: async_channel::Sender<Job>,
        receiver_channel: async_channel::Receiver<Job>,
        cfg: Cfg,
    ) -> Self {
        let expiry = MXExpiry;
        let mx_cache: Cache<_, _> = Cache::builder()
            .max_capacity(10000)
            .expire_after(expiry)
            .build();

        // Start workers.
        let worker_count = cfg.server.workers.unwrap_or(1).max(1);
        for _ in 0..worker_count {
            let receiver_channel = receiver_channel.clone();
            let storage_cloned = storage.clone();
            let dkim = cfg.server.dkim.clone();
            let mx_cache = mx_cache.clone();
            tokio::spawn(async move {
                let mut worker = Worker::new(
                    receiver_channel,
                    storage_cloned.clone(),
                    &dkim,
                    cfg.server.disable_outbound.unwrap_or(false),
                    cfg.server.outbound_local.unwrap_or(false),
                    mx_cache,
                    cfg.server.pool_size.unwrap_or(100),
                )
                .await
                .expect("Failed to create worker");
                worker.run().await;
            });
        }

        // Create the auth mapping.
        let mut auth_mapping = HashMap::new();

        if let Some(auth) = &cfg.server.auth {
            for auth in auth.iter() {
                auth_mapping.insert(auth.username.clone(), auth.password.clone());
            }
        }

        Callbacks {
            storage,
            sender_channel,
            cfg,
            auth_mapping: Mutex::new(auth_mapping),
        }
    }

    /// Processes an email by parsing it, storing it, and sending it to a worker.
    async fn process_email(&self, email: &Email) -> Result<(), SmtpError> {
        let ulid = Ulid::new().to_string();
        // We are using ulid as the message id instead of message_id from the email.
        // The issue is we can't depend on the email client to provide a unique message id.
        let stored_email = StoredEmail {
            message_id: ulid.clone(),
            from: email.from.clone(),
            to: email.to.clone(),
            body: email.body.clone(),
        };
        // Map any error into a SmtpError.
        self.storage
            .put(stored_email, Status::Queued)
            .await
            .map_err(|e| SmtpError::ParseError {
                message: format!("Failed to store email: {}", e),
                span: (0, email.body.len()).into(),
            })?;

        // Send the email to the worker.
        let job = Job::new(ulid, 0);
        self.sender_channel
            .send(job)
            .await
            .map_err(|e| SmtpError::ParseError {
                message: format!("Failed to send email to worker: {}", e),
                span: (0, email.body.len()).into(),
            })?;
        Ok(())
    }
}

// Implements the SmtpCallbacks trait for the Callbacks struct.
#[async_trait]
impl SmtpCallbacks for Callbacks {
    // Handles the EHLO command.
    async fn on_ehlo(&self, _domain: &str) -> Result<(), SmtpError> {
        // println!("EHLO from {}", domain);
        Ok(())
    }

    // Handles the AUTH command.
    async fn on_auth(&self, username: &str, password: &str) -> Result<bool, SmtpError> {
        if self.cfg.server.auth.is_none() {
            return Ok(false);
        }

        let auth_mapping = self.auth_mapping.lock().await;
        if let Some(expected_password) = auth_mapping.get(username) {
            let is_valid = constant_time_eq(password.as_bytes(), expected_password.as_bytes());
            return Ok(is_valid);
        }
        Ok(false)
    }

    // Handles the MAIL FROM command.
    async fn on_mail_from(
        &self,
        from_command: &smtp::parser::MailFromCommand,
    ) -> Result<(), SmtpError> {
        let from_path = &from_command.address;
        let sender_domain_opt: Option<String> = extract_domain_from_path(from_path);

        if let Some(filters) = &self.cfg.filters {
            let from_domain_filters: Vec<_> = filters
                .iter()
                .filter(|f| matches!(f.typ, FilterType::FromDomain))
                .collect();

            if from_domain_filters.is_empty() {
                // No FromDomain filters specifically, so this check passes.
                return Ok(());
            }

            // 1. Check DENY rules
            if let Some(ref sender_domain) = sender_domain_opt {
                for filter in &from_domain_filters {
                    if matches!(filter.action, FilterAction::Deny) {
                        if filter
                            .domain
                            .iter()
                            .any(|d| d.eq_ignore_ascii_case(sender_domain))
                        {
                            let message = format!("Sender domain {} is denied.", sender_domain);
                            tracing::warn!("Denying email from [{}]: {}", from_path, message);
                            return Err(SmtpError::MailFromDenied { message });
                        }
                    }
                }
            }
            // If sender_domain_opt is None, it cannot be denied by a specific domain DENY rule.

            // 2. Check ALLOW rules, if any FromDomain Allow rules exist
            let has_from_domain_allow_rules = from_domain_filters
                .iter()
                .any(|f| matches!(f.action, FilterAction::Allow));

            if has_from_domain_allow_rules {
                let mut explicitly_allowed = false;
                if let Some(ref sender_domain) = sender_domain_opt {
                    for filter in &from_domain_filters {
                        if matches!(filter.action, FilterAction::Allow) {
                            if filter
                                .domain
                                .iter()
                                .any(|d| d.eq_ignore_ascii_case(sender_domain))
                            {
                                explicitly_allowed = true;
                                break;
                            }
                        }
                    }
                }
                // If no domain could be parsed, or if a domain was parsed but didn't match any allow rule,
                // then it's not explicitly allowed.
                if !explicitly_allowed {
                    let message = if let Some(ref sd) = sender_domain_opt {
                        // Ensure 'sd' is used as a reference if sender_domain_opt contained a String
                        format!("Sender domain {} is not in the allowed list.", sd)
                    } else {
                        format!("Sender address '{}' (no domain/unparsable) is not in the allowed list.", from_path)
                    };
                    tracing::warn!("Denying email from [{}]: {}", from_path, message);
                    return Err(SmtpError::MailFromDenied { message });
                }
            }
            // If we reached here:
            // - No DENY rule matched (or sender had no domain to match against specific DENY rules).
            // - AND ( (there are no FromDomain ALLOW rules) OR (an ALLOW rule matched) ).
            // So, allow.
        }

        // If self.cfg.filters is None, or if it's Some but contains no FromDomain filters,
        // or if it passed all applicable FromDomain filters.
        Ok(())
    }

    // Handles the RCPT TO command.
    async fn on_rcpt_to(&self, rcpt_path: &str) -> Result<(), SmtpError> {
        let recipient_domain_opt: Option<String> = extract_domain_from_path(rcpt_path);

        if let Some(filters) = &self.cfg.filters {
            let to_domain_filters: Vec<_> = filters
                .iter()
                .filter(|f| matches!(f.typ, FilterType::ToDomain))
                .collect();

            if to_domain_filters.is_empty() {
                // No ToDomain filters specifically, so this check passes.
                return Ok(());
            }

            // 1. Check DENY rules
            if let Some(ref recipient_domain) = recipient_domain_opt {
                for filter in &to_domain_filters {
                    if matches!(filter.action, FilterAction::Deny) {
                        if filter
                            .domain
                            .iter()
                            .any(|d| d.eq_ignore_ascii_case(recipient_domain))
                        {
                            let message =
                                format!("Recipient domain {} is denied.", recipient_domain);
                            tracing::warn!("Denying email to [{}]: {}", rcpt_path, message);
                            return Err(SmtpError::RcptToDenied { message });
                        }
                    }
                }
            }
            // If recipient_domain_opt is None, it cannot be denied by a specific domain DENY rule.

            // 2. Check ALLOW rules, if any ToDomain Allow rules exist
            let has_to_domain_allow_rules = to_domain_filters
                .iter()
                .any(|f| matches!(f.action, FilterAction::Allow));

            if has_to_domain_allow_rules {
                let mut explicitly_allowed = false;
                if let Some(ref recipient_domain) = recipient_domain_opt {
                    for filter in &to_domain_filters {
                        if matches!(filter.action, FilterAction::Allow) {
                            if filter
                                .domain
                                .iter()
                                .any(|d| d.eq_ignore_ascii_case(recipient_domain))
                            {
                                explicitly_allowed = true;
                                break;
                            }
                        }
                    }
                }
                // If no domain could be parsed, or if a domain was parsed but didn't match any allow rule,
                // then it's not explicitly allowed.
                if !explicitly_allowed {
                    let message = if let Some(ref rd) = recipient_domain_opt {
                        format!("Recipient domain {} is not in the allowed list.", rd)
                    } else {
                        format!("Recipient address '{}' (no domain/unparsable) is not in the allowed list.", rcpt_path)
                    };
                    tracing::warn!("Denying email to [{}]: {}", rcpt_path, message);
                    return Err(SmtpError::RcptToDenied { message });
                }
            }
            // If we reached here:
            // - No DENY rule matched (or recipient had no domain to match against specific DENY rules).
            // - AND ( (there are no ToDomain ALLOW rules) OR (an ALLOW rule matched) ).
            // So, allow.
        }

        // If self.cfg.filters is None, or if it's Some but contains no ToDomain filters,
        // or if it passed all applicable ToDomain filters.
        Ok(())
    }

    // Handles the DATA command.
    async fn on_data(&self, email: &Email) -> Result<(), SmtpError> {
        self.process_email(email).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CfgAuth, CfgFilter, CfgLog, CfgServer, CfgStorage};
    use crate::worker::EmailMetadata;
    use camino::Utf8PathBuf;
    use futures::{stream, Stream};
    use miette::Result;
    use std::pin::Pin;

    // Mock Storage implementation for testing
    #[derive(Debug, Clone)]
    struct MockStorage;

    #[async_trait]
    impl Storage for MockStorage {
        async fn get(&self, _key: &str, _status: Status) -> Result<Option<StoredEmail>> {
            Ok(None)
        }

        async fn put(&self, _email: StoredEmail, _status: Status) -> Result<Utf8PathBuf> {
            // The actual path doesn't matter for current tests, but it must be a Utf8PathBuf
            Ok(Utf8PathBuf::from("mock/path/to/email"))
        }

        async fn get_meta(&self, _key: &str) -> Result<Option<EmailMetadata>> {
            Ok(None)
        }

        async fn put_meta(&self, _key: &str, _meta: &EmailMetadata) -> Result<Utf8PathBuf> {
            Ok(Utf8PathBuf::from("mock/path/to/meta"))
        }

        async fn delete_meta(&self, _key: &str) -> Result<()> {
            Ok(())
        }

        async fn delete(&self, _key: &str, _status: Status) -> Result<()> {
            Ok(())
        }

        async fn mv(
            &self,
            _src_key: &str,
            _dest_key: &str,
            _src_status: Status,
            _dest_status: Status,
        ) -> Result<()> {
            Ok(())
        }

        fn list(&self, _status: Status) -> Pin<Box<dyn Stream<Item = Result<StoredEmail>> + Send>> {
            Box::pin(stream::empty())
        }

        fn list_meta(&self) -> Pin<Box<dyn Stream<Item = Result<EmailMetadata>> + Send>> {
            Box::pin(stream::empty())
        }
    }

    // Helper function to create Callbacks instance for tests
    fn create_test_callbacks(filters: Option<Vec<CfgFilter>>) -> Callbacks {
        let cfg = Cfg {
            log: CfgLog::default(),
            server: CfgServer {
                addr: "127.0.0.1:2525".to_string(),
                workers: Some(1),
                max_retries: Some(3),
                auth: Some(vec![CfgAuth {
                    username: "testuser".to_string(),
                    password: "testpassword".to_string(),
                }]),
                dkim: None,
                disable_outbound: Some(false),
                outbound_local: Some(false),
                pool_size: Some(10),
                tls: None,
            },
            storage: CfgStorage {
                storage_type: "mock".to_string(),
                base_path: "/tmp/hedwig".to_string(),
            },
            filters,
        };

        let (sender_channel, receiver_channel) = async_channel::unbounded::<worker::Job>();
        let storage: Arc<dyn Storage> = Arc::new(MockStorage);

        Callbacks::new(storage, sender_channel, receiver_channel, cfg)
    }

    fn create_mail_from_command(address: &str) -> smtp::parser::MailFromCommand {
        smtp::parser::MailFromCommand {
            address: address.to_string(),
            size: None,
            other_params: vec![],
        }
    }

    // Tests for on_mail_from
    #[tokio::test]
    async fn test_on_mail_from_no_filters() {
        let callbacks = create_test_callbacks(None);
        let result = callbacks
            .on_mail_from(&create_mail_from_command("test@example.com"))
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_on_mail_from_allow_domain_match() {
        let filters = vec![CfgFilter {
            typ: FilterType::FromDomain,
            domain: vec!["example.com".to_string()],
            action: FilterAction::Allow,
        }];
        let callbacks = create_test_callbacks(Some(filters));
        let result = callbacks
            .on_mail_from(&create_mail_from_command("test@example.com"))
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_on_mail_from_allow_domain_no_match() {
        let filters = vec![CfgFilter {
            typ: FilterType::FromDomain,
            domain: vec!["another.com".to_string()],
            action: FilterAction::Allow,
        }];
        let callbacks = create_test_callbacks(Some(filters));
        let result = callbacks
            .on_mail_from(&create_mail_from_command("test@example.com"))
            .await;
        assert!(result.is_err());
        if let Err(SmtpError::MailFromDenied { message }) = result {
            assert_eq!(
                message,
                "Sender domain example.com is not in the allowed list."
            );
        } else {
            panic!("Expected MailFromDenied error");
        }
    }

    #[tokio::test]
    async fn test_on_mail_from_allow_domain_no_match_path_no_domain() {
        let filters = vec![CfgFilter {
            typ: FilterType::FromDomain,
            domain: vec!["example.com".to_string()],
            action: FilterAction::Allow,
        }];
        let callbacks = create_test_callbacks(Some(filters));
        let result = callbacks
            .on_mail_from(&create_mail_from_command("testuser"))
            .await; // No domain in from_path
        assert!(result.is_err());
        if let Err(SmtpError::MailFromDenied { message }) = result {
            assert_eq!(
                message,
                "Sender address \'testuser\' (no domain/unparsable) is not in the allowed list."
            );
        } else {
            panic!("Expected MailFromDenied error");
        }
    }

    #[tokio::test]
    async fn test_on_mail_from_deny_domain_match() {
        let filters = vec![CfgFilter {
            typ: FilterType::FromDomain,
            domain: vec!["example.com".to_string()],
            action: FilterAction::Deny,
        }];
        let callbacks = create_test_callbacks(Some(filters));
        let result = callbacks
            .on_mail_from(&create_mail_from_command("test@example.com"))
            .await;
        assert!(result.is_err());
        if let Err(SmtpError::MailFromDenied { message }) = result {
            assert_eq!(message, "Sender domain example.com is denied.");
        } else {
            panic!("Expected MailFromDenied error");
        }
    }

    #[tokio::test]
    async fn test_on_mail_from_deny_domain_no_match() {
        let filters = vec![CfgFilter {
            typ: FilterType::FromDomain,
            domain: vec!["another.com".to_string()],
            action: FilterAction::Deny,
        }];
        let callbacks = create_test_callbacks(Some(filters));
        let result = callbacks
            .on_mail_from(&create_mail_from_command("test@example.com"))
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_on_mail_from_deny_allow_interaction_denied() {
        let filters = vec![
            CfgFilter {
                // Deny example.com
                typ: FilterType::FromDomain,
                domain: vec!["example.com".to_string()],
                action: FilterAction::Deny,
            },
            CfgFilter {
                // Allow specific.example.com
                typ: FilterType::FromDomain,
                domain: vec!["specific.example.com".to_string()],
                action: FilterAction::Allow,
            },
        ];
        let callbacks = create_test_callbacks(Some(filters));
        // This should be denied because example.com is denied, even if specific.example.com is on an allow list.
        // Deny rules take precedence if matched.
        let result = callbacks
            .on_mail_from(&create_mail_from_command("user@example.com"))
            .await;
        assert!(result.is_err());
        if let Err(SmtpError::MailFromDenied { message }) = result {
            assert_eq!(message, "Sender domain example.com is denied.");
        } else {
            panic!("Expected MailFromDenied error for user@example.com");
        }
    }

    #[tokio::test]
    async fn test_on_mail_from_deny_allow_interaction_allowed() {
        let filters = vec![
            CfgFilter {
                // Deny bad.com
                typ: FilterType::FromDomain,
                domain: vec!["bad.com".to_string()],
                action: FilterAction::Deny,
            },
            CfgFilter {
                // Allow example.com
                typ: FilterType::FromDomain,
                domain: vec!["example.com".to_string()],
                action: FilterAction::Allow,
            },
        ];
        let callbacks = create_test_callbacks(Some(filters));
        // Allowed because example.com is explicitly allowed and not bad.com
        let result_allowed = callbacks
            .on_mail_from(&create_mail_from_command("user@example.com"))
            .await;
        assert!(result_allowed.is_ok());

        // Denied because bad.com is denied
        let result_denied = callbacks
            .on_mail_from(&create_mail_from_command("user@bad.com"))
            .await;
        assert!(result_denied.is_err());
        if let Err(SmtpError::MailFromDenied { message }) = result_denied {
            assert_eq!(message, "Sender domain bad.com is denied.");
        } else {
            panic!("Expected MailFromDenied error for user@bad.com");
        }
    }

    #[tokio::test]
    async fn test_on_mail_from_only_allow_not_matching_path_no_domain() {
        let filters = vec![CfgFilter {
            typ: FilterType::FromDomain,
            domain: vec!["example.com".to_string()],
            action: FilterAction::Allow,
        }];
        let callbacks = create_test_callbacks(Some(filters));
        let result = callbacks
            .on_mail_from(&create_mail_from_command("<testuser>"))
            .await; // no domain
        assert!(result.is_err());
        if let Err(SmtpError::MailFromDenied { message }) = result {
            assert_eq!(
                message,
                "Sender address \'<testuser>\' (no domain/unparsable) is not in the allowed list."
            );
        } else {
            panic!("Expected MailFromDenied error");
        }
    }

    // Tests for on_rcpt_to
    #[tokio::test]
    async fn test_on_rcpt_to_no_filters() {
        let callbacks = create_test_callbacks(None);
        let result = callbacks.on_rcpt_to("test@example.com").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_on_rcpt_to_allow_domain_match() {
        let filters = vec![CfgFilter {
            typ: FilterType::ToDomain,
            domain: vec!["example.com".to_string()],
            action: FilterAction::Allow,
        }];
        let callbacks = create_test_callbacks(Some(filters));
        let result = callbacks.on_rcpt_to("test@example.com").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_on_rcpt_to_allow_domain_no_match() {
        let filters = vec![CfgFilter {
            typ: FilterType::ToDomain,
            domain: vec!["another.com".to_string()],
            action: FilterAction::Allow,
        }];
        let callbacks = create_test_callbacks(Some(filters));
        let result = callbacks.on_rcpt_to("test@example.com").await;
        assert!(result.is_err());
        if let Err(SmtpError::RcptToDenied { message }) = result {
            assert_eq!(
                message,
                "Recipient domain example.com is not in the allowed list."
            );
        } else {
            panic!("Expected RcptToDenied error");
        }
    }

    #[tokio::test]
    async fn test_on_rcpt_to_allow_domain_no_match_path_no_domain() {
        let filters = vec![CfgFilter {
            typ: FilterType::ToDomain,
            domain: vec!["example.com".to_string()],
            action: FilterAction::Allow,
        }];
        let callbacks = create_test_callbacks(Some(filters));
        let result = callbacks.on_rcpt_to("testuser").await; // No domain
        assert!(result.is_err());
        if let Err(SmtpError::RcptToDenied { message }) = result {
            assert_eq!(
                message,
                "Recipient address \'testuser\' (no domain/unparsable) is not in the allowed list."
            );
        } else {
            panic!("Expected RcptToDenied error");
        }
    }

    #[tokio::test]
    async fn test_on_rcpt_to_deny_domain_match() {
        let filters = vec![CfgFilter {
            typ: FilterType::ToDomain,
            domain: vec!["example.com".to_string()],
            action: FilterAction::Deny,
        }];
        let callbacks = create_test_callbacks(Some(filters));
        let result = callbacks.on_rcpt_to("test@example.com").await;
        assert!(result.is_err());
        if let Err(SmtpError::RcptToDenied { message }) = result {
            assert_eq!(message, "Recipient domain example.com is denied.");
        } else {
            panic!("Expected RcptToDenied error");
        }
    }

    #[tokio::test]
    async fn test_on_rcpt_to_deny_domain_no_match() {
        let filters = vec![CfgFilter {
            typ: FilterType::ToDomain,
            domain: vec!["another.com".to_string()],
            action: FilterAction::Deny,
        }];
        let callbacks = create_test_callbacks(Some(filters));
        let result = callbacks.on_rcpt_to("test@example.com").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_on_rcpt_to_deny_allow_interaction_denied() {
        let filters = vec![
            CfgFilter {
                // Deny example.com
                typ: FilterType::ToDomain,
                domain: vec!["example.com".to_string()],
                action: FilterAction::Deny,
            },
            CfgFilter {
                // Allow specific.example.com
                typ: FilterType::ToDomain,
                domain: vec!["specific.example.com".to_string()],
                action: FilterAction::Allow,
            },
        ];
        let callbacks = create_test_callbacks(Some(filters));

        let result = callbacks.on_rcpt_to("user@example.com").await;
        assert!(result.is_err());
        if let Err(SmtpError::RcptToDenied { message }) = result {
            assert_eq!(message, "Recipient domain example.com is denied.");
        } else {
            panic!("Expected RcptToDenied error for user@example.com");
        }
    }

    #[tokio::test]
    async fn test_on_rcpt_to_deny_allow_interaction_allowed() {
        let filters = vec![
            CfgFilter {
                // Deny bad.com
                typ: FilterType::ToDomain,
                domain: vec!["bad.com".to_string()],
                action: FilterAction::Deny,
            },
            CfgFilter {
                // Allow example.com
                typ: FilterType::ToDomain,
                domain: vec!["example.com".to_string()],
                action: FilterAction::Allow,
            },
        ];
        let callbacks = create_test_callbacks(Some(filters));
        // Allowed because example.com is explicitly allowed and not bad.com
        let result_allowed = callbacks.on_rcpt_to("user@example.com").await;
        assert!(result_allowed.is_ok());

        // Denied because bad.com is denied
        let result_denied = callbacks.on_rcpt_to("user@bad.com").await;
        assert!(result_denied.is_err());
        if let Err(SmtpError::RcptToDenied { message }) = result_denied {
            assert_eq!(message, "Recipient domain bad.com is denied.");
        } else {
            panic!("Expected RcptToDenied error for user@bad.com");
        }
    }

    #[tokio::test]
    async fn test_extract_domain_from_path_normal() {
        assert_eq!(
            extract_domain_from_path("test@example.com"),
            Some("example.com".to_string())
        );
    }

    #[tokio::test]
    async fn test_extract_domain_from_full_email_addr() {
        assert_eq!(
            extract_domain_from_path("Testing <testing@hedwig.example.com>"),
            Some("hedwig.example.com".to_string())
        );
    }

    #[tokio::test]
    async fn test_extract_domain_from_path_with_angle_brackets() {
        assert_eq!(
            extract_domain_from_path("<test@example.com>"),
            Some("example.com".to_string())
        );
    }

    #[tokio::test]
    async fn test_extract_domain_from_path_no_domain() {
        assert_eq!(extract_domain_from_path("testuser"), None);
    }

    #[tokio::test]
    async fn test_extract_domain_from_path_empty_string() {
        assert_eq!(extract_domain_from_path(""), None);
    }

    #[tokio::test]
    async fn test_extract_domain_from_path_just_at() {
        assert_eq!(extract_domain_from_path("@"), None);
    }

    #[tokio::test]
    async fn test_extract_domain_from_path_malformed() {
        assert_eq!(extract_domain_from_path("test@"), None); // Or None, depending on desired strictness
        assert_eq!(extract_domain_from_path("@domain.com"), None);
    }
}
