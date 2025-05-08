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
    let mut email_part = path.trim();
    if email_part.starts_with('<') && email_part.ends_with('>') {
        email_part = &email_part[1..email_part.len() - 1];
    }
    email_part.rsplit_once('@').map(|(_, domain)| domain.to_lowercase())
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
    async fn on_mail_from(&self, from_path: &str) -> Result<(), SmtpError> {
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
                        if filter.domain.iter().any(|d| d.eq_ignore_ascii_case(sender_domain)) {
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
                            if filter.domain.iter().any(|d| d.eq_ignore_ascii_case(sender_domain)) {
                                explicitly_allowed = true;
                                break;
                            }
                        }
                    }
                }
                // If no domain could be parsed, or if a domain was parsed but didn't match any allow rule,
                // then it's not explicitly allowed.
                if !explicitly_allowed {
                    let message = if let Some(ref sd) = sender_domain_opt { // Ensure 'sd' is used as a reference if sender_domain_opt contained a String
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
    async fn on_rcpt_to(&self, _to: &str) -> Result<(), SmtpError> {
        Ok(())
    }

    // Handles the DATA command.
    async fn on_data(&self, email: &Email) -> Result<(), SmtpError> {
        self.process_email(email).await?;
        Ok(())
    }
}
