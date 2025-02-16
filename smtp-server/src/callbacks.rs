/// This file defines the callbacks for the SMTP server.
///
/// This module implements the `SmtpCallbacks` trait, providing the logic for
/// handling SMTP commands such as `EHLO`, `AUTH`, `MAIL FROM`, `RCPT TO`, and `DATA`.
use std::sync::Arc;

use async_trait::async_trait;
use smtp::{Email, SmtpCallbacks, SmtpError};
use ulid::Ulid;

use crate::{
    config::Cfg,
    constant_time_eq,
    storage::{Status, Storage, StoredEmail},
    worker::{self, Job, Worker},
};

/// The Callbacks struct holds the configuration, storage, and sender channel.
pub struct Callbacks {
    cfg: Cfg,
    storage: Arc<dyn Storage>,
    sender_channel: async_channel::Sender<worker::Job>,
}

impl Callbacks {
    /// Creates a new Callbacks instance.
    pub fn new(
        storage: Arc<dyn Storage>,
        sender_channel: async_channel::Sender<Job>,
        receiver_channel: async_channel::Receiver<Job>,
        cfg: Cfg,
    ) -> Self {
        // Start workers.
        let worker_count = cfg.server.workers.unwrap_or(1).max(1);
        for _ in 0..worker_count {
            let receiver_channel = receiver_channel.clone();
            let storage_cloned = storage.clone();
            let dkim = cfg.server.dkim.clone();
            tokio::spawn(async move {
                let mut worker = Worker::new(
                    receiver_channel,
                    storage_cloned.clone(),
                    &dkim,
                    cfg.server.disable_outbound.unwrap_or(false),
                    cfg.server.outbound_local.unwrap_or(false),
                    cfg.server.pool_size.unwrap_or(100),
                )
                .await
                .expect("Failed to create worker");
                worker.run().await;
            });
        }

        Callbacks {
            storage,
            sender_channel,
            cfg,
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
        match &self.cfg.server.auth {
            Some(auth) => {
                // Use constant-time comparison to prevent timing attacks
                let username_match =
                    constant_time_eq(username.as_bytes(), auth.username.as_bytes());
                let password_match =
                    constant_time_eq(password.as_bytes(), auth.password.as_bytes());
                Ok(username_match && password_match)
            }
            None => Ok(false), // Authentication is disabled
        }
    }

    // Handles the MAIL FROM command.
    async fn on_mail_from(&self, _from: &str) -> Result<(), SmtpError> {
        // println!("Mail from: {}", from);
        Ok(())
    }

    // Handles the RCPT TO command.
    async fn on_rcpt_to(&self, _to: &str) -> Result<(), SmtpError> {
        // println!("Rcpt to: {}", to);
        Ok(())
    }

    // Handles the DATA command.
    async fn on_data(&self, email: &Email) -> Result<(), SmtpError> {
        self.process_email(email).await?;
        Ok(())
    }
}
