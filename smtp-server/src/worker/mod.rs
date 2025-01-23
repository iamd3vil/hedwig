use async_channel::Receiver;
use email_address_parser::EmailAddress;
use hickory_resolver::{
    name_server::{GenericConnector, TokioRuntimeProvider},
    AsyncResolver, TokioAsyncResolver,
};
use lettre::{address::Envelope, Address, AsyncSmtpTransport, AsyncTransport, Tokio1Executor};
use mail_auth::common::headers::HeaderWriter;
use mail_auth::{
    common::crypto::{RsaKey, Sha256},
    dkim::DkimSigner,
};
use mail_parser::{Message, MessageParser};
use mail_send::Error;
use miette::{bail, Context, IntoDiagnostic, Result};
// use pool::SmtpClientPool;
use pool::PoolManager;
use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use std::{sync::Arc, time::Duration};
use tokio::fs;
use tracing::{debug, error, info, warn};

use crate::{
    config::CfgDKIM,
    storage::{Status, Storage},
};

pub mod deferred_worker;
mod pool;

const DKIM_HEADERS: [&str; 5] = ["From", "To", "Subject", "Date", "Message-ID"];

#[derive(Serialize, Deserialize, Debug)]
pub struct EmailMetadata {
    pub attempts: u32,
    pub last_attempt: SystemTime,
    pub next_attempt: SystemTime,
    pub msg_id: String,
}

pub struct Worker {
    channel: Receiver<Job>,
    storage: Arc<Box<dyn Storage>>,
    resolver: AsyncResolver<GenericConnector<TokioRuntimeProvider>>,

    pool: PoolManager,
    dkim: Option<CfgDKIM>,

    /// outbound_local when set true, all outbound smtp connections will use unencrypted
    /// connections to the local smtp server. This is useful for testing.
    // outbound_local: bool,

    /// disable_outbound when set true, all outbound emails will be discarded.
    disable_outbound: bool,

    /// initial_delay is the initial delay before retrying a deferred email.
    initial_delay: Duration,

    /// max_delay is the maximum delay before retrying a deferred email.
    max_delay: Duration,
}

impl Worker {
    pub fn new(
        channel: Receiver<Job>,
        storage: Arc<Box<dyn Storage>>,
        dkim: Option<CfgDKIM>,
        disable_outbound: bool,
        outbound_local: bool,
        pool_size: u64,
    ) -> Result<Self> {
        info!("Initializing SMTP worker");
        let resolver = TokioAsyncResolver::tokio_from_system_conf()
            .into_diagnostic()
            .wrap_err("creating dns resolver")?;
        let pool = PoolManager::new(pool_size, outbound_local);
        Ok(Worker {
            channel,
            storage,
            resolver,
            pool,
            dkim,
            disable_outbound,
            initial_delay: Duration::from_secs(60),
            max_delay: Duration::from_secs(60 * 60 * 24),
        })
    }

    pub async fn run(&mut self) {
        loop {
            let job = self.channel.recv().await;
            match job {
                Ok(job) => {
                    if let Err(e) = self.process_job(&job).await {
                        println!("Error processing job: {:?}", e);
                    }
                }
                Err(_) => {
                    break;
                }
            }
        }
    }

    async fn process_job(&self, job: &Job) -> Result<()> {
        debug!(msg_id = ?job.msg_id, "Processing job");
        let email = match self.storage.get(&job.msg_id, Status::QUEUED).await {
            Ok(Some(email)) => email,
            Ok(None) => {
                warn!(msg_id = ?job.msg_id, "Email not found in queue");
                return self.storage.delete(&job.msg_id, Status::QUEUED).await;
            }
            Err(e) => return Err(e).wrap_err("failed to get email from storage"),
        };

        let msg = match MessageParser::default().parse(&email.body) {
            Some(msg) => msg,
            None => {
                error!(msg_id = ?job.msg_id, "Failed to parse email body");
                bail!("failed to parse email body")
            }
        };

        if self.disable_outbound {
            info!(
                msg_id = job.msg_id,
                "Outbound mail disabled, dropping message"
            );
            return self.storage.delete(&job.msg_id, Status::QUEUED).await;
        }

        match self.send_email(&msg, &email.body).await {
            Ok(_) => {
                info!(msg_id = job.msg_id, "Successfully sent email");
                self.storage.delete(&job.msg_id, Status::QUEUED).await?;
                // Delete any meta file in deferred.
                self.storage
                    .delete_meta(&job.msg_id)
                    .await
                    .wrap_err("deleting meta file")?;
                Ok(())
            }
            Err(e) => {
                match e.downcast_ref::<Error>() {
                    Some(Error::UnexpectedReply(resp)) => {
                        if Self::is_retryable(resp.code()) {
                            warn!(
                                msg_id = ?job.msg_id,
                                code = resp.code(),
                                "Retryable error encountered, deferring email"
                            );
                            // Defer the email.
                            println!("Error sending email: {:?}", e);
                            self.defer_email(job).await?;
                        }
                        Ok(())
                    }
                    _ => {
                        error!(msg_id = ?job.msg_id, ?e, "Non-retryable error, bouncing email");
                        // Bounce the email.
                        println!("Error sending email: {:?}", e);
                        self.storage
                            .mv(&job.msg_id, &job.msg_id, Status::QUEUED, Status::BOUNCED)
                            .await
                            .wrap_err("moving from queued to bounced")
                    }
                }
            }
        }
    }

    async fn defer_email(&self, job: &Job) -> Result<()> {
        let delay = self.initial_delay * (2_u32.pow(job.attempts));
        let delay = std::cmp::min(delay, self.max_delay);

        info!(
            msg_id = ?job.msg_id,
            attempts = job.attempts + 1,
            ?delay,
            "Deferring email"
        );

        let meta = EmailMetadata {
            msg_id: job.msg_id.clone(),
            attempts: job.attempts + 1,
            last_attempt: SystemTime::now(),
            next_attempt: SystemTime::now() + delay,
        };

        self.storage
            .put_meta(&job.msg_id, &meta)
            .await
            .wrap_err("storing meta file")?;

        self.storage
            .mv(&job.msg_id, &job.msg_id, Status::QUEUED, Status::DEFERRED)
            .await
            .wrap_err("moving from queued to deferred")?;

        Ok(())
    }

    async fn send_email<'a>(&self, email: &'a Message<'a>, body: &str) -> Result<()> {
        // Parse to address for each.
        for to in email.to().iter() {
            let to = to.first().unwrap().address.as_ref().unwrap();
            let from = email
                .from()
                .unwrap()
                .first()
                .unwrap()
                .address
                .as_ref()
                .unwrap();
            info!(?to, ?from, "Attempting to send email");
            // Strip `<` and `>` from email address.
            let to = to.trim_matches(|c| c == '<' || c == '>');
            let parsed_email_id = EmailAddress::parse(to, None);
            if let None = parsed_email_id {
                continue;
            }

            let parsed_email_id = parsed_email_id.unwrap();

            debug!(?parsed_email_id, "Looking up MX records");

            // Resolve MX record for domain.
            let mx = self
                .resolver
                .mx_lookup(parsed_email_id.get_domain())
                .await
                .into_diagnostic()
                .wrap_err("getting mx record")?;
            if mx.iter().count() == 0 {
                warn!(domain = ?parsed_email_id.get_domain(), "No MX records found");
                continue;
            }

            let from: String = email
                .from()
                .unwrap()
                .first()
                .unwrap()
                .address()
                .as_ref()
                .unwrap()
                .to_string();

            let from_address: Address = from.as_str().parse().unwrap();
            let to_address: Address = to.to_string().parse().unwrap();

            let envelope = Envelope::new(Some(from_address), vec![to_address]).unwrap();

            // Try each MX record in order of preference
            let mut success = false;
            for mx_record in mx.iter().collect::<Vec<_>>() {
                debug!(mx = ?mx_record.exchange(), "Attempting delivery via MX server");

                let transport: AsyncSmtpTransport<Tokio1Executor> =
                    self.pool.get(&mx_record.exchange().to_string()).await?;

                if let Some(dkim) = &self.dkim {
                    debug!("Signing email with DKIM");
                    let priv_key = fs::read(&dkim.private_key)
                        .await
                        .into_diagnostic()
                        .wrap_err("reading private key")?;

                    let priv_key_str = String::from_utf8(priv_key)
                        .into_diagnostic()
                        .wrap_err("converting private key to string")?;

                    let pk_rsa = RsaKey::<Sha256>::from_rsa_pem(&priv_key_str)
                        .expect("error reading priv key");

                    let raw_email = body.as_bytes();
                    let signature = DkimSigner::from_key(pk_rsa)
                        .domain(&dkim.domain)
                        .selector(&dkim.selector)
                        .headers(DKIM_HEADERS)
                        .expiration(60 * 60 * 7)
                        .body_canonicalization(mail_auth::dkim::Canonicalization::Relaxed)
                        .header_canonicalization(mail_auth::dkim::Canonicalization::Relaxed)
                        .sign(raw_email)
                        .into_diagnostic()
                        .wrap_err("signing message")?
                        .to_header();

                    // Insert DKIM signature.
                    let raw_email = Self::insert_dkim_signature(raw_email, &signature)?;

                    transport
                        .send_raw(&envelope, &raw_email)
                        .await
                        .into_diagnostic()
                        .wrap_err("sending raw message, with dkim")?;
                    info!("Successfully sent email with DKIM signature");
                    success = true
                } else {
                    transport
                        .send_raw(&envelope, &body.as_bytes())
                        .await
                        .into_diagnostic()
                        .wrap_err("sending raw message")?;
                    success = true
                };

                if success {
                    break;
                }
            }

            if !success {
                error!(to = ?to, "Failed to send email through any MX server");
                bail!("failed to send email through any MX server");
            }
        }
        Ok(())
    }

    /// Determines if a status code indicates the operation can be retried.
    ///
    /// Retryable codes include:
    /// - 421: Service not available, closing transmission channel
    /// - 450-452, 454, 458: Various temporary failures
    /// - 500-504: Server errors
    /// - 521: Server is down
    /// - 530, 550-554: Authentication/policy failures
    fn is_retryable(code: u16) -> bool {
        const RETRYABLE_CODES: &[u16] = &[
            421, 450, 451, 452, 454, 458, 500, 501, 502, 503, 504, 521, 530, 550, 551, 552, 553,
            554,
        ];
        RETRYABLE_CODES.contains(&code)
    }

    /// Inserts a DKIM signature into a raw email body.
    /// The signature should be inserted after the last existing header but before the message body.
    pub fn insert_dkim_signature(raw_email: &[u8], dkim_signature: &str) -> Result<Vec<u8>> {
        // Convert raw email to string for easier manipulation
        let email_str = String::from_utf8(raw_email.to_vec()).into_diagnostic()?;

        // Find the boundary between headers and body
        // Headers and body are separated by \r\n\r\n according to RFC 5322
        let parts: Vec<&str> = email_str.split("\r\n\r\n").collect();

        if parts.len() < 2 {
            bail!("Invalid email format: Could not find header-body boundary");
        }

        // Split headers into lines
        let headers = parts[0];

        // Format DKIM signature as a proper header
        // Remove any existing DKIM-Signature header if present
        let headers: Vec<&str> = headers
            .lines()
            .filter(|line| !line.starts_with("DKIM-Signature:"))
            .collect();

        // Construct new email with DKIM signature
        let mut new_email = String::with_capacity(email_str.len() + dkim_signature.len() + 100);

        // Add existing headers
        for header in headers {
            new_email.push_str(header);
            new_email.push_str("\r\n");
        }

        // Add DKIM signature
        new_email.push_str(dkim_signature);
        // new_email.push_str("\r\n");
        new_email.push_str("\r\n");
        new_email.push_str(parts[1]);

        // If there are more parts, add all the remaining parts of the email.
        if parts.len() > 2 {
            for part in parts.iter().skip(2) {
                new_email.push_str("\r\n\r\n");
                new_email.push_str(part);
            }
        }

        Ok(new_email.into_bytes())
    }
}

#[derive(Clone, Debug)]
pub struct Job {
    pub msg_id: String,
    pub attempts: u32,
}

impl Job {
    pub fn new(msg_id: String, attempts: u32) -> Job {
        Job { msg_id, attempts }
    }
}
