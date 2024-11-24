use async_channel::Receiver;
use email_address_parser::EmailAddress;
use hickory_resolver::{
    name_server::{GenericConnector, TokioRuntimeProvider},
    AsyncResolver, TokioAsyncResolver,
};
use mail_parser::{Message, MessageParser};
use mail_send::{
    mail_auth::{
        common::crypto::{RsaKey, Sha256},
        dkim::DkimSigner,
    },
    smtp::message::Message as EmailMessage,
    Error,
};
use miette::{bail, Context, IntoDiagnostic, Result};
use pool::SmtpClientPool;
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
    pool: SmtpClientPool,
    dkim: Option<CfgDKIM>,
    disable_outbound: bool,
    initial_delay: Duration,
    max_delay: Duration,
}

impl Worker {
    pub fn new(
        channel: Receiver<Job>,
        storage: Arc<Box<dyn Storage>>,
        dkim: Option<CfgDKIM>,
        disable_outbound: bool,
    ) -> Result<Self> {
        info!("Initializing SMTP worker");
        let resolver = TokioAsyncResolver::tokio_from_system_conf()
            .into_diagnostic()
            .wrap_err("creating dns resolver")?;
        let pool = SmtpClientPool::new();
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

        match self.send_email(&msg).await {
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

    async fn send_email<'a>(&self, email: &'a Message<'a>) -> Result<()> {
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

            let raw_message = email.raw_message.clone();
            let message = EmailMessage::new(from.to_string(), vec![to.to_string()], raw_message);

            // Try each MX record in order of preference
            let mut success = false;
            for mx_record in mx.iter().collect::<Vec<_>>() {
                debug!(mx = ?mx_record.exchange(), "Attempting delivery via MX server");
                match self
                    .pool
                    .get_client(mx_record.exchange().to_string().as_ref(), 25)
                    .await
                {
                    Ok(mut client) => {
                        // If we get a client, try to send the email
                        let result = if let Some(dkim) = &self.dkim {
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

                            let signer = DkimSigner::from_key(pk_rsa)
                                .domain(&dkim.domain)
                                .selector(&dkim.selector)
                                .headers(["From", "To", "Subject"])
                                .expiration(60 * 60 * 7);

                            client.send_signed(message.clone(), &signer).await
                        } else {
                            client.send(message.clone()).await
                        };

                        match result {
                            Ok(_) => {
                                info!(mx = ?mx_record.exchange(), "Email sent successfully");
                                success = true;
                                break;
                            }
                            Err(e) => {
                                warn!(mx = ?mx_record.exchange(), ?e, "Failed to send via MX server");
                                continue;
                            }
                        }
                    }
                    Err(e) => {
                        warn!(mx = ?mx_record.exchange(), ?e, "Failed to connect to MX server");
                        continue;
                    }
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
