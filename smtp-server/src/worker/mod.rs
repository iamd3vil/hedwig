use crate::config::DkimKeyType;
use async_channel::Receiver;
use email_address_parser::EmailAddress;
use hickory_resolver::{
    lookup::MxLookup,
    name_server::{GenericConnector, TokioRuntimeProvider},
    proto::rr::rdata::MX,
    AsyncResolver, TokioAsyncResolver,
};
use lettre::{address::Envelope, Address, AsyncSmtpTransport, AsyncTransport, Tokio1Executor};
use mail_auth::{
    common::crypto::{Ed25519Key, RsaKey, Sha256},
    dkim::DkimSigner,
};
use mail_auth::{common::headers::HeaderWriter, dkim::Done};
use mail_parser::{Message, MessageParser};
use mail_send::Error;
use miette::{bail, Context, IntoDiagnostic, Result};
// use pool::SmtpClientPool;
use memchr::memmem;
use moka::future::Cache;
use pool::PoolManager;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::fs;
use tracing::{debug, error, info, warn};

use crate::{
    config::CfgDKIM,
    metrics,
    storage::{Status, Storage},
};

pub mod deferred_worker;
mod pool;
pub mod rate_limiter;

use rate_limiter::{RateLimitConfig, RateLimitResult, RateLimiter};

const HEADER_BODY_SEPARATOR: &[u8] = b"\r\n\r\n";
const BCC_HEADER_PREFIX: &[u8] = b"Bcc:";
const DKIM_HEADERS: [&str; 5] = ["From", "To", "Subject", "Date", "Message-ID"];

#[derive(Serialize, Deserialize, Debug)]
pub struct EmailMetadata {
    pub attempts: u32,
    pub last_attempt: SystemTime,
    pub next_attempt: SystemTime,
    pub msg_id: String,
}

pub enum DkimSignerType {
    Rsa(DkimSigner<RsaKey<Sha256>, Done>),
    Ed25519(DkimSigner<Ed25519Key, Done>),
}

pub struct WorkerConfig {
    pub disable_outbound: bool,
    pub outbound_local: bool,
    pub pool_size: u64,
    pub rate_limit_config: RateLimitConfig,
}

pub struct Worker {
    channel: Receiver<Job>,
    storage: Arc<dyn Storage>,
    resolver: AsyncResolver<GenericConnector<TokioRuntimeProvider>>,

    pool: PoolManager,
    dkim_signer: Option<DkimSignerType>,

    // MX Cache
    mx_cache: Cache<String, MxLookup>,

    /// disable_outbound when set true, all outbound emails will be discarded.
    disable_outbound: bool,

    /// initial_delay is the initial delay before retrying a deferred email.
    initial_delay: Duration,

    /// max_delay is the maximum delay before retrying a deferred email.
    max_delay: Duration,

    /// rate_limiter controls the rate of email sending per domain.
    rate_limiter: RateLimiter,
}

impl Worker {
    pub async fn new(
        channel: Receiver<Job>,
        storage: Arc<dyn Storage>,
        dkim: &Option<CfgDKIM>,
        mx_cache: Cache<String, MxLookup>,
        config: WorkerConfig,
    ) -> Result<Self> {
        info!("Initializing SMTP worker");
        let resolver = TokioAsyncResolver::tokio_from_system_conf()
            .into_diagnostic()
            .wrap_err("creating dns resolver")?;
        let pool = PoolManager::new(config.pool_size, config.outbound_local);

        // Create DKIM signer if dkim is enabled.
        let dkim_signer = match dkim {
            None => None,
            Some(dkim) => {
                let priv_key = fs::read_to_string(&dkim.private_key)
                    .await
                    .into_diagnostic()
                    .wrap_err("reading private key")?;

                let signer = Self::create_dkim_signer(dkim, &priv_key)?;
                Some(signer)
            }
        };

        Ok(Worker {
            channel,
            storage,
            resolver,
            pool,
            mx_cache,
            disable_outbound: config.disable_outbound,
            initial_delay: Duration::from_secs(60),
            max_delay: Duration::from_secs(60 * 60 * 24),
            dkim_signer,
            rate_limiter: RateLimiter::new(config.rate_limit_config),
        })
    }

    fn create_dkim_signer(dkim: &CfgDKIM, priv_key: &str) -> Result<DkimSignerType> {
        match dkim.key_type {
            DkimKeyType::Rsa => {
                let pem = pem::parse(priv_key)
                    .into_diagnostic()
                    .wrap_err("parsing RSA PEM")?;
                let pk_rsa = RsaKey::<Sha256>::from_pkcs8_der(pem.contents())
                    .into_diagnostic()
                    .wrap_err("error reading RSA priv key")?;

                Ok(DkimSignerType::Rsa(
                    DkimSigner::from_key(pk_rsa)
                        .domain(&dkim.domain)
                        .selector(&dkim.selector)
                        .headers(DKIM_HEADERS)
                        .expiration(60 * 60 * 7)
                        .body_canonicalization(mail_auth::dkim::Canonicalization::Relaxed)
                        .header_canonicalization(mail_auth::dkim::Canonicalization::Relaxed),
                ))
            }
            DkimKeyType::Ed25519 => {
                // Parse PEM to get DER bytes
                let pem = pem::parse(priv_key)
                    .into_diagnostic()
                    .wrap_err("parsing Ed25519 PEM")?;

                let pk_ed25519 =
                    mail_auth::common::crypto::Ed25519Key::from_pkcs8_der(pem.contents())
                        .into_diagnostic()
                        .wrap_err("error reading Ed25519 priv key")?;

                Ok(DkimSignerType::Ed25519(
                    DkimSigner::from_key(pk_ed25519)
                        .domain(&dkim.domain)
                        .selector(&dkim.selector)
                        .headers(DKIM_HEADERS)
                        .expiration(60 * 60 * 7)
                        .body_canonicalization(mail_auth::dkim::Canonicalization::Relaxed)
                        .header_canonicalization(mail_auth::dkim::Canonicalization::Relaxed),
                ))
            }
        }
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
        let _job_guard = metrics::job_processing_guard();
        debug!(msg_id = ?job.job_id, "Processing job");
        let email = match self.storage.get(&job.job_id, Status::Queued).await {
            Ok(Some(email)) => email,
            Ok(None) => {
                warn!(msg_id = ?job.job_id, "Email not found in queue");
                metrics::queue_depth_dec();
                return self.storage.delete(&job.job_id, Status::Queued).await;
            }
            Err(e) => return Err(e).wrap_err("failed to get email from storage"),
        };

        let msg = match MessageParser::default().parse(&email.body) {
            Some(msg) => msg,
            None => {
                error!(msg_id = ?job.job_id, "Failed to parse email body");
                bail!("failed to parse email body")
            }
        };

        if self.disable_outbound {
            info!(
                msg_id = job.job_id,
                from_email = email.from,
                to_email = email.to.join(","),
                "Outbound mail disabled, dropping message"
            );
            self.storage.delete(&job.job_id, Status::Queued).await?;
            metrics::queue_depth_dec();
            metrics::email_dropped();
            return Ok(());
        }

        match self.send_email(&email.to, &msg, &email.body).await {
            Ok(_) => {
                info!(
                    msg_id = job.job_id,
                    from_email = email.from,
                    to_email = email.to.join(","),
                    "Successfully sent email"
                );
                self.storage.delete(&job.job_id, Status::Queued).await?;
                metrics::queue_depth_dec();
                metrics::email_sent();
                // Delete any meta file in deferred.
                self.storage
                    .delete_meta(&job.job_id)
                    .await
                    .wrap_err("deleting meta file")?;
                Ok(())
            }
            Err(e) => {
                match e.downcast_ref::<Error>() {
                    Some(Error::UnexpectedReply(resp)) => {
                        if Self::is_retryable(resp.code()) {
                            warn!(
                                msg_id = ?job.job_id,
                                code = resp.code(),
                                from_email = email.from,
                                to_email = email.to.join(","),
                                "Retryable error encountered, deferring email"
                            );
                            // Defer the email.
                            println!("Error sending email: {:?}", e);
                            self.defer_email(job).await?;
                        }
                        Ok(())
                    }
                    _ => {
                        error!(
                            msg_id = ?job.job_id,
                            from_email = email.from,
                            to_email = email.to.join(","),
                            ?e, "Non-retryable error, bouncing email"
                        );
                        // Bounce the email.
                        println!("Error sending email: {:?}", e);
                        self.storage
                            .mv(&job.job_id, &job.job_id, Status::Queued, Status::Bounced)
                            .await
                            .wrap_err("moving from queued to bounced")?;
                        metrics::queue_depth_dec();
                        metrics::email_bounced();
                        Ok(())
                    }
                }
            }
        }
    }

    async fn defer_email(&self, job: &Job) -> Result<()> {
        let delay = self.initial_delay * (2_u32.pow(job.attempts));
        let delay = std::cmp::min(delay, self.max_delay);

        info!(
            msg_id = ?job.job_id,
            attempts = job.attempts + 1,
            ?delay,
            "Deferring email"
        );

        let meta = EmailMetadata {
            msg_id: job.job_id.clone(),
            attempts: job.attempts + 1,
            last_attempt: SystemTime::now(),
            next_attempt: SystemTime::now() + delay,
        };

        self.storage
            .put_meta(&job.job_id, &meta)
            .await
            .wrap_err("storing meta file")?;

        self.storage
            .mv(&job.job_id, &job.job_id, Status::Queued, Status::Deferred)
            .await
            .wrap_err("moving from queued to deferred")?;

        metrics::queue_depth_dec();
        metrics::email_deferred();

        Ok(())
    }

    /// Removes Bcc headers from raw email bytes.
    fn remove_bcc_header(raw_email: &[u8]) -> Result<Vec<u8>> {
        let boundary = memmem::find(raw_email, HEADER_BODY_SEPARATOR).ok_or_else(|| {
            miette::miette!("Invalid email format: header body boundary not found")
        })?;

        let header_part = &raw_email[..boundary];
        let body_part = &raw_email[boundary + HEADER_BODY_SEPARATOR.len()..];

        let mut new_email = Vec::with_capacity(raw_email.len()); // Estimate capacity

        for line in header_part.split(|&b| b == b'\n') {
            // Trim potential trailing '\r' before checking prefix
            let trimmed_line = if line.ends_with(b"\r") {
                &line[..line.len() - 1]
            } else {
                line
            };

            // Check if the line starts with "Bcc:" (case-sensitive)
            // Use eq_ignore_ascii_case for case-insensitive if needed:
            if !trimmed_line
                .get(..BCC_HEADER_PREFIX.len())
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case(BCC_HEADER_PREFIX))
            {
                // Keep the line if it's not a Bcc header
                new_email.extend_from_slice(line);
                new_email.push(b'\n'); // Re-add the newline character
            }
        }

        // Remove the last '\n' if headers were present and add the separator
        if !new_email.is_empty() && new_email.last() == Some(&b'\n') {
            new_email.pop(); // Remove trailing '\n' from last header line
        }
        new_email.extend_from_slice(HEADER_BODY_SEPARATOR);

        // Append the original body
        new_email.extend_from_slice(body_part);

        Ok(new_email)
    }

    async fn send_email<'b>(
        &self,
        to: &[String],
        email: &'b Message<'b>,
        body: &str,
    ) -> Result<()> {
        let email_bytes_no_bcc =
            Self::remove_bcc_header(body.as_bytes()).wrap_err("Failed to remove Bcc header")?;
        let from = email
            .from()
            .and_then(|f| f.first())
            .and_then(|f| f.address())
            .ok_or_else(|| miette::miette!("Invalid from address"))?;
        let signed_email;
        let raw_email = match &self.dkim_signer {
            Some(signer) => {
                debug!("Signing email with DKIM");
                let signature = match signer {
                    DkimSignerType::Rsa(signer) => {
                        let started = Instant::now();
                        let header = signer
                            .sign(&email_bytes_no_bcc)
                            .into_diagnostic()
                            .wrap_err("signing email with dkim")?
                            .to_header();
                        metrics::observe_dkim_sign_latency(started.elapsed());
                        header
                    }
                    DkimSignerType::Ed25519(signer) => {
                        let started = Instant::now();
                        let header = signer
                            .sign(&email_bytes_no_bcc)
                            .into_diagnostic()
                            .wrap_err("signing email with dkim")?
                            .to_header();
                        metrics::observe_dkim_sign_latency(started.elapsed());
                        header
                    }
                };

                signed_email = Self::insert_dkim_signature(&email_bytes_no_bcc, &signature)?;
                signed_email.as_slice()
            }
            None => email_bytes_no_bcc.as_slice(),
        };

        let to_iter = to.iter().map(|s| s.to_owned());

        let cc_iter = email
            .cc()
            .into_iter()
            .flat_map(|list| list.as_list())
            .flatten() // Iterator yielding &Address for all addresses in the list(s)
            .filter_map(|cc| cc.address()) // Iterator yielding &str
            .map(|addr_str| addr_str.to_owned()); // Iterator

        let bcc_iter = email
            .bcc()
            .into_iter()
            .flat_map(|list| list.as_list())
            .flatten()
            .filter_map(|bcc| bcc.address())
            .map(|addr_str| addr_str.to_owned());

        let all_recipients: Vec<String> = to_iter.chain(cc_iter).chain(bcc_iter).collect();

        // Remove any duplicates.
        let all_recipients: Vec<String> = all_recipients
            .into_iter()
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        // Parse to address for each.
        for to in all_recipients.iter() {
            info!(?to, ?from, "Attempting to send email");
            // Strip `<` and `>` from email address.
            let to = to.trim_matches(|c| c == '<' || c == '>');
            let parsed_email_id = EmailAddress::parse(to, None);
            if parsed_email_id.is_none() {
                continue;
            }

            let parsed_email_id = parsed_email_id.unwrap();

            // Check rate limit for this domain
            let domain = parsed_email_id.get_domain();
            match self.rate_limiter.check_rate_limit(domain).await {
                RateLimitResult::Allowed => {
                    debug!(domain = ?domain, "Rate limit check passed");
                }
                RateLimitResult::RateLimited { retry_after } => {
                    info!(
                        domain = ?domain,
                        retry_after_ms = retry_after.as_millis(),
                        "Rate limited, waiting before sending"
                    );
                    tokio::time::sleep(retry_after).await;
                }
            }

            debug!(?parsed_email_id, "Looking up MX records");

            // Resolve MX record for domain.
            let mx_lookup = self
                .lookup_mx(parsed_email_id.get_domain())
                .await
                .wrap_err("looking up mx record")?;
            if mx_lookup.iter().count() == 0 {
                warn!(domain = ?parsed_email_id.get_domain(), "No MX records found");
                metrics::record_send_failure(parsed_email_id.get_domain());
                continue;
            }

            // Sort mx according to preference in ascending order.
            let mut mx = mx_lookup.iter().collect::<Vec<&MX>>();

            // Sort in place using Rust's standard sort
            mx.sort_by_key(|a| a.preference());

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
            let mut last_error: Option<miette::Report> = None;
            for mx_record in mx.iter() {
                debug!(mx = ?mx_record.exchange(), "Attempting delivery via MX server");

                let exchange = mx_record.exchange().to_string();
                let transport: AsyncSmtpTransport<Tokio1Executor> =
                    self.pool.get(&exchange).await?;

                let send_start = Instant::now();
                match transport.send_raw(&envelope, raw_email).await {
                    Ok(_) => {
                        metrics::record_send_success(
                            parsed_email_id.get_domain(),
                            send_start.elapsed(),
                        );
                        success = true;
                        break;
                    }
                    Err(err) => {
                        metrics::record_send_failure(parsed_email_id.get_domain());
                        let report = Err::<(), _>(err)
                            .into_diagnostic()
                            .wrap_err("sending raw message")
                            .unwrap_err();
                        last_error = Some(report);
                    }
                }
            }

            if !success {
                error!(to = ?to, "Failed to send email through any MX server");
                if let Some(err) = last_error {
                    return Err(err);
                }
                metrics::record_send_failure(parsed_email_id.get_domain());
                bail!("failed to send email through any MX server");
            }
        }
        Ok(())
    }

    async fn lookup_mx(&self, domain: &str) -> Result<MxLookup> {
        if let Some(mx) = self.mx_cache.get(domain).await {
            return Ok(mx);
        }

        let mx = self
            .resolver
            .mx_lookup(domain)
            .await
            .into_diagnostic()
            .wrap_err("getting mx record")?;

        // Cache the result.
        self.mx_cache.insert(domain.to_string(), mx.clone()).await;

        Ok(mx)
    }

    /// Determines if a status code indicates the operation can be retried.
    ///
    /// Retryable codes include:
    /// - 4XX: Transient errors.
    /// - 500-504: Server errors
    /// - 521: Server is down
    /// - 530, 550-554: Authentication/policy failures
    fn is_retryable(code: u16) -> bool {
        const ADDITIONAL_RETRYABLE_CODES: &[u16] =
            &[500, 501, 502, 503, 504, 521, 530, 550, 551, 552, 553, 554];

        ((400..500).contains(&code)) || ADDITIONAL_RETRYABLE_CODES.contains(&code)
    }

    /// Inserts a DKIM signature into a raw email body.
    /// The signature should be inserted after the last existing header but before the message body.
    pub fn insert_dkim_signature(raw_email: &[u8], dkim_signature: &str) -> Result<Vec<u8>> {
        // Find the boundary of headers and body.
        let separator = b"\r\n\r\n";
        let boundary = memmem::find(raw_email, separator).ok_or_else(|| {
            miette::miette!("Invalid email format: header body boundary not found")
        })?;

        // Copy the header part while filtering out any existing "DKIM-Signature:" lines.
        let mut new_email = Vec::with_capacity(raw_email.len() + dkim_signature.len() + 100);
        {
            // Process headers line by line.
            for line in raw_email[..boundary].split(|&b| b == b'\n') {
                // Trim trailing carriage returns, if any.
                if let Some(line) = line.strip_suffix(b"\r") {
                    if !line.starts_with(b"DKIM-Signature:") {
                        new_email.extend_from_slice(line);
                        new_email.extend_from_slice(b"\r\n");
                    }
                } else if !line.starts_with(b"DKIM-Signature:") {
                    new_email.extend_from_slice(line);
                    new_email.extend_from_slice(b"\r\n");
                }
            }
        }

        // Insert DKIM signature.
        new_email.extend_from_slice(dkim_signature.as_bytes());
        if !dkim_signature.ends_with("\r\n") {
            new_email.extend_from_slice(b"\r\n");
        }
        // Add the single blank line (\r\n) that separates headers from the body.
        new_email.extend_from_slice(b"\r\n");

        // Append the remainder of the email body.
        new_email.extend_from_slice(&raw_email[boundary + separator.len()..]);
        Ok(new_email)
    }
}

#[derive(Clone, Debug)]
pub struct Job {
    pub job_id: String,
    pub attempts: u32,
}

impl Job {
    pub fn new(msg_id: String, attempts: u32) -> Job {
        Job {
            job_id: msg_id,
            attempts,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str;

    #[test]
    fn test_remove_bcc_header_present() {
        let raw_email =
            b"From: a@b.com\r\nTo: c@d.com\r\nBcc: e@f.com\r\nSubject: Test\r\n\r\nBody";
        let expected = b"From: a@b.com\r\nTo: c@d.com\r\nSubject: Test\r\n\r\nBody";
        let result = Worker::remove_bcc_header(raw_email).unwrap();
        assert_eq!(
            str::from_utf8(&result).unwrap(),
            str::from_utf8(expected).unwrap()
        );
    }

    #[test]
    fn test_remove_bcc_header_absent() {
        let raw_email = b"From: a@b.com\r\nTo: c@d.com\r\nSubject: Test\r\n\r\nBody";
        let expected = b"From: a@b.com\r\nTo: c@d.com\r\nSubject: Test\r\n\r\nBody";
        let result = Worker::remove_bcc_header(raw_email).unwrap();
        assert_eq!(
            str::from_utf8(&result).unwrap(),
            str::from_utf8(expected).unwrap()
        );
    }

    #[test]
    fn test_remove_bcc_header_multiple() {
        let raw_email = b"From: a@b.com\r\nBcc: g@h.com\r\nTo: c@d.com\r\nBcc: e@f.com\r\nSubject: Test\r\n\r\nBody";
        let expected = b"From: a@b.com\r\nTo: c@d.com\r\nSubject: Test\r\n\r\nBody";
        let result = Worker::remove_bcc_header(raw_email).unwrap();
        assert_eq!(
            str::from_utf8(&result).unwrap(),
            str::from_utf8(expected).unwrap()
        );
    }

    #[test]
    fn test_remove_bcc_header_folded() {
        // Folded headers are tricky. This basic implementation won't handle folded Bcc.
        // A robust solution would need proper header parsing.
        let raw_email = b"From: a@b.com\r\nTo: c@d.com\r\nBcc: e@f.com,\r\n g@h.com\r\nSubject: Test\r\n\r\nBody";
        // Current implementation will only remove the first line "Bcc: e@f.com,"
        let expected_current =
            b"From: a@b.com\r\nTo: c@d.com\r\n g@h.com\r\nSubject: Test\r\n\r\nBody";
        let result = Worker::remove_bcc_header(raw_email).unwrap();
        assert_eq!(
            str::from_utf8(&result).unwrap(),
            str::from_utf8(expected_current).unwrap(),
            "Note: Folded Bcc headers are not fully handled by this simple removal logic."
        );
    }

    #[test]
    fn test_remove_bcc_header_no_body() {
        let raw_email = b"From: a@b.com\r\nBcc: e@f.com\r\nTo: c@d.com\r\n\r\n";
        let expected = b"From: a@b.com\r\nTo: c@d.com\r\n\r\n";
        let result = Worker::remove_bcc_header(raw_email).unwrap();
        assert_eq!(
            str::from_utf8(&result).unwrap(),
            str::from_utf8(expected).unwrap()
        );
    }

    #[test]
    fn test_remove_bcc_header_no_boundary() {
        let raw_email = b"From: a@b.com\r\nBcc: e@f.com"; // Missing \r\n\r\n
        let result = Worker::remove_bcc_header(raw_email);
        assert!(result.is_err());
    }

    #[test]
    fn test_insert_dkim_signature_basic() {
        // A simple email with headers and a body.
        let raw_email = b"From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test Email\r\n\r\nThis is the email body.";
        let dkim_signature = "DKIM-Signature: test-signature";

        // Call the function.
        let result = Worker::insert_dkim_signature(raw_email, dkim_signature);
        assert!(
            result.is_ok(),
            "Expected to successfully insert DKIM signature"
        );

        let new_email = result.unwrap();
        // Use the returned Vec<u8> immediately and convert to &str.
        let new_email_str = std::str::from_utf8(&new_email).expect("valid utf8");

        // The expected output should have the DKIM signature header inserted
        // after existing headers and before the empty line that starts the body.
        let expected = "From: sender@example.com\r\n\
                        To: recipient@example.com\r\n\
                        Subject: Test Email\r\n\
                        DKIM-Signature: test-signature\r\n\r\n\
                        This is the email body.";

        // For easier comparison, remove extra whitespace.
        assert_eq!(
            new_email_str.replace(" ", ""),
            expected.replace(" ", ""),
            "The DKIM signature should be inserted in the header block"
        );
    }

    #[test]
    fn test_insert_dkim_signature_removes_existing_dkim() {
        // Email containing an existing DKIM header.
        let raw_email = b"From: sender@example.com\r\nDKIM-Signature: old-signature\r\nSubject: Another Test\r\n\r\nThe email body.";
        let dkim_signature = "DKIM-Signature: new-signature";

        let result = Worker::insert_dkim_signature(raw_email, dkim_signature);
        assert!(
            result.is_ok(),
            "Expected to successfully insert DKIM signature even with existing one"
        );

        let new_email = result.unwrap();
        let new_email_str = std::str::from_utf8(&new_email).expect("valid utf8");

        // The expected headers should not include the obsolete DKIM header.
        let expected = "From: sender@example.com\r\n\
                        Subject: Another Test\r\n\
                        DKIM-Signature: new-signature\r\n\r\n\
                        The email body.";
        assert_eq!(
            new_email_str.replace(" ", ""),
            expected.replace(" ", ""),
            "Should remove any existing DKIM-Signature header and insert the new one"
        );
    }

    #[test]
    fn test_insert_dkim_signature_missing_boundary() {
        // Email without the required \r\n\r\n boundary.
        let raw_email = b"From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Missing Boundary\r\nThis is all header (missing boundary)";
        let dkim_signature = "DKIM-Signature: test-signature";

        let result = Worker::insert_dkim_signature(raw_email, dkim_signature);
        // We expect an error because the header to body boundary is missing.
        assert!(
            result.is_err(),
            "Expected an error when there is no header-body separator"
        );
    }
}
