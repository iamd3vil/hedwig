use crate::config::DkimKeyType;
use async_channel::Receiver;
use chrono::{DateTime, SecondsFormat, Utc};
use email_address_parser::EmailAddress;
use hickory_resolver::{
    lookup::MxLookup,
    name_server::{GenericConnector, TokioRuntimeProvider},
    proto::rr::rdata::MX,
    AsyncResolver,
};
use lettre::{address::Envelope, Address, AsyncSmtpTransport, AsyncTransport, Tokio1Executor};
use mail_auth::{
    common::crypto::{Ed25519Key, RsaKey, Sha256},
    dkim::DkimSigner,
};
use mail_auth::{common::headers::HeaderWriter, dkim::Done};
use mail_parser::{Message, MessageParser};
use miette::{bail, Context, IntoDiagnostic, Result};
use rustls_pki_types::{PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer};
// use pool::SmtpClientPool;
use memchr::memmem;
use moka::future::Cache;
pub(crate) use pool::PoolManager;
pub use pool::{
    SmtpPoolConfig, DEFAULT_SMTP_CACHE_SIZE, DEFAULT_SMTP_POOL_MAX_SIZE, DEFAULT_SMTP_POOL_MIN_IDLE,
};
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::fs;
use tracing::{debug, error, info, warn};

use crate::mta_sts::cache::MtaStsResolver;
use crate::mta_sts::policy::{self as mta_sts_policy, MtaStsEnforcementError, PolicyMode};
use crate::{
    config::CfgDKIM,
    metrics,
    storage::{Status, Storage, StoredEmail},
};

pub mod deferred_worker;
pub mod log_worker;
mod pool;
pub mod rate_limiter;

use rate_limiter::{RateLimitConfig, RateLimitResult, RateLimiter};

const HEADER_BODY_SEPARATOR: &[u8] = b"\r\n\r\n";
const BCC_HEADER_PREFIX: &[u8] = b"Bcc:";
const DKIM_HEADERS: [&str; 3] = ["From", "Subject", "To"];

struct DeliveryContext<'a> {
    job_id: &'a str,
    stored_email: &'a StoredEmail,
    subject: Option<&'a str>,
    attempt: u32,
}

fn strip_brackets(s: &str) -> &str {
    s.trim_matches(|c| c == '<' || c == '>')
}

fn fmt_option<T: std::fmt::Display>(opt: Option<T>) -> String {
    match opt {
        Some(v) => v.to_string(),
        None => String::new(),
    }
}

fn fmt_rfc3339(ts: DateTime<Utc>) -> String {
    ts.to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn fmt_option_rfc3339(opt: Option<DateTime<Utc>>) -> String {
    opt.map(fmt_rfc3339).unwrap_or_default()
}

fn calc_delay_ms(queued_at: Option<DateTime<Utc>>, logged_at: DateTime<Utc>) -> Option<i64> {
    queued_at.map(|queued| {
        logged_at
            .signed_duration_since(queued)
            .num_milliseconds()
            .max(0)
    })
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EmailMetadata {
    pub attempts: u32,
    pub last_attempt: SystemTime,
    pub next_attempt: SystemTime,
    pub msg_id: String,
    /// The SMTP response (or enforcement error) from the most recent failed
    /// attempt, so the final exhaustion bounce can report why the message
    /// kept deferring. `default` keeps meta files written by older versions
    /// deserializable.
    #[serde(default)]
    pub last_error: Option<String>,
}

pub enum DkimSignerType {
    Rsa(DkimSigner<RsaKey<Sha256>, Done>),
    Ed25519(DkimSigner<Ed25519Key, Done>),
}

pub struct WorkerConfig {
    pub disable_outbound: bool,
}

#[derive(Clone)]
pub(crate) struct WorkerResources {
    mx_cache: Cache<String, MxLookup>,
    pool: Arc<PoolManager>,
    resolver: AsyncResolver<GenericConnector<TokioRuntimeProvider>>,
    mta_sts: Arc<MtaStsResolver>,
    rate_limiter: RateLimiter,
}

impl WorkerResources {
    /// The process-wide rate limiter (clones share the same buckets); used
    /// by the log-queue dispatcher's dispatch-time gate.
    pub(crate) fn rate_limiter(&self) -> RateLimiter {
        self.rate_limiter.clone()
    }

    pub(crate) fn new(
        mx_cache: Cache<String, MxLookup>,
        pool: Arc<PoolManager>,
        resolver: AsyncResolver<GenericConnector<TokioRuntimeProvider>>,
        mta_sts: Arc<MtaStsResolver>,
        rate_limit_config: RateLimitConfig,
    ) -> Self {
        Self {
            mx_cache,
            pool,
            resolver,
            mta_sts,
            rate_limiter: RateLimiter::new(rate_limit_config),
        }
    }
}

pub struct Worker {
    channel: Receiver<Job>,
    storage: Arc<dyn Storage>,
    resolver: AsyncResolver<GenericConnector<TokioRuntimeProvider>>,

    pool: Arc<PoolManager>,
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

    /// MTA-STS resolver for looking up and enforcing recipient domain policies.
    mta_sts: Arc<MtaStsResolver>,
}

impl Worker {
    pub async fn new(
        channel: Receiver<Job>,
        storage: Arc<dyn Storage>,
        dkim: &Option<CfgDKIM>,
        config: WorkerConfig,
        resources: WorkerResources,
    ) -> Result<Self> {
        info!("Initializing SMTP worker");

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

        let WorkerResources {
            mx_cache,
            pool,
            resolver,
            mta_sts,
            rate_limiter,
        } = resources;

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
            rate_limiter,
            mta_sts,
        })
    }

    fn create_dkim_signer(dkim: &CfgDKIM, priv_key: &str) -> Result<DkimSignerType> {
        match dkim.key_type {
            DkimKeyType::Rsa => {
                let pem = pem::parse(priv_key)
                    .into_diagnostic()
                    .wrap_err("parsing RSA PEM")?;
                let pk_rsa = match pem.tag() {
                    "PRIVATE KEY" => RsaKey::<Sha256>::from_key_der(PrivateKeyDer::Pkcs8(
                        PrivatePkcs8KeyDer::from(pem.contents()),
                    ))
                    .into_diagnostic()
                    .wrap_err("error reading PKCS#8 RSA private key")?,
                    "RSA PRIVATE KEY" => RsaKey::<Sha256>::from_key_der(PrivateKeyDer::Pkcs1(
                        PrivatePkcs1KeyDer::from(pem.contents()),
                    ))
                    .into_diagnostic()
                    .wrap_err("error reading PKCS#1 RSA private key")?,
                    "ENCRYPTED PRIVATE KEY" => bail!(
                        "encrypted RSA private keys are not supported; use an unencrypted PKCS#8 or PKCS#1 PEM key"
                    ),
                    tag => bail!(
                        "unsupported RSA private key PEM tag {tag:?}; expected \"PRIVATE KEY\" or \"RSA PRIVATE KEY\""
                    ),
                };

                Ok(DkimSignerType::Rsa(
                    DkimSigner::from_key(pk_rsa)
                        .domain(&dkim.domain)
                        .selector(&dkim.selector)
                        .headers(DKIM_HEADERS)
                        .expiration(60 * 60 * 7)
                        .body_canonicalization(mail_auth::dkim::Canonicalization::Simple)
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
                        .body_canonicalization(mail_auth::dkim::Canonicalization::Simple)
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

        let subject = msg.subject().map(|s| s.to_string());

        if self.disable_outbound {
            let logged_at = Utc::now();
            let delay_ms = calc_delay_ms(email.queued_at, logged_at);
            info!(
                job_id = %job.job_id,
                from_email = %strip_brackets(&email.from),
                recipient = %email.to.iter().map(|s| strip_brackets(s)).collect::<Vec<_>>().join(","),
                subject = %fmt_option(subject.as_deref()),
                status = "dropped",
                smtp_response = "outbound disabled",
                queued_at = %fmt_option_rfc3339(email.queued_at),
                logged_at = %fmt_rfc3339(logged_at),
                delay_ms = %fmt_option(delay_ms),
                attempt = %job.attempts,
                "email delivery"
            );
            self.storage.delete(&job.job_id, Status::Queued).await?;
            self.storage
                .delete_meta(&job.job_id)
                .await
                .wrap_err("deleting meta file")?;
            metrics::queue_depth_dec();
            metrics::email_dropped();
            return Ok(());
        }

        let ctx = DeliveryContext {
            job_id: &job.job_id,
            stored_email: &email,
            subject: subject.as_deref(),
            attempt: job.attempts,
        };

        match self.send_email(&email.to, &msg, &email.body, &ctx).await {
            Ok(_) => {
                self.storage.delete(&job.job_id, Status::Queued).await?;
                metrics::queue_depth_dec();
                metrics::email_sent();
                self.storage
                    .delete_meta(&job.job_id)
                    .await
                    .wrap_err("deleting meta file")?;
                Ok(())
            }
            Err(e) => {
                // MTA-STS enforcement failures are always deferred, never bounced.
                if e.downcast_ref::<MtaStsEnforcementError>().is_some() {
                    let logged_at = Utc::now();
                    let delay_ms = calc_delay_ms(email.queued_at, logged_at);
                    info!(
                        job_id = %job.job_id,
                        from_email = %strip_brackets(&email.from),
                        recipient = %email.to.iter().map(|s| strip_brackets(s)).collect::<Vec<_>>().join(","),
                        subject = %fmt_option(subject.as_deref()),
                        status = "deferred",
                        smtp_response = "MTA-STS enforcement failure",
                        queued_at = %fmt_option_rfc3339(email.queued_at),
                        logged_at = %fmt_rfc3339(logged_at),
                        delay_ms = %fmt_option(delay_ms),
                        attempt = %(job.attempts + 1),
                        "email delivery"
                    );
                    self.defer_email(job, "MTA-STS enforcement failure").await?;
                    return Ok(());
                }

                // SMTP failures are classified inside `send_email` (where the
                // live `lettre::Error` is still typed) and carried up via a
                // `ClassifiedSendError` typed error. If we can downcast to it,
                // use its outcome and pre-formatted SMTP response. Otherwise
                // (MX-lookup failure, body-parse error, etc.) bounce with the
                // generic display — same as before for non-SMTP failures.
                let (outcome, smtp_response) = match e.downcast_ref::<ClassifiedSendError>() {
                    Some(c) => (c.outcome, c.smtp_response.clone()),
                    None => (SendOutcome::Bounce, format!("{:#}", e)),
                };

                let logged_at = Utc::now();
                let delay_ms = calc_delay_ms(email.queued_at, logged_at);

                match outcome {
                    SendOutcome::Defer => {
                        info!(
                            job_id = %job.job_id,
                            from_email = %strip_brackets(&email.from),
                            recipient = %email.to.iter().map(|s| strip_brackets(s)).collect::<Vec<_>>().join(","),
                            subject = %fmt_option(subject.as_deref()),
                            status = "deferred",
                            smtp_response = %smtp_response,
                            queued_at = %fmt_option_rfc3339(email.queued_at),
                            logged_at = %fmt_rfc3339(logged_at),
                            delay_ms = %fmt_option(delay_ms),
                            attempt = %(job.attempts + 1),
                            "email delivery"
                        );
                        self.defer_email(job, &smtp_response).await?;
                        Ok(())
                    }
                    SendOutcome::Bounce => {
                        info!(
                            job_id = %job.job_id,
                            from_email = %strip_brackets(&email.from),
                            recipient = %email.to.iter().map(|s| strip_brackets(s)).collect::<Vec<_>>().join(","),
                            subject = %fmt_option(subject.as_deref()),
                            status = "bounced",
                            smtp_response = %smtp_response,
                            queued_at = %fmt_option_rfc3339(email.queued_at),
                            logged_at = %fmt_rfc3339(logged_at),
                            delay_ms = %fmt_option(delay_ms),
                            attempt = %job.attempts,
                            "email delivery"
                        );
                        self.storage
                            .mv(&job.job_id, &job.job_id, Status::Queued, Status::Bounced)
                            .await
                            .wrap_err("moving from queued to bounced")?;
                        // A retried job still has its deferred metadata on
                        // disk; bounce is terminal, so remove it.
                        self.storage
                            .delete_meta(&job.job_id)
                            .await
                            .wrap_err("deleting meta file")?;
                        metrics::queue_depth_dec();
                        metrics::email_bounced();
                        Ok(())
                    }
                }
            }
        }
    }

    async fn defer_email(&self, job: &Job, smtp_response: &str) -> Result<()> {
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
            last_error: Some(smtp_response.to_string()),
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

    /// Strip Bcc headers and DKIM-sign (when configured), producing the
    /// final outbound bytes.
    fn sign_outbound(&self, body: &[u8]) -> Result<Vec<u8>> {
        let email_bytes_no_bcc =
            Self::remove_bcc_header(body).wrap_err("Failed to remove Bcc header")?;
        match &self.dkim_signer {
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
                Self::insert_dkim_signature(&email_bytes_no_bcc, &signature)
            }
            None => Ok(email_bytes_no_bcc),
        }
    }

    /// The union of envelope recipients and any Cc/Bcc addresses parsed out
    /// of the message, deduplicated (historical behavior of `send_email`).
    fn merge_recipients(to: &[String], email: &Message<'_>) -> Vec<String> {
        let to_iter = to.iter().map(|s| s.to_owned());

        let cc_iter = email
            .cc()
            .into_iter()
            .flat_map(|list| list.as_list())
            .flatten()
            .filter_map(|cc| cc.address())
            .map(|addr_str| addr_str.to_owned());

        let bcc_iter = email
            .bcc()
            .into_iter()
            .flat_map(|list| list.as_list())
            .flatten()
            .filter_map(|bcc| bcc.address())
            .map(|addr_str| addr_str.to_owned());

        let all_recipients: Vec<String> = to_iter.chain(cc_iter).chain(bcc_iter).collect();
        all_recipients
            .into_iter()
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect()
    }

    /// Attempt delivery of one recipient through its MX servers, applying
    /// MTA-STS policy. Rate limiting and outcome logging stay with the
    /// caller. `Err` is reserved for infrastructure failures (MX lookup,
    /// transport pool); SMTP-level failures return `Failed` with the
    /// classification made while the typed transport error is live.
    async fn deliver_recipient(
        &self,
        raw_email: &[u8],
        from: &str,
        to_trimmed: &str,
        parsed_email_id: &EmailAddress,
    ) -> Result<RecipientDelivery> {
        let domain = parsed_email_id.get_domain();
        debug!(?parsed_email_id, "Looking up MX records");

        let mx_lookup = self
            .lookup_mx(domain)
            .await
            .wrap_err("looking up mx record")?;
        if mx_lookup.iter().count() == 0 {
            warn!(domain = ?domain, "No MX records found");
            metrics::record_send_failure(domain);
            return Ok(RecipientDelivery::Skipped("no MX records"));
        }

        // Sort mx according to preference in ascending order.
        let mut mx = mx_lookup.iter().collect::<Vec<&MX>>();
        // Shuffle first so the stable sort randomizes equal-preference MXes.
        mx.shuffle(&mut rand::thread_rng());
        mx.sort_by_key(|a| a.preference());

        // Look up MTA-STS policy for the recipient domain.
        let mta_sts_policy = self.mta_sts.get_policy(domain).await;
        if let Some(ref policy) = mta_sts_policy {
            debug!(domain = ?domain, mode = %policy.mode, "MTA-STS policy found");
        }

        let from_address: Address = from
            .parse()
            .map_err(|e| miette::miette!("invalid from address {from:?}: {e}"))?;
        let to_address: Address = to_trimmed
            .parse()
            .map_err(|e| miette::miette!("invalid recipient address {to_trimmed:?}: {e}"))?;
        let envelope = Envelope::new(Some(from_address), vec![to_address]).into_diagnostic()?;

        // Track the most recent per-MX failure as a typed error. We classify
        // here — while the live `lettre::transport::smtp::Error` is still
        // accessible — rather than wrapping it in a `miette::Report` and
        // trying to downcast later (which doesn't work; see the unit test
        // `into_diagnostic_makes_original_error_unreachable`).
        let mut last_error: Option<ClassifiedSendError> = None;
        for mx_record in mx.iter() {
            debug!(mx = ?mx_record.exchange(), "Attempting delivery via MX server");

            let exchange = mx_record.exchange().to_string();

            // MTA-STS: validate MX hostname against policy.
            if let Some(ref policy) = mta_sts_policy {
                let mx_valid = mta_sts_policy::mx_matches_policy(&exchange, policy);

                match policy.mode {
                    PolicyMode::Enforce => {
                        if !mx_valid {
                            warn!(
                                domain = ?domain,
                                mx = %exchange,
                                "MTA-STS enforce: MX host does not match policy, skipping"
                            );
                            metrics::mta_sts_enforcement("enforce", "fail");
                            continue;
                        }
                        metrics::mta_sts_enforcement("enforce", "pass");
                    }
                    PolicyMode::Testing => {
                        if !mx_valid {
                            warn!(
                                domain = ?domain,
                                mx = %exchange,
                                "MTA-STS testing: MX host does not match policy (would be rejected in enforce mode)"
                            );
                            metrics::mta_sts_enforcement("testing", "fail");
                        } else {
                            metrics::mta_sts_enforcement("testing", "pass");
                        }
                    }
                    PolicyMode::None => {}
                }
            }
            let transport: AsyncSmtpTransport<Tokio1Executor> = self.pool.get(&exchange).await?;

            let send_start = Instant::now();
            match transport.send_raw(&envelope, raw_email).await {
                Ok(response) => {
                    metrics::record_send_success(domain, send_start.elapsed());
                    let smtp_response = response.message().collect::<Vec<_>>().join(" ");
                    return Ok(RecipientDelivery::Delivered {
                        smtp_response: format!("{} {}", response.code(), smtp_response),
                        exchange,
                    });
                }
                Err(err) => {
                    metrics::record_send_failure(domain);
                    // Classify here, where `err` still has its concrete
                    // lettre type. Build the response string up-front so
                    // the wrapping for `Report` carries no live error.
                    let outcome = classify_smtp_outcome(
                        err.is_transient(),
                        err.is_permanent(),
                        err.status().map(u16::from),
                    );
                    let smtp_response = format!("sending raw message: {}", err);
                    warn!(
                        mx = %exchange,
                        outcome = ?outcome,
                        error = %smtp_response,
                        "MX delivery attempt failed"
                    );
                    last_error = Some(ClassifiedSendError {
                        outcome,
                        smtp_response,
                    });
                }
            }
        }

        // If MTA-STS enforce mode caused all MXes to be skipped by policy
        // (no transport-level errors), report that specifically so callers
        // defer instead of bouncing.
        if let Some(ref policy) = mta_sts_policy {
            if policy.mode == PolicyMode::Enforce && last_error.is_none() {
                return Ok(RecipientDelivery::MtaStsBlocked);
            }
        }
        if let Some(classified) = last_error {
            return Ok(RecipientDelivery::Failed(classified));
        }
        metrics::record_send_failure(domain);
        Ok(RecipientDelivery::Failed(ClassifiedSendError {
            outcome: SendOutcome::Bounce,
            smtp_response: "failed to send email through any MX server".to_string(),
        }))
    }

    /// Deliver one log-queue claim and translate the result into a
    /// [`JobOutcome`]. This is the log backend's counterpart to
    /// `process_job`: recipients are tracked individually so a retry only
    /// re-sends to those that have not accepted the message, and a
    /// rate-limit loss is reported instead of slept on — the worker slot is
    /// never parked.
    pub(crate) async fn process_claim(
        &self,
        job: &crate::logqueue::dispatcher::DeliveryJob,
        body: &[u8],
    ) -> crate::logqueue::dispatcher::JobOutcome {
        use crate::logqueue::dispatcher::JobOutcome;

        let _job_guard = metrics::job_processing_guard();
        let queued_at = chrono::DateTime::from_timestamp_millis(job.enqueue_ms);
        let log_delivery = |status: &str, recipient: &str, smtp_response: &str, attempt: u32| {
            let logged_at = Utc::now();
            info!(
                job_id = %job.message_id,
                from_email = %strip_brackets(&job.sender),
                recipient = %strip_brackets(recipient),
                status = %status,
                smtp_response = %smtp_response,
                queued_at = %fmt_option_rfc3339(queued_at),
                logged_at = %fmt_rfc3339(logged_at),
                delay_ms = %fmt_option(calc_delay_ms(queued_at, logged_at)),
                attempt = %attempt,
                "email delivery"
            );
        };

        let Some(msg) = MessageParser::default().parse(body) else {
            error!(msg_id = %job.message_id, "Failed to parse email body");
            return self
                .bounce_claim(job, body, "unparseable message body".into())
                .await;
        };

        if self.disable_outbound {
            log_delivery("dropped", &job.recipients.join(","), "outbound disabled", job.attempts);
            metrics::email_dropped();
            return JobOutcome::Delivered {
                response: "outbound disabled".into(),
            };
        }

        // First attempt widens to Cc/Bcc like the legacy path; retries use
        // exactly the persisted remaining set.
        let recipients = if job.attempts == 0 {
            Self::merge_recipients(&job.recipients, &msg)
        } else {
            job.recipients.clone()
        };

        let raw_email = match self.sign_outbound(body) {
            Ok(raw) => raw,
            Err(e) => {
                return self
                    .bounce_claim(job, body, format!("preparing outbound message: {e:#}"))
                    .await;
            }
        };
        let Some(from) = msg
            .from()
            .and_then(|f| f.first())
            .and_then(|f| f.address())
        else {
            return self
                .bounce_claim(job, body, "invalid from address".into())
                .await;
        };

        let mut remaining: Vec<String> = Vec::new();
        let mut rate_limited_wait: Option<Duration> = None;
        let mut attempted = false;
        let mut last_defer_error: Option<String> = None;
        let mut bounce_reason: Option<String> = None;
        let mut delivered_any = false;

        for to in &recipients {
            let to_trimmed = to.trim_matches(|c| c == '<' || c == '>');
            let Some(parsed_email_id) = EmailAddress::parse(to_trimmed, None) else {
                continue; // dropped, matching legacy behavior
            };
            let domain = parsed_email_id.get_domain();

            match self.rate_limiter.check_rate_limit(domain).await {
                RateLimitResult::Allowed => {}
                RateLimitResult::RateLimited { retry_after } => {
                    remaining.push(to.clone());
                    rate_limited_wait =
                        Some(rate_limited_wait.map_or(retry_after, |w: Duration| w.max(retry_after)));
                    continue;
                }
            }

            match self
                .deliver_recipient(&raw_email, from, to_trimmed, &parsed_email_id)
                .await
            {
                Ok(RecipientDelivery::Delivered { smtp_response, .. }) => {
                    attempted = true;
                    delivered_any = true;
                    log_delivery("delivered", to_trimmed, &smtp_response, job.attempts);
                }
                Ok(RecipientDelivery::Skipped(reason)) => {
                    attempted = true;
                    debug!(to = ?to, reason, "recipient skipped");
                }
                Ok(RecipientDelivery::MtaStsBlocked) => {
                    attempted = true;
                    remaining.push(to.clone());
                    last_defer_error = Some("MTA-STS enforcement failure".into());
                    log_delivery(
                        "deferred",
                        to_trimmed,
                        "MTA-STS enforcement failure",
                        job.attempts + 1,
                    );
                }
                Ok(RecipientDelivery::Failed(classified)) => {
                    attempted = true;
                    match classified.outcome {
                        SendOutcome::Defer => {
                            remaining.push(to.clone());
                            log_delivery(
                                "deferred",
                                to_trimmed,
                                &classified.smtp_response,
                                job.attempts + 1,
                            );
                            last_defer_error = Some(classified.smtp_response);
                        }
                        SendOutcome::Bounce => {
                            log_delivery(
                                "bounced",
                                to_trimmed,
                                &classified.smtp_response,
                                job.attempts,
                            );
                            bounce_reason = Some(classified.smtp_response);
                        }
                    }
                }
                Err(e) => {
                    attempted = true;
                    let response = format!("{e:#}");
                    log_delivery("bounced", to_trimmed, &response, job.attempts);
                    bounce_reason = Some(response);
                }
            }
        }

        if !remaining.is_empty() {
            if !attempted {
                if let Some(retry_after) = rate_limited_wait {
                    // Pure rate-limit loss: not an attempt.
                    return JobOutcome::RateLimited { retry_after };
                }
            }
            let delay = std::cmp::min(
                self.initial_delay * 2_u32.pow(job.attempts.min(24)),
                self.max_delay,
            );
            metrics::email_deferred();
            return JobOutcome::Deferred {
                next_attempt_ms: Utc::now().timestamp_millis() + delay.as_millis() as i64,
                remaining_recipients: remaining,
                error: last_defer_error.unwrap_or_else(|| "rate limited".into()),
            };
        }

        match bounce_reason {
            Some(reason) if !delivered_any => self.bounce_claim(job, body, reason).await,
            _ => {
                metrics::email_sent();
                JobOutcome::Delivered {
                    response: "delivered".into(),
                }
            }
        }
    }

    /// Terminal bounce for a claim that exhausted its retry budget.
    pub(crate) async fn bounce_claim_for_retry_limit(
        &self,
        job: &crate::logqueue::dispatcher::DeliveryJob,
        body: &[u8],
    ) -> crate::logqueue::dispatcher::JobOutcome {
        self.bounce_claim(job, body, "maximum retry attempts exceeded".into())
            .await
    }

    /// Archive a bounced message to the bounce store (retention handled by
    /// the storage cleanup task), then report the terminal outcome. Archive
    /// failure is logged but never blocks the bounce: at-least-once applies
    /// to delivery, not to the archive copy.
    async fn bounce_claim(
        &self,
        job: &crate::logqueue::dispatcher::DeliveryJob,
        body: &[u8],
        reason: String,
    ) -> crate::logqueue::dispatcher::JobOutcome {
        let archived = StoredEmail {
            message_id: job.message_id.to_string(),
            from: job.sender.clone(),
            to: job.recipients.clone(),
            body: String::from_utf8_lossy(body).into_owned(),
            queued_at: chrono::DateTime::from_timestamp_millis(job.enqueue_ms),
        };
        if let Err(e) = self.storage.put(archived, Status::Bounced).await {
            error!(msg_id = %job.message_id, error = %e, "failed to archive bounced message");
        }
        metrics::email_bounced();
        crate::logqueue::dispatcher::JobOutcome::Bounced { reason }
    }

    async fn send_email<'b>(
        &self,
        to: &[String],
        email: &'b Message<'b>,
        body: &str,
        ctx: &DeliveryContext<'b>,
    ) -> Result<()> {
        let raw_email = self.sign_outbound(body.as_bytes())?;
        let from = email
            .from()
            .and_then(|f| f.first())
            .and_then(|f| f.address())
            .ok_or_else(|| miette::miette!("Invalid from address"))?;

        let all_recipients = Self::merge_recipients(to, email);

        // Parse to address for each.
        for to in all_recipients.iter() {
            info!(?to, ?from, "Attempting to send email");
            // Strip `<` and `>` from email address.
            let to_trimmed = to.trim_matches(|c| c == '<' || c == '>');
            let Some(parsed_email_id) = EmailAddress::parse(to_trimmed, None) else {
                continue;
            };
            let domain = parsed_email_id.get_domain();

            // Check rate limit for this domain
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

            match self
                .deliver_recipient(&raw_email, from, to_trimmed, &parsed_email_id)
                .await?
            {
                RecipientDelivery::Delivered {
                    smtp_response,
                    exchange,
                } => {
                    let logged_at = Utc::now();
                    let delay_ms = calc_delay_ms(ctx.stored_email.queued_at, logged_at);
                    info!(
                        job_id = %ctx.job_id,
                        from_email = %strip_brackets(&ctx.stored_email.from),
                        recipient = %strip_brackets(to_trimmed),
                        subject = %fmt_option(ctx.subject),
                        status = "delivered",
                        smtp_response = %smtp_response,
                        dest_ip = %exchange,
                        queued_at = %fmt_option_rfc3339(ctx.stored_email.queued_at),
                        logged_at = %fmt_rfc3339(logged_at),
                        delay_ms = %fmt_option(delay_ms),
                        attempt = %ctx.attempt,
                        "email delivery"
                    );
                }
                RecipientDelivery::Skipped(reason) => {
                    debug!(to = ?to, reason, "recipient skipped");
                }
                RecipientDelivery::MtaStsBlocked => {
                    error!(to = ?to, "MTA-STS enforce: all MX hosts failed policy validation");
                    metrics::record_send_failure(domain);
                    // Use `Report::new` (NOT `into_diagnostic`) so the typed
                    // error survives downcast in `process_job`.
                    return Err(miette::Report::new(MtaStsEnforcementError {
                        domain: domain.to_string(),
                    }));
                }
                RecipientDelivery::Failed(classified) => {
                    error!(to = ?to, "Failed to send email through any MX server");
                    // Use `Report::new` (NOT `into_diagnostic`) so the typed
                    // error survives downcast in `process_job`.
                    return Err(miette::Report::new(classified));
                }
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
}

/// Result of attempting one recipient through its MX servers.
pub(crate) enum RecipientDelivery {
    Delivered {
        /// Pre-formatted "code message" SMTP response.
        smtp_response: String,
        exchange: String,
    },
    /// Historically-silent skips: unparseable address, no MX records.
    Skipped(&'static str),
    /// MTA-STS enforce mode rejected every MX host.
    MtaStsBlocked,
    /// Transport-level failure through every usable MX.
    Failed(ClassifiedSendError),
}

/// What `process_job` should do with a failed delivery attempt.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum SendOutcome {
    /// Move the email to the deferred queue and retry later with backoff.
    Defer,
    /// Move the email to the bounced queue. Permanent failure.
    Bounce,
}

/// An SMTP delivery failure that has already been classified into
/// defer-vs-bounce by `send_email`, plus the SMTP response string for logging.
///
/// Why a typed error rather than `miette::Report`: `process_job` needs to read
/// the outcome back out, and miette's `into_diagnostic` wraps the original
/// error in a `pub(crate) DiagnosticError` whose inner type is unreachable
/// from user code (`Report::downcast_ref` and `Report::chain().find_map` both
/// fail to recover it — see the unit test
/// `into_diagnostic_makes_original_error_unreachable`). So `send_email`
/// classifies inside the per-MX loop, where it still has the live
/// `lettre::transport::smtp::Error`, and returns a `Report` constructed
/// directly from this typed error via `Report::new(...)`. That `Report` IS
/// downcastable to `ClassifiedSendError`, so `process_job` reads `outcome`
/// and `smtp_response` straight off it without any chain walking.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
#[error("{smtp_response}")]
pub(crate) struct ClassifiedSendError {
    pub(crate) outcome: SendOutcome,
    pub(crate) smtp_response: String,
}

/// Classify an SMTP delivery failure into defer-vs-bounce.
///
/// Inputs are *facts* extracted from the underlying `lettre::transport::smtp::Error`
/// (transient/permanent flags + status code) rather than the error itself,
/// because lettre's `Kind` enum and `Error` constructors are crate-private.
/// This keeps the policy a pure function we can exhaustively unit-test.
///
/// Policy:
/// - Transient (4xx) → defer (RFC 5321: try again later).
/// - Permanent (5xx) → defer if the code is in `Worker::is_retryable`'s list,
///   otherwise bounce.
/// - Anything else (network / TLS / timeout / connection / parse) → defer,
///   because those are transient infrastructure failures and bouncing them
///   silently loses mail on momentary blips.
pub(crate) fn classify_smtp_outcome(
    is_transient: bool,
    is_permanent: bool,
    status: Option<u16>,
) -> SendOutcome {
    if is_transient {
        return SendOutcome::Defer;
    }
    if is_permanent {
        return match status {
            Some(code) if Worker::is_retryable(code) => SendOutcome::Defer,
            _ => SendOutcome::Bounce,
        };
    }
    SendOutcome::Defer
}

impl Worker {
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
    use crate::config::{CfgDKIM, DkimKeyType};
    use std::str;

    #[test]
    fn test_create_dkim_signer_accepts_pkcs1_rsa_pem() {
        use rsa::pkcs1::EncodeRsaPrivateKey;

        let mut rng = rand::thread_rng();
        let key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("generate test RSA key");
        let pem = key
            .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
            .expect("encode test RSA key as PKCS#1 PEM");
        let dkim = CfgDKIM {
            domain: "example.com".to_string(),
            selector: "default".to_string(),
            private_key: "unused-in-this-test.pem".to_string(),
            key_type: DkimKeyType::Rsa,
        };

        assert!(matches!(
            Worker::create_dkim_signer(&dkim, &pem),
            Ok(DkimSignerType::Rsa(_))
        ));
    }

    #[test]
    fn test_create_dkim_signer_rejects_encrypted_rsa_pem_with_clear_error() {
        let dkim = CfgDKIM {
            domain: "example.com".to_string(),
            selector: "default".to_string(),
            private_key: "unused-in-this-test.pem".to_string(),
            key_type: DkimKeyType::Rsa,
        };
        let err = match Worker::create_dkim_signer(
            &dkim,
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAA==\n-----END ENCRYPTED PRIVATE KEY-----\n",
        ) {
            Ok(_) => panic!("encrypted RSA PEM should be rejected"),
            Err(err) => err,
        };

        assert!(
            err.to_string()
                .contains("encrypted RSA private keys are not supported"),
            "unexpected error: {err:#}"
        );
    }

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

    // --- classify_smtp_outcome ---
    //
    // These tests pin the policy used to decide whether a failed delivery should
    // be deferred (retried later) or permanently bounced. The classifier takes
    // *facts* extracted from the underlying error rather than the lettre Error
    // itself, because lettre's Kind enum and Error constructors are crate-private
    // — this lets us exhaustively unit-test the policy without smuggling in
    // crate-private types.

    #[test]
    fn classify_transient_4xx_defers() {
        // A 421 from Yahoo (TSS04 reputation throttle) must defer, not bounce.
        let outcome = classify_smtp_outcome(true, false, Some(421));
        assert_eq!(outcome, SendOutcome::Defer);
    }

    #[test]
    fn classify_transient_no_status_defers() {
        // Defensive: lettre's Kind::Transient always carries a code today, but
        // if status() ever returns None, we still defer (transient = retry).
        let outcome = classify_smtp_outcome(true, false, None);
        assert_eq!(outcome, SendOutcome::Defer);
    }

    #[test]
    fn classify_permanent_550_defers_per_policy() {
        // 550 is in is_retryable()'s additional-codes list; classifier honors it.
        let outcome = classify_smtp_outcome(false, true, Some(550));
        assert_eq!(outcome, SendOutcome::Defer);
    }

    #[test]
    fn classify_permanent_521_defers_per_policy() {
        let outcome = classify_smtp_outcome(false, true, Some(521));
        assert_eq!(outcome, SendOutcome::Defer);
    }

    #[test]
    fn classify_permanent_555_bounces() {
        // 555 (Mail/Rcpt parameters not implemented) is not in the retryable list.
        let outcome = classify_smtp_outcome(false, true, Some(555));
        assert_eq!(outcome, SendOutcome::Bounce);
    }

    #[test]
    fn classify_permanent_no_status_bounces() {
        // Defensive: a permanent error without a status is treated as bounce.
        let outcome = classify_smtp_outcome(false, true, None);
        assert_eq!(outcome, SendOutcome::Bounce);
    }

    /// Pins the trap that ate the first version of this fix:
    /// `into_diagnostic()` wraps the original error in miette's `pub(crate)`
    /// `DiagnosticError(Box<dyn Error>)` with `#[error(transparent)]`. That
    /// renders the original error type **unreachable from user code** —
    /// `Report::downcast_ref` and `Report::chain().find_map` both fail to
    /// recover it. The only working pattern is to construct the `Report`
    /// directly from a type we own (via `Report::new(typed_err)`), which is
    /// what `send_email` now does for SMTP failures.
    #[test]
    fn into_diagnostic_makes_original_error_unreachable() {
        use miette::{IntoDiagnostic, WrapErr};
        let err: Result<(), std::io::Error> = Err(std::io::Error::other("boom"));
        let report = err
            .into_diagnostic()
            .wrap_err("sending raw message")
            .unwrap_err();

        // Both fail because miette's DiagnosticError swallows the inner type.
        assert!(report.downcast_ref::<std::io::Error>().is_none());
        assert!(report
            .chain()
            .find_map(|e| e.downcast_ref::<std::io::Error>())
            .is_none());
    }

    /// Counter-test: a `Report` built directly from our own typed error
    /// IS downcastable. This is the pattern `send_email` uses for the
    /// pre-classified `ClassifiedSendError`, so `process_job` can read
    /// the outcome back out.
    #[test]
    fn report_built_from_owned_type_is_downcastable() {
        let classified = ClassifiedSendError {
            outcome: SendOutcome::Defer,
            smtp_response: "transient error (421): TSS04".to_string(),
        };
        let report = miette::Report::new(classified);

        let recovered = report.downcast_ref::<ClassifiedSendError>();
        assert!(recovered.is_some());
        assert_eq!(recovered.unwrap().outcome, SendOutcome::Defer);
    }

    /// Same trap as `into_diagnostic_makes_original_error_unreachable`,
    /// but specifically for `MtaStsEnforcementError`. Pins the bug that
    /// previously made `process_job`'s "MTA-STS enforcement failures are
    /// always deferred" comment a lie: the downcast on line 296 always
    /// returned None because the error was wrapped via `into_diagnostic`
    /// at the originating `Err(...)` site, making the typed error
    /// unreachable. Enforce failures silently fell through to the bounce
    /// path.
    #[test]
    fn mta_sts_error_via_into_diagnostic_is_unreachable() {
        use miette::{IntoDiagnostic, WrapErr};
        let report = Err::<(), _>(MtaStsEnforcementError {
            domain: "example.com".to_string(),
        })
        .into_diagnostic()
        .wrap_err("MTA-STS enforcement failure")
        .unwrap_err();

        assert!(report.downcast_ref::<MtaStsEnforcementError>().is_none());
    }

    /// Counter-test: `Report::new(MtaStsEnforcementError { ... })` IS
    /// downcastable, which is the pattern `send_email` must use so
    /// `process_job` can recognize MTA-STS enforce failures and defer.
    #[test]
    fn mta_sts_error_via_report_new_is_downcastable() {
        let err = MtaStsEnforcementError {
            domain: "example.com".to_string(),
        };
        let report = miette::Report::new(err);

        let recovered = report.downcast_ref::<MtaStsEnforcementError>();
        assert!(recovered.is_some());
        assert_eq!(recovered.unwrap().domain, "example.com");
    }

    #[test]
    fn classify_non_response_error_defers() {
        // Network / TLS / Timeout / Connection errors aren't transient or
        // permanent SMTP responses. They're transient infrastructure issues
        // and must be deferred — bouncing them silently loses mail when a
        // single TLS handshake hiccups.
        let outcome = classify_smtp_outcome(false, false, None);
        assert_eq!(outcome, SendOutcome::Defer);
    }
}
