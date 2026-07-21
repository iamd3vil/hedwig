//! Log-queue delivery workers: pull claims from the dispatcher, read the
//! message body by location, deliver, and report the outcome. Unlike the
//! legacy channel workers they never sleep on rate limits and never touch
//! the queue storage — the dispatcher owns all queue state.

use std::time::Duration;

use chrono::Utc;
use tracing::{error, info};

use crate::logqueue::dispatcher::{DispatcherHandle, JobOutcome, RateGate};
use crate::worker::rate_limiter::RateLimiter;
use crate::worker::Worker;

/// Bridges the shared per-domain [`RateLimiter`] into the dispatcher's
/// dispatch-time gate. The gate peeks (non-consuming); the worker's check
/// immediately before transmission is the real token acquisition.
pub struct LimiterGate(pub RateLimiter);

impl RateGate for LimiterGate {
    fn check(&self, domain: &str) -> Option<Duration> {
        self.0.peek_sync(domain)
    }
}

pub struct LogWorker {
    worker: Worker,
    dispatcher: DispatcherHandle,
    max_retries: u32,
}

impl LogWorker {
    pub fn new(worker: Worker, dispatcher: DispatcherHandle, max_retries: u32) -> Self {
        Self {
            worker,
            dispatcher,
            max_retries,
        }
    }

    /// Pull-and-deliver loop; exits when the dispatcher shuts down.
    pub async fn run(self) {
        while let Some(claim) = self.dispatcher.claim().await {
            let job = claim.job.clone();

            let body = match self.dispatcher.read_body(job.location).await {
                Ok(body) => body,
                Err(e) => {
                    // Unreadable payload: defer with backoff rather than
                    // guessing terminal state; a transient I/O problem must
                    // not lose mail.
                    error!(msg_id = %job.message_id, error = %e, "failed to read message body");
                    claim.report(JobOutcome::Deferred {
                        next_attempt_ms: Utc::now().timestamp_millis()
                            + 60_000 * (1 << job.attempts.min(10)) as i64,
                        remaining_recipients: job.recipients.clone(),
                        error: format!("payload read failed: {e}"),
                    });
                    continue;
                }
            };

            if job.attempts >= self.max_retries {
                info!(
                    msg_id = %job.message_id,
                    attempts = job.attempts,
                    max_retries = self.max_retries,
                    "maximum retry attempts exceeded; bouncing"
                );
                let outcome = self
                    .worker
                    .bounce_claim_for_retry_limit(&job, &body)
                    .await;
                claim.report(outcome);
                continue;
            }

            let outcome = self.worker.process_claim(&job, &body).await;
            claim.report(outcome);
        }
        tracing::debug!("log worker stopped: dispatcher closed");
    }
}
