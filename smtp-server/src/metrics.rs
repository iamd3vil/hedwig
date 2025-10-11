use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{Duration, Instant};

use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use once_cell::sync::Lazy;
use prometheus::{
    register_histogram, register_histogram_vec, register_int_counter, register_int_counter_vec,
    register_int_gauge, Encoder, Histogram, HistogramVec, IntCounter, IntCounterVec, IntGauge,
    TextEncoder,
};
use tracing::{error, info, warn};

/// Holds references to all registered metrics so we can update them safely.
struct MetricsHandles {
    queue_depth: IntGauge,
    retry_total: IntCounter,
    pool_entries: IntGauge,
    dkim_sign_latency: Histogram,
    emails_received: IntCounter,
    emails_sent: IntCounter,
    emails_deferred: IntCounter,
    emails_bounced: IntCounter,
    emails_dropped: IntCounter,
    worker_jobs_processed: IntCounter,
    worker_job_duration: Histogram,
    send_latency: HistogramVec,
    send_outcomes: IntCounterVec,
}

/// Global registry for all metrics exposed by the server.
static METRICS: Lazy<MetricsHandles> = Lazy::new(|| MetricsHandles {
    queue_depth: register_int_gauge!(
        "hedwig_queue_depth",
        "Number of emails currently queued for delivery."
    )
    .expect("register hedwig_queue_depth gauge"),
    retry_total: register_int_counter!(
        "hedwig_retry_attempts_total",
        "Total number of retry attempts scheduled for delivery."
    )
    .expect("register hedwig_retry_attempts_total counter"),
    pool_entries: register_int_gauge!(
        "hedwig_connection_pool_entries",
        "Number of SMTP transports currently cached in the outbound connection pool."
    )
    .expect("register hedwig_connection_pool_entries gauge"),
    dkim_sign_latency: register_histogram!(
        "hedwig_dkim_signing_latency_seconds",
        "Latency of DKIM signing operations in seconds.",
        vec![0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]
    )
    .expect("register hedwig_dkim_signing_latency_seconds histogram"),
    emails_received: register_int_counter!(
        "hedwig_emails_received_total",
        "Total number of emails accepted by the server."
    )
    .expect("register hedwig_emails_received_total counter"),
    emails_sent: register_int_counter!(
        "hedwig_emails_sent_total",
        "Total number of emails successfully delivered upstream."
    )
    .expect("register hedwig_emails_sent_total counter"),
    emails_deferred: register_int_counter!(
        "hedwig_emails_deferred_total",
        "Total number of emails deferred for retry."
    )
    .expect("register hedwig_emails_deferred_total counter"),
    emails_bounced: register_int_counter!(
        "hedwig_emails_bounced_total",
        "Total number of emails bounced after a permanent failure."
    )
    .expect("register hedwig_emails_bounced_total counter"),
    emails_dropped: register_int_counter!(
        "hedwig_emails_dropped_total",
        "Total number of emails dropped without attempting delivery (e.g. outbound disabled)."
    )
    .expect("register hedwig_emails_dropped_total counter"),
    worker_jobs_processed: register_int_counter!(
        "hedwig_worker_jobs_processed_total",
        "Total number of jobs processed by outbound workers."
    )
    .expect("register hedwig_worker_jobs_processed_total counter"),
    worker_job_duration: register_histogram!(
        "hedwig_worker_job_duration_seconds",
        "Time taken to process queued jobs through completion.",
        vec![0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0]
    )
    .expect("register hedwig_worker_job_duration_seconds histogram"),
    send_latency: register_histogram_vec!(
        "hedwig_send_latency_seconds",
        "Latency to hand off email to upstream MX servers, labelled by recipient domain.",
        &["domain"],
        vec![0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
    )
    .expect("register hedwig_send_latency_seconds histogram vec"),
    send_outcomes: register_int_counter_vec!(
        "hedwig_send_attempts_total",
        "Total send attempts grouped by domain and outcome (success/failure).",
        &["domain", "status"]
    )
    .expect("register hedwig_send_attempts_total counter vec"),
});

const STATUS_SUCCESS: &str = "success";
const STATUS_FAILURE: &str = "failure";

/// Tracks the current queue depth so we can update the gauge atomically.
static QUEUE_DEPTH: AtomicI64 = AtomicI64::new(0);

/// Increments the queued email gauge.
pub fn queue_depth_inc() {
    let new_value = QUEUE_DEPTH.fetch_add(1, Ordering::SeqCst) + 1;
    METRICS.queue_depth.set(new_value);
}

/// Decrements the queued email gauge, saturating at zero.
pub fn queue_depth_dec() {
    let mut current = QUEUE_DEPTH.load(Ordering::SeqCst);
    loop {
        if current <= 0 {
            METRICS.queue_depth.set(0);
            return;
        }

        match QUEUE_DEPTH.compare_exchange(current, current - 1, Ordering::SeqCst, Ordering::SeqCst)
        {
            Ok(_) => {
                METRICS.queue_depth.set(current - 1);
                return;
            }
            Err(actual) => current = actual,
        }
    }
}

/// Explicitly sets the queue depth gauge.
pub fn queue_depth_set(count: usize) {
    let value = count as i64;
    QUEUE_DEPTH.store(value, Ordering::SeqCst);
    METRICS.queue_depth.set(value);
}

/// Adds a retry attempt to the counter.
pub fn retry_scheduled() {
    METRICS.retry_total.inc();
}

/// Updates the pool utilisation gauge based on the current number of cached transports.
pub fn set_pool_entries(entries: u64) {
    METRICS.pool_entries.set(entries as i64);
}

/// Records the time taken to sign an email with DKIM.
pub fn observe_dkim_sign_latency(duration: Duration) {
    METRICS.dkim_sign_latency.observe(duration.as_secs_f64());
}

/// Records that we accepted an email from a client.
pub fn email_received() {
    METRICS.emails_received.inc();
}

/// Records that the worker successfully delivered an email upstream.
pub fn email_sent() {
    METRICS.emails_sent.inc();
}

/// Records that an email was deferred for retry.
pub fn email_deferred() {
    METRICS.emails_deferred.inc();
}

/// Records that an email permanently bounced.
pub fn email_bounced() {
    METRICS.emails_bounced.inc();
}

/// Records emails that were dropped without a delivery attempt.
pub fn email_dropped() {
    METRICS.emails_dropped.inc();
}

/// Guard that measures the lifetime of a worker job and updates metrics when dropped.
pub struct JobProcessingGuard {
    started: Instant,
}

impl JobProcessingGuard {
    pub fn new() -> Self {
        Self {
            started: Instant::now(),
        }
    }
}

impl Default for JobProcessingGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for JobProcessingGuard {
    fn drop(&mut self) {
        let elapsed = self.started.elapsed().as_secs_f64();
        METRICS.worker_jobs_processed.inc();
        METRICS.worker_job_duration.observe(elapsed);
    }
}

/// Returns a guard that tracks overall job processing time.
pub fn job_processing_guard() -> JobProcessingGuard {
    JobProcessingGuard::new()
}

fn normalize_domain(domain: &str) -> String {
    domain.trim_end_matches('.').to_ascii_lowercase()
}

/// Records a successful upstream delivery, including latency.
pub fn record_send_success(domain: &str, duration: Duration) {
    let normalized = normalize_domain(domain);
    METRICS
        .send_latency
        .with_label_values(&[normalized.as_str()])
        .observe(duration.as_secs_f64());
    METRICS
        .send_outcomes
        .with_label_values(&[normalized.as_str(), STATUS_SUCCESS])
        .inc();
}

/// Records a failed upstream delivery attempt.
pub fn record_send_failure(domain: &str) {
    let normalized = normalize_domain(domain);
    METRICS
        .send_outcomes
        .with_label_values(&[normalized.as_str(), STATUS_FAILURE])
        .inc();
}

/// Spawns the HTTP server that exposes Prometheus-compatible metrics.
pub fn spawn_metrics_server(addr: SocketAddr) {
    info!(%addr, "starting metrics endpoint");

    tokio::spawn(async move {
        let make_svc = make_service_fn(|_conn| async {
            Ok::<_, Infallible>(service_fn(handle_metrics_request))
        });

        if let Err(err) = Server::bind(&addr).serve(make_svc).await {
            error!(%addr, error = %err, "metrics server exited unexpectedly");
        } else {
            info!(%addr, "metrics server stopped");
        }
    });
}

async fn handle_metrics_request(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/metrics") | (&Method::HEAD, "/metrics") => {
            let encoder = TextEncoder::new();
            let metric_families = prometheus::gather();
            let mut buffer = Vec::new();

            if let Err(err) = encoder.encode(&metric_families, &mut buffer) {
                warn!(error = %err, "failed to encode metrics payload");
                let response = Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::from("failed to encode metrics"))
                    .expect("failed to build metrics error response");
                return Ok(response);
            }

            let response = Response::builder()
                .status(StatusCode::OK)
                .header(hyper::header::CONTENT_TYPE, encoder.format_type())
                .body(Body::from(buffer))
                .expect("failed to build metrics response");
            Ok(response)
        }
        _ => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from("not found"))
            .expect("failed to build metrics 404 response")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn queue_depth_updates_gauge() {
        queue_depth_set(0);
        queue_depth_inc();
        queue_depth_inc();
        queue_depth_dec();
        assert_eq!(QUEUE_DEPTH.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn queue_depth_does_not_go_negative() {
        queue_depth_set(0);
        queue_depth_dec();
        assert_eq!(QUEUE_DEPTH.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn retry_counter_increments() {
        let before = METRICS.retry_total.get();
        retry_scheduled();
        assert_eq!(METRICS.retry_total.get(), before + 1);
    }

    #[test]
    fn pool_entries_sets_value() {
        set_pool_entries(42);
        assert_eq!(METRICS.pool_entries.get(), 42);
    }

    #[test]
    fn histogram_accepts_samples() {
        observe_dkim_sign_latency(Duration::from_millis(5));
        // Ensure we collected at least one observation.
        assert!(METRICS.dkim_sign_latency.get_sample_count() >= 1);
    }

    #[test]
    fn job_guard_records_duration_and_count() {
        let before_count = METRICS.worker_jobs_processed.get();
        let before_samples = METRICS.worker_job_duration.get_sample_count();
        {
            let _guard = job_processing_guard();
            thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(METRICS.worker_jobs_processed.get(), before_count + 1);
        assert!(METRICS.worker_job_duration.get_sample_count() > before_samples);
    }

    #[test]
    fn record_send_success_updates_metrics() {
        let domain = "Example.COM.";
        let normalized = normalize_domain(domain);
        let before_success = METRICS
            .send_outcomes
            .with_label_values(&[normalized.as_str(), STATUS_SUCCESS])
            .get();
        let before_latency = METRICS
            .send_latency
            .with_label_values(&[normalized.as_str()])
            .get_sample_count();
        record_send_success(domain, Duration::from_millis(20));
        assert_eq!(
            METRICS
                .send_outcomes
                .with_label_values(&[normalized.as_str(), STATUS_SUCCESS])
                .get(),
            before_success + 1
        );
        assert!(
            METRICS
                .send_latency
                .with_label_values(&[normalized.as_str()])
                .get_sample_count()
                > before_latency
        );
    }

    #[test]
    fn record_send_failure_increments_counter() {
        let domain = "Failure.Test";
        let normalized = normalize_domain(domain);
        let before_failure = METRICS
            .send_outcomes
            .with_label_values(&[normalized.as_str(), STATUS_FAILURE])
            .get();
        record_send_failure(domain);
        assert_eq!(
            METRICS
                .send_outcomes
                .with_label_values(&[normalized.as_str(), STATUS_FAILURE])
                .get(),
            before_failure + 1
        );
    }

    #[test]
    fn email_counters_increment() {
        let before_received = METRICS.emails_received.get();
        email_received();
        assert_eq!(METRICS.emails_received.get(), before_received + 1);

        let before_sent = METRICS.emails_sent.get();
        email_sent();
        assert_eq!(METRICS.emails_sent.get(), before_sent + 1);

        let before_deferred = METRICS.emails_deferred.get();
        email_deferred();
        assert_eq!(METRICS.emails_deferred.get(), before_deferred + 1);

        let before_bounced = METRICS.emails_bounced.get();
        email_bounced();
        assert_eq!(METRICS.emails_bounced.get(), before_bounced + 1);

        let before_dropped = METRICS.emails_dropped.get();
        email_dropped();
        assert_eq!(METRICS.emails_dropped.get(), before_dropped + 1);
    }
}
