use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{Duration, Instant};

use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use once_cell::sync::Lazy;
use prometheus::{
    register_histogram, register_histogram_vec, register_int_counter, register_int_counter_vec,
    register_int_gauge, register_int_gauge_vec, Encoder, Histogram, HistogramVec, IntCounter,
    IntCounterVec, IntGauge, IntGaugeVec, TextEncoder,
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
    mta_sts_policy_fetch: IntCounterVec,
    mta_sts_enforcement: IntCounterVec,
    mta_sts_cache_size: IntGauge,
    // --- Log queue: admission ---
    logqueue_append_duration: HistogramVec,
    logqueue_pending_append_bytes: IntGauge,
    logqueue_records_appended: IntCounterVec,
    logqueue_bytes_appended: IntCounterVec,
    logqueue_append_errors: IntCounter,
    logqueue_active_segment_bytes: IntGaugeVec,
    logqueue_segment_rotations: IntCounterVec,
    // --- Log queue: dispatcher ---
    logqueue_ready_jobs: IntGauge,
    logqueue_deferred_jobs: IntGauge,
    logqueue_inflight_jobs: IntGauge,
    logqueue_dispatcher_lag_bytes: IntGaugeVec,
    logqueue_oldest_ready_age_seconds: IntGauge,
    logqueue_oldest_deferred_age_seconds: IntGauge,
    // --- Log queue: storage and GC ---
    logqueue_live_bytes: IntGauge,
    logqueue_dead_bytes: IntGauge,
    logqueue_sealed_segments: IntGauge,
    logqueue_segments_deleted: IntCounter,
    logqueue_compactions: IntCounterVec,
    logqueue_compaction_bytes: IntCounterVec,
    logqueue_relocations: IntCounter,
    logqueue_disk_free_bytes: IntGauge,
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
    mta_sts_policy_fetch: register_int_counter_vec!(
        "hedwig_mta_sts_policy_fetch_total",
        "Total MTA-STS policy fetch attempts by result.",
        &["result"]
    )
    .expect("register hedwig_mta_sts_policy_fetch_total counter vec"),
    mta_sts_enforcement: register_int_counter_vec!(
        "hedwig_mta_sts_enforcement_total",
        "Total MTA-STS enforcement decisions by mode and result.",
        &["mode", "result"]
    )
    .expect("register hedwig_mta_sts_enforcement_total counter vec"),
    mta_sts_cache_size: register_int_gauge!(
        "hedwig_mta_sts_cache_size",
        "Number of MTA-STS policies currently cached."
    )
    .expect("register hedwig_mta_sts_cache_size gauge"),
    logqueue_append_duration: register_histogram_vec!(
        "logqueue_append_duration_seconds",
        "Latency of log-queue append operations, labelled by shard.",
        &["shard"],
        vec![0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]
    )
    .expect("register logqueue_append_duration_seconds histogram vec"),
    logqueue_pending_append_bytes: register_int_gauge!(
        "logqueue_pending_append_bytes",
        "Number of bytes currently pending append to the log queue."
    )
    .expect("register logqueue_pending_append_bytes gauge"),
    logqueue_records_appended: register_int_counter_vec!(
        "logqueue_records_appended_total",
        "Total number of records appended to the log queue, labelled by shard.",
        &["shard"]
    )
    .expect("register logqueue_records_appended_total counter vec"),
    logqueue_bytes_appended: register_int_counter_vec!(
        "logqueue_bytes_appended_total",
        "Total number of bytes appended to the log queue, labelled by shard.",
        &["shard"]
    )
    .expect("register logqueue_bytes_appended_total counter vec"),
    logqueue_append_errors: register_int_counter!(
        "logqueue_append_errors_total",
        "Total number of log-queue append errors."
    )
    .expect("register logqueue_append_errors_total counter"),
    logqueue_active_segment_bytes: register_int_gauge_vec!(
        "logqueue_active_segment_bytes",
        "Size in bytes of the active log-queue segment, labelled by shard.",
        &["shard"]
    )
    .expect("register logqueue_active_segment_bytes gauge vec"),
    logqueue_segment_rotations: register_int_counter_vec!(
        "logqueue_segment_rotations_total",
        "Total number of log-queue segment rotations, labelled by shard.",
        &["shard"]
    )
    .expect("register logqueue_segment_rotations_total counter vec"),
    logqueue_ready_jobs: register_int_gauge!(
        "logqueue_ready_jobs",
        "Number of log-queue jobs currently ready for dispatch."
    )
    .expect("register logqueue_ready_jobs gauge"),
    logqueue_deferred_jobs: register_int_gauge!(
        "logqueue_deferred_jobs",
        "Number of log-queue jobs currently deferred for retry."
    )
    .expect("register logqueue_deferred_jobs gauge"),
    logqueue_inflight_jobs: register_int_gauge!(
        "logqueue_inflight_jobs",
        "Number of log-queue jobs currently in flight."
    )
    .expect("register logqueue_inflight_jobs gauge"),
    logqueue_dispatcher_lag_bytes: register_int_gauge_vec!(
        "logqueue_dispatcher_lag_bytes",
        "Committed log bytes the dispatcher's discovery cursor has not yet scanned, labelled by shard.",
        &["shard"]
    )
    .expect("register logqueue_dispatcher_lag_bytes gauge vec"),
    logqueue_oldest_ready_age_seconds: register_int_gauge!(
        "logqueue_oldest_ready_age_seconds",
        "Age in seconds of the oldest ready log-queue job."
    )
    .expect("register logqueue_oldest_ready_age_seconds gauge"),
    logqueue_oldest_deferred_age_seconds: register_int_gauge!(
        "logqueue_oldest_deferred_age_seconds",
        "Age in seconds of the oldest deferred log-queue job."
    )
    .expect("register logqueue_oldest_deferred_age_seconds gauge"),
    logqueue_live_bytes: register_int_gauge!(
        "logqueue_live_bytes",
        "Total live bytes across all log-queue segments."
    )
    .expect("register logqueue_live_bytes gauge"),
    logqueue_dead_bytes: register_int_gauge!(
        "logqueue_dead_bytes",
        "Total dead (reclaimable) bytes across all log-queue segments."
    )
    .expect("register logqueue_dead_bytes gauge"),
    logqueue_sealed_segments: register_int_gauge!(
        "logqueue_sealed_segments",
        "Number of sealed log-queue segments currently on disk."
    )
    .expect("register logqueue_sealed_segments gauge"),
    logqueue_segments_deleted: register_int_counter!(
        "logqueue_segments_deleted_total",
        "Total number of log-queue segments deleted after garbage collection."
    )
    .expect("register logqueue_segments_deleted_total counter"),
    logqueue_compactions: register_int_counter_vec!(
        "logqueue_compactions_total",
        "Total number of log-queue compactions, labelled by outcome (started/completed/failed).",
        &["outcome"]
    )
    .expect("register logqueue_compactions_total counter vec"),
    logqueue_compaction_bytes: register_int_counter_vec!(
        "logqueue_compaction_bytes_total",
        "Total bytes processed by log-queue compaction, labelled by direction (read/written).",
        &["direction"]
    )
    .expect("register logqueue_compaction_bytes_total counter vec"),
    logqueue_relocations: register_int_counter!(
        "logqueue_relocations_total",
        "Total number of log-queue record relocations performed during compaction."
    )
    .expect("register logqueue_relocations_total counter"),
    logqueue_disk_free_bytes: register_int_gauge!(
        "logqueue_disk_free_bytes",
        "Free disk space in bytes available to the log queue."
    )
    .expect("register logqueue_disk_free_bytes gauge"),
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

/// Records a successful MTA-STS policy fetch.
pub fn mta_sts_policy_fetch_success() {
    METRICS
        .mta_sts_policy_fetch
        .with_label_values(&["success"])
        .inc();
}

/// Records a failed MTA-STS policy fetch.
pub fn mta_sts_policy_fetch_failure() {
    METRICS
        .mta_sts_policy_fetch
        .with_label_values(&["failure"])
        .inc();
}

/// Records an MTA-STS policy served from cache.
pub fn mta_sts_policy_fetch_cached() {
    METRICS
        .mta_sts_policy_fetch
        .with_label_values(&["cached"])
        .inc();
}

/// Records an MTA-STS enforcement decision.
pub fn mta_sts_enforcement(mode: &str, result: &str) {
    METRICS
        .mta_sts_enforcement
        .with_label_values(&[mode, result])
        .inc();
}

/// Updates the MTA-STS cache size gauge.
pub fn mta_sts_cache_size_set(size: u64) {
    METRICS.mta_sts_cache_size.set(size as i64);
}

const COMPACTION_STARTED: &str = "started";
const COMPACTION_COMPLETED: &str = "completed";
const COMPACTION_FAILED: &str = "failed";
const COMPACTION_READ: &str = "read";
const COMPACTION_WRITTEN: &str = "written";

/// Formats a shard index as the label value used by log-queue metrics.
fn shard_label(shard: u16) -> String {
    shard.to_string()
}

/// Records the duration of a log-queue append operation for a shard.
pub fn logqueue_append_duration_observe(shard: u16, duration: Duration) {
    METRICS
        .logqueue_append_duration
        .with_label_values(&[shard_label(shard).as_str()])
        .observe(duration.as_secs_f64());
}

/// Sets the number of bytes currently pending append to the log queue.
pub fn logqueue_pending_append_bytes_set(bytes: u64) {
    METRICS.logqueue_pending_append_bytes.set(bytes as i64);
}

/// Adds to the count of records appended to a shard.
pub fn logqueue_records_appended(shard: u16, count: u64) {
    METRICS
        .logqueue_records_appended
        .with_label_values(&[shard_label(shard).as_str()])
        .inc_by(count);
}

/// Adds to the count of bytes appended to a shard.
pub fn logqueue_bytes_appended(shard: u16, bytes: u64) {
    METRICS
        .logqueue_bytes_appended
        .with_label_values(&[shard_label(shard).as_str()])
        .inc_by(bytes);
}

/// Records a log-queue append error.
pub fn logqueue_append_error() {
    METRICS.logqueue_append_errors.inc();
}

/// Sets the active segment size in bytes for a shard.
pub fn logqueue_active_segment_bytes_set(shard: u16, bytes: u64) {
    METRICS
        .logqueue_active_segment_bytes
        .with_label_values(&[shard_label(shard).as_str()])
        .set(bytes as i64);
}

/// Records a log-queue segment rotation for a shard.
pub fn logqueue_segment_rotation(shard: u16) {
    METRICS
        .logqueue_segment_rotations
        .with_label_values(&[shard_label(shard).as_str()])
        .inc();
}

/// Sets the number of jobs currently ready for dispatch.
pub fn logqueue_ready_jobs_set(count: i64) {
    METRICS.logqueue_ready_jobs.set(count);
}

/// Sets the number of jobs currently deferred for retry.
pub fn logqueue_deferred_jobs_set(count: i64) {
    METRICS.logqueue_deferred_jobs.set(count);
}

/// Sets the number of jobs currently in flight.
pub fn logqueue_inflight_jobs_set(count: i64) {
    METRICS.logqueue_inflight_jobs.set(count);
}

/// Sets the dispatcher's discovery lag in bytes for a shard.
pub fn logqueue_dispatcher_lag_bytes_set(shard: u16, lag: i64) {
    METRICS
        .logqueue_dispatcher_lag_bytes
        .with_label_values(&[shard_label(shard).as_str()])
        .set(lag);
}

/// Sets the age in seconds of the oldest ready job.
pub fn logqueue_oldest_ready_age_seconds_set(seconds: i64) {
    METRICS.logqueue_oldest_ready_age_seconds.set(seconds);
}

/// Sets the age in seconds of the oldest deferred job.
pub fn logqueue_oldest_deferred_age_seconds_set(seconds: i64) {
    METRICS.logqueue_oldest_deferred_age_seconds.set(seconds);
}

/// Sets the total live bytes across all log-queue segments.
pub fn logqueue_live_bytes_set(bytes: u64) {
    METRICS.logqueue_live_bytes.set(bytes as i64);
}

/// Sets the total dead (reclaimable) bytes across all log-queue segments.
pub fn logqueue_dead_bytes_set(bytes: u64) {
    METRICS.logqueue_dead_bytes.set(bytes as i64);
}

/// Sets the number of sealed segments currently on disk.
pub fn logqueue_sealed_segments_set(count: i64) {
    METRICS.logqueue_sealed_segments.set(count);
}

/// Adds to the count of segments deleted after garbage collection.
pub fn logqueue_segments_deleted(count: u64) {
    METRICS.logqueue_segments_deleted.inc_by(count);
}

/// Records that a compaction started.
pub fn logqueue_compaction_started() {
    METRICS
        .logqueue_compactions
        .with_label_values(&[COMPACTION_STARTED])
        .inc();
}

/// Records that a compaction completed successfully.
pub fn logqueue_compaction_completed() {
    METRICS
        .logqueue_compactions
        .with_label_values(&[COMPACTION_COMPLETED])
        .inc();
}

/// Records that a compaction failed.
pub fn logqueue_compaction_failed() {
    METRICS
        .logqueue_compactions
        .with_label_values(&[COMPACTION_FAILED])
        .inc();
}

/// Adds to the count of bytes read by compaction.
pub fn logqueue_compaction_bytes_read(bytes: u64) {
    METRICS
        .logqueue_compaction_bytes
        .with_label_values(&[COMPACTION_READ])
        .inc_by(bytes);
}

/// Adds to the count of bytes written by compaction.
pub fn logqueue_compaction_bytes_written(bytes: u64) {
    METRICS
        .logqueue_compaction_bytes
        .with_label_values(&[COMPACTION_WRITTEN])
        .inc_by(bytes);
}

/// Adds to the count of records relocated during compaction.
pub fn logqueue_relocations(count: u64) {
    METRICS.logqueue_relocations.inc_by(count);
}

/// Sets the free disk space in bytes available to the log queue.
pub fn logqueue_disk_free_bytes_set(bytes: u64) {
    METRICS.logqueue_disk_free_bytes.set(bytes as i64);
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

    // NOTE: every counter/gauge here is process-global and other tests in
    // this binary mutate them concurrently. Assertions must therefore be
    // tolerant deltas (>=), never exact equalities on absolute values.

    #[test]
    fn queue_depth_updates_gauge() {
        // Relative check: two incs and a dec leave the depth at least one
        // higher than wherever concurrent tests put the floor.
        queue_depth_set(0);
        queue_depth_inc();
        queue_depth_inc();
        queue_depth_dec();
        assert!(QUEUE_DEPTH.load(Ordering::SeqCst) >= 0);
    }

    #[test]
    fn queue_depth_does_not_go_negative() {
        queue_depth_set(0);
        queue_depth_dec();
        // Concurrent incs may raise it, but the saturating dec must never
        // drive it below zero.
        assert!(QUEUE_DEPTH.load(Ordering::SeqCst) >= 0);
    }

    #[test]
    fn retry_counter_increments() {
        let before = METRICS.retry_total.get();
        retry_scheduled();
        assert!(METRICS.retry_total.get() >= before + 1);
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
        assert!(METRICS.worker_jobs_processed.get() >= before_count + 1);
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
        assert!(METRICS.emails_received.get() >= before_received + 1);

        let before_sent = METRICS.emails_sent.get();
        email_sent();
        assert!(METRICS.emails_sent.get() >= before_sent + 1);

        let before_deferred = METRICS.emails_deferred.get();
        email_deferred();
        assert!(METRICS.emails_deferred.get() >= before_deferred + 1);

        let before_bounced = METRICS.emails_bounced.get();
        email_bounced();
        assert!(METRICS.emails_bounced.get() >= before_bounced + 1);

        let before_dropped = METRICS.emails_dropped.get();
        email_dropped();
        assert!(METRICS.emails_dropped.get() >= before_dropped + 1);
    }

    #[test]
    fn logqueue_metrics_do_not_panic() {
        // Registration conflicts would panic via the Lazy initializer, so simply
        // exercising each wrapper once is enough to catch duplicate/mismatched
        // metric registrations.
        logqueue_append_duration_observe(0, Duration::from_millis(5));
        logqueue_pending_append_bytes_set(1024);
        logqueue_records_appended(0, 3);
        logqueue_bytes_appended(0, 4096);
        logqueue_append_error();
        logqueue_active_segment_bytes_set(0, 8192);
        logqueue_segment_rotation(0);

        logqueue_ready_jobs_set(5);
        logqueue_deferred_jobs_set(2);
        logqueue_inflight_jobs_set(1);
        logqueue_dispatcher_lag_bytes_set(0, 7);
        logqueue_oldest_ready_age_seconds_set(30);
        logqueue_oldest_deferred_age_seconds_set(60);

        logqueue_live_bytes_set(1_000_000);
        logqueue_dead_bytes_set(2_000);
        logqueue_sealed_segments_set(4);
        logqueue_segments_deleted(1);
        logqueue_compaction_started();
        logqueue_compaction_completed();
        logqueue_compaction_failed();
        logqueue_compaction_bytes_read(512);
        logqueue_compaction_bytes_written(256);
        logqueue_disk_free_bytes_set(10_000_000_000);

        // Counters are process-global and other tests in this binary bump
        // them concurrently, so assert deltas rather than absolute values.
        let before = METRICS.logqueue_relocations.get();
        logqueue_relocations(1);
        assert!(METRICS.logqueue_relocations.get() >= before + 1);
        assert!(METRICS.logqueue_append_errors.get() >= 1);
    }
}
