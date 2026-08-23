//! Rate limiting module for controlling email sending rates to destination domains.
//!
//! This module implements a token bucket algorithm to rate limit outbound email
//! delivery on a per-domain basis. This prevents overwhelming destination SMTP
//! servers and helps maintain good sender reputation.
//!
//! # Features
//!
//! - **Per-Domain Limits**: Independent rate limits for each destination domain
//! - **Token Bucket Algorithm**: Allows burst sending up to limit, then enforces steady rate
//! - **Configurable Limits**: Both default and domain-specific rate limits
//! - **Thread Safety**: Safe concurrent access across multiple worker threads
//! - **Non-Blocking**: Workers wait asynchronously when rate limited
//!
//! # Usage
//!
//! ```rust,no_run
//! use hedwig::worker::rate_limiter::{RateLimiter, RateLimitConfig, RateLimitResult};
//! use std::collections::HashMap;
//!
//! # async fn example() {
//! // Create configuration
//! let mut domain_limits = HashMap::new();
//! domain_limits.insert("gmail.com".to_string(), 30);
//!
//! let config = RateLimitConfig {
//!     enabled: true,
//!     default_limit: None,
//!     domain_limits,
//! };
//!
//! // Create rate limiter
//! let limiter = RateLimiter::new(config);
//!
//! // Check rate limit before sending
//! match limiter.check_rate_limit("gmail.com").await {
//!     RateLimitResult::Allowed => {
//!         // Send email
//!     }
//!     RateLimitResult::RateLimited { retry_after } => {
//!         // Wait before retrying
//!         tokio::time::sleep(retry_after).await;
//!     }
//! }
//! # }
//! ```

use std::{
    collections::HashMap,
    hash::{Hash, Hasher},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

/// Number of independently locked bucket maps. Checks hash their domain to
/// one of these, so unrelated destinations never serialize against each
/// other. A critical section is pure arithmetic on one bucket — no I/O and
/// never an await — so a std Mutex is the right primitive.
const BUCKET_SHARDS: usize = 16;

/// Buckets untouched for this long are dropped by the sweep below.
const BUCKET_IDLE_TTL: Duration = Duration::from_secs(10 * 60);

/// A shard sweeps idle buckets when it grows past this many entries. Without
/// it the map keeps one bucket per distinct recipient domain forever.
const SWEEP_THRESHOLD: usize = 1024;

/// Configuration for rate limiting email sending.
///
/// This structure defines the rate limiting behavior for outbound email delivery.
/// Rate limits are expressed in emails per minute.
#[derive(Debug, Clone, Default)]
pub struct RateLimitConfig {
    /// Enable or disable rate limiting globally.
    pub enabled: bool,
    /// Optional fallback limit for domains without a domain-specific limit.
    /// When absent or zero, unconfigured domains are not rate limited.
    pub default_limit: Option<u32>,
    /// Domain-specific rate limits that override the optional fallback.
    pub domain_limits: HashMap<String, u32>,
}

/// Token bucket implementation for rate limiting.
///
/// A token bucket maintains a bucket of tokens that are consumed when performing
/// rate-limited operations. Tokens are refilled at a steady rate, allowing for
/// burst capacity up to the bucket's capacity while maintaining the overall rate limit.
struct TokenBucket {
    /// Current number of available tokens
    tokens: u32,
    /// Maximum number of tokens the bucket can hold
    capacity: u32,
    /// Last time tokens were refilled
    last_refill: Instant,
    /// Rate at which tokens are refilled (tokens per minute)
    refill_rate: u32,
    /// Last time this bucket was consulted, for idle eviction. Distinct
    /// from `last_refill`, which only moves when tokens are actually added.
    last_seen: Instant,
}

impl TokenBucket {
    /// Creates a new token bucket with the specified capacity and refill rate.
    ///
    /// # Arguments
    /// * `capacity` - Maximum number of tokens the bucket can hold
    /// * `refill_rate` - Rate at which tokens are added (tokens per minute)
    fn new(capacity: u32, refill_rate: u32) -> Self {
        let now = Instant::now();
        Self {
            tokens: capacity,
            capacity,
            last_refill: now,
            refill_rate,
            last_seen: now,
        }
    }

    /// Attempts to consume one token from the bucket.
    ///
    /// Returns `true` if a token was successfully consumed, `false` if no tokens are available.
    fn try_consume(&mut self) -> bool {
        self.refill();
        if self.tokens > 0 {
            self.tokens -= 1;
            true
        } else {
            false
        }
    }

    /// Refills tokens based on elapsed time since last refill.
    ///
    /// Tokens are added proportionally to the time elapsed, up to the bucket's capacity.
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill);

        if elapsed >= Duration::from_secs(1) {
            let seconds_elapsed = elapsed.as_secs_f64();
            let tokens_to_add = ((self.refill_rate as f64 / 60.0) * seconds_elapsed) as u32;

            if tokens_to_add > 0 {
                self.tokens = (self.tokens + tokens_to_add).min(self.capacity);
                self.last_refill = now;
            }
        }
    }

    /// Calculates how long to wait until a token becomes available.
    ///
    /// Returns `Duration::ZERO` if tokens are currently available.
    fn time_until_token_available(&mut self) -> Duration {
        self.refill();
        if self.tokens > 0 {
            Duration::ZERO
        } else {
            // Calculate how long until next token is available
            let tokens_per_second = self.refill_rate as f64 / 60.0;
            let seconds_until_token = 1.0 / tokens_per_second;
            Duration::from_secs_f64(seconds_until_token)
        }
    }
}

/// Per-domain token buckets, split across independently locked shards.
struct Buckets {
    shards: Vec<Mutex<HashMap<String, TokenBucket>>>,
}

impl Buckets {
    fn new() -> Self {
        Self {
            shards: (0..BUCKET_SHARDS)
                .map(|_| Mutex::new(HashMap::new()))
                .collect(),
        }
    }

    fn shard_for(&self, domain: &str) -> &Mutex<HashMap<String, TokenBucket>> {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        domain.hash(&mut hasher);
        &self.shards[hasher.finish() as usize % self.shards.len()]
    }

    /// Run `f` against `domain`'s bucket, creating it on first use.
    ///
    /// The hit path looks the bucket up by `&str`, so a check against an
    /// existing domain allocates nothing. A poisoned lock is recovered from
    /// rather than propagated: the worst case is one bucket with stale
    /// token accounting, which must not take down mail delivery.
    fn with_bucket<R>(
        &self,
        domain: &str,
        limit: u32,
        f: impl FnOnce(&mut TokenBucket) -> R,
    ) -> R {
        let mut shard = self
            .shard_for(domain)
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(bucket) = shard.get_mut(domain) {
            bucket.last_seen = Instant::now();
            return f(bucket);
        }
        if shard.len() >= SWEEP_THRESHOLD {
            let now = Instant::now();
            shard.retain(|_, b| now.duration_since(b.last_seen) < BUCKET_IDLE_TTL);
        }
        let bucket = shard
            .entry(domain.to_string())
            .or_insert_with(|| TokenBucket::new(limit, limit));
        f(bucket)
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.shards
            .iter()
            .map(|s| s.lock().expect("test locks are not poisoned").len())
            .sum()
    }
}

/// Rate limiter for controlling email sending rates per domain.
///
/// The RateLimiter maintains a collection of token buckets, one for each domain,
/// and enforces rate limits when checking before sending emails.
#[derive(Clone)]
pub struct RateLimiter {
    config: RateLimitConfig,
    /// Thread-safe storage for per-domain token buckets
    buckets: Arc<Buckets>,
}

impl RateLimiter {
    /// Creates a new rate limiter with the given configuration.
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            buckets: Arc::new(Buckets::new()),
        }
    }

    /// The configured limit for `domain`, or `None` when it is unlimited.
    fn limit_for(&self, domain: &str) -> Option<u32> {
        if !self.config.enabled {
            return None;
        }
        let limit = self
            .config
            .domain_limits
            .get(domain)
            .copied()
            .or(self.config.default_limit)?;
        (limit > 0).then_some(limit)
    }

    /// Checks if an email can be sent to the specified domain.
    ///
    /// Returns `RateLimitResult::Allowed` if the email can be sent immediately,
    /// or `RateLimitResult::RateLimited` with the duration to wait before retrying.
    ///
    /// # Arguments
    /// * `domain` - The destination domain to check rate limits for
    ///
    /// # Returns
    /// * `RateLimitResult::Allowed` - Email can be sent immediately
    /// * `RateLimitResult::RateLimited { retry_after }` - Must wait before sending
    pub async fn check_rate_limit(&self, domain: &str) -> RateLimitResult {
        let Some(limit) = self.limit_for(domain) else {
            return RateLimitResult::Allowed;
        };

        self.buckets.with_bucket(domain, limit, |bucket| {
            if bucket.try_consume() {
                RateLimitResult::Allowed
            } else {
                RateLimitResult::RateLimited {
                    retry_after: bucket.time_until_token_available(),
                }
            }
        })
    }

    /// Non-consuming availability check used by the log-queue dispatcher to
    /// gate claims: `None` when a token is available (or the domain is not
    /// limited), otherwise roughly how long until one is. The worker's
    /// consuming check before transmission remains authoritative.
    pub fn peek_sync(&self, domain: &str) -> Option<Duration> {
        let limit = self.limit_for(domain)?;
        self.buckets.with_bucket(domain, limit, |bucket| {
            let wait = bucket.time_until_token_available();
            (!wait.is_zero()).then_some(wait)
        })
    }
}

/// Result of a rate limit check.
///
/// Indicates whether an operation is allowed to proceed or should be delayed.
#[derive(Debug, Clone)]
pub enum RateLimitResult {
    /// Operation is allowed to proceed immediately.
    Allowed,
    /// Operation is rate limited and should be retried after the specified duration.
    RateLimited {
        /// Duration to wait before retrying the operation.
        retry_after: Duration,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{sleep, Duration};

    #[tokio::test]
    async fn test_rate_limiter_disabled() {
        let config = RateLimitConfig {
            enabled: false,
            default_limit: Some(1),
            domain_limits: HashMap::new(),
        };

        let limiter = RateLimiter::new(config);

        // Should always allow when disabled
        for _ in 0..10 {
            let result = limiter.check_rate_limit("example.com").await;
            assert!(matches!(result, RateLimitResult::Allowed));
        }
    }

    #[tokio::test]
    async fn test_rate_limiter_default_limit() {
        let config = RateLimitConfig {
            enabled: true,
            default_limit: Some(2),
            domain_limits: HashMap::new(),
        };

        let limiter = RateLimiter::new(config);

        // First two should be allowed
        assert!(matches!(
            limiter.check_rate_limit("example.com").await,
            RateLimitResult::Allowed
        ));
        assert!(matches!(
            limiter.check_rate_limit("example.com").await,
            RateLimitResult::Allowed
        ));

        // Third should be rate limited
        let result = limiter.check_rate_limit("example.com").await;
        assert!(matches!(result, RateLimitResult::RateLimited { .. }));
    }

    #[tokio::test]
    async fn test_rate_limiter_domain_specific_limit() {
        let mut domain_limits = HashMap::new();
        domain_limits.insert("special.com".to_string(), 5);

        let config = RateLimitConfig {
            enabled: true,
            default_limit: Some(2),
            domain_limits,
        };

        let limiter = RateLimiter::new(config);

        // special.com should have limit of 5
        for _ in 0..5 {
            assert!(matches!(
                limiter.check_rate_limit("special.com").await,
                RateLimitResult::Allowed
            ));
        }

        // Sixth should be rate limited
        let result = limiter.check_rate_limit("special.com").await;
        assert!(matches!(result, RateLimitResult::RateLimited { .. }));

        // regular.com should have default limit of 2
        for _ in 0..2 {
            assert!(matches!(
                limiter.check_rate_limit("regular.com").await,
                RateLimitResult::Allowed
            ));
        }

        let result = limiter.check_rate_limit("regular.com").await;
        assert!(matches!(result, RateLimitResult::RateLimited { .. }));
    }

    #[tokio::test]
    async fn test_clones_share_domain_buckets() {
        let limiter = RateLimiter::new(RateLimitConfig {
            enabled: true,
            default_limit: Some(1),
            domain_limits: HashMap::new(),
        });
        let other_worker = limiter.clone();

        assert!(matches!(
            limiter.check_rate_limit("example.com").await,
            RateLimitResult::Allowed
        ));
        assert!(matches!(
            other_worker.check_rate_limit("example.com").await,
            RateLimitResult::RateLimited { .. }
        ));
    }

    #[tokio::test]
    async fn test_unconfigured_domain_allowed_without_default_limit() {
        let mut domain_limits = HashMap::new();
        domain_limits.insert("limited.com".to_string(), 1);
        let limiter = RateLimiter::new(RateLimitConfig {
            enabled: true,
            default_limit: None,
            domain_limits,
        });

        for _ in 0..10 {
            assert!(matches!(
                limiter.check_rate_limit("unconfigured.com").await,
                RateLimitResult::Allowed
            ));
        }

        assert!(matches!(
            limiter.check_rate_limit("limited.com").await,
            RateLimitResult::Allowed
        ));
        assert!(matches!(
            limiter.check_rate_limit("limited.com").await,
            RateLimitResult::RateLimited { .. }
        ));
    }

    #[tokio::test]
    async fn test_zero_default_limit_allows_unconfigured_domains() {
        let mut domain_limits = HashMap::new();
        domain_limits.insert("limited.com".to_string(), 1);
        let limiter = RateLimiter::new(RateLimitConfig {
            enabled: true,
            default_limit: Some(0),
            domain_limits,
        });

        for _ in 0..10 {
            assert!(matches!(
                limiter.check_rate_limit("unconfigured.com").await,
                RateLimitResult::Allowed
            ));
        }

        assert!(matches!(
            limiter.check_rate_limit("limited.com").await,
            RateLimitResult::Allowed
        ));
        assert!(matches!(
            limiter.check_rate_limit("limited.com").await,
            RateLimitResult::RateLimited { .. }
        ));
    }

    #[tokio::test]
    async fn test_idle_buckets_are_swept_once_a_shard_grows() {
        // The sweep only runs on a miss in a shard past SWEEP_THRESHOLD, so
        // drive the retain predicate directly with an already-elapsed TTL.
        let buckets = Buckets::new();
        buckets.with_bucket("a.example", 10, |b| b.try_consume());
        buckets.with_bucket("b.example", 10, |b| b.try_consume());
        assert_eq!(buckets.len(), 2);

        for shard in &buckets.shards {
            let mut shard = shard.lock().unwrap();
            let now = Instant::now();
            shard.retain(|_, b| now.duration_since(b.last_seen) < Duration::ZERO);
        }
        assert_eq!(buckets.len(), 0, "idle buckets must not accumulate");
    }

    #[tokio::test]
    async fn test_repeated_checks_reuse_one_bucket_per_domain() {
        let limiter = RateLimiter::new(RateLimitConfig {
            enabled: true,
            default_limit: Some(100),
            domain_limits: HashMap::new(),
        });
        for _ in 0..50 {
            limiter.check_rate_limit("example.com").await;
            limiter.peek_sync("example.com");
        }
        assert_eq!(limiter.buckets.len(), 1);
    }

    #[tokio::test]
    async fn test_peek_sync_reports_exhaustion_without_consuming() {
        let limiter = RateLimiter::new(RateLimitConfig {
            enabled: true,
            default_limit: Some(1),
            domain_limits: HashMap::new(),
        });

        // Peeking must not consume the only token, however often it runs.
        for _ in 0..5 {
            assert!(limiter.peek_sync("example.com").is_none());
        }
        assert!(matches!(
            limiter.check_rate_limit("example.com").await,
            RateLimitResult::Allowed
        ));
        // Now exhausted, the gate reports a wait instead of allowing.
        assert!(limiter.peek_sync("example.com").is_some());
    }

    #[tokio::test]
    async fn test_token_bucket_refill() {
        let mut bucket = TokenBucket::new(2, 120); // 2 tokens per minute

        // Consume all tokens
        assert!(bucket.try_consume());
        assert!(bucket.try_consume());
        assert!(!bucket.try_consume()); // Should fail

        // Wait for token refill (simulate 1 second = 2 tokens)
        sleep(Duration::from_millis(1100)).await;

        // Should have refilled some tokens
        bucket.refill();
        assert!(bucket.try_consume()); // Should succeed now
    }

    #[tokio::test]
    async fn test_different_domains_independent_limits() {
        let config = RateLimitConfig {
            enabled: true,
            default_limit: Some(1),
            domain_limits: HashMap::new(),
        };

        let limiter = RateLimiter::new(config);

        // Each domain should have independent rate limits
        assert!(matches!(
            limiter.check_rate_limit("domain1.com").await,
            RateLimitResult::Allowed
        ));
        assert!(matches!(
            limiter.check_rate_limit("domain2.com").await,
            RateLimitResult::Allowed
        ));

        // Both domains should now be rate limited
        assert!(matches!(
            limiter.check_rate_limit("domain1.com").await,
            RateLimitResult::RateLimited { .. }
        ));
        assert!(matches!(
            limiter.check_rate_limit("domain2.com").await,
            RateLimitResult::RateLimited { .. }
        ));
    }
}
