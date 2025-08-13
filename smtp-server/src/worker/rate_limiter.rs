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
//! ```rust
//! use crate::worker::rate_limiter::{RateLimiter, RateLimitConfig, RateLimitResult};
//! use std::collections::HashMap;
//!
//! // Create configuration
//! let mut domain_limits = HashMap::new();
//! domain_limits.insert("gmail.com".to_string(), 30);
//!
//! let config = RateLimitConfig {
//!     enabled: true,
//!     default_limit: 60,  // 60 emails per minute
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
//! ```

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::RwLock;

/// Configuration for rate limiting email sending.
///
/// This structure defines the rate limiting behavior for outbound email delivery.
/// Rate limits are expressed in emails per minute.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Enable or disable rate limiting globally.
    pub enabled: bool,
    /// Default rate limit applied to all domains (emails per minute).
    pub default_limit: u32,
    /// Domain-specific rate limits that override the default (emails per minute).
    pub domain_limits: HashMap<String, u32>,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            default_limit: 60, // 60 emails per minute by default
            domain_limits: HashMap::new(),
        }
    }
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
}

impl TokenBucket {
    /// Creates a new token bucket with the specified capacity and refill rate.
    ///
    /// # Arguments
    /// * `capacity` - Maximum number of tokens the bucket can hold
    /// * `refill_rate` - Rate at which tokens are added (tokens per minute)
    fn new(capacity: u32, refill_rate: u32) -> Self {
        Self {
            tokens: capacity,
            capacity,
            last_refill: Instant::now(),
            refill_rate,
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

/// Rate limiter for controlling email sending rates per domain.
///
/// The RateLimiter maintains a collection of token buckets, one for each domain,
/// and enforces rate limits when checking before sending emails.
pub struct RateLimiter {
    config: RateLimitConfig,
    /// Thread-safe storage for per-domain token buckets
    buckets: Arc<RwLock<HashMap<String, TokenBucket>>>,
}

impl RateLimiter {
    /// Creates a new rate limiter with the given configuration.
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            buckets: Arc::new(RwLock::new(HashMap::new())),
        }
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
        if !self.config.enabled {
            return RateLimitResult::Allowed;
        }

        let limit = self
            .config
            .domain_limits
            .get(domain)
            .copied()
            .unwrap_or(self.config.default_limit);

        let mut buckets = self.buckets.write().await;
        let bucket = buckets
            .entry(domain.to_string())
            .or_insert_with(|| TokenBucket::new(limit, limit));

        if bucket.try_consume() {
            RateLimitResult::Allowed
        } else {
            let delay = bucket.time_until_token_available();
            RateLimitResult::RateLimited { retry_after: delay }
        }
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
            default_limit: 1,
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
            default_limit: 2,
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
            default_limit: 2,
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
            default_limit: 1,
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
