use std::sync::Arc;
use std::time::{Duration, Instant};

use moka::{future::Cache, Expiry};
use tracing::{debug, info, warn};

use super::fetcher::MtaStsFetcher;
use super::policy::{CachedPolicy, MtaStsPolicy};
use crate::metrics;

const CACHE_CAPACITY: u64 = 10_000;
const FETCH_FAILURE_COOLDOWN: Duration = Duration::from_secs(5 * 60);
/// How long "this domain has no MTA-STS record" is remembered. Most
/// destinations have no policy, so without this every delivery re-runs the
/// TXT lookup.
const NEGATIVE_CACHE_TTL: Duration = Duration::from_secs(5 * 60);

/// Moka expiry that uses each policy's `max_age` as the TTL.
struct PolicyExpiry;

impl Expiry<String, CachedPolicy> for PolicyExpiry {
    fn expire_after_create(
        &self,
        _key: &String,
        value: &CachedPolicy,
        _created_at: Instant,
    ) -> Option<Duration> {
        Some(Duration::from_secs(value.policy.max_age))
    }
}

pub struct MtaStsResolver {
    fetcher: MtaStsFetcher,
    cache: Cache<String, CachedPolicy>,
    /// Domains recently observed to have no MTA-STS TXT record.
    negative_cache: Cache<String, ()>,
    failure_cooldowns: Cache<String, Instant>,
}

impl MtaStsResolver {
    pub fn new(fetcher: MtaStsFetcher) -> Self {
        let cache = Cache::builder()
            .max_capacity(CACHE_CAPACITY)
            .expire_after(PolicyExpiry)
            .build();
        let negative_cache = Cache::builder()
            .max_capacity(CACHE_CAPACITY)
            .time_to_live(NEGATIVE_CACHE_TTL)
            .build();
        let failure_cooldowns = Cache::builder()
            .max_capacity(CACHE_CAPACITY)
            .time_to_live(FETCH_FAILURE_COOLDOWN)
            .build();

        Self {
            fetcher,
            cache,
            negative_cache,
            failure_cooldowns,
        }
    }

    /// A cached policy is trusted until its `max_age` expiry (RFC 8461 §5.1;
    /// the background refresher revalidates the TXT id), so the per-delivery
    /// hot path here does no DNS at all for cached and known-absent domains.
    pub async fn get_policy(&self, domain: &str) -> Option<Arc<MtaStsPolicy>> {
        let domain = domain.to_ascii_lowercase();

        if let Some(cached) = self.cache.get(&domain).await {
            metrics::mta_sts_policy_fetch_cached();
            return Some(cached.policy);
        }
        if self.negative_cache.get(&domain).await.is_some() {
            return None;
        }

        let txt_record = match self.fetcher.lookup_txt(&domain).await {
            Ok(Some(record)) => record,
            Ok(None) => {
                self.negative_cache.insert(domain, ()).await;
                return None;
            }
            Err(error) => {
                warn!(%domain, ?error, "failed to lookup MTA-STS TXT record");
                return None;
            }
        };

        if self.failure_cooldowns.get(&domain).await.is_some() {
            debug!(%domain, "MTA-STS fetch cooldown active");
            return None;
        }

        match self.fetcher.fetch_policy(&domain).await {
            Ok(Some(policy)) => {
                let policy = Arc::new(policy);
                let cached_policy = CachedPolicy {
                    policy: Arc::clone(&policy),
                    txt_id: txt_record.id,
                };

                info!(%domain, mode = %policy.mode, max_age = policy.max_age, "cached MTA-STS policy");
                self.cache.insert(domain, cached_policy).await;
                metrics::mta_sts_policy_fetch_success();
                metrics::mta_sts_cache_size_set(self.cache.entry_count());
                Some(policy)
            }
            Ok(None) => {
                metrics::mta_sts_policy_fetch_failure();
                self.failure_cooldowns.insert(domain, Instant::now()).await;
                None
            }
            Err(error) => {
                warn!(%domain, ?error, "failed to fetch MTA-STS policy");
                metrics::mta_sts_policy_fetch_failure();
                self.failure_cooldowns.insert(domain, Instant::now()).await;
                None
            }
        }
    }

    pub(crate) fn cache(&self) -> &Cache<String, CachedPolicy> {
        &self.cache
    }

    pub(crate) fn fetcher(&self) -> &MtaStsFetcher {
        &self.fetcher
    }
}
