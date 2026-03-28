use std::time::{Duration, Instant};

use moka::future::Cache;
use tracing::{debug, info, warn};

use super::fetcher::MtaStsFetcher;
use super::policy::{CachedPolicy, MtaStsPolicy};

const CACHE_CAPACITY: u64 = 10_000;
const FETCH_FAILURE_COOLDOWN: Duration = Duration::from_secs(5 * 60);

pub struct MtaStsResolver {
    fetcher: MtaStsFetcher,
    cache: Cache<String, CachedPolicy>,
    failure_cooldowns: Cache<String, Instant>,
}

impl MtaStsResolver {
    pub fn new(fetcher: MtaStsFetcher) -> Self {
        let cache = Cache::builder().max_capacity(CACHE_CAPACITY).build();
        let failure_cooldowns = Cache::builder()
            .max_capacity(CACHE_CAPACITY)
            .time_to_live(FETCH_FAILURE_COOLDOWN)
            .build();

        Self {
            fetcher,
            cache,
            failure_cooldowns,
        }
    }

    pub async fn get_policy(&self, domain: &str) -> Option<MtaStsPolicy> {
        let domain = domain.to_ascii_lowercase();

        let txt_record = match self.fetcher.lookup_txt(&domain).await {
            Ok(Some(record)) => record,
            Ok(None) => return self.get_cached_policy(&domain).await,
            Err(error) => {
                warn!(%domain, ?error, "failed to lookup MTA-STS TXT record, using cached policy if available");
                return self.get_cached_policy(&domain).await;
            }
        };

        if let Some(cached) = self.cache.get(&domain).await {
            if cached.txt_id == txt_record.id {
                debug!(%domain, txt_id = %txt_record.id, "MTA-STS cache hit with matching TXT id");
                return Some(cached.policy.clone());
            }
        }

        if self.failure_cooldowns.get(&domain).await.is_some() {
            debug!(%domain, "MTA-STS fetch cooldown active, using cached policy if available");
            return self.get_cached_policy(&domain).await;
        }

        match self.fetcher.fetch_policy(&domain).await {
            Ok(Some(policy)) => {
                let cached_policy = CachedPolicy {
                    policy: policy.clone(),
                    txt_id: txt_record.id,
                    fetched_at: Instant::now(),
                };

                info!(%domain, mode = %policy.mode, max_age = policy.max_age, "cached MTA-STS policy");
                self.cache.insert(domain, cached_policy).await;
                Some(policy)
            }
            Ok(None) => {
                self.failure_cooldowns
                    .insert(domain.clone(), Instant::now())
                    .await;
                self.get_cached_policy(&domain).await
            }
            Err(error) => {
                warn!(%domain, ?error, "failed to fetch MTA-STS policy");
                self.failure_cooldowns
                    .insert(domain.clone(), Instant::now())
                    .await;
                self.get_cached_policy(&domain).await
            }
        }
    }

    async fn get_cached_policy(&self, domain: &str) -> Option<MtaStsPolicy> {
        self.cache
            .get(domain)
            .await
            .map(|cached| cached.policy.clone())
    }

    pub(crate) fn cache(&self) -> &Cache<String, CachedPolicy> {
        &self.cache
    }

    pub(crate) fn fetcher(&self) -> &MtaStsFetcher {
        &self.fetcher
    }
}
