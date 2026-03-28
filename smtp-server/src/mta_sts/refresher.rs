use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::time::MissedTickBehavior;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use super::cache::MtaStsResolver;
use super::policy::{CachedPolicy, PolicyMode};

pub async fn run_refresh_loop(resolver: Arc<MtaStsResolver>, shutdown: CancellationToken) {
    info!("starting MTA-STS policy refresher loop");

    let mut interval = tokio::time::interval(Duration::from_secs(24 * 60 * 60));
    interval.set_missed_tick_behavior(MissedTickBehavior::Delay);

    interval.tick().await;

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => {
                info!("received shutdown signal for MTA-STS policy refresher loop");
                break;
            }
            _ = interval.tick() => {
                refresh_all_policies(&resolver).await;
            }
        }
    }

    info!("stopped MTA-STS policy refresher loop");
}

async fn refresh_all_policies(resolver: &MtaStsResolver) {
    info!("starting MTA-STS policy refresh scan");

    let cached_policies = resolver
        .cache()
        .iter()
        .map(|(domain, cached)| ((*domain).clone(), cached.clone()))
        .collect::<Vec<_>>();

    let total = cached_policies.len();
    let mut refreshed = 0usize;
    let mut failures = 0usize;
    let mut skipped = 0usize;

    for (domain, cached) in cached_policies {
        if cached.policy.mode == PolicyMode::None {
            skipped += 1;
            debug!(%domain, "skipping proactive refresh for mode=none policy");
            continue;
        }

        let txt_record = match resolver.fetcher().lookup_txt(&domain).await {
            Ok(Some(txt_record)) => txt_record,
            Ok(None) => {
                skipped += 1;
                debug!(%domain, "MTA-STS TXT record missing during refresh, keeping cached policy");
                continue;
            }
            Err(error) => {
                failures += 1;
                warn!(%domain, ?error, "failed MTA-STS TXT lookup during refresh");
                continue;
            }
        };

        if txt_record.id == cached.txt_id {
            let refreshed_policy = CachedPolicy {
                fetched_at: Instant::now(),
                ..cached
            };

            resolver.cache().insert(domain.clone(), refreshed_policy).await;
            refreshed += 1;
            debug!(%domain, txt_id = %txt_record.id, "MTA-STS TXT id unchanged, extended cache freshness");
            continue;
        }

        debug!(
            %domain,
            old_txt_id = %cached.txt_id,
            new_txt_id = %txt_record.id,
            "MTA-STS TXT id changed, fetching updated policy"
        );

        match resolver.fetcher().fetch_policy(&domain).await {
            Ok(Some(policy)) => {
                let mode = policy.mode;
                let max_age = policy.max_age;

                let refreshed_policy = CachedPolicy {
                    policy,
                    txt_id: txt_record.id,
                    fetched_at: Instant::now(),
                };

                resolver.cache().insert(domain.clone(), refreshed_policy).await;
                refreshed += 1;
                info!(%domain, %mode, max_age, "refreshed cached MTA-STS policy after TXT id update");
            }
            Ok(None) => {
                failures += 1;
                warn!(%domain, "updated MTA-STS policy unavailable, keeping cached version");
            }
            Err(error) => {
                failures += 1;
                warn!(%domain, ?error, "failed to fetch updated MTA-STS policy, keeping cached version");
            }
        }
    }

    info!(total, refreshed, failures, skipped, "completed MTA-STS policy refresh scan");
}
