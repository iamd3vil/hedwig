use lettre::{transport::smtp::PoolConfig, AsyncSmtpTransport, Tokio1Executor};
use miette::{Context, IntoDiagnostic, Result};
use moka::future::Cache;

pub struct PoolManager {
    outbound_local: bool,
    pools: Cache<String, AsyncSmtpTransport<Tokio1Executor>>,
}

impl PoolManager {
    pub fn new(pool_size: u64, outbound_local: bool) -> Self {
        let cache: Cache<String, AsyncSmtpTransport<Tokio1Executor>> = Cache::new(pool_size);
        PoolManager {
            outbound_local,
            // pools: Arc::new(RwLock::new(HashMap::new())),
            pools: cache,
        }
    }

    pub async fn get(&self, key: &str) -> Result<AsyncSmtpTransport<Tokio1Executor>> {
        let transport = self
            .pools
            .try_get_with(key.to_string(), async {
                self.get_smtp_client(key)
                    .await
                    .wrap_err("Failed to create SMTP transport")
            })
            .await
            .map_err(|e| miette::Error::msg(e.to_string()))?;

        Ok(transport)
    }

    pub async fn get_smtp_client(
        &self,
        domain: &str,
    ) -> Result<AsyncSmtpTransport<Tokio1Executor>> {
        // If outbound_local is set, use builder_dangerous to create a client.
        if self.outbound_local {
            return Ok(AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(domain).build());
        }

        // Try relay first, if it doesn't work let's try starttls.
        match AsyncSmtpTransport::<Tokio1Executor>::relay(domain) {
            Ok(transport) => {
                let pool_cfg = PoolConfig::new().min_idle(10).max_size(100);
                Ok(transport.pool_config(pool_cfg).build())
            }
            Err(_) => {
                let transport = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(domain)
                    .into_diagnostic()
                    .wrap_err("creating transport")?
                    .build();
                Ok(transport)
            }
        }
    }
}
