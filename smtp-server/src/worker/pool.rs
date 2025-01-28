use lettre::{
    transport::smtp::{client::TlsParameters, PoolConfig},
    AsyncSmtpTransport, Tokio1Executor,
};
use miette::{Context, IntoDiagnostic, Result};
use moka::future::Cache;

/// Manages a pool of SMTP transports.
pub struct PoolManager {
    /// Indicates if the outbound connection is to a local server.
    outbound_local: bool,
    /// A cache of SMTP transports, keyed by domain.
    pools: Cache<String, AsyncSmtpTransport<Tokio1Executor>>,
}

impl PoolManager {
    /// Creates a new `PoolManager`.
    ///
    /// # Arguments
    ///
    /// * `pool_size` - The maximum number of SMTP transports to cache.
    /// * `outbound_local` - If true, the manager will create a client without TLS.
    pub fn new(pool_size: u64, outbound_local: bool) -> Self {
        let cache: Cache<String, AsyncSmtpTransport<Tokio1Executor>> = Cache::new(pool_size);
        PoolManager {
            outbound_local,
            pools: cache,
        }
    }

    /// Retrieves an SMTP transport from the pool, creating one if it doesn't exist.
    ///
    /// # Arguments
    ///
    /// * `key` - The domain to get the transport for.
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

    /// Creates a new SMTP client.
    ///
    /// # Arguments
    ///
    /// * `domain` - The domain to create the client for.
    pub async fn get_smtp_client(
        &self,
        domain: &str,
    ) -> Result<AsyncSmtpTransport<Tokio1Executor>> {
        // If outbound_local is set, use builder_dangerous to create a client.
        if self.outbound_local {
            return Ok(AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(domain).build());
        }

        let pool_cfg = PoolConfig::new().min_idle(10).max_size(100);
        let tls_params = TlsParameters::new(domain.into())
            .into_diagnostic()
            .wrap_err("tls params")?;
        let transport = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(domain)
            .port(25)
            .tls(lettre::transport::smtp::client::Tls::Required(tls_params))
            .timeout(Some(std::time::Duration::from_secs(10)))
            .pool_config(pool_cfg)
            .build();
        Ok(transport)
    }
}
