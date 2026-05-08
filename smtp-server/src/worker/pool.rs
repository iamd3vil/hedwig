use crate::metrics;
use lettre::{
    transport::smtp::{client::TlsParameters, extension::ClientId, PoolConfig},
    AsyncSmtpTransport, Tokio1Executor,
};
use miette::{Context, IntoDiagnostic, Result};
use moka::future::Cache;

pub const DEFAULT_SMTP_CACHE_SIZE: u64 = 100;
pub const DEFAULT_SMTP_POOL_MIN_IDLE: u32 = 2;
pub const DEFAULT_SMTP_POOL_MAX_SIZE: u32 = 10;

#[derive(Debug, Clone)]
pub struct SmtpPoolConfig {
    pub cache_size: u64,
    pub min_idle: u32,
    pub max_size: u32,
}

impl Default for SmtpPoolConfig {
    fn default() -> Self {
        Self {
            cache_size: DEFAULT_SMTP_CACHE_SIZE,
            min_idle: DEFAULT_SMTP_POOL_MIN_IDLE,
            max_size: DEFAULT_SMTP_POOL_MAX_SIZE,
        }
    }
}

/// Manages a pool of SMTP transports.
pub struct PoolManager {
    /// Indicates if the outbound connection is to a local server.
    outbound_local: bool,
    /// Optional public FQDN to use for HELO/EHLO.
    helo_hostname: Option<String>,
    /// Connection pool settings for each destination SMTP transport.
    pool_config: SmtpPoolConfig,
    /// A cache of SMTP transports, keyed by domain.
    pools: Cache<String, AsyncSmtpTransport<Tokio1Executor>>,
}

impl PoolManager {
    /// Creates a new `PoolManager`.
    ///
    /// # Arguments
    ///
    /// * `pool_config` - SMTP transport cache and per-destination pool settings.
    /// * `outbound_local` - If true, the manager will create a client without TLS.
    /// * `helo_hostname` - Optional public FQDN to advertise in HELO/EHLO.
    pub fn new(
        pool_config: SmtpPoolConfig,
        outbound_local: bool,
        helo_hostname: Option<String>,
    ) -> Self {
        let cache: Cache<String, AsyncSmtpTransport<Tokio1Executor>> =
            Cache::new(pool_config.cache_size);
        PoolManager {
            outbound_local,
            helo_hostname,
            pool_config,
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

        metrics::set_pool_entries(self.pools.entry_count());

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
            let mut builder = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(domain)
                .pool_config(self.lettre_pool_config());
            if let Some(name) = self.helo_hostname.as_deref() {
                builder = builder.hello_name(ClientId::Domain(name.to_string()));
            }
            return Ok(builder.build());
        }

        let pool_cfg = self.lettre_pool_config();
        let tls_params = TlsParameters::new(domain.into())
            .into_diagnostic()
            .wrap_err("tls params")?;
        let mut builder = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(domain)
            .port(25)
            .tls(lettre::transport::smtp::client::Tls::Required(tls_params))
            .timeout(Some(std::time::Duration::from_secs(10)))
            .pool_config(pool_cfg);
        if let Some(name) = self.helo_hostname.as_deref() {
            builder = builder.hello_name(ClientId::Domain(name.to_string()));
        }
        Ok(builder.build())
    }

    fn lettre_pool_config(&self) -> PoolConfig {
        PoolConfig::new()
            .min_idle(self.pool_config.min_idle)
            .max_size(self.pool_config.max_size)
    }
}
