use lettre::{transport::smtp::PoolConfig, AsyncSmtpTransport, Tokio1Executor};
use miette::{Context, IntoDiagnostic, Result};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

pub struct PoolManager {
    outbound_local: bool,
    pools: Arc<RwLock<HashMap<String, AsyncSmtpTransport<Tokio1Executor>>>>,
}

impl PoolManager {
    pub fn new(outbound_local: bool) -> Self {
        PoolManager {
            outbound_local,
            pools: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn get(&self, key: &str) -> Result<AsyncSmtpTransport<Tokio1Executor>> {
        let pools = self.pools.read().await;

        if let Some(transport) = pools.get(key) {
            Ok(transport.clone())
        } else {
            // Drop the read lock before acquiring the write lock.
            drop(pools);

            let mut pools = self.pools.write().await;
            // Create a new transport
            let new_transport = self.get_smtp_client(key).wrap_err("creating transport")?;
            pools.insert(key.to_string(), new_transport.clone());
            Ok(new_transport)
        }
    }

    pub fn get_smtp_client(&self, domain: &str) -> Result<AsyncSmtpTransport<Tokio1Executor>> {
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
