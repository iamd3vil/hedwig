use deadpool::managed::{Manager, Metrics, Object, Pool, PoolError};
use mail_send::{SmtpClient, SmtpClientBuilder};
use miette::{Context, IntoDiagnostic, Result};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::client::TlsStream;

pub struct SmtpClientManager {
    domain: String,
    port: u16,
}

impl Manager for SmtpClientManager {
    type Type = SmtpClient<TlsStream<TcpStream>>;
    type Error = miette::Error;

    async fn create(&self) -> Result<Self::Type, Self::Error> {
        SmtpClientBuilder::new(self.domain.clone(), self.port)
            .helo_host("mailtest.alertify.sh")
            .allow_invalid_certs()
            .implicit_tls(false)
            .connect()
            .await
            .into_diagnostic()
            .wrap_err("error creating smtp client")
    }

    async fn recycle(
        &self,
        _client: &mut Self::Type,
        _metrics: &Metrics,
    ) -> deadpool::managed::RecycleResult<Self::Error> {
        // For SMTP, we might want to check if the connection is still alive
        // For simplicity, we'll assume it's always ok to reuse
        Ok(())
    }
}

pub struct SmtpClientPool {
    pools: Arc<Mutex<HashMap<String, Pool<SmtpClientManager>>>>,
}

impl SmtpClientPool {
    pub fn new() -> Self {
        SmtpClientPool {
            pools: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn get_client(
        &self,
        domain: &str,
        port: u16,
    ) -> Result<Object<SmtpClientManager>, PoolError<miette::Error>> {
        let mut pools = self.pools.lock().await;
        if !pools.contains_key(domain) {
            let manager = SmtpClientManager {
                domain: domain.to_string(),
                port,
            };
            let pool = Pool::builder(manager)
                .max_size(10) // Adjust this value as needed
                .build()
                .expect("Failed to build pool");
            pools.insert(domain.to_string(), pool);
        }
        pools.get(domain).unwrap().get().await
    }
}
