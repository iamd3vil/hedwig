use crate::{metrics, mta_sts::policy::PolicyMode};
use lettre::{
    transport::smtp::{
        client::{Tls, TlsParameters},
        extension::ClientId,
        AsyncSmtpTransportBuilder, PoolConfig,
    },
    AsyncSmtpTransport, Tokio1Executor,
};
use miette::{Context, IntoDiagnostic, Result};
use moka::future::Cache;

pub const DEFAULT_SMTP_CACHE_SIZE: u64 = 100;
pub const DEFAULT_SMTP_POOL_MIN_IDLE: u32 = 2;
pub const DEFAULT_SMTP_POOL_MAX_SIZE: u32 = 10;

/// The recipient domain's policy, even when several domains share one MX.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum OutboundTlsMode {
    Opportunistic,
    Required,
}

impl OutboundTlsMode {
    pub(super) fn from_policy(mode: Option<PolicyMode>) -> Self {
        match mode {
            Some(PolicyMode::Enforce) => Self::Required,
            _ => Self::Opportunistic,
        }
    }

    fn tls(self, domain: &str) -> Result<Tls> {
        let params = TlsParameters::builder(domain.to_string())
            // RFC 3207 permits unauthenticated encryption when no policy
            // requires authentication. This accepts mismatched, expired,
            // and self-signed certificates, but still negotiates TLS.
            .dangerous_accept_invalid_certs(self == Self::Opportunistic)
            .dangerous_accept_invalid_hostnames(self == Self::Opportunistic)
            .build()
            .into_diagnostic()
            .wrap_err("tls params")?;
        Ok(match self {
            Self::Opportunistic => Tls::Opportunistic(params),
            Self::Required => Tls::Required(params),
        })
    }
}

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
    /// Include the policy so strict deliveries never reuse unauthenticated
    /// connections to a shared MX, including after a policy changes.
    pools: Cache<(String, OutboundTlsMode), AsyncSmtpTransport<Tokio1Executor>>,
}

impl PoolManager {
    /// Creates a new `PoolManager`.
    ///
    /// # Arguments
    ///
    /// * `pool_config` - SMTP transport cache and per-destination pool settings.
    /// * `outbound_local` - Skip TLS for local delivery unless MTA-STS enforces it.
    /// * `helo_hostname` - Optional public FQDN to advertise in HELO/EHLO.
    pub fn new(
        pool_config: SmtpPoolConfig,
        outbound_local: bool,
        helo_hostname: Option<String>,
    ) -> Self {
        let cache = Cache::new(pool_config.cache_size);
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
    /// * `domain` - The destination MX hostname.
    /// * `tls_mode` - TLS policy selected for the recipient domain.
    pub(super) async fn get(
        &self,
        domain: &str,
        tls_mode: OutboundTlsMode,
    ) -> Result<AsyncSmtpTransport<Tokio1Executor>> {
        let transport = self
            .pools
            .try_get_with((domain.to_string(), tls_mode), async {
                self.smtp_client_builder(domain, tls_mode)
                    .map(|builder| builder.build())
                    .wrap_err("Failed to create SMTP transport")
            })
            .await
            .map_err(|e| miette::Error::msg(e.to_string()))?;

        metrics::set_pool_entries(self.pools.entry_count());

        Ok(transport)
    }

    fn smtp_client_builder(
        &self,
        domain: &str,
        tls_mode: OutboundTlsMode,
    ) -> Result<AsyncSmtpTransportBuilder> {
        // Local development can skip TLS, but cannot override MTA-STS enforce.
        if self.outbound_local && tls_mode == OutboundTlsMode::Opportunistic {
            let mut builder = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(domain)
                .pool_config(self.lettre_pool_config());
            if let Some(name) = self.helo_hostname.as_deref() {
                builder = builder.hello_name(ClientId::Domain(name.to_string()));
            }
            return Ok(builder);
        }

        let pool_cfg = self.lettre_pool_config();
        let mut builder = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(domain)
            .port(25)
            .tls(tls_mode.tls(domain)?)
            .timeout(Some(std::time::Duration::from_secs(10)))
            .pool_config(pool_cfg);
        if let Some(name) = self.helo_hostname.as_deref() {
            builder = builder.hello_name(ClientId::Domain(name.to_string()));
        }
        Ok(builder)
    }

    fn lettre_pool_config(&self) -> PoolConfig {
        PoolConfig::new()
            .min_idle(self.pool_config.min_idle)
            .max_size(self.pool_config.max_size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lettre::{address::Envelope, AsyncTransport};
    use std::{sync::Arc, time::Duration};
    use tokio::{
        io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
        net::TcpListener,
        time::timeout,
    };
    use tokio_rustls::TlsAcceptor;

    fn manager(outbound_local: bool) -> PoolManager {
        let _ = rustls::crypto::ring::default_provider().install_default();
        PoolManager::new(
            SmtpPoolConfig {
                min_idle: 0,
                max_size: 1,
                ..SmtpPoolConfig::default()
            },
            outbound_local,
            Some("sender.test".to_string()),
        )
    }

    #[derive(Clone, Copy)]
    enum ServerTls {
        UntrustedCertificate,
        Unavailable,
        BrokenHandshake,
    }

    trait TestStream: AsyncRead + AsyncWrite + Unpin + Send {}
    impl<T: AsyncRead + AsyncWrite + Unpin + Send> TestStream for T {}

    #[derive(Debug, Default)]
    struct Session {
        commands: Vec<String>,
        delivered_with_tls: Option<bool>,
    }

    async fn serve(listener: TcpListener, tls: ServerTls) -> Session {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = BufReader::new(Box::new(stream) as Box<dyn TestStream>);
        stream
            .get_mut()
            .write_all(b"220 destination.test ESMTP\r\n")
            .await
            .unwrap();
        let mut session = Session::default();
        let mut encrypted = false;
        loop {
            let mut line = String::new();
            if stream.read_line(&mut line).await.unwrap_or(0) == 0 {
                return session;
            }
            let command = line.trim_end().to_string();
            session.commands.push(command.clone());
            let reply: &[u8] = if command.starts_with("EHLO") {
                if !encrypted && !matches!(tls, ServerTls::Unavailable) {
                    b"250-destination.test\r\n250 STARTTLS\r\n"
                } else {
                    b"250 destination.test\r\n"
                }
            } else if command == "STARTTLS" {
                stream
                    .get_mut()
                    .write_all(b"220 start TLS\r\n")
                    .await
                    .unwrap();
                if matches!(tls, ServerTls::BrokenHandshake) {
                    stream
                        .get_mut()
                        .write_all(b"invalid TLS\r\n")
                        .await
                        .unwrap();
                    return session;
                }
                let certs = rustls_pemfile::certs(
                    &mut include_bytes!("../../../dev/certs/mailpit.pem").as_slice(),
                )
                .collect::<std::io::Result<Vec<_>>>()
                .unwrap();
                let key = rustls_pemfile::private_key(
                    &mut include_bytes!("../../../dev/certs/mailpit-key.pem").as_slice(),
                )
                .unwrap()
                .unwrap();
                let config = rustls::ServerConfig::builder_with_provider(Arc::new(
                    rustls::crypto::ring::default_provider(),
                ))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .unwrap();
                match TlsAcceptor::from(Arc::new(config))
                    .accept(stream.into_inner())
                    .await
                {
                    Ok(tls_stream) => {
                        stream = BufReader::new(Box::new(tls_stream) as Box<dyn TestStream>);
                        encrypted = true;
                        continue;
                    }
                    Err(_) => return session,
                }
            } else if command == "DATA" {
                stream
                    .get_mut()
                    .write_all(b"354 send message\r\n")
                    .await
                    .unwrap();
                loop {
                    line.clear();
                    assert_ne!(stream.read_line(&mut line).await.unwrap(), 0);
                    if line == ".\r\n" {
                        break;
                    }
                }
                session.delivered_with_tls = Some(encrypted);
                stream
                    .get_mut()
                    .write_all(b"250 accepted\r\n")
                    .await
                    .unwrap();
                return session;
            } else {
                b"250 ok\r\n"
            };
            if stream.get_mut().write_all(reply).await.is_err() {
                return session;
            }
        }
    }

    async fn deliver(
        mode: OutboundTlsMode,
        server_tls: ServerTls,
        outbound_local: bool,
    ) -> (bool, Session) {
        timeout(Duration::from_secs(5), async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let server = tokio::spawn(serve(listener, server_tls));
            // The test certificate is for mailpit, not this IP, and its CA is
            // not trusted by lettre. Both certificate checks must be relaxed.
            let transport = manager(outbound_local)
                .smtp_client_builder("127.0.0.1", mode)
                .unwrap()
                .port(port)
                .build::<Tokio1Executor>();
            let envelope = Envelope::new(
                Some("sender@sender.test".parse().unwrap()),
                vec!["recipient@destination.test".parse().unwrap()],
            )
            .unwrap();
            let delivered = transport
                .send_raw(&envelope, b"Subject: TLS test\r\n\r\nhello\r\n")
                .await
                .is_ok();
            drop(transport);
            (delivered, server.await.unwrap())
        })
        .await
        .expect("SMTP exchange timed out")
    }

    #[tokio::test]
    async fn only_enforce_requires_authenticated_tls() {
        for policy in [None, Some(PolicyMode::None), Some(PolicyMode::Testing)] {
            let (delivered, session) = deliver(
                OutboundTlsMode::from_policy(policy),
                ServerTls::UntrustedCertificate,
                false,
            )
            .await;
            assert!(delivered, "{policy:?}: {session:?}");
            assert_eq!(session.delivered_with_tls, Some(true));
            assert!(session.commands.iter().any(|c| c == "EHLO sender.test"));
        }
        let (delivered, session) = deliver(
            OutboundTlsMode::from_policy(Some(PolicyMode::Enforce)),
            ServerTls::UntrustedCertificate,
            false,
        )
        .await;
        assert!(!delivered);
        assert_eq!(session.delivered_with_tls, None);
        assert!(!session.commands.iter().any(|c| c.starts_with("MAIL")));
    }

    #[tokio::test]
    async fn plaintext_is_allowed_only_without_enforcement() {
        for mode in [OutboundTlsMode::Opportunistic, OutboundTlsMode::Required] {
            // outbound_local must not bypass an enforced policy either.
            for outbound_local in [false, true] {
                let (delivered, session) =
                    deliver(mode, ServerTls::Unavailable, outbound_local).await;
                assert_eq!(delivered, mode == OutboundTlsMode::Opportunistic);
                assert_eq!(
                    session.delivered_with_tls,
                    if delivered { Some(false) } else { None }
                );
            }
        }
    }

    #[tokio::test]
    async fn broken_tls_handshake_does_not_send_mail_in_plaintext() {
        let (delivered, session) = deliver(
            OutboundTlsMode::Opportunistic,
            ServerTls::BrokenHandshake,
            false,
        )
        .await;
        assert!(!delivered);
        assert_eq!(session.delivered_with_tls, None);
        assert!(!session.commands.iter().any(|c| c.starts_with("MAIL")));
    }

    #[tokio::test]
    async fn shared_mx_and_policy_changes_use_separate_pools() {
        let manager = manager(false);
        for mode in [
            OutboundTlsMode::Opportunistic,
            OutboundTlsMode::Required,
            OutboundTlsMode::Opportunistic,
            OutboundTlsMode::Required,
        ] {
            manager.get("shared-mx.test", mode).await.unwrap();
        }
        manager.pools.run_pending_tasks().await;
        assert_eq!(manager.pools.entry_count(), 2);
    }
}
