use base64::Engine;
use clap::Parser;
use config::{CfgDKIM, CfgStorage, DkimKeyType};
use futures::StreamExt;
use miette::{bail, Context, IntoDiagnostic, Result};
use pkcs8::EncodePrivateKey;
use rand::rngs::OsRng;
use rsa::{
    pkcs8::{EncodePublicKey, LineEnding},
    RsaPrivateKey,
};
use rustls::pki_types::CertificateDer;
use smtp::{SmtpServer, SmtpStream};
use std::sync::Arc;
use storage::{fs_storage::FileSystemStorage, Status, Storage};
use subtle::ConstantTimeEq;
use tokio::net::TcpListener;
use tokio::time::MissedTickBehavior;
use tokio_rustls::rustls::{self, ServerConfig};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, Level};
use worker::{deferred_worker::DeferredWorker, Job};

mod callbacks;
mod config;
mod metrics;
mod storage;
mod worker;

const DEFAULT_DKIM_KEY_BITS: usize = 2048;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to config file
    #[arg(short, long, default_value = "config.toml")]
    config: String,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(clap::Subcommand)]
enum Commands {
    /// Start the SMTP server (default)
    Server,
    /// Generate DKIM keys
    DkimGenerate(DkimGenerateArgs),
}

#[derive(Parser)]
struct DkimGenerateArgs {
    /// Domain for DKIM signature
    #[arg(long)]
    domain: Option<String>,

    /// DKIM selector
    #[arg(long)]
    selector: Option<String>,

    /// Path to save the private key
    #[arg(long)]
    private_key: Option<String>,

    /// Key type (rsa or ed25519)
    #[arg(long, default_value = "rsa")]
    key_type: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let args = Args::parse();

    // Set up the default provider for rustls.
    let _ = rustls::crypto::ring::default_provider().install_default();

    match args.command.unwrap_or(Commands::Server) {
        Commands::Server => run_server(&args.config).await,
        Commands::DkimGenerate(dkim_args) => generate_dkim_keys(&args.config, dkim_args).await,
    }
}

async fn run_server(config_path: &str) -> Result<()> {
    // Load the configuration from the file.
    let cfg = config::Cfg::load(config_path).wrap_err("error loading configuration")?;

    let level: Level = cfg
        .log
        .level
        .parse()
        .into_diagnostic()
        .wrap_err("error parsing log level")?;

    // Initialize the tracing subscriber
    let ts = tracing_subscriber::fmt()
        .with_max_level(level)
        .with_target(false)
        .with_line_number(false)
        .with_level(true)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("HEDWIG_LOG_LEVEL")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("hedwig=info")),
        );

    if cfg.log.format == "json" {
        ts.json().init();
    } else {
        ts.init();
    }

    if cfg.server.dkim.is_some() {
        info!("DKIM is enabled");
    } else {
        info!("DKIM is disabled");
    }

    if let Some(metrics_cfg) = &cfg.server.metrics {
        let addr: std::net::SocketAddr = metrics_cfg
            .bind
            .parse()
            .into_diagnostic()
            .wrap_err("invalid metrics bind address")?;
        metrics::spawn_metrics_server(addr);
    }

    // Initialize channels for background processing of emails.
    let (sender_channel, receiver_channel) = async_channel::bounded(1);

    // Initialize storage.
    let storage = get_storage_type(&cfg.storage)
        .await
        .wrap_err("error getting storage type")?;
    let storage = Arc::new(storage);

    // Capture the current queue depth before workers start consuming jobs.
    let mut queued_jobs = Vec::new();
    {
        let mut stream = storage.list(Status::Queued);
        while let Some(email) = stream.next().await {
            let email = email?;
            queued_jobs.push(email.message_id.clone());
        }
    }
    metrics::queue_depth_set(queued_jobs.len());

    // Spawn periodic cleanup for any storage retention policy that has been configured.
    let cleanup_config = cfg.storage.cleanup_config();
    if cleanup_config.is_enabled() {
        info!(
            deferred_ttl_seconds = cleanup_config
                .deferred_retention
                .map(|duration| duration.as_secs()),
            bounced_ttl_seconds = cleanup_config
                .bounced_retention
                .map(|duration| duration.as_secs()),
            interval_seconds = cleanup_config.interval.as_secs(),
            "starting storage cleanup task"
        );

        // Run once during startup so old data is purged even before the first tick fires.
        if let Err(err) = storage.cleanup(&cleanup_config).await {
            error!("error performing initial storage cleanup: {:#}", err);
        }

        let storage_for_cleanup = Arc::clone(&storage);
        let cleanup_config_task = cleanup_config.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(cleanup_config_task.interval);
            ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

            loop {
                ticker.tick().await;
                if let Err(err) = storage_for_cleanup.cleanup(&cleanup_config_task).await {
                    error!("error performing storage cleanup: {:#}", err);
                }
            }
        });
    }
    // Create TLS acceptors for each listener that has TLS configured
    let mut tls_acceptors = Vec::new();
    for listener_config in &cfg.server.listeners {
        let tls_acceptor = if let Some(tls_config) = &listener_config.tls {
            let cert_file = tokio::fs::File::open(&tls_config.cert_path)
                .await
                .into_diagnostic()
                .wrap_err("Failed to open certificate file")?;
            let key_file = tokio::fs::File::open(&tls_config.key_path)
                .await
                .into_diagnostic()
                .wrap_err("Failed to open private key file")?;

            let certs: Vec<CertificateDer<'static>> =
                rustls_pemfile::certs(&mut std::io::BufReader::new(cert_file.into_std().await))
                    .collect::<std::io::Result<Vec<_>>>()
                    .into_diagnostic()?;

            let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(
                key_file.into_std().await,
            ))
            .into_diagnostic()?
            .ok_or_else(|| miette::miette!("No private key found"))?;

            let config = ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .into_diagnostic()?;

            Some(TlsAcceptor::from(Arc::new(config)))
        } else {
            None
        };
        tls_acceptors.push(tls_acceptor);
    }

    let auth_enabled = cfg.server.auth.is_some();

    info!("Auth enabled: {}", auth_enabled);

    let smtp_server = SmtpServer::new(
        callbacks::Callbacks::new(
            Arc::clone(&storage),
            sender_channel.clone(),
            receiver_channel.clone(),
            cfg.clone(),
        ),
        auth_enabled,
    );

    // Replay any queued emails so workers process them immediately.
    if !queued_jobs.is_empty() {
        info!(
            queued = queued_jobs.len(),
            "replaying queued jobs to workers"
        );
        for msg_id in queued_jobs {
            let job = Job::new(msg_id, 0);
            sender_channel
                .send(job)
                .await
                .into_diagnostic()
                .wrap_err("error sending job to receiver channel")?;
        }
        info!("replayed queued jobs");
    } else {
        info!("no queued jobs found on startup");
    }

    // Start the deferred worker.
    tokio::spawn(async move {
        let worker = DeferredWorker::new(
            Arc::clone(&storage),
            sender_channel.clone(),
            cfg.server.max_retries,
        );
        let res = worker.process_deferred_jobs().await;
        if let Err(e) = res {
            error!("Error running deferred worker: {:#}", e);
        }
    });

    // Create listeners for each configured address
    let mut listeners = Vec::new();
    for (i, listener_config) in cfg.server.listeners.iter().enumerate() {
        let listener = TcpListener::bind(&listener_config.addr)
            .await
            .into_diagnostic()
            .wrap_err_with(|| format!("Failed to bind to address: {}", listener_config.addr))?;

        let tls_status = if listener_config.tls.is_some() {
            "TLS"
        } else {
            "plaintext"
        };
        info!(
            storage_type = cfg.storage.storage_type,
            "SMTP server listening on {} ({})", listener_config.addr, tls_status
        );

        listeners.push((listener, i));
    }

    // Spawn a task for each listener
    let mut listener_tasks = Vec::new();
    for (listener, acceptor_index) in listeners {
        let server_clone = smtp_server.clone();
        let tls_acceptor = tls_acceptors[acceptor_index].clone();

        let task = tokio::spawn(async move {
            loop {
                let (socket, _) = match listener.accept().await {
                    Ok(conn) => conn,
                    Err(e) => {
                        error!("Error accepting tcp connection: {:#}", e);
                        continue;
                    }
                };

                debug!("Accepted connection");
                let server_clone = server_clone.clone();
                let tls_acceptor = tls_acceptor.clone();

                tokio::spawn(async move {
                    let mut boxed_socket: Box<dyn SmtpStream> = if let Some(acceptor) = tls_acceptor
                    {
                        match acceptor.accept(socket).await {
                            Ok(tls_stream) => Box::new(tls_stream),
                            Err(e) => {
                                // Ignore if it's EOF.
                                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                                    debug!("TLS handshake failed: {}", e);
                                } else {
                                    // Log the error.
                                    error!("TLS handshake failed: {}", e);
                                }

                                return;
                            }
                        }
                    } else {
                        Box::new(socket)
                    };

                    if let Err(e) = server_clone.handle_client(&mut boxed_socket).await {
                        error!("Error handling client: {:#}", e);
                    }
                });
            }
        });

        listener_tasks.push(task);
    }

    // Wait for all listener tasks to complete (which should never happen)
    futures::future::join_all(listener_tasks).await;

    Ok(())
}

async fn generate_dkim_keys(config_path: &str, args: DkimGenerateArgs) -> Result<()> {
    let cfg = config::Cfg::load(config_path).wrap_err("error loading configuration")?;

    let dkim_config =
        if args.domain.is_some() || args.selector.is_some() || args.private_key.is_some() {
            let domain = match args.domain {
                Some(d) => d,
                None => match &cfg.server.dkim {
                    Some(config) => config.domain.clone(),
                    None => bail!("Domain is required when not in config file"),
                },
            };

            let selector = match args.selector {
                Some(s) => s,
                None => match &cfg.server.dkim {
                    Some(config) => config.selector.clone(),
                    None => bail!("Selector is required when not in config file"),
                },
            };

            let private_key = match args.private_key {
                Some(p) => p,
                None => match &cfg.server.dkim {
                    Some(config) => config.private_key.clone(),
                    None => bail!("Private key path is required when not in config file"),
                },
            };

            let key_type = match args.key_type.as_str() {
                "rsa" => DkimKeyType::Rsa,
                "ed25519" => DkimKeyType::Ed25519,
                _ => bail!("Invalid key type. Use 'rsa' or 'ed25519'"),
            };

            CfgDKIM {
                domain,
                selector,
                private_key,
                key_type,
            }
        } else {
            match &cfg.server.dkim {
                Some(config) => config.clone(),
                None => bail!("DKIM configuration is missing in config file and no flags provided"),
            }
        };

    match dkim_config.key_type {
        DkimKeyType::Rsa => generate_rsa_keys(&dkim_config).await,
        DkimKeyType::Ed25519 => generate_ed25519_keys(&dkim_config).await,
    }
}

async fn generate_rsa_keys(dkim_config: &CfgDKIM) -> Result<()> {
    let mut rng = OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, DEFAULT_DKIM_KEY_BITS)
        .into_diagnostic()
        .wrap_err("Failed to generate RSA key pair")?;

    let private_key_pem = private_key
        .to_pkcs8_pem(LineEnding::LF)
        .into_diagnostic()
        .wrap_err("Failed to encode private key to PEM")?;

    tokio::fs::write(&dkim_config.private_key, private_key_pem.as_bytes())
        .await
        .into_diagnostic()
        .wrap_err("Failed to write private key")?;

    let public_key = private_key.to_public_key();
    let public_key_der = public_key
        .to_public_key_der()
        .into_diagnostic()
        .wrap_err("Failed to encode public key")?;

    output_dns_record(dkim_config, public_key_der.as_bytes(), "rsa")
}

async fn generate_ed25519_keys(dkim_config: &CfgDKIM) -> Result<()> {
    use ed25519_dalek::SigningKey;
    use pkcs8::{EncodePrivateKey, LineEnding};
    use rand::RngCore;

    let mut rng = OsRng;

    // Generate random bytes for the secret key
    let mut secret_bytes = [0u8; 32];
    rng.fill_bytes(&mut secret_bytes);

    // Create signing key from random bytes
    let signing_key = SigningKey::from_bytes(&secret_bytes);
    let verifying_key = signing_key.verifying_key();

    // Convert directly to PKCS8 PEM using the EncodePrivateKey trait
    let private_key_pem = signing_key
        .to_pkcs8_pem(LineEnding::LF)
        .into_diagnostic()
        .wrap_err("Failed to encode private key to PEM")?;

    tokio::fs::write(&dkim_config.private_key, private_key_pem.as_bytes())
        .await
        .into_diagnostic()
        .wrap_err("Failed to write private key")?;

    output_dns_record(dkim_config, verifying_key.as_bytes(), "ed25519")
}

fn output_dns_record(dkim_config: &CfgDKIM, public_key_bytes: &[u8], key_type: &str) -> Result<()> {
    let public_key_base64 = base64::engine::general_purpose::STANDARD.encode(public_key_bytes);
    let dns_record = format!(
        "{}._domainkey.{} IN TXT \"v=DKIM1; k={}; p={}\"",
        dkim_config.selector, dkim_config.domain, key_type, public_key_base64
    );

    println!("DKIM keys generated successfully!");
    println!("Private key saved to: {}", dkim_config.private_key);
    println!("\nAdd the following TXT record to your DNS configuration:");
    println!("{}", dns_record);

    Ok(())
}

async fn get_storage_type(cfg: &CfgStorage) -> Result<Arc<dyn Storage>> {
    match cfg.storage_type.as_ref() {
        "fs" => {
            let st = FileSystemStorage::new(cfg.base_path.clone()).await?;
            Ok(Arc::new(st))
        }
        _ => bail!("Unknown storage type: {}", cfg.storage_type),
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}
