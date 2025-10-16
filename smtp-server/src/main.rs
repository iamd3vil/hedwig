use clap::Parser;
use config::CfgStorage;
use futures::StreamExt;
use miette::{bail, Context, IntoDiagnostic, Result};
use rustls::pki_types::CertificateDer;
use smtp::{SmtpServer, SmtpStream};
use std::sync::Arc;
use storage::{fs_storage::FileSystemStorage, Status, Storage};
use subtle::ConstantTimeEq;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;
use tokio_rustls::rustls::{self, ServerConfig};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn, Level};
use worker::{deferred_worker::DeferredWorker, Job};

mod callbacks;
mod config;
mod dkim;
mod health;
mod metrics;
mod storage;
mod worker;

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
    DkimGenerate(dkim::DkimGenerateArgs),
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let args = Args::parse();

    // Set up the default provider for rustls.
    let _ = rustls::crypto::ring::default_provider().install_default();

    match args.command.unwrap_or(Commands::Server) {
        Commands::Server => run_server(&args.config).await,
        Commands::DkimGenerate(dkim_args) => {
            dkim::generate_dkim_keys(&args.config, dkim_args).await
        }
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
    // Initialize the work queue that powers outbound processing. Closing these channels
    // later is the cue for workers to stop draining jobs.
    let (sender_channel, receiver_channel) = async_channel::bounded(1);
    // Shared cancellation token used to broadcast a shutdown request to every task we spawn.
    let shutdown_token = CancellationToken::new();
    if let Some(health_cfg) = &cfg.server.health {
        let addr: std::net::SocketAddr = health_cfg
            .bind
            .parse()
            .into_diagnostic()
            .wrap_err("invalid health bind address")?;
        health::spawn_health_server(addr, shutdown_token.clone());
    }
    // Track JoinHandles for background tasks so we can await them during shutdown.
    let mut background_tasks: Vec<JoinHandle<()>> = Vec::new();

    // Initialize storage.
    let storage = get_storage_type(&cfg.storage)
        .await
        .wrap_err("error getting storage type")?;

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
        let cleanup_shutdown = shutdown_token.clone();
        let handle = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(cleanup_config_task.interval);
            ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

            loop {
                tokio::select! {
                    _ = cleanup_shutdown.cancelled() => {
                        info!("storage cleanup task shutting down");
                        break;
                    }
                    _ = ticker.tick() => {
                        if let Err(err) = storage_for_cleanup.cleanup(&cleanup_config_task).await {
                            error!("error performing storage cleanup: {:#}", err);
                        }
                    }
                }
            }
            info!("storage cleanup task stopped");
        });
        background_tasks.push(handle);
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

    let (callbacks, worker_handles) = callbacks::Callbacks::new(
        Arc::clone(&storage),
        sender_channel.clone(),
        receiver_channel.clone(),
        cfg.clone(),
    );

    let smtp_server = SmtpServer::new(callbacks, auth_enabled);

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
    let deferred_storage = Arc::clone(&storage);
    let deferred_sender = sender_channel.clone();
    let max_retries = cfg.server.max_retries;
    let deferred_handle = tokio::spawn(async move {
        let worker = DeferredWorker::new(deferred_storage, deferred_sender, max_retries);
        if let Err(e) = worker.process_deferred_jobs().await {
            error!("Error running deferred worker: {:#}", e);
        }
    });
    background_tasks.push(deferred_handle);

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

    for (listener, acceptor_index) in listeners {
        let server_clone = smtp_server.clone();
        let tls_acceptor = tls_acceptors[acceptor_index].clone();
        let shutdown = shutdown_token.clone();
        let listener_addr = cfg.server.listeners[acceptor_index].addr.clone();

        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => {
                        info!(%listener_addr, "listener shutting down");
                        break;
                    }
                    accept_result = listener.accept() => {
                        let (socket, _) = match accept_result {
                            Ok(conn) => conn,
                            Err(e) => {
                                error!(%listener_addr, "Error accepting tcp connection: {:#}", e);
                                continue;
                            }
                        };

                        debug!("Accepted connection");
                        let server_clone = server_clone.clone();
                        let tls_acceptor = tls_acceptor.clone();

                        tokio::spawn(async move {
                            let mut boxed_socket: Box<dyn SmtpStream> =
                                if let Some(acceptor) = tls_acceptor {
                                    match acceptor.accept(socket).await {
                                        Ok(tls_stream) => Box::new(tls_stream),
                                        Err(e) => {
                                            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                                                debug!("TLS handshake failed: {}", e);
                                            } else {
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
                }
            }
            info!(%listener_addr, "listener stopped");
        });

        background_tasks.push(handle);
    }

    wait_for_shutdown_signal().await?;
    info!("shutdown signal received, beginning graceful shutdown");

    // Notify every background task to stop accepting new work, then close the queues to
    // allow worker loops to observe the shutdown.
    shutdown_token.cancel();
    sender_channel.close();
    receiver_channel.close();

    for handle in worker_handles {
        if let Err(err) = handle.await {
            if err.is_cancelled() {
                warn!("worker task cancelled before completion");
            } else if err.is_panic() {
                error!("worker task panicked: {:?}", err);
            } else {
                error!("worker task failed: {}", err);
            }
        }
    }

    for handle in background_tasks {
        if let Err(err) = handle.await {
            if err.is_cancelled() {
                warn!("background task cancelled before completion");
            } else if err.is_panic() {
                error!("background task panicked: {:?}", err);
            } else {
                error!("background task failed: {}", err);
            }
        }
    }

    info!("shutdown complete");
    Ok(())
}

/// Block until an OS signal such as Ctrl+C (and SIGTERM on Unix) is delivered, giving the
/// server a clear indication it should begin graceful shutdown.
async fn wait_for_shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};

        let mut sigterm = signal(SignalKind::terminate())
            .into_diagnostic()
            .wrap_err("failed to listen for SIGTERM")?;

        tokio::select! {
            ctrl_c = tokio::signal::ctrl_c() => {
                ctrl_c
                    .into_diagnostic()
                    .wrap_err("failed to wait for ctrl+c")?;
            }
            _ = sigterm.recv() => {}
        }
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .into_diagnostic()
            .wrap_err("failed to wait for ctrl+c")?;
    }

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
