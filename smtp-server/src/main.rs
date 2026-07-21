use clap::Parser;
use config::CfgStorage;
use futures::StreamExt;
use miette::{bail, Context, IntoDiagnostic, Result};
use mta_sts::refresher;
use rustls::pki_types::CertificateDer;
use smtp::{MaybeTlsStream, SmtpServer, SmtpStream};
use std::sync::Arc;
use storage::{fs_storage::FileSystemStorage, sqlite_storage::SqliteStorage, Status, Storage};
use subtle::ConstantTimeEq;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
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
mod logqueue;
mod metrics;
mod mta_sts;
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
            tracing_subscriber::EnvFilter::try_from_env("HEDWIG_LOG_LEVEL").unwrap_or_else(|_| {
                tracing_subscriber::EnvFilter::new(format!("hedwig={}", level))
            }),
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
    let queue_buffer = cfg.server.queue_buffer.unwrap_or(1000);
    let (sender_channel, receiver_channel) = async_channel::bounded(queue_buffer);
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

    // Initialize storage. The "log" backend replaces queue storage with the
    // durable append log; a filesystem store remains as the bounced-message
    // archive (with the usual retention cleanup).
    let is_log_backend = cfg.storage.storage_type == "log";
    let storage: Arc<dyn Storage> = if is_log_backend {
        Arc::new(
            FileSystemStorage::new(cfg.storage.base_path.clone())
                .await
                .wrap_err("error creating bounce archive storage")?,
        )
    } else {
        get_storage_type(&cfg.storage)
            .await
            .wrap_err("error getting storage type")?
    };

    // Capture the current queue depth before workers start consuming jobs.
    // The log backend recovers its backlog through the dispatcher instead of
    // feeding it through the bounded channel.
    let mut queued_jobs = Vec::new();
    if !is_log_backend {
        let mut stream = storage.list(Status::Queued);
        while let Some(email) = stream.next().await {
            let email = email?;
            queued_jobs.push(email.message_id.clone());
        }
        metrics::queue_depth_set(queued_jobs.len());
    }

    // Spawn periodic cleanup for any storage retention policy that has been configured.
    let mut cleanup_config = cfg.storage.cleanup_config();
    if is_log_backend {
        // On the log backend the fs store is only the bounce archive. Its
        // deferred/ directory, if present, is an unmigrated legacy spool —
        // retention cleanup must never delete live legacy mail.
        cleanup_config.deferred_retention = None;
    }
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

    let max_message_size = cfg.server.max_message_size.unwrap_or(25 * 1024 * 1024);

    // Log-queue runtime pieces that outlive setup. The Spool must live
    // until exit: dropping it releases the exclusive spool lock.
    let mut log_runtime: Option<(logqueue::spool::Spool, logqueue::writer::LogWriters, JoinHandle<()>)> = None;

    let (callbacks, worker_handles, mta_sts_resolver) = if is_log_backend {
        let qcfg = cfg.queue();
        qcfg.validate(max_message_size)
            .wrap_err("invalid [queue] configuration")?;

        let spool_root = std::path::Path::new(&cfg.storage.base_path).join("spool");
        let spool = logqueue::spool::Spool::open(&spool_root, qcfg.append_writers())
            .map_err(miette::Report::new)
            .wrap_err("error opening log-queue spool")?;
        let max_record_len = (max_message_size as u64
            + logqueue::spool::ENVELOPE_ALLOWANCE
            + logqueue::record::FIXED_HEADER_LEN as u64) as u32;
        let writers = logqueue::writer::LogWriters::start(
            &spool,
            logqueue::writer::WriterConfig {
                segment_target_bytes: qcfg.segment_target_bytes(),
                max_record_len,
                pending_append_bytes: qcfg.pending_append_bytes(),
            },
        )
        .map_err(miette::Report::new)
        .wrap_err("error starting append writers")?;

        let mut shard_inits = Vec::new();
        for shard_dir in spool.shards() {
            let (store, recovered) = logqueue::state::ShardStateStore::recover(
                shard_dir.path(),
                shard_dir.shard(),
            )
            .map_err(miette::Report::new)
            .wrap_err_with(|| format!("error recovering shard {}", shard_dir.shard()))?;
            shard_inits.push(logqueue::dispatcher::ShardInit {
                dir: shard_dir.path().to_path_buf(),
                shared: writers.handle().shard_shared(shard_dir.shard()),
                store,
                recovered,
            });
        }

        let tap = callbacks::LogQueueTap {
            append: writers.handle(),
            spool_root,
            disk_reserve_bytes: qcfg.disk_reserve_bytes(),
        };
        let (callbacks, worker_resources, mta_sts_resolver) =
            callbacks::Callbacks::new_log(Arc::clone(&storage), tap, cfg.clone())
                .await
                .wrap_err("failed to initialize SMTP callbacks (log backend)")?;

        let gate = Arc::new(worker::log_worker::LimiterGate(
            worker_resources.rate_limiter(),
        ));
        let dispatcher_config = logqueue::dispatcher::DispatcherConfig {
            max_record_len,
            checkpoint_interval_bytes: qcfg.checkpoint_interval_bytes(),
            compaction_dead_ratio: qcfg.compaction_dead_ratio(),
            compaction_min_age: qcfg.compaction_min_age(),
            ..Default::default()
        };
        let (dispatcher_handle, dispatcher_task) = logqueue::dispatcher::Dispatcher::start(
            shard_inits,
            writers.handle(),
            gate,
            dispatcher_config,
            shutdown_token.clone(),
        );

        let worker_count = cfg.server.workers.unwrap_or(1).max(1);
        let max_retries = cfg.server.max_retries.unwrap_or(5);
        let mut handles = Vec::new();
        for worker_index in 0..worker_count {
            let delivery_worker = worker::Worker::new(
                receiver_channel.clone(), // inert on the log path
                Arc::clone(&storage),
                &cfg.server.dkim.clone(),
                worker::WorkerConfig {
                    disable_outbound: cfg.server.disable_outbound.unwrap_or(false),
                },
                worker_resources.clone(),
            )
            .await
            .wrap_err_with(|| format!("failed to create log worker {worker_index}"))?;
            let log_worker = worker::log_worker::LogWorker::new(
                delivery_worker,
                dispatcher_handle.clone(),
                max_retries,
            );
            handles.push(tokio::spawn(log_worker.run()));
        }
        info!(
            workers = worker_count,
            shards = spool.shard_count(),
            "log-queue backend active"
        );
        log_runtime = Some((spool, writers, dispatcher_task));
        (callbacks, handles, mta_sts_resolver)
    } else {
        callbacks::Callbacks::new(
            Arc::clone(&storage),
            sender_channel.clone(),
            receiver_channel.clone(),
            cfg.clone(),
        )
        .await
        .wrap_err("failed to initialize SMTP callbacks and workers")?
    };
    let cmd_timeout = cfg
        .server
        .cmd_timeout
        .unwrap_or(std::time::Duration::from_secs(5 * 60));
    let data_timeout = cfg
        .server
        .data_timeout
        .unwrap_or(std::time::Duration::from_secs(10 * 60));
    // Inbound identity for the 220 greeting and EHLO reply: config wins,
    // otherwise the OS hostname, with "localhost" as the last resort.
    let smtp_hostname = cfg.server.hostname.clone().unwrap_or_else(|| {
        hostname::get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_else(|| String::from("localhost"))
    });
    info!("Inbound SMTP hostname: {}", smtp_hostname);
    let smtp_server = SmtpServer::new(callbacks, auth_enabled)
        .with_max_message_size(max_message_size)
        .with_cmd_timeout(cmd_timeout)
        .with_data_timeout(data_timeout)
        .with_hostname(smtp_hostname);

    // Replay any queued emails so workers process them immediately.
    if is_log_backend {
        // Backlog recovery already happened through checkpoints, journal
        // replay, and dispatcher discovery; nothing goes through the channel.
    } else if !queued_jobs.is_empty() {
        info!(
            queued = queued_jobs.len(),
            "replaying queued jobs to workers"
        );
        for msg_id in queued_jobs {
            // A message that was mid-retry when we stopped still has its
            // deferred metadata; seed the attempt count from it so restarts
            // don't grant a fresh set of retries.
            let attempts = match storage.get_meta(&msg_id).await {
                Ok(Some(meta)) => meta.attempts,
                Ok(None) => 0,
                Err(e) => {
                    warn!(msg_id = %msg_id, "error reading meta during replay, assuming attempt 0: {:#}", e);
                    0
                }
            };
            let job = Job::new(msg_id, attempts);
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

    // Start the deferred worker (periodic retry loop). The log backend
    // schedules retries in the dispatcher's due-time heap instead.
    if !is_log_backend {
        let deferred_storage = Arc::clone(&storage);
        let deferred_sender = sender_channel.clone();
        let max_retries = cfg.server.max_retries;
        let deferred_shutdown = shutdown_token.clone();
        let deferred_handle = tokio::spawn(async move {
            let worker = DeferredWorker::new(deferred_storage, deferred_sender, max_retries);
            worker.run(deferred_shutdown).await;
        });
        background_tasks.push(deferred_handle);
    }

    // Start the MTA-STS background policy refresher.
    let mta_sts_shutdown = shutdown_token.clone();
    let mta_sts_for_refresh = Arc::clone(&mta_sts_resolver);
    let mta_sts_handle = tokio::spawn(async move {
        refresher::run_refresh_loop(mta_sts_for_refresh, mta_sts_shutdown).await;
    });
    background_tasks.push(mta_sts_handle);
    info!("MTA-STS policy enforcement enabled");

    // Limit concurrent inbound connections to prevent resource exhaustion.
    let max_connections = cfg.server.max_connections.unwrap_or(10_000);
    let conn_semaphore = Arc::new(Semaphore::new(max_connections));

    // Create listeners for each configured address
    let mut listeners = Vec::new();
    for (i, listener_config) in cfg.server.listeners.iter().enumerate() {
        let listener = TcpListener::bind(&listener_config.addr)
            .await
            .into_diagnostic()
            .wrap_err_with(|| format!("Failed to bind to address: {}", listener_config.addr))?;

        let tls_status = match &listener_config.tls {
            Some(tls) if tls.mode == config::TlsMode::Starttls => "STARTTLS",
            Some(_) => "TLS",
            None => "plaintext",
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
        let tls_mode = cfg.server.listeners[acceptor_index]
            .tls
            .as_ref()
            .map(|tls| tls.mode)
            .unwrap_or_default();
        let shutdown = shutdown_token.clone();
        let listener_addr = cfg.server.listeners[acceptor_index].addr.clone();
        let conn_semaphore = Arc::clone(&conn_semaphore);

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

                        // Enforce the connection limit. If we're at capacity, reject immediately.
                        let permit = match conn_semaphore.clone().try_acquire_owned() {
                            Ok(permit) => permit,
                            Err(_) => {
                                warn!(%listener_addr, "max connections reached, rejecting");
                                let mut sock: Box<dyn SmtpStream> = Box::new(socket);
                                let _ = sock.write_line(b"421 4.7.0 Too many connections, try again later\r\n").await;
                                continue;
                            }
                        };

                        debug!("Accepted connection");
                        let server_clone = server_clone.clone();
                        let tls_acceptor = tls_acceptor.clone();

                        tokio::spawn(async move {
                            // Hold the permit for the lifetime of this connection.
                            let _permit = permit;

                            let mut boxed_socket: Box<dyn SmtpStream> = match tls_acceptor {
                                // Implicit TLS: the handshake happens before any SMTP traffic.
                                // Bounded so a silent client can't hold a connection permit forever.
                                Some(acceptor) if tls_mode == config::TlsMode::Implicit => {
                                    match tokio::time::timeout(
                                        cmd_timeout,
                                        acceptor.accept(socket),
                                    )
                                    .await
                                    {
                                        Ok(Ok(tls_stream)) => Box::new(tls_stream),
                                        Ok(Err(e)) => {
                                            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                                                debug!("TLS handshake failed: {}", e);
                                            } else {
                                                error!("TLS handshake failed: {}", e);
                                            }

                                            return;
                                        }
                                        Err(_) => {
                                            debug!("TLS handshake timed out");
                                            return;
                                        }
                                    }
                                }
                                // STARTTLS: start in plaintext, upgrade when the client asks.
                                Some(acceptor) => {
                                    Box::new(MaybeTlsStream::Plain(socket, Some(acceptor)))
                                }
                                None => Box::new(socket),
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

    // Log backend: the dispatcher has drained in-flight outcomes and written
    // final checkpoints (it observes the same cancellation token); close
    // append admission last so every accepted message is on disk.
    if let Some((spool, writers, dispatcher_task)) = log_runtime {
        if let Err(err) = dispatcher_task.await {
            error!("dispatcher task failed during shutdown: {:?}", err);
        }
        writers.shutdown().await;
        drop(spool); // releases the exclusive spool lock
        info!("log queue flushed and stopped");
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
        "sqlite" => {
            let num_shards = cfg.num_shards.unwrap_or(16);
            let batch_size = cfg.batch_size.unwrap_or(100);
            let batch_timeout_ms = cfg.batch_timeout_ms.unwrap_or(5);
            let sqlite_cfg = cfg.sqlite.clone().unwrap_or_default();
            let st = SqliteStorage::new(
                &cfg.base_path,
                num_shards,
                batch_size,
                batch_timeout_ms,
                &sqlite_cfg,
            )
            .await?;
            Ok(Arc::new(st))
        }
        _ => bail!("Unknown storage type: {}", cfg.storage_type),
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}
