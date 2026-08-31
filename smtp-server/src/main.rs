use clap::Parser;
use futures::StreamExt;
use hedwig::config::CfgStorage;
use hedwig::mta_sts::refresher;
use hedwig::storage::{fs_storage::FileSystemStorage, Status, Storage};
use hedwig::worker::{deferred_worker::DeferredWorker, Job};
use hedwig::{callbacks, config, dkim, health, inbound, logqueue, metrics, queue_cli, worker};
use miette::{bail, Context, IntoDiagnostic, Result};
use rustls::pki_types::CertificateDer;
use smtp::SmtpServer;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;
use tokio_rustls::rustls::{self, ServerConfig};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn, Level};

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
    /// Inspect a log-queue spool, read-only (see docs/plans/2026-07-20-durable-log-queue.md §25)
    Queue(queue_cli::QueueArgs),
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
        Commands::Queue(queue_args) => queue_cli::run(queue_args).await,
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
    if is_log_backend {
        warn_about_unmigrated_legacy_spool(&cfg.storage.base_path);
    }
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
    let mut log_runtime: Option<(
        logqueue::spool::Spool,
        logqueue::writer::LogWriters,
        JoinHandle<()>,
    )> = None;

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
            let (store, recovered) =
                logqueue::state::ShardStateStore::recover(shard_dir.path(), shard_dir.shard())
                    .map_err(miette::Report::new)
                    .wrap_err_with(|| format!("error recovering shard {}", shard_dir.shard()))?;
            shard_inits.push(logqueue::dispatcher::ShardInit {
                dir: shard_dir.path().to_path_buf(),
                shared: writers.handle().shard_shared(shard_dir.shard()),
                store,
                recovered,
            });
        }

        let tap =
            callbacks::LogQueueTap::new(writers.handle(), spool_root, qcfg.disk_reserve_bytes());
        let (callbacks, worker_resources, mta_sts_resolver) =
            callbacks::Callbacks::new_log(Arc::clone(&storage), tap, cfg.clone())
                .await
                .wrap_err("failed to initialize SMTP callbacks (log backend)")?;

        let gate = Arc::new(worker::log_worker::LimiterGate(
            worker_resources.rate_limiter(),
        ));
        let dispatcher_config = logqueue::dispatcher::DispatcherConfig {
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
        )
        .map_err(miette::Report::new)
        .wrap_err("error starting log-queue dispatcher")?;

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

    // Inbound runs on dedicated compio (io_uring) threads; every thread
    // binds each listener address with SO_REUSEPORT so the kernel spreads
    // accepted connections across rings.
    let mut inbound_specs = Vec::new();
    for (i, listener_config) in cfg.server.listeners.iter().enumerate() {
        let tls_status = match &listener_config.tls {
            Some(tls) if tls.mode == config::TlsMode::Starttls => "STARTTLS",
            Some(_) => "TLS",
            None => "plaintext",
        };
        info!(
            storage_type = cfg.storage.storage_type,
            "SMTP server listening on {} ({}) [compio/io_uring]", listener_config.addr, tls_status
        );
        inbound_specs.push(inbound::ListenerSpec {
            addr: listener_config.addr.clone(),
            acceptor: tls_acceptors[i].clone(),
            tls_mode: listener_config
                .tls
                .as_ref()
                .map(|tls| tls.mode)
                .unwrap_or_default(),
        });
    }

    let inbound_thread_count = inbound::inbound_thread_count();
    info!(threads = inbound_thread_count, "starting compio inbound threads");
    let inbound_threads = inbound::spawn_inbound_threads(
        inbound_specs,
        smtp_server,
        Arc::clone(&conn_semaphore),
        shutdown_token.clone(),
        cmd_timeout,
        inbound_thread_count,
        tokio::runtime::Handle::current(),
    )?;

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

    // Inbound threads observe the cancellation token; wait for their accept
    // loops to wind down off the async runtime.
    let join_inbound = tokio::task::spawn_blocking(move || {
        for handle in inbound_threads {
            if handle.join().is_err() {
                error!("inbound thread panicked");
            }
        }
    });
    if let Err(err) = join_inbound.await {
        error!("failed to join inbound threads: {:?}", err);
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

/// The log backend never reads the legacy one-file-per-message spool; mail
/// sitting there is preserved but undelivered until `hedwig queue migrate`
/// runs. Make that state loud at startup instead of silently ignoring it.
fn warn_about_unmigrated_legacy_spool(base_path: &str) {
    let mut counts = Vec::new();
    for dir in ["queued", "deferred"] {
        let path = std::path::Path::new(base_path).join(dir);
        let n = std::fs::read_dir(&path)
            .map(|entries| entries.filter_map(|e| e.ok()).count())
            .unwrap_or(0);
        if n > 0 {
            counts.push(format!("{n} entries in {}", path.display()));
        }
    }
    if !counts.is_empty() {
        warn!(
            "unmigrated legacy spool detected ({}); this mail is preserved but will NOT be              delivered until you stop the server and run `hedwig queue migrate --config <config>`",
            counts.join(", ")
        );
    }
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
