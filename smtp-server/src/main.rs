use config::CfgStorage;
use miette::{bail, Context, IntoDiagnostic, Result};
use smtp::SmtpServer;
use std::sync::Arc;
use storage::{fs_storage::FileSystemStorage, Storage};
use subtle::ConstantTimeEq;
use tokio::net::TcpListener;
use tracing::{debug, error, info};
use worker::deferred_worker::DeferredWorker;

mod callbacks;
mod config;
mod storage;
mod worker;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize the tracing subscriber
    tracing_subscriber::fmt()
        .with_target(false)
        .with_line_number(false)
        .with_level(true)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("HEDWIG_LOG_LEVEL")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("hedwig=info")),
        )
        .init();

    // Load the configuration from the file.
    let cfg = config::Cfg::load("config.toml").wrap_err("error loading configuration")?;

    if cfg.server.dkim.is_some() {
        info!("DKIM is enabled");
    } else {
        info!("DKIM is disabled");
    }

    // Initialize channels for background processing of emails.
    let (sender_channel, receiver_channel) = async_channel::bounded(1);

    // Initialize storage.
    let storage = get_storage_type(&cfg.storage)
        .await
        .wrap_err("error getting storage type")?;
    let storage = Arc::new(storage);
    let smtp_server = SmtpServer::new(
        callbacks::Callbacks::new(
            storage.clone(),
            sender_channel.clone(),
            receiver_channel.clone(),
            cfg.clone(),
        ),
        true,
    );

    // Start the deferred worker.
    tokio::spawn(async move {
        let worker = DeferredWorker::new(storage, sender_channel.clone());
        let res = worker.process_deferred_jobs().await;
        if let Err(e) = res {
            error!("Error running deferred worker: {:#}", e);
        }
    });

    let listener = TcpListener::bind(&cfg.server.addr)
        .await
        .into_diagnostic()?;
    info!(
        storage_type = cfg.storage.storage_type,
        "SMTP server listening on {}", cfg.server.addr
    );

    loop {
        let (socket, _) = listener
            .accept()
            .await
            .into_diagnostic()
            .wrap_err("error accepting tcp connection")?;
        debug!("Accepted connection");
        let server_clone = smtp_server.clone();
        tokio::spawn(async move {
            if let Err(e) = server_clone.handle_client(socket).await {
                error!("Error handling client: {:#}", e);
            }
        });
    }
}

async fn get_storage_type(cfg: &CfgStorage) -> Result<Box<dyn Storage>> {
    match cfg.storage_type.as_ref() {
        "fs" => {
            let st = FileSystemStorage::new(cfg.base_path.clone()).await?;
            Ok(Box::new(st))
        }
        _ => bail!("Unknown storage type: {}", cfg.storage_type),
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}
