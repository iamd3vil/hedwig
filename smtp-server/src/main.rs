use base64::Engine;
use clap::Parser;
use config::{CfgDKIM, CfgStorage, DkimKeyType};
use futures::StreamExt;
use miette::{bail, Context, IntoDiagnostic, Result};
use rand::rngs::OsRng;
use rsa::{
    pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding},
    RsaPrivateKey,
};
use rustls::pki_types::CertificateDer;
use smtp::{SmtpServer, SmtpStream};
use std::sync::Arc;
use storage::{fs_storage::FileSystemStorage, Status, Storage};
use subtle::ConstantTimeEq;
use tokio::net::TcpListener;
use tokio_rustls::rustls::{self, ServerConfig};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, Level};
use worker::{deferred_worker::DeferredWorker, Job};

mod callbacks;
mod config;
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
    DkimGenerate,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let args = Args::parse();

    match args.command.unwrap_or(Commands::Server) {
        Commands::Server => run_server(&args.config).await,
        Commands::DkimGenerate => generate_dkim_keys(&args.config).await,
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

    // tracing_subscriber::fmt()
    //     .with_target(false)
    //     .with_line_number(false)
    //     .with_level(true)
    //     .with_env_filter(
    //         tracing_subscriber::EnvFilter::try_from_env("HEDWIG_LOG_LEVEL")
    //             .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("hedwig=info")),
    //     )
    //     .init();

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
    // Initialize TLS if configured
    let tls_acceptor = if let Some(tls_config) = &cfg.server.tls {
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

        let key =
            rustls_pemfile::private_key(&mut std::io::BufReader::new(key_file.into_std().await))
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

    let smtp_server = SmtpServer::new(
        callbacks::Callbacks::new(
            Arc::clone(&storage),
            sender_channel.clone(),
            receiver_channel.clone(),
            cfg.clone(),
        ),
        true,
    );

    // Check if there are any emails to process.
    // Spawn a task to process the emails.
    info!("checking for any emails to process in queue");
    let mut emails = storage.list(Status::Queued);
    while let Some(email) = emails.next().await {
        let email = email.unwrap();
        let job = Job::new(email.message_id, 0);
        sender_channel
            .send(job)
            .await
            .into_diagnostic()
            .wrap_err("error sending job to receiver channel")?;
    }
    info!("processed queued emails");

    // Start the deferred worker.
    tokio::spawn(async move {
        let worker = DeferredWorker::new(Arc::clone(&storage), sender_channel.clone());
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
        let tls_acceptor = tls_acceptor.clone();

        tokio::spawn(async move {
            let mut boxed_socket: Box<dyn SmtpStream> = if let Some(acceptor) = tls_acceptor {
                match acceptor.accept(socket).await {
                    Ok(tls_stream) => Box::new(tls_stream),
                    Err(e) => {
                        error!("TLS handshake failed: {}", e);
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

async fn generate_dkim_keys(config_path: &str) -> Result<()> {
    let cfg = config::Cfg::load(config_path).wrap_err("error loading configuration")?;

    let dkim_config = match &cfg.server.dkim {
        Some(config) => config,
        None => bail!("DKIM configuration is missing in config file"),
    };

    match dkim_config.key_type {
        DkimKeyType::Rsa => generate_rsa_keys(dkim_config).await,
        DkimKeyType::Ed25519 => generate_ed25519_keys(dkim_config).await,
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
    use rand::RngCore;

    let mut rng = OsRng;

    // Generate random bytes for the secret key
    let mut secret_bytes = [0u8; 32];
    rng.fill_bytes(&mut secret_bytes);

    // Create signing key from random bytes
    let signing_key = SigningKey::from_bytes(&secret_bytes);
    let verifying_key = signing_key.verifying_key();

    // Convert to PKCS8 PEM
    let private_key_bytes = signing_key.to_bytes().to_vec();
    let pem = pem::Pem::new("PRIVATE KEY", private_key_bytes);
    let private_key_pem = pem::encode(&pem);

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
