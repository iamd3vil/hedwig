use async_trait::async_trait;
use config::CfgStorage;
use mail_parser::MessageParser;
use miette::{bail, Context, IntoDiagnostic, Result};
use smtp::{Email, SmtpCallbacks, SmtpError, SmtpServer};
use std::sync::Arc;
use storage::{fs_storage::FileSystemStorage, Storage, StoredEmail};
use tokio::net::TcpListener;
use ulid::Ulid;
use worker::{Job, Worker};

mod config;
mod storage;
mod worker;

struct MySmtpCallbacks {
    storage: Arc<Box<dyn Storage>>,
    sender_channel: async_channel::Sender<worker::Job>,
}

impl MySmtpCallbacks {
    pub fn new(storage: Box<dyn Storage>, worker_count: usize) -> Self {
        let (sender_channel, receiver_channel) = async_channel::bounded(1);

        let storage = Arc::new(storage);
        // Start workers.
        for _ in 0..worker_count {
            let receiver_channel = receiver_channel.clone();
            let storage_cloned = storage.clone();
            tokio::spawn(async move {
                let mut worker = Worker::new(receiver_channel, storage_cloned.clone());
                worker.run().await;
            });
        }

        MySmtpCallbacks {
            storage,
            sender_channel,
        }
    }

    async fn process_email(&self, email: &Email) -> Result<(), SmtpError> {
        println!("Received email: {:?}", email);
        // Parse email body.
        let msg = MessageParser::default().parse(&email.body);
        if let Some(msg) = msg {
            // Print each header and html, text body.
            // Check if message_id exists, or else let's generate one.
            let ulid = Ulid::new().to_string();
            let message_id = msg.message_id().unwrap_or(&ulid);
            println!("Message-ID: {}", message_id);
            let stored_email = StoredEmail {
                message_id: message_id.to_string(),
                from: email.from.clone(),
                to: email.to.clone(),
                body: email.body.clone(),
            };
            // Map any error into a SmtpError.
            self.storage
                .put(stored_email)
                .await
                .map_err(|e| SmtpError::ParseError {
                    message: format!("Failed to store email: {}", e),
                    span: (0, email.body.len()).into(),
                })?;

            // Send the email to the worker.
            let job = Job::new(message_id.to_owned());
            self.sender_channel
                .send(job)
                .await
                .map_err(|e| SmtpError::ParseError {
                    message: format!("Failed to send email to worker: {}", e),
                    span: (0, email.body.len()).into(),
                })?;
        } else {
            eprintln!("Error parsing email body, skipping");
            return Err(SmtpError::ParseError {
                message: "error parsing email body".into(),
                span: (0, email.body.len()).into(),
            });
        }
        Ok(())
    }
}

#[async_trait]
impl SmtpCallbacks for MySmtpCallbacks {
    async fn on_ehlo(&self, domain: &str) -> Result<(), SmtpError> {
        println!("EHLO from {}", domain);
        Ok(())
    }

    async fn on_auth(&self, username: &str, password: &str) -> Result<bool, SmtpError> {
        // println!("Auth attempt: {}:{}", username, password);
        Ok(username == "test" && password == "test")
    }

    async fn on_mail_from(&self, from: &str) -> Result<(), SmtpError> {
        println!("Mail from: {}", from);
        Ok(())
    }

    async fn on_rcpt_to(&self, to: &str) -> Result<(), SmtpError> {
        println!("Rcpt to: {}", to);
        Ok(())
    }

    async fn on_data(&self, email: &Email) -> Result<(), SmtpError> {
        self.process_email(email).await?;
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Load the configuration from the file.
    let cfg = config::Cfg::load("config.toml").wrap_err("error loading configuration")?;

    let storage = get_storage_type(&cfg.storage).wrap_err("error getting storage type")?;
    let smtp_server = SmtpServer::new(
        MySmtpCallbacks::new(storage, cfg.server.workers.unwrap_or(1)),
        false,
    );

    let listener = TcpListener::bind(&cfg.server.addr)
        .await
        .into_diagnostic()?;
    println!("SMTP server listening on {}", cfg.server.addr);

    loop {
        let (socket, _) = listener
            .accept()
            .await
            .into_diagnostic()
            .wrap_err("error accepting tcp connection")?;
        let server_clone = smtp_server.clone();
        tokio::spawn(async move {
            if let Err(e) = server_clone.handle_client(socket).await {
                eprintln!("Error handling client: {:#}", e);
            }
        });
    }
}

fn get_storage_type(cfg: &CfgStorage) -> Result<Box<dyn Storage>> {
    match cfg.storage_type.as_ref() {
        "fs" => Ok(Box::new(FileSystemStorage::new(cfg.base_path.clone()))),
        _ => bail!("Unknown storage type: {}", cfg.storage_type),
    }
}
