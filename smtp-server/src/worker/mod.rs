use async_channel::Receiver;
use email_address_parser::EmailAddress;
use hickory_resolver::{
    name_server::{GenericConnector, TokioRuntimeProvider},
    AsyncResolver, TokioAsyncResolver,
};
use mail_parser::{Message, MessageParser};
use mail_send::{
    mail_auth::{
        common::crypto::{RsaKey, Sha256},
        dkim::DkimSigner,
    },
    smtp::message::Message as EmailMessage,
};
use miette::{bail, Context, IntoDiagnostic, Result};
use pool::SmtpClientPool;
use std::sync::Arc;
use tokio::fs;

use crate::{
    config::CfgDKIM,
    storage::{Status, Storage},
};

mod pool;

pub struct Worker {
    channel: Receiver<Job>,
    storage: Arc<Box<dyn Storage>>,
    resolver: AsyncResolver<GenericConnector<TokioRuntimeProvider>>,
    pool: SmtpClientPool,
    dkim: Option<CfgDKIM>,
}

impl Worker {
    pub fn new(
        channel: Receiver<Job>,
        storage: Arc<Box<dyn Storage>>,
        dkim: Option<CfgDKIM>,
    ) -> Result<Self> {
        let resolver = TokioAsyncResolver::tokio_from_system_conf()
            .into_diagnostic()
            .wrap_err("creating dns resolver")?;
        let pool = SmtpClientPool::new();
        Ok(Worker {
            channel,
            storage,
            resolver,
            pool,
            dkim,
        })
    }

    pub async fn run(&mut self) {
        loop {
            let job = self.channel.recv().await;
            match job {
                Ok(job) => {
                    if let Err(e) = self.process_job(&job).await {
                        println!("Error processing job: {:?}", e);
                    }
                }
                Err(_) => {
                    break;
                }
            }
        }
    }

    async fn process_job(&self, job: &Job) -> Result<()> {
        let email = match self.storage.get(&job.msg_id, Status::QUEUED).await {
            Ok(Some(email)) => email,
            Ok(None) => {
                println!("Email not found: {:?}", job.msg_id);
                return self.storage.delete(&job.msg_id, Status::QUEUED).await;
            }
            Err(e) => return Err(e).wrap_err("failed to get email from storage"),
        };

        let msg = match MessageParser::default().parse(&email.body) {
            Some(msg) => msg,
            None => bail!("failed to parse email body"),
        };

        match self.send_email(&msg).await {
            Ok(_) => self.storage.delete(&job.msg_id, Status::QUEUED).await,
            Err(e) => {
                println!("Error sending email: {:?}", e);
                self.defer_email(&job.msg_id).await
            }
        }
    }

    async fn defer_email(&self, msg_id: &str) -> Result<()> {
        self.storage
            .mv(msg_id, msg_id, Status::QUEUED, Status::DEFERRED)
            .await
            .wrap_err("moving email to deferred")?;

        self.storage
            .delete(msg_id, Status::QUEUED)
            .await
            .wrap_err("deleting email from queued")
    }

    async fn send_email<'a>(&self, email: &'a Message<'a>) -> Result<()> {
        // Parse to address for each.
        for to in email.to().iter() {
            let to = to.first().unwrap().address.as_ref().unwrap();
            let from = email
                .from()
                .unwrap()
                .first()
                .unwrap()
                .address
                .as_ref()
                .unwrap();
            println!("Sending email to: {}, from: {}", to, from);
            // Strip `<` and `>` from email address.
            let to = to.trim_matches(|c| c == '<' || c == '>');
            let parsed_email_id = EmailAddress::parse(to, None);
            if let None = parsed_email_id {
                continue;
            }

            let parsed_email_id = parsed_email_id.unwrap();

            // Resolve MX record for domain.
            let mx = self
                .resolver
                .mx_lookup(parsed_email_id.get_domain())
                .await
                .into_diagnostic()
                .wrap_err("getting mx record")?;
            if mx.iter().count() == 0 {
                continue;
            }
            // Sort by priority.
            let mx = mx.iter().min_by_key(|mx| mx.preference()).unwrap();

            let raw_message = email.raw_message.clone();

            // Send email to mx record.
            let message = EmailMessage::new(from.to_string(), vec![to.to_string()], raw_message);

            let mut client = self
                .pool
                .get_client(mx.exchange().to_string().as_ref(), 25)
                .await
                .unwrap();

            if let Some(dkim) = &self.dkim {
                let priv_key = fs::read(&dkim.private_key)
                    .await
                    .into_diagnostic()
                    .wrap_err("reading private key")?;

                let priv_key_str = String::from_utf8(priv_key)
                    .into_diagnostic()
                    .wrap_err("converting private key to string")?;

                let pk_rsa =
                    RsaKey::<Sha256>::from_rsa_pem(&priv_key_str).expect("error reading priv key");

                let signer = DkimSigner::from_key(pk_rsa)
                    .domain(&dkim.domain)
                    .selector(&dkim.selector)
                    .headers(["From", "To", "Subject"])
                    .expiration(60 * 60 * 7);

                client
                    .send_signed(message, &signer)
                    .await
                    .into_diagnostic()
                    .wrap_err("sending email using client")?;

                println!("Email sent with DKIM");
            } else {
                client
                    .send(message)
                    .await
                    .into_diagnostic()
                    .wrap_err("sending email using client")?;
            }
        }
        return Ok(());
    }
}

#[derive(Clone)]
pub struct Job {
    pub msg_id: String,
}

impl Job {
    pub fn new(msg_id: String) -> Job {
        Job { msg_id }
    }
}
