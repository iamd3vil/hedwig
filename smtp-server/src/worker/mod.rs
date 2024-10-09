use async_channel::Receiver;
use email_address_parser::EmailAddress;
use hickory_resolver::{
    name_server::{GenericConnector, TokioRuntimeProvider},
    AsyncResolver, TokioAsyncResolver,
};
use mail_parser::{Message, MessageParser};
use mail_send::{mail_builder::MessageBuilder, SmtpClientBuilder};
use miette::{Context, IntoDiagnostic, Result};
use std::{borrow::Cow, sync::Arc};

use crate::storage::Storage;

pub struct Worker {
    channel: Receiver<Job>,
    storage: Arc<Box<dyn Storage>>,
    resolver: AsyncResolver<GenericConnector<TokioRuntimeProvider>>,
}

impl Worker {
    pub fn new(channel: Receiver<Job>, storage: Arc<Box<dyn Storage>>) -> Result<Self> {
        let resolver = TokioAsyncResolver::tokio_from_system_conf()
            .into_diagnostic()
            .wrap_err("creating dns resolver")?;
        Ok(Worker {
            channel,
            storage,
            resolver,
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
        // println!("Processing job: {:?}", job.msg_id);
        let email = self.storage.get(&job.msg_id).await?;
        if let Some(email) = email {
            let msg = MessageParser::default().parse(&email.body);
            if let Some(msg) = msg {
                self.send_email(&msg)
                    .await
                    .wrap_err("error sending email")?;
            }
        } else {
            println!("Email not found: {:?}", job.msg_id);
        }
        self.storage.delete(&job.msg_id).await
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
            println!("Sending email to: {}, from: {:?}", to, email);
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
            println!("mx record: {}", mx.exchange().to_string());

            // Send email to mx record.
            let message = MessageBuilder::new()
                .from(from.to_string())
                .to(to.to_string())
                .subject(email.subject().unwrap_or(""))
                .text_body(email.body_text(0).unwrap_or(Cow::Borrowed("")))
                .html_body(email.body_html(0).unwrap_or(Cow::Borrowed("")));
            let mut client =
                SmtpClientBuilder::new(mx.exchange().to_string().strip_suffix(".").unwrap(), 25)
                    .implicit_tls(false)
                    .connect()
                    .await
                    .into_diagnostic()?;
            client
                .send(message)
                .await
                .into_diagnostic()
                .wrap_err("sending email using client")?;
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
