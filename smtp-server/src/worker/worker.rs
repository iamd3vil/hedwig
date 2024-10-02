use async_channel::Receiver;
use miette::Result;
use std::sync::Arc;

use crate::storage::Storage;

use super::Job;

pub struct Worker {
    channel: Receiver<Job>,
    storage: Arc<Box<dyn Storage>>,
}

impl Worker {
    pub fn new(channel: Receiver<Job>, storage: Arc<Box<dyn Storage>>) -> Self {
        Worker { channel, storage }
    }

    pub async fn run(&mut self) {
        loop {
            let job = self.channel.recv().await;
            match job {
                Ok(job) => {
                    self.process_job(&job).await;
                }
                Err(_) => {
                    break;
                }
            }
        }
    }

    async fn process_job(&self, job: &Job) -> Result<()> {
        println!("Processing job: {:?}", job.msg_id);
        let email = self.storage.get(&job.msg_id).await?;
        if email.is_some() {
            let email = email.unwrap();
            println!("Email found, from: {}, to: {:?}", email.from, email.to);
        } else {
            println!("Email not found: {:?}", job.msg_id);
        }
        self.storage.delete(&job.msg_id).await
    }
}
