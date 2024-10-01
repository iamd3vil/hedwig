use async_channel::Receiver;
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
                    job.process().await;
                    self.storage
                        .delete(&job.email_path.to_string())
                        .await
                        .unwrap();
                }
                Err(_) => {
                    break;
                }
            }
        }
    }
}
