pub mod worker;

#[derive(Clone)]
pub struct Job {
    pub msg_id: String,
}

impl Job {
    pub fn new<'a>(msg_id: String) -> Job {
        Job { msg_id }
    }
}
