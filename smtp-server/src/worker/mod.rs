use camino::Utf8PathBuf;

pub mod worker;

#[derive(Clone)]
pub struct Job {
    email_path: Utf8PathBuf,
}

impl Job {
    pub fn new<'a>(email_path: Utf8PathBuf) -> Job {
        Job { email_path }
    }

    pub async fn process(&self) {
        println!("Processing email: {:?}", self.email_path);
    }
}
