use async_trait::async_trait;
use smtp::Email;

pub mod domain_filter;

#[async_trait]
pub trait MailFromFilter: Send + Sync {
    async fn filter_mail_from(&self, from: &str) -> FilterOutcome;
    fn name(&self) -> &'static str; // For logging/identification
}

#[async_trait]
pub trait RcptToFilter: Send + Sync {
    async fn filter_rcpt_to(&self, to: &str) -> FilterOutcome;
    fn name(&self) -> &'static str;
}

#[async_trait]
pub trait DataFilter: Send + Sync {
    async fn filter_data(&self, email: &Email) -> FilterOutcome;
    fn name(&self) -> &'static str;
}

pub enum FilterOutcome {
    Allow,
    Deny(String),
    Neutral,
}
