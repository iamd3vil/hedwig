use async_trait::async_trait;
use miette::{Context, IntoDiagnostic, Result};
use smtp::{Email, SmtpCallbacks, SmtpError, SmtpServer};
use tokio::net::TcpListener;

struct MySmtpCallbacks;

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
        println!("Received email: {:?}", email);
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let smtp_server = SmtpServer::new(MySmtpCallbacks, false);

    let listener = TcpListener::bind("127.0.0.1:2525")
        .await
        .into_diagnostic()?;
    println!("SMTP server listening on port 2525");

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
