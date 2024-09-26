use miette::{Context, IntoDiagnostic, Result};
use smtp::SmtpServer;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<()> {
    let smtp_server = SmtpServer::new()
        .on_ehlo(|domain| {
            println!("EHLO from {}", domain);
            Ok(())
        })
        .on_auth(|username, password| {
            println!("Auth attempt: {}:{}", username, password);
            Ok(username == "test" && password == "test")
        })
        .on_mail_from(|from| {
            println!("Mail from: {}", from);
            Ok(())
        })
        .on_rcpt_to(|to| {
            println!("Rcpt to: {}", to);
            Ok(())
        })
        .on_data(|email| {
            println!("Received email: {:?}", email);
            Ok(())
        });

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
