use async_trait::async_trait;
use base64::prelude::*;
use miette::{bail, Context, Diagnostic, IntoDiagnostic, Result, SourceSpan};
use nom::{
    branch::alt,
    bytes::complete::{tag, take_while1},
    combinator::{map, opt},
    sequence::preceded,
    IResult,
};
use std::sync::Arc;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

mod parser;
pub use parser::*;

#[derive(Debug, Error, Diagnostic)]
pub enum SmtpError {
    #[error("IO error")]
    #[diagnostic(code(smtp::io_error))]
    IoError(#[from] std::io::Error),

    #[error("Parse error: {message}")]
    #[diagnostic(code(smtp::parse_error))]
    ParseError {
        message: String,
        #[label("This bit here")]
        span: SourceSpan,
    },

    #[error("Authentication error")]
    #[diagnostic(code(smtp::auth_error))]
    AuthError,
}

#[derive(Debug)]
pub struct Email {
    pub from: String,
    pub to: Vec<String>,
    pub body: String,
}

#[derive(Debug, PartialEq)]
pub enum SessionState {
    Connected,
    Greeted,
    AuthenticatingUsername,
    AuthenticatingPassword(String),
    Authenticated,
    ReceivingMailFrom,
    ReceivingRcptTo,
    ReceivingData,
}

#[async_trait]
pub trait SmtpCallbacks: Send + Sync {
    async fn on_ehlo(&self, domain: &str) -> Result<(), SmtpError>;
    async fn on_auth(&self, username: &str, password: &str) -> Result<bool, SmtpError>;
    async fn on_mail_from(&self, from: &str) -> Result<(), SmtpError>;
    async fn on_rcpt_to(&self, to: &str) -> Result<(), SmtpError>;
    async fn on_data(&self, email: &Email) -> Result<(), SmtpError>;
}

#[derive(Clone)]
pub struct SmtpServer {
    callbacks: Arc<dyn SmtpCallbacks>,
    auth_enabled: bool,
}

impl SmtpServer {
    pub fn new<T: SmtpCallbacks + 'static>(callbacks: T, auth_enabled: bool) -> Self {
        SmtpServer {
            callbacks: Arc::new(callbacks),
            auth_enabled,
        }
    }

    pub async fn handle_client(&self, mut socket: TcpStream) -> Result<()> {
        let mut session = SmtpSession::new();
        let mut buffer = [0; 4028];
        let mut data_buffer = Vec::new();

        socket
            .write_all(b"220 localhost ESMTP server ready\r\n")
            .await
            .into_diagnostic()?;

        loop {
            let n = socket.read(&mut buffer).await.into_diagnostic()?;
            if n == 0 {
                return Ok(());
            }

            if session.state == SessionState::ReceivingData {
                data_buffer.extend_from_slice(&buffer[..n]);
                if let Some(end_index) = data_buffer
                    .windows(5)
                    .position(|window| window == b"\r\n.\r\n")
                {
                    let email_body = String::from_utf8_lossy(&data_buffer[..end_index]).to_string();
                    session.email.body = email_body;
                    self.callbacks.on_data(&session.email).await?;
                    socket.write_all(b"250 OK\r\n").await.into_diagnostic()?;
                    session.state = SessionState::Authenticated;
                    data_buffer.clear();
                    continue;
                }
            } else {
                let command = String::from_utf8_lossy(&buffer[..n]).trim().to_string();
                match parse_command(&command, &session.state) {
                    Ok(cmd) => {
                        if self.handle_command(&mut session, cmd, &mut socket).await? {
                            return Ok(());
                        }
                    }
                    Err(e) => {
                        eprintln!("Parse error: {}", e);
                        socket
                            .write_all(b"500 Syntax error, command unrecognized\r\n")
                            .await
                            .into_diagnostic()?;
                    }
                }
            }
        }
    }

    async fn handle_command(
        &self,
        session: &mut SmtpSession,
        command: SmtpCommand,
        socket: &mut TcpStream,
    ) -> Result<bool> {
        match (&session.state, command) {
            (SessionState::Connected, SmtpCommand::Ehlo(domain)) => {
                self.callbacks.on_ehlo(&domain).await?;
                socket
                    .write_all(b"250-localhost\r\n250-AUTH PLAIN LOGIN\r\n250 OK\r\n")
                    .await
                    .into_diagnostic()?;
                if self.auth_enabled {
                    session.state = SessionState::Greeted;
                } else {
                    session.state = SessionState::Authenticated;
                }
            }
            (SessionState::Greeted, SmtpCommand::AuthPlain(auth_data)) => {
                self.handle_auth_plain(session, auth_data, socket).await?;
            }
            (SessionState::Greeted, SmtpCommand::AuthLogin) => {
                session.state = SessionState::AuthenticatingUsername;
                socket
                    .write_all(b"334 VXNlcm5hbWU6\r\n")
                    .await
                    .into_diagnostic()?;
            }
            (SessionState::AuthenticatingUsername, SmtpCommand::AuthUsername(username)) => {
                let decoded_username = decode_base64(&username)?;
                session.state = SessionState::AuthenticatingPassword(decoded_username);
                socket
                    .write_all(b"334 UGFzc3dvcmQ6\r\n")
                    .await
                    .into_diagnostic()?;
            }
            (
                SessionState::AuthenticatingPassword(username),
                SmtpCommand::AuthPassword(password),
            ) => {
                self.handle_auth_login(session, username.to_string(), password, socket)
                    .await?;
            }
            (SessionState::Authenticated, SmtpCommand::MailFrom(from)) => {
                self.callbacks.on_mail_from(&from).await?;
                session.email.from = from;
                socket.write_all(b"250 OK\r\n").await.into_diagnostic()?;
                session.state = SessionState::ReceivingMailFrom;
            }
            (SessionState::ReceivingMailFrom, SmtpCommand::RcptTo(to))
            | (SessionState::ReceivingRcptTo, SmtpCommand::RcptTo(to)) => {
                self.callbacks.on_rcpt_to(&to).await?;
                session.email.to.push(to); // Consider changing this to a Vec<String> to support multiple recipients
                socket.write_all(b"250 OK\r\n").await.into_diagnostic()?;
                session.state = SessionState::ReceivingRcptTo;
            }
            (SessionState::ReceivingRcptTo, SmtpCommand::MailFrom(from)) => {
                // Start a new email transaction
                self.callbacks.on_mail_from(&from).await?;
                session.email = Email {
                    from,
                    to: Vec::with_capacity(1),
                    body: String::new(),
                };
                socket.write_all(b"250 OK\r\n").await.into_diagnostic()?;
                session.state = SessionState::ReceivingMailFrom;
            }
            (SessionState::ReceivingRcptTo, SmtpCommand::Data) => {
                socket
                    .write_all(b"354 Start mail input; end with <CRLF>.<CRLF>\r\n")
                    .await
                    .into_diagnostic()?;
                session.state = SessionState::ReceivingData;
            }
            (_, SmtpCommand::Quit) => {
                socket.write_all(b"221 Bye\r\n").await.into_diagnostic()?;
                return Ok(true);
            }
            cmd => {
                if !session.can_accept_mail_commands() {
                    socket
                        .write_all(b"530 Authentication required\r\n")
                        .await
                        .into_diagnostic()?;
                } else {
                    eprintln!("Unknown command: {:?}", cmd);
                    socket
                        .write_all(b"500 Unknown command\r\n")
                        .await
                        .into_diagnostic()?;
                }
            }
        }
        Ok(false)
    }

    async fn handle_auth_plain(
        &self,
        session: &mut SmtpSession,
        auth_data: String,
        socket: &mut TcpStream,
    ) -> Result<()> {
        let decoded = decode_base64(&auth_data)?;
        let parts: Vec<&str> = decoded.split('\0').collect();
        if parts.len() != 3 {
            bail!("Invalid AUTH PLAIN data");
        }
        self.handle_authentication(session, parts[1], parts[2], socket)
            .await
    }

    async fn handle_auth_login(
        &self,
        session: &mut SmtpSession,
        username: String,
        password: String,
        socket: &mut TcpStream,
    ) -> Result<()> {
        let decoded_password = decode_base64(&password)?;
        self.handle_authentication(session, &username, &decoded_password, socket)
            .await
    }

    async fn handle_authentication(
        &self,
        session: &mut SmtpSession,
        username: &str,
        password: &str,
        socket: &mut TcpStream,
    ) -> Result<()> {
        match self.callbacks.on_auth(username, password).await {
            Ok(true) => {
                session.state = SessionState::Authenticated;
                socket
                    .write_all(b"235 Authentication successful\r\n")
                    .await
                    .into_diagnostic()?;
            }
            Ok(false) | Err(_) => {
                session.state = SessionState::Greeted;
                socket
                    .write_all(b"535 Authentication failed\r\n")
                    .await
                    .into_diagnostic()
                    .wrap_err("Authentication failed")?;
            }
        }
        Ok(())
    }
}

struct SmtpSession {
    state: SessionState,
    email: Email,
}

impl SmtpSession {
    fn new() -> Self {
        SmtpSession {
            state: SessionState::Connected,
            email: Email {
                from: String::new(),
                to: Vec::with_capacity(1),
                body: String::new(),
            },
        }
    }

    // Implement other methods (handle_command, parse_email_body, etc.) here...
    fn can_accept_mail_commands(&self) -> bool {
        matches!(
            self.state,
            SessionState::Authenticated
                | SessionState::ReceivingMailFrom
                | SessionState::ReceivingRcptTo
        )
    }
}

pub fn decode_base64(input: &str) -> Result<String, SmtpError> {
    String::from_utf8(
        BASE64_STANDARD
            .decode(input)
            .map_err(|_| SmtpError::AuthError)?,
    )
    .map_err(|_| SmtpError::AuthError)
}
