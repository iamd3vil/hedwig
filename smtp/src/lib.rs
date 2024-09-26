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
    pub to: String,
    pub body: String,
}

#[derive(Debug)]
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

#[derive(Clone)]
pub struct SmtpServer {
    on_ehlo: Arc<dyn Fn(&str) -> Result<(), SmtpError> + Send + Sync>,
    on_auth: Arc<dyn Fn(&str, &str) -> Result<bool, SmtpError> + Send + Sync>,
    on_mail_from: Arc<dyn Fn(&str) -> Result<(), SmtpError> + Send + Sync>,
    on_rcpt_to: Arc<dyn Fn(&str) -> Result<(), SmtpError> + Send + Sync>,
    on_data: Arc<dyn Fn(&Email) -> Result<(), SmtpError> + Send + Sync>,
}

impl SmtpServer {
    pub fn new() -> Self {
        SmtpServer {
            on_ehlo: Arc::new(|_| Ok(())),
            on_auth: Arc::new(|_, _| Ok(true)),
            on_mail_from: Arc::new(|_| Ok(())),
            on_rcpt_to: Arc::new(|_| Ok(())),
            on_data: Arc::new(|_| Ok(())),
        }
    }

    pub fn on_ehlo<F>(mut self, f: F) -> Self
    where
        F: Fn(&str) -> Result<(), SmtpError> + Send + Sync + 'static,
    {
        self.on_ehlo = Arc::new(f);
        self
    }

    pub fn on_auth<F>(mut self, f: F) -> Self
    where
        F: Fn(&str, &str) -> Result<bool, SmtpError> + Send + Sync + 'static,
    {
        self.on_auth = Arc::new(f);
        self
    }

    pub fn on_mail_from<F>(mut self, f: F) -> Self
    where
        F: Fn(&str) -> Result<(), SmtpError> + Send + Sync + 'static,
    {
        self.on_mail_from = Arc::new(f);
        self
    }

    pub fn on_rcpt_to<F>(mut self, f: F) -> Self
    where
        F: Fn(&str) -> Result<(), SmtpError> + Send + Sync + 'static,
    {
        self.on_rcpt_to = Arc::new(f);
        self
    }

    pub fn on_data<F>(mut self, f: F) -> Self
    where
        F: Fn(&Email) -> Result<(), SmtpError> + Send + Sync + 'static,
    {
        self.on_data = Arc::new(f);
        self
    }

    pub async fn handle_client(&self, mut socket: TcpStream) -> Result<()> {
        let mut session = SmtpSession::new();
        let mut buffer = [0; 1024];

        socket
            .write_all(b"220 localhost ESMTP server ready\r\n")
            .await
            .into_diagnostic()?;

        loop {
            let n = socket.read(&mut buffer).await.into_diagnostic()?;
            if n == 0 {
                return Ok(());
            }

            let command = String::from_utf8_lossy(&buffer[..n]).trim().to_string();

            if let SessionState::ReceivingData = session.state {
                session.parse_email_body(&buffer[..n]).await?;
                (self.on_data)(&session.email)?;
                socket.write_all(b"250 OK\r\n").await.into_diagnostic()?;
                session.state = SessionState::Authenticated;
                continue;
            }

            match session.parse_command(&command) {
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

    async fn handle_command(
        &self,
        session: &mut SmtpSession,
        command: SmtpCommand,
        socket: &mut TcpStream,
    ) -> Result<bool> {
        match (&session.state, command) {
            (SessionState::Connected, SmtpCommand::Ehlo(domain)) => {
                (self.on_ehlo)(&domain)?;
                socket
                    .write_all(b"250-localhost\r\n250-AUTH PLAIN LOGIN\r\n250 OK\r\n")
                    .await
                    .into_diagnostic()?;
                session.state = SessionState::Greeted;
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
                (self.on_mail_from)(&from)?;
                session.email.from = from;
                socket.write_all(b"250 OK\r\n").await.into_diagnostic()?;
                session.state = SessionState::ReceivingMailFrom;
            }
            (SessionState::ReceivingMailFrom, SmtpCommand::RcptTo(to)) => {
                (self.on_rcpt_to)(&to)?;
                session.email.to = to;
                socket.write_all(b"250 OK\r\n").await.into_diagnostic()?;
                session.state = SessionState::ReceivingRcptTo;
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
            _ => {
                if !session.can_accept_mail_commands() {
                    socket
                        .write_all(b"530 Authentication required\r\n")
                        .await
                        .into_diagnostic()?;
                } else {
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
        match (self.on_auth)(username, password) {
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
                to: String::new(),
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

    async fn parse_email_body(&mut self, data: &[u8]) -> Result<()> {
        let mut body = String::new();
        let chunk = String::from_utf8_lossy(&data);
        for line in chunk.lines() {
            if line.trim() == "." {
                self.email.body = body;
                self.state = SessionState::Authenticated;
                break;
            }
            body.push_str(&format!("{}\n", line));
        }
        Ok(())
    }

    fn parse_command(&self, input: &str) -> Result<SmtpCommand, SmtpError> {
        let parse_result: IResult<&str, SmtpCommand> = match self.state {
            SessionState::AuthenticatingUsername => {
                map(take_while1(|c: char| c.is_ascii()), |s: &str| {
                    SmtpCommand::AuthUsername(s.to_string())
                })(input)
            }
            SessionState::AuthenticatingPassword(_) => {
                map(take_while1(|c: char| c.is_ascii()), |s: &str| {
                    SmtpCommand::AuthPassword(s.to_string())
                })(input)
            }
            _ => alt((
                map(
                    preceded(tag("EHLO "), take_while1(is_alphanumeric)),
                    |s: &str| SmtpCommand::Ehlo(s.to_string()),
                ),
                map(
                    preceded(tag("AUTH PLAIN "), take_while1(|c: char| c.is_ascii())),
                    |s: &str| SmtpCommand::AuthPlain(s.to_string()),
                ),
                map(tag("AUTH LOGIN"), |_| SmtpCommand::AuthLogin),
                map(
                    preceded(tag("MAIL FROM:"), opt(take_while1(is_alphanumeric))),
                    |_| SmtpCommand::MailFrom(input.trim_start_matches("MAIL FROM:").to_string()),
                ),
                map(
                    preceded(tag("RCPT TO:"), opt(take_while1(is_alphanumeric))),
                    |_| SmtpCommand::RcptTo(input.trim_start_matches("RCPT TO:").to_string()),
                ),
                map(tag("DATA"), |_| SmtpCommand::Data),
                map(tag("QUIT"), |_| SmtpCommand::Quit),
            ))(input),
        };

        match parse_result {
            Ok((_, command)) => Ok(command),
            Err(e) => Err(SmtpError::ParseError {
                message: e.to_string(),
                span: (0, input.len()).into(),
            }),
        }
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

fn is_alphanumeric(c: char) -> bool {
    c.is_alphanumeric() || c == '.' || c == '-'
}
