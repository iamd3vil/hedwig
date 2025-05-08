use async_trait::async_trait;
use base64::prelude::*;
use bytes::BytesMut;
use memchr::memchr;
use miette::{bail, Context, Diagnostic, IntoDiagnostic, Result, SourceSpan};
use std::os::unix::io::AsRawFd; // or windows equivalent
use std::os::unix::io::FromRawFd;
use std::sync::Arc;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use rustls::pki_types::CertificateDer;
use std::path::Path;
use tokio_rustls::rustls::{self, ServerConfig};
use tokio_rustls::{server::TlsStream, TlsAcceptor};

mod parser;
use parser::{parse_command, SmtpCommand};

#[async_trait]
pub trait SmtpStream: AsyncRead + AsyncWrite + Unpin + Send {
    async fn write_line(&mut self, line: &[u8]) -> Result<()> {
        self.write_all(line).await.into_diagnostic()?;
        Ok(())
    }

    async fn upgrade_to_tls(
        &mut self,
        _acceptor: &TlsAcceptor,
    ) -> Result<Option<TlsStream<TcpStream>>> {
        Ok(None)
    }
}

#[async_trait]
impl SmtpStream for TcpStream {
    async fn upgrade_to_tls(
        &mut self,
        acceptor: &TlsAcceptor,
    ) -> Result<Option<TlsStream<TcpStream>>> {
        let fd = self.as_raw_fd();
        let stream = unsafe { TcpStream::from_std(std::net::TcpStream::from_raw_fd(fd)) }
            .into_diagnostic()?;
        let tls_stream = acceptor.accept(stream).await.into_diagnostic()?;
        Ok(Some(tls_stream))
    }
}

#[async_trait]
impl SmtpStream for TlsStream<TcpStream> {}

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

    #[error("Mail rejected: {message}")]
    MailFromDenied { message: String },

    #[error("Authentication error")]
    #[diagnostic(code(smtp::auth_error))]
    AuthError,
}

/// Represents an email message.
#[derive(Debug)]
pub struct Email {
    /// The sender's email address.
    pub from: String,
    /// A list of recipient email addresses.
    pub to: Vec<String>,
    /// The full content of the email, including headers and body.
    pub body: String,
}

#[derive(Debug, PartialEq)]
enum SessionState {
    Connected,
    Greeted,
    AuthenticatingUsername,
    AuthenticatingPassword(String),
    Authenticated,
    ReceivingMailFrom,
    ReceivingRcptTo,
    ReceivingData,
}

/// Trait defining callback methods for SMTP server events.
///
/// Implementations of this trait can be used to customize the behavior of the SMTP server
/// at various stages of the SMTP transaction.
#[async_trait]
pub trait SmtpCallbacks: Send + Sync {
    /// Called when a client sends an EHLO command.
    ///
    /// # Arguments
    /// * `domain` - The domain name provided by the client in the EHLO command.
    async fn on_ehlo(&self, domain: &str) -> Result<(), SmtpError>;

    /// Called when a client attempts to authenticate.
    ///
    /// # Arguments
    /// * `username` - The username provided by the client.
    /// * `password` - The password provided by the client.
    ///
    /// # Returns
    /// `Ok(true)` if authentication is successful, `Ok(false)` or `Err` otherwise.
    async fn on_auth(&self, username: &str, password: &str) -> Result<bool, SmtpError>;

    /// Called when a client sends a MAIL FROM command.
    ///
    /// # Arguments
    /// * `from` - The email address of the sender.
    async fn on_mail_from(&self, from: &str) -> Result<(), SmtpError>;

    /// Called when a client sends an RCPT TO command.
    ///
    /// # Arguments
    /// * `to` - The email address of the recipient.
    async fn on_rcpt_to(&self, to: &str) -> Result<(), SmtpError>;

    /// Called when a client sends the email data.
    ///
    /// # Arguments
    /// * `email` - The `Email` struct containing the parsed email data.
    async fn on_data(&self, email: &Email) -> Result<(), SmtpError>;
}

/// Represents an SMTP server instance.
#[derive(Clone)]
pub struct SmtpServer {
    // Callbacks for handling various SMTP events.
    callbacks: Arc<dyn SmtpCallbacks>,
    // Indicates whether authentication is enabled for this server.
    auth_enabled: bool,

    // TLS acceptor for handling encrypted connections.
    tls_acceptor: Option<TlsAcceptor>,
}

impl SmtpServer {
    /// Creates a new SMTP server instance.
    ///
    /// # Arguments
    ///
    /// * `callbacks` - An implementation of `SmtpCallbacks` to handle SMTP events.
    /// * `auth_enabled` - A boolean indicating whether authentication is required.
    ///
    /// # Returns
    ///
    /// A new `SmtpServer` instance.
    pub fn new<T: SmtpCallbacks + 'static>(callbacks: T, auth_enabled: bool) -> Self {
        SmtpServer {
            callbacks: Arc::new(callbacks),
            auth_enabled,
            tls_acceptor: None,
        }
    }

    pub fn with_tls(
        mut self,
        cert_path: impl AsRef<Path>,
        key_path: impl AsRef<Path>,
    ) -> Result<Self> {
        let cert_file = std::fs::File::open(cert_path)
            .into_diagnostic()
            .wrap_err("Failed to open certificate file")?;
        let key_file = std::fs::File::open(key_path)
            .into_diagnostic()
            .wrap_err("Failed to open private key file")?;

        let certs: Vec<CertificateDer<'static>> =
            rustls_pemfile::certs(&mut std::io::BufReader::new(cert_file))
                .collect::<std::io::Result<Vec<_>>>()
                .into_diagnostic()?;

        let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(key_file))
            .into_diagnostic()?
            .ok_or_else(|| miette::miette!("No private key found"))?;

        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .into_diagnostic()?;

        self.tls_acceptor = Some(TlsAcceptor::from(Arc::new(config)));
        Ok(self)
    }

    /// Handles a client connection.
    ///
    /// This method processes SMTP commands from the client and manages the SMTP session.
    ///
    /// # Arguments
    ///
    /// * `socket` - A `TcpStream` representing the client connection.
    ///
    /// # Returns
    ///
    /// A `Result` indicating success or failure of the client handling process.
    pub async fn handle_client(&self, socket: &mut Box<dyn SmtpStream>) -> Result<()> {
        let mut session = SmtpSession::new();

        socket
            .write_line(b"220 localhost ESMTP server ready\r\n")
            .await?;

        let res = self.handle_connection(&mut session, socket).await;
        if let Err(e) = res {
            match e.downcast::<SmtpError>() {
                Ok(e) => match e {
                    SmtpError::MailFromDenied { message } => {
                        socket
                            .write_line(format!("550 {}", message).as_bytes())
                            .await
                    }
                    _ => socket.write_line(b"500 Internal server error\r\n").await,
                },
                _ => return Ok(()),
            }
        } else {
            // Handle successful connection termination
            socket.write_line(b"221 Bye\r\n").await
        }
    }

    async fn handle_connection(
        &self,
        session: &mut SmtpSession,
        stream: &mut Box<dyn SmtpStream>,
    ) -> Result<()> {
        let mut buf = BytesMut::with_capacity(32768); // 32kb
        let mut data_buffer = BytesMut::new();

        loop {
            let n = stream.read_buf(&mut buf).await.into_diagnostic()?;
            if n == 0 {
                return Ok(());
            }

            if session.state == SessionState::ReceivingData {
                // Accumulate the incoming bytes.
                data_buffer.extend_from_slice(&buf[..]);
                buf.clear();

                let mut termination_found = false;
                for pos in memchr::memchr_iter(b'\r', &data_buffer) {
                    if pos + 5 <= data_buffer.len() && &data_buffer[pos..pos + 5] == b"\r\n.\r\n" {
                        // raw_message holds all data up to the termination sequence.
                        let raw_message = &data_buffer[..pos];
                        // Instead of converting to a string, unstuff directly on the bytes.
                        let unstuffed_bytes = unstuff_dot_lines(raw_message);
                        // If your processing expects a string, convert once at the end.
                        session.email.body = String::from_utf8(unstuffed_bytes).map_err(|_| {
                            SmtpError::ParseError {
                                message: "Invalid UTF-8 in email body".into(),
                                span: (0, data_buffer.len()).into(),
                            }
                        })?;
                        self.callbacks.on_data(&session.email).await?;
                        stream.write_line(b"250 OK\r\n").await?;
                        session.state = SessionState::Authenticated;
                        data_buffer.clear();
                        termination_found = true;
                        break;
                    }
                }
                if termination_found {
                    continue;
                }
                continue;
            }

            // Process normal commands by scanning for CRLF in buf.
            while let Some(cr) = memchr(b'\r', &buf) {
                if cr + 1 < buf.len() && buf[cr + 1] == b'\n' {
                    // Extract the complete line, including CRLF.
                    let line = buf.split_to(cr + 2);
                    // Remove CRLF.
                    let line = &line[..line.len().saturating_sub(2)];
                    let command = std::str::from_utf8(line)
                        .map_err(|err| SmtpError::ParseError {
                            message: format!("Invalid UTF-8 sequence: {}", err),
                            span: (0, line.len()).into(),
                        })?
                        .trim()
                        .to_string();

                    match parse_command(&command, &session.state) {
                        Ok(cmd) => {
                            if self.handle_command(session, cmd, stream).await? {
                                return Ok(());
                            }
                        }
                        Err(e) => {
                            eprintln!("Parse error: {}", e);
                            stream
                                .write_line(b"500 Syntax error, command unrecognized\r\n")
                                .await?;
                        }
                    }
                } else {
                    // If we find a CR that isn’t followed by LF, break and wait for more data.
                    break;
                }
            }
        }
    }

    async fn handle_command(
        &self,
        session: &mut SmtpSession,
        command: SmtpCommand,
        stream: &mut Box<dyn SmtpStream>,
    ) -> Result<bool> {
        match (&session.state, command) {
            (SessionState::Connected, SmtpCommand::Ehlo(domain)) => {
                self.callbacks.on_ehlo(&domain).await?;
                let mut response = String::from("250-localhost\r\n");
                if self.tls_acceptor.is_some() {
                    response.push_str("250-STARTTLS\r\n");
                }
                // Add AUTH support if enabled.
                if self.auth_enabled {
                    response.push_str("250-AUTH PLAIN LOGIN\r\n");
                }
                response.push_str("250 OK\r\n");
                stream.write_line(response.as_bytes()).await?;
                if self.auth_enabled {
                    session.state = SessionState::Greeted;
                } else {
                    session.state = SessionState::Authenticated;
                }
            }
            (SessionState::Greeted, SmtpCommand::AuthPlain(auth_data)) => {
                self.handle_auth_plain(session, auth_data, stream).await?;
            }
            (SessionState::Greeted, SmtpCommand::AuthLogin) => {
                session.state = SessionState::AuthenticatingUsername;
                stream.write_line(b"334 VXNlcm5hbWU6\r\n").await?;
            }
            (SessionState::AuthenticatingUsername, SmtpCommand::AuthUsername(username)) => {
                let decoded_username = decode_base64(&username)?;
                session.state = SessionState::AuthenticatingPassword(decoded_username);
                stream.write_line(b"334 UGFzc3dvcmQ6\r\n").await?;
            }
            (
                SessionState::AuthenticatingPassword(username),
                SmtpCommand::AuthPassword(password),
            ) => {
                self.handle_auth_login(session, username.to_string(), password, stream)
                    .await?;
            }
            (SessionState::Authenticated, SmtpCommand::MailFrom(from)) => {
                self.callbacks.on_mail_from(&from).await?;
                session.email.from = from;
                stream.write_line(b"250 OK\r\n").await?;
                session.state = SessionState::ReceivingMailFrom;
            }
            (SessionState::ReceivingMailFrom, SmtpCommand::RcptTo(to))
            | (SessionState::ReceivingRcptTo, SmtpCommand::RcptTo(to)) => {
                self.callbacks.on_rcpt_to(&to).await?;
                session.email.to.push(to); // Consider changing this to a Vec<String> to support multiple recipients
                stream.write_line(b"250 OK\r\n").await?;
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
                stream.write_line(b"250 OK\r\n").await?;
                session.state = SessionState::ReceivingMailFrom;
            }
            (SessionState::ReceivingRcptTo, SmtpCommand::Data) => {
                stream
                    .write_line(b"354 Start mail input; end with <CRLF>.<CRLF>\r\n")
                    .await?;
                session.state = SessionState::ReceivingData;
            }
            (_, SmtpCommand::StartTls) => {
                if let Some(acceptor) = &self.tls_acceptor {
                    stream.write_line(b"220 Ready to start TLS\r\n").await?;

                    if let Some(tls_stream) = stream.upgrade_to_tls(acceptor).await? {
                        session.state = SessionState::Connected;
                        let mut new_stream = Box::new(tls_stream) as Box<dyn SmtpStream>;
                        // Wrap the recursive call in Box::pin
                        Box::pin(self.handle_connection(session, &mut new_stream)).await?;
                        return Ok(true);
                    } else {
                        stream
                            .write_line(b"454 TLS not available due to temporary reason\r\n")
                            .await?;
                    }
                } else {
                    stream.write_line(b"502 STARTTLS not supported\r\n").await?;
                }
            }
            (_, SmtpCommand::Quit) => {
                stream.write_line(b"221 Bye\r\n").await?;
                return Ok(true);
            }
            (_, SmtpCommand::Rset) => {
                // Reset the session state
                session.reset();
                stream.write_line(b"250 OK\r\n").await?;
            }
            (_, SmtpCommand::Noop) => {
                stream.write_line(b"250 OK\r\n").await?;
            }
            cmd => {
                if !session.can_accept_mail_commands() {
                    stream
                        .write_line(b"530 Authentication required\r\n")
                        .await?;
                } else {
                    eprintln!("Unknown command: {:?}", cmd);
                    stream.write_line(b"500 Unknown command\r\n").await?;
                }
            }
        }
        Ok(false)
    }

    async fn handle_auth_plain(
        &self,
        session: &mut SmtpSession,
        auth_data: String,
        stream: &mut Box<dyn SmtpStream>,
    ) -> Result<()> {
        let decoded = decode_base64(&auth_data)?;
        let parts: Vec<&str> = decoded.split('\0').collect();
        if parts.len() != 3 {
            bail!("Invalid AUTH PLAIN data");
        }
        self.handle_authentication(session, parts[1], parts[2], stream)
            .await
    }

    async fn handle_auth_login(
        &self,
        session: &mut SmtpSession,
        username: String,
        password: String,
        stream: &mut Box<dyn SmtpStream>,
    ) -> Result<()> {
        let decoded_password = decode_base64(&password)?;
        self.handle_authentication(session, &username, &decoded_password, stream)
            .await
    }

    async fn handle_authentication(
        &self,
        session: &mut SmtpSession,
        username: &str,
        password: &str,
        stream: &mut Box<dyn SmtpStream>,
    ) -> Result<()> {
        match self.callbacks.on_auth(username, password).await {
            Ok(true) => {
                session.state = SessionState::Authenticated;
                stream
                    .write_line(b"235 Authentication successful\r\n")
                    .await?;
            }
            Ok(false) | Err(_) => {
                session.state = SessionState::Greeted;
                stream
                    .write_line(b"535 Authentication failed\r\n")
                    .await
                    .wrap_err("Authentication failed")?;
            }
        }
        Ok(())
    }
}

// unstuff_dot_lines removes dot-stuffing from a raw message slice in place without converting to a string.
fn unstuff_dot_lines(input: &[u8]) -> Vec<u8> {
    // Prepare an output buffer with the same capacity as the input.
    let mut output = Vec::with_capacity(input.len());

    let mut offset = 0;
    while offset < input.len() {
        // Find the next CR. We assume lines end with "\r\n"
        if let Some(cr_index) = memchr::memchr(b'\r', &input[offset..]) {
            let line_end = offset + cr_index;
            // If we have a CRLF pair
            if line_end + 1 < input.len() && input[line_end + 1] == b'\n' {
                // Process the line: check if it begins with a dot
                if (line_end > offset) && (input[offset] == b'.') {
                    // Skip the dot: append from offset+1 to line_end
                    output.extend_from_slice(&input[offset + 1..line_end]);
                } else {
                    output.extend_from_slice(&input[offset..line_end]);
                }
                // Append the CRLF separator unmodified.
                output.extend_from_slice(b"\r\n");
                offset = line_end + 2;
            } else {
                // CR is not followed by LF; copy the rest and break.
                output.extend_from_slice(&input[offset..]);
                break;
            }
        } else {
            // No CR found, copy the remaining bytes.
            output.extend_from_slice(&input[offset..]);
            break;
        }
    }
    output
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

    fn reset(&mut self) {
        self.email = Email {
            from: String::new(),
            to: Vec::with_capacity(1),
            body: String::new(),
        };
        // Reset the state, but keep authentication
        if self.state != SessionState::Connected && self.state != SessionState::Greeted {
            self.state = SessionState::Authenticated;
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
