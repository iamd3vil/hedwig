#![allow(unused_assignments)]

use async_trait::async_trait;
use base64::prelude::*;
use bytes::BytesMut;
use memchr::memchr;
use miette::{bail, Context, Diagnostic, IntoDiagnostic, Result, SourceSpan};
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;

use tokio_rustls::{server::TlsStream, TlsAcceptor};

pub mod parser;
use parser::{parse_command, SmtpCommand};

#[async_trait]
pub trait SmtpStream: AsyncRead + AsyncWrite + Unpin + Send {
    async fn write_line(&mut self, line: &[u8]) -> Result<()> {
        self.write_all(line).await.into_diagnostic()?;
        Ok(())
    }

    /// Whether this stream can be upgraded to TLS via STARTTLS.
    fn supports_starttls(&self) -> bool {
        false
    }

    /// Upgrades the stream to TLS in place. Only valid when
    /// `supports_starttls()` returns true.
    async fn upgrade_to_tls(&mut self) -> Result<()> {
        bail!("STARTTLS not supported on this stream")
    }
}

#[async_trait]
impl SmtpStream for TcpStream {}

#[async_trait]
impl SmtpStream for TlsStream<TcpStream> {}

/// A connection that starts out as plain TCP and may be upgraded to TLS
/// mid-session via STARTTLS. Carrying the acceptor with the stream lets each
/// listener decide independently whether to offer STARTTLS.
pub enum MaybeTlsStream {
    Plain(TcpStream, Option<TlsAcceptor>),
    Tls(Box<TlsStream<TcpStream>>),
    /// Transient state while the TLS handshake runs; only observable if the
    /// handshake fails, after which the connection is unusable.
    Upgrading,
}

impl AsyncRead for MaybeTlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(s, _) => Pin::new(s).poll_read(cx, buf),
            MaybeTlsStream::Tls(s) => Pin::new(s).poll_read(cx, buf),
            MaybeTlsStream::Upgrading => Poll::Ready(Err(upgrading_io_error())),
        }
    }
}

impl AsyncWrite for MaybeTlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(s, _) => Pin::new(s).poll_write(cx, buf),
            MaybeTlsStream::Tls(s) => Pin::new(s).poll_write(cx, buf),
            MaybeTlsStream::Upgrading => Poll::Ready(Err(upgrading_io_error())),
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(s, _) => Pin::new(s).poll_flush(cx),
            MaybeTlsStream::Tls(s) => Pin::new(s).poll_flush(cx),
            MaybeTlsStream::Upgrading => Poll::Ready(Err(upgrading_io_error())),
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(s, _) => Pin::new(s).poll_shutdown(cx),
            MaybeTlsStream::Tls(s) => Pin::new(s).poll_shutdown(cx),
            MaybeTlsStream::Upgrading => Poll::Ready(Err(upgrading_io_error())),
        }
    }
}

fn upgrading_io_error() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::NotConnected,
        "connection unusable after failed TLS upgrade",
    )
}

#[async_trait]
impl SmtpStream for MaybeTlsStream {
    fn supports_starttls(&self) -> bool {
        matches!(self, MaybeTlsStream::Plain(_, Some(_)))
    }

    async fn upgrade_to_tls(&mut self) -> Result<()> {
        match std::mem::replace(self, MaybeTlsStream::Upgrading) {
            MaybeTlsStream::Plain(tcp, Some(acceptor)) => {
                let tls_stream = acceptor
                    .accept(tcp)
                    .await
                    .into_diagnostic()
                    .wrap_err("TLS handshake failed during STARTTLS upgrade")?;
                *self = MaybeTlsStream::Tls(Box::new(tls_stream));
                Ok(())
            }
            other => {
                *self = other;
                bail!("STARTTLS not supported on this stream")
            }
        }
    }
}

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

    /// A temporary local failure (storage backpressure, disk reserve
    /// reached). Reported to the client as `452` so it retries later.
    #[error("Transient failure: {message}")]
    #[diagnostic(code(smtp::transient))]
    Transient { message: String },

    #[error("Mail rejected: {message}")]
    MailFromDenied { message: String },

    #[error("Mail rejected: {message}")]
    RcptToDenied { message: String },

    #[error("Authentication error")]
    #[diagnostic(code(smtp::auth_error))]
    AuthError,
}

/// Represents an email message.
#[derive(Debug, Default)]
pub struct Email {
    /// The sender's email address.
    pub from: String,
    /// A list of recipient email addresses.
    pub to: Vec<String>,
    /// The full content of the email, including headers and body.
    pub body: String,
}

#[derive(Debug, PartialEq)]
pub enum SessionState {
    Connected,
    Greeted,
    AuthenticatingUsername,
    AuthenticatingPassword(String),
    /// Waiting for the client's CRAM-MD5 response; holds the issued challenge.
    AuthenticatingCramMd5(String),
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

    /// Whether this implementation supports CRAM-MD5. The mechanism is
    /// advertised in EHLO and accepted only when this returns true, so
    /// implementations overriding `on_auth_cram_md5` must also override
    /// this to return true.
    fn supports_cram_md5(&self) -> bool {
        false
    }

    /// Called when a client responds to a CRAM-MD5 challenge (RFC 2195).
    ///
    /// The implementation must recompute `HMAC-MD5(password, challenge)` for
    /// the user's stored password and compare it against `digest`. The
    /// default implementation rejects every attempt; override it (together
    /// with `supports_cram_md5`) to support CRAM-MD5.
    ///
    /// # Arguments
    /// * `username` - The username from the client's response.
    /// * `challenge` - The exact challenge string previously sent to the client.
    /// * `digest` - The hex-encoded HMAC-MD5 digest from the client's response.
    ///
    /// # Returns
    /// `Ok(true)` if authentication is successful, `Ok(false)` or `Err` otherwise.
    async fn on_auth_cram_md5(
        &self,
        _username: &str,
        _challenge: &str,
        _digest: &str,
    ) -> Result<bool, SmtpError> {
        Ok(false)
    }

    /// Called when a client sends a MAIL FROM command.
    ///
    /// # Arguments
    /// * `from_command` - The MAIL FROM command containing address and ESMTP parameters.
    async fn on_mail_from(&self, from_command: &parser::MailFromCommand) -> Result<(), SmtpError>;

    /// Called when a client sends an RCPT TO command.
    ///
    /// # Arguments
    /// * `to` - The email address of the recipient.
    async fn on_rcpt_to(&self, to: &str) -> Result<(), SmtpError>;

    /// Called when a client sends the email data.
    ///
    /// # Arguments
    /// * `email` - The `Email` struct containing the parsed email data.
    async fn on_data(&self, email: Email) -> Result<(), SmtpError>;
}

/// Default maximum message size: 25 MiB.
const DEFAULT_MAX_MESSAGE_SIZE: usize = 25 * 1024 * 1024;
/// End-of-DATA sequence: a lone dot on its own line.
const DATA_TERMINATOR: &[u8] = b"\r\n.\r\n";

/// Incrementally searches `buffer` for the DATA terminator.
///
/// `scanned` is the buffer length after the previous (unsuccessful) search;
/// the search resumes 4 bytes before it so a terminator split across two
/// reads is still found, while keeping the total work linear in message size
/// instead of rescanning from the start on every read.
fn find_data_terminator(buffer: &[u8], scanned: usize) -> Option<usize> {
    let start = scanned.saturating_sub(DATA_TERMINATOR.len() - 1);
    memchr::memmem::find(&buffer[start..], DATA_TERMINATOR).map(|pos| start + pos)
}
/// Default idle timeout between commands: 5 minutes (RFC 5321).
const DEFAULT_CMD_TIMEOUT: Duration = Duration::from_secs(5 * 60);
/// Default timeout during DATA transfer: 10 minutes.
const DEFAULT_DATA_TIMEOUT: Duration = Duration::from_secs(10 * 60);

/// Represents an SMTP server instance.
#[derive(Clone)]
pub struct SmtpServer {
    // Callbacks for handling various SMTP events.
    callbacks: Arc<dyn SmtpCallbacks>,
    // Indicates whether authentication is enabled for this server.
    auth_enabled: bool,

    // Maximum message size in bytes. Enforced during DATA and advertised via SIZE in EHLO.
    max_message_size: usize,

    // Idle timeout between commands.
    cmd_timeout: Duration,
    // Timeout during DATA transfer reads.
    data_timeout: Duration,

    // Hostname announced in the 220 greeting and the EHLO reply.
    hostname: String,
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
            max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
            cmd_timeout: DEFAULT_CMD_TIMEOUT,
            data_timeout: DEFAULT_DATA_TIMEOUT,
            hostname: String::from("localhost"),
        }
    }

    pub fn with_max_message_size(mut self, size: usize) -> Self {
        self.max_message_size = size;
        self
    }

    pub fn with_cmd_timeout(mut self, timeout: Duration) -> Self {
        self.cmd_timeout = timeout;
        self
    }

    pub fn with_data_timeout(mut self, timeout: Duration) -> Self {
        self.data_timeout = timeout;
        self
    }

    /// Sets the hostname announced in the 220 greeting and the EHLO reply.
    pub fn with_hostname(mut self, hostname: String) -> Self {
        self.hostname = hostname;
        self
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
            .write_line(format!("220 {} ESMTP server ready\r\n", self.hostname).as_bytes())
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
                    SmtpError::RcptToDenied { message } => {
                        socket
                            .write_line(format!("550 {}", message).as_bytes())
                            .await
                    }
                    SmtpError::Transient { message } => {
                        socket
                            .write_line(format!("452 {}\r\n", message).as_bytes())
                            .await
                    }
                    _ => socket.write_line(b"500 Internal server error\r\n").await,
                },
                _ => Ok(()),
            }
        } else {
            // Clean termination: QUIT already answered with 221, and on
            // EOF/timeout the client is gone — nothing more to write.
            Ok(())
        }
    }

    async fn handle_connection(
        &self,
        session: &mut SmtpSession,
        stream: &mut Box<dyn SmtpStream>,
    ) -> Result<()> {
        let mut buf = BytesMut::with_capacity(32768); // 32kb
        let mut data_buffer = BytesMut::new();
        // Length of data_buffer already searched for the DATA terminator;
        // lets each read scan only the newly received bytes.
        let mut data_scanned: usize = 0;

        loop {
            let timeout = if session.state == SessionState::ReceivingData {
                self.data_timeout
            } else {
                self.cmd_timeout
            };
            let n = match tokio::time::timeout(timeout, stream.read_buf(&mut buf)).await {
                Ok(result) => result.into_diagnostic()?,
                Err(_) => {
                    let _ = stream
                        .write_line(b"421 4.4.2 Connection timed out\r\n")
                        .await;
                    return Ok(());
                }
            };
            if n == 0 {
                return Ok(());
            }

            if session.state == SessionState::ReceivingData {
                // Accumulate the incoming bytes.
                data_buffer.extend_from_slice(&buf[..]);
                buf.clear();

                // Only the newly received bytes need to be searched; earlier
                // reads already covered the rest.
                let terminator = find_data_terminator(&data_buffer, data_scanned);

                // Enforce message size limit.
                // After rejecting, keep discarding until the DATA terminator
                // (<CRLF>.<CRLF>) so the remaining body bytes aren't
                // misparsed as SMTP commands on this connection.
                if data_buffer.len() > self.max_message_size {
                    if terminator.is_some() {
                        stream.write_line(b"552 5.3.4 Message too big\r\n").await?;
                        data_buffer.clear();
                        data_scanned = 0;
                        session.state = SessionState::Authenticated;
                    }
                    // Otherwise keep accumulating until terminator arrives,
                    // but shed already-scanned bytes to bound memory usage.
                    // We only need to keep the last 4 bytes for a split terminator.
                    else if data_buffer.len() > self.max_message_size + 4096 {
                        let keep_from = data_buffer.len() - 4;
                        let tail: Vec<u8> = data_buffer[keep_from..].to_vec();
                        data_buffer.clear();
                        data_buffer.extend_from_slice(&tail);
                        data_scanned = 0;
                    } else {
                        data_scanned = data_buffer.len();
                    }
                    continue;
                }

                match terminator {
                    Some(pos) => {
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
                        self.callbacks
                            .on_data(std::mem::take(&mut session.email))
                            .await?;
                        stream.write_line(b"250 OK\r\n").await?;
                        session.state = SessionState::Authenticated;
                        data_buffer.clear();
                        data_scanned = 0;
                    }
                    None => {
                        data_scanned = data_buffer.len();
                    }
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
                    // Deliberate leniency: surrounding whitespace is trimmed
                    // before parsing, so padded commands from sloppy clients
                    // (e.g. "STARTTLS \r\n") are accepted.
                    let command = std::str::from_utf8(line)
                        .map_err(|err| SmtpError::ParseError {
                            message: format!("Invalid UTF-8 sequence: {}", err),
                            span: (0, line.len()).into(),
                        })?
                        .trim()
                        .to_string();

                    match parse_command(&command, &session.state) {
                        // STARTTLS is handled here rather than in handle_command
                        // because the upgrade must also discard any bytes the
                        // client pipelined after the command (RFC 3207: possible
                        // plaintext injection) — and those live in `buf`.
                        Ok(SmtpCommand::StartTls) => {
                            if !stream.supports_starttls() {
                                stream.write_line(b"502 STARTTLS not supported\r\n").await?;
                            } else if matches!(
                                session.state,
                                SessionState::ReceivingMailFrom | SessionState::ReceivingRcptTo
                            ) {
                                stream
                                    .write_line(
                                        b"503 STARTTLS not allowed during mail transaction\r\n",
                                    )
                                    .await?;
                            } else {
                                stream.write_line(b"220 Ready to start TLS\r\n").await?;
                                buf.clear();
                                data_buffer.clear();
                                // Bound the handshake so a client that goes
                                // silent after STARTTLS can't hold the
                                // connection (and its permit) forever.
                                match tokio::time::timeout(
                                    self.cmd_timeout,
                                    stream.upgrade_to_tls(),
                                )
                                .await
                                {
                                    Ok(result) => result?,
                                    // The handshake never completed; the stream
                                    // is unusable, so just drop the connection.
                                    Err(_) => return Ok(()),
                                }
                                // RFC 3207: the session is reset to its initial
                                // state; the client must EHLO again.
                                session.email = Email::default();
                                session.state = SessionState::Connected;
                            }
                        }
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
                let mut response = format!("250-{}\r\n", self.hostname);
                response.push_str(&format!("250-SIZE {}\r\n", self.max_message_size));
                if stream.supports_starttls() {
                    response.push_str("250-STARTTLS\r\n");
                }
                // Add AUTH support if enabled.
                if self.auth_enabled {
                    if self.callbacks.supports_cram_md5() {
                        response.push_str("250-AUTH PLAIN LOGIN CRAM-MD5\r\n");
                    } else {
                        response.push_str("250-AUTH PLAIN LOGIN\r\n");
                    }
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
            (SessionState::Greeted, SmtpCommand::AuthCramMd5) => {
                if !self.callbacks.supports_cram_md5() {
                    stream
                        .write_line(b"504 Unrecognized authentication type\r\n")
                        .await?;
                    return Ok(false);
                }
                let challenge = self.generate_cram_md5_challenge();
                let encoded = BASE64_STANDARD.encode(&challenge);
                session.state = SessionState::AuthenticatingCramMd5(challenge);
                stream
                    .write_line(format!("334 {}\r\n", encoded).as_bytes())
                    .await?;
            }
            // RFC 4954 §4: a client may cancel an in-progress AUTH exchange
            // by sending "*"; the server must answer 501 and keep the
            // session usable.
            (
                SessionState::AuthenticatingUsername
                | SessionState::AuthenticatingPassword(_)
                | SessionState::AuthenticatingCramMd5(_),
                SmtpCommand::AuthUsername(ref line)
                | SmtpCommand::AuthPassword(ref line)
                | SmtpCommand::AuthCramMd5Response(ref line),
            ) if line == "*" => {
                session.state = SessionState::Greeted;
                stream
                    .write_line(b"501 Authentication cancelled\r\n")
                    .await?;
            }
            (
                SessionState::AuthenticatingCramMd5(challenge),
                SmtpCommand::AuthCramMd5Response(response),
            ) => {
                self.handle_auth_cram_md5(session, challenge.clone(), response, stream)
                    .await?;
            }
            (SessionState::AuthenticatingUsername, SmtpCommand::AuthUsername(username)) => {
                match decode_base64(&username) {
                    Ok(decoded_username) => {
                        session.state = SessionState::AuthenticatingPassword(decoded_username);
                        stream.write_line(b"334 UGFzc3dvcmQ6\r\n").await?;
                    }
                    Err(_) => self.reject_malformed_auth(session, stream).await?,
                }
            }
            (
                SessionState::AuthenticatingPassword(username),
                SmtpCommand::AuthPassword(password),
            ) => {
                self.handle_auth_login(session, username.to_string(), password, stream)
                    .await?;
            }
            (SessionState::Authenticated, SmtpCommand::MailFrom(from_command)) => {
                self.callbacks.on_mail_from(&from_command).await?;
                session.email.from = from_command.address.clone();
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
            (SessionState::ReceivingRcptTo, SmtpCommand::MailFrom(from_command)) => {
                // Start a new email transaction
                self.callbacks.on_mail_from(&from_command).await?;
                session.email = Email {
                    from: from_command.address.clone(),
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

    /// Rejects a malformed AUTH exchange with 501 and returns the session to
    /// `Greeted`, keeping the connection usable for another attempt instead
    /// of tearing it down.
    async fn reject_malformed_auth(
        &self,
        session: &mut SmtpSession,
        stream: &mut Box<dyn SmtpStream>,
    ) -> Result<()> {
        session.state = SessionState::Greeted;
        stream
            .write_line(b"501 Invalid authentication data\r\n")
            .await?;
        Ok(())
    }

    async fn handle_auth_plain(
        &self,
        session: &mut SmtpSession,
        auth_data: String,
        stream: &mut Box<dyn SmtpStream>,
    ) -> Result<()> {
        let credentials = decode_base64(&auth_data).ok().and_then(|decoded| {
            let parts: Vec<&str> = decoded.split('\0').collect();
            (parts.len() == 3).then(|| (parts[1].to_string(), parts[2].to_string()))
        });
        let Some((username, password)) = credentials else {
            return self.reject_malformed_auth(session, stream).await;
        };
        self.handle_authentication(session, &username, &password, stream)
            .await
    }

    async fn handle_auth_login(
        &self,
        session: &mut SmtpSession,
        username: String,
        password: String,
        stream: &mut Box<dyn SmtpStream>,
    ) -> Result<()> {
        let Ok(decoded_password) = decode_base64(&password) else {
            return self.reject_malformed_auth(session, stream).await;
        };
        self.handle_authentication(session, &username, &decoded_password, stream)
            .await
    }

    async fn handle_auth_cram_md5(
        &self,
        session: &mut SmtpSession,
        challenge: String,
        response: String,
        stream: &mut Box<dyn SmtpStream>,
    ) -> Result<()> {
        // RFC 2195: the response is "<username> <hex digest>". The digest
        // never contains spaces, so split on the last one to tolerate
        // usernames that do.
        let credentials = decode_base64(&response).ok().and_then(|decoded| {
            decoded
                .rsplit_once(' ')
                .map(|(u, d)| (u.to_string(), d.to_string()))
        });
        let Some((username, digest)) = credentials else {
            return self.reject_malformed_auth(session, stream).await;
        };
        let result = self
            .callbacks
            .on_auth_cram_md5(&username, &challenge, &digest)
            .await;
        self.finish_authentication(session, result, stream).await
    }

    /// Generates a unique RFC 2195 challenge (`<counter.nanos@hostname>`).
    /// Uniqueness per session is what prevents replaying a captured digest;
    /// the counter plus wall-clock nanoseconds guarantees it without a
    /// dependency on a randomness crate.
    fn generate_cram_md5_challenge(&self) -> String {
        static CHALLENGE_COUNTER: std::sync::atomic::AtomicU64 =
            std::sync::atomic::AtomicU64::new(0);
        let seq = CHALLENGE_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        format!("<{}.{}@{}>", seq, nanos, self.hostname)
    }

    async fn handle_authentication(
        &self,
        session: &mut SmtpSession,
        username: &str,
        password: &str,
        stream: &mut Box<dyn SmtpStream>,
    ) -> Result<()> {
        let result = self.callbacks.on_auth(username, password).await;
        self.finish_authentication(session, result, stream).await
    }

    async fn finish_authentication(
        &self,
        session: &mut SmtpSession,
        result: Result<bool, SmtpError>,
        stream: &mut Box<dyn SmtpStream>,
    ) -> Result<()> {
        match result {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn test_find_data_terminator_in_one_chunk() {
        let buf = b"hello world\r\n.\r\n";
        assert_eq!(find_data_terminator(buf, 0), Some(11));
    }

    #[test]
    fn test_find_data_terminator_absent() {
        let buf = b"hello world\r\n..\r\n";
        assert_eq!(find_data_terminator(buf, 0), None);
    }

    #[test]
    fn test_find_data_terminator_split_across_reads() {
        // Terminator arrives split at every possible boundary; the overlap
        // window must still find it once the second half lands.
        let full = b"body text\r\n.\r\n";
        let term_start = 9;
        for split in term_start + 1..full.len() {
            // First read: no terminator yet.
            assert_eq!(
                find_data_terminator(&full[..split], 0),
                None,
                "false positive at split {split}"
            );
            // Second read appends the rest; scan resumes from the old length.
            assert_eq!(
                find_data_terminator(full, split),
                Some(term_start),
                "missed terminator at split {split}"
            );
        }
    }

    #[test]
    fn test_find_data_terminator_matches_full_rescan_on_random_chunkings() {
        // Differential test: across random buffers dense in terminator
        // fragments and random read chunkings, the incremental scan must
        // agree with a from-scratch scan of the whole buffer at every step.
        let mut seed: u64 = 0x5EED_CAFE;
        let mut next = move || {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (seed >> 33) as usize
        };
        // Heavily weighted toward terminator bytes to hit split/overlap cases.
        let alphabet: &[u8] = b"\r\n.\r\n.a";
        for case in 0..5000 {
            let len = next() % 200 + 1;
            let data: Vec<u8> = (0..len)
                .map(|_| alphabet[next() % alphabet.len()])
                .collect();

            let mut buffer: Vec<u8> = Vec::new();
            let mut scanned = 0usize;
            let mut offset = 0usize;
            while offset < data.len() {
                let end = (offset + next() % 7 + 1).min(data.len());
                buffer.extend_from_slice(&data[offset..end]);
                offset = end;

                let incremental = find_data_terminator(&buffer, scanned);
                let full_rescan = memchr::memmem::find(&buffer, DATA_TERMINATOR);
                assert_eq!(
                    incremental, full_rescan,
                    "case {case}: divergence on buffer {buffer:?} (scanned={scanned})"
                );
                match incremental {
                    // The session consumes the message and resets state here;
                    // stop this case at the first find like the real loop.
                    Some(_) => break,
                    None => scanned = buffer.len(),
                }
            }
        }
    }

    #[test]
    fn test_find_data_terminator_skips_already_scanned_region() {
        // A terminator fully inside the already-scanned region (minus the
        // 4-byte overlap) is not refound; callers reset state after acting
        // on a find, so this situation only occurs for stale offsets.
        let buf = b"x\r\n.\r\nyyyyyyyyyy";
        assert_eq!(find_data_terminator(buf, 10), None);
    }

    struct RecordingCallbacks {
        emails: StdMutex<Vec<Email>>,
    }

    #[async_trait]
    impl SmtpCallbacks for RecordingCallbacks {
        async fn on_ehlo(&self, _domain: &str) -> Result<(), SmtpError> {
            Ok(())
        }
        async fn on_auth(&self, _username: &str, _password: &str) -> Result<bool, SmtpError> {
            Ok(true)
        }
        async fn on_mail_from(
            &self,
            _from_command: &parser::MailFromCommand,
        ) -> Result<(), SmtpError> {
            Ok(())
        }
        async fn on_rcpt_to(&self, _to: &str) -> Result<(), SmtpError> {
            Ok(())
        }
        async fn on_data(&self, email: Email) -> Result<(), SmtpError> {
            self.emails.lock().unwrap().push(email);
            Ok(())
        }
    }

    #[async_trait]
    impl SmtpStream for tokio::io::DuplexStream {}

    /// Drives a full session over an in-memory duplex stream, sending the
    /// DATA body in `chunk_size`-byte writes, and returns the received body.
    async fn run_chunked_data_session(body: &str, chunk_size: usize) -> String {
        let callbacks = Arc::new(RecordingCallbacks {
            emails: StdMutex::new(Vec::new()),
        });
        let server = SmtpServer {
            callbacks: callbacks.clone(),
            auth_enabled: false,
            max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
            cmd_timeout: Duration::from_secs(5),
            data_timeout: Duration::from_secs(5),
            hostname: "test.local".to_string(),
        };

        let (client, server_side) = tokio::io::duplex(4096);
        let mut server_stream: Box<dyn SmtpStream> = Box::new(server_side);
        let server_task =
            tokio::spawn(async move { server.handle_client(&mut server_stream).await });

        let (mut reader, mut writer) = tokio::io::split(client);

        async fn read_reply<R: tokio::io::AsyncRead + Unpin>(
            reader: &mut R,
            expected: &str,
        ) -> String {
            let mut buf = vec![0u8; 512];
            let n = reader.read(&mut buf).await.unwrap();
            let reply = String::from_utf8_lossy(&buf[..n]).to_string();
            assert!(
                reply.contains(expected),
                "expected {expected:?}, got {reply:?}"
            );
            reply
        }

        // Greeting + handshake up to DATA.
        read_reply(&mut reader, "220").await;
        writer.write_all(b"EHLO client.test\r\n").await.unwrap();
        read_reply(&mut reader, "250").await;
        writer
            .write_all(b"MAIL FROM:<a@example.com>\r\n")
            .await
            .unwrap();
        read_reply(&mut reader, "250").await;
        writer
            .write_all(b"RCPT TO:<b@example.org>\r\n")
            .await
            .unwrap();
        read_reply(&mut reader, "250").await;
        writer.write_all(b"DATA\r\n").await.unwrap();
        read_reply(&mut reader, "354").await;

        // Body plus terminator, in small chunks with explicit flushes so the
        // server sees many partial reads (including one that splits the
        // terminator itself).
        let mut wire = body.as_bytes().to_vec();
        wire.extend_from_slice(DATA_TERMINATOR);
        for chunk in wire.chunks(chunk_size) {
            writer.write_all(chunk).await.unwrap();
            writer.flush().await.unwrap();
            tokio::task::yield_now().await;
        }
        read_reply(&mut reader, "250").await;

        writer.write_all(b"QUIT\r\n").await.unwrap();
        drop(writer);
        server_task.await.unwrap().unwrap();

        let emails = callbacks.emails.lock().unwrap();
        assert_eq!(emails.len(), 1);
        emails[0].body.clone()
    }

    #[tokio::test]
    async fn test_data_body_received_in_tiny_chunks() {
        let body = "Subject: chunked\r\n\r\nline one\r\nline two with a . dot\r\n";
        // 3-byte chunks guarantee the CRLF.CRLF terminator is split across
        // multiple reads.
        let received = run_chunked_data_session(body, 3).await;
        assert_eq!(received, body);
    }

    #[tokio::test]
    async fn test_data_dot_stuffed_lines_are_unstuffed() {
        let sent = "Subject: dots\r\n\r\n..leading dot line\r\nmiddle\r\n";
        let expected = "Subject: dots\r\n\r\n.leading dot line\r\nmiddle\r\n";
        let received = run_chunked_data_session(sent, 7).await;
        assert_eq!(received, expected);
    }

    /// Accepts CRAM-MD5 attempts whose digest equals `accept_digest`, and
    /// records every attempt so the test can assert what reached the callback.
    struct CramCallbacks {
        attempts: StdMutex<Vec<(String, String, String)>>,
        accept_digest: String,
    }

    #[async_trait]
    impl SmtpCallbacks for CramCallbacks {
        async fn on_ehlo(&self, _domain: &str) -> Result<(), SmtpError> {
            Ok(())
        }
        async fn on_auth(&self, _username: &str, _password: &str) -> Result<bool, SmtpError> {
            Ok(false)
        }
        fn supports_cram_md5(&self) -> bool {
            true
        }
        async fn on_auth_cram_md5(
            &self,
            username: &str,
            challenge: &str,
            digest: &str,
        ) -> Result<bool, SmtpError> {
            self.attempts.lock().unwrap().push((
                username.to_string(),
                challenge.to_string(),
                digest.to_string(),
            ));
            Ok(digest == self.accept_digest)
        }
        async fn on_mail_from(
            &self,
            _from_command: &parser::MailFromCommand,
        ) -> Result<(), SmtpError> {
            Ok(())
        }
        async fn on_rcpt_to(&self, _to: &str) -> Result<(), SmtpError> {
            Ok(())
        }
        async fn on_data(&self, _email: Email) -> Result<(), SmtpError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_auth_cram_md5_flow() {
        let good_digest = "64b2a43c1f6ed6806a980914e23e75f0";
        let callbacks = Arc::new(CramCallbacks {
            attempts: StdMutex::new(Vec::new()),
            accept_digest: good_digest.to_string(),
        });
        let server = SmtpServer {
            callbacks: callbacks.clone(),
            auth_enabled: true,
            max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
            cmd_timeout: Duration::from_secs(5),
            data_timeout: Duration::from_secs(5),
            hostname: "test.local".to_string(),
        };

        let (client, server_side) = tokio::io::duplex(4096);
        let mut server_stream: Box<dyn SmtpStream> = Box::new(server_side);
        let server_task =
            tokio::spawn(async move { server.handle_client(&mut server_stream).await });

        let (mut reader, mut writer) = tokio::io::split(client);

        async fn read_reply<R: tokio::io::AsyncRead + Unpin>(
            reader: &mut R,
            expected: &str,
        ) -> String {
            let mut buf = vec![0u8; 512];
            let n = reader.read(&mut buf).await.unwrap();
            let reply = String::from_utf8_lossy(&buf[..n]).to_string();
            assert!(
                reply.contains(expected),
                "expected {expected:?}, got {reply:?}"
            );
            reply
        }

        /// Requests a CRAM-MD5 challenge and returns it decoded.
        async fn request_challenge<R: tokio::io::AsyncRead + Unpin, W: AsyncWrite + Unpin>(
            reader: &mut R,
            writer: &mut W,
        ) -> String {
            writer.write_all(b"AUTH CRAM-MD5\r\n").await.unwrap();
            let mut buf = vec![0u8; 512];
            let n = reader.read(&mut buf).await.unwrap();
            let reply = String::from_utf8_lossy(&buf[..n]).to_string();
            let encoded = reply
                .strip_prefix("334 ")
                .unwrap_or_else(|| panic!("expected 334 challenge, got {reply:?}"))
                .trim();
            String::from_utf8(BASE64_STANDARD.decode(encoded).unwrap()).unwrap()
        }

        read_reply(&mut reader, "220").await;
        writer.write_all(b"EHLO client.test\r\n").await.unwrap();
        read_reply(&mut reader, "250-AUTH PLAIN LOGIN CRAM-MD5").await;

        // A wrong digest is rejected and the session returns to Greeted.
        let challenge1 = request_challenge(&mut reader, &mut writer).await;
        assert!(
            challenge1.starts_with('<') && challenge1.ends_with("@test.local>"),
            "malformed challenge: {challenge1:?}"
        );
        let bad = BASE64_STANDARD.encode(format!("alice {}", "0".repeat(32)));
        writer
            .write_all(format!("{}\r\n", bad).as_bytes())
            .await
            .unwrap();
        read_reply(&mut reader, "535").await;

        // Cancelling the exchange with "*" (RFC 4954) gets a 501 and keeps
        // the session usable.
        let _ = request_challenge(&mut reader, &mut writer).await;
        writer.write_all(b"*\r\n").await.unwrap();
        read_reply(&mut reader, "501").await;

        // Malformed responses — invalid base64, and valid base64 missing the
        // "username digest" separator — also get 501 without dropping the
        // connection.
        let _ = request_challenge(&mut reader, &mut writer).await;
        writer.write_all(b"!!!not-base64!!!\r\n").await.unwrap();
        read_reply(&mut reader, "501").await;
        let _ = request_challenge(&mut reader, &mut writer).await;
        let no_separator = BASE64_STANDARD.encode("nospace");
        writer
            .write_all(format!("{}\r\n", no_separator).as_bytes())
            .await
            .unwrap();
        read_reply(&mut reader, "501").await;

        // Cancelling AUTH LOGIN mid-exchange behaves the same way.
        writer.write_all(b"AUTH LOGIN\r\n").await.unwrap();
        read_reply(&mut reader, "334").await;
        writer.write_all(b"*\r\n").await.unwrap();
        read_reply(&mut reader, "501").await;

        // A second attempt gets a fresh challenge; the right digest succeeds.
        let challenge2 = request_challenge(&mut reader, &mut writer).await;
        assert_ne!(challenge1, challenge2, "challenges must be unique");
        let good = BASE64_STANDARD.encode(format!("alice {}", good_digest));
        writer
            .write_all(format!("{}\r\n", good).as_bytes())
            .await
            .unwrap();
        read_reply(&mut reader, "235").await;

        // The session is authenticated: mail commands are accepted.
        writer
            .write_all(b"MAIL FROM:<a@example.com>\r\n")
            .await
            .unwrap();
        read_reply(&mut reader, "250").await;

        writer.write_all(b"QUIT\r\n").await.unwrap();
        read_reply(&mut reader, "221").await;
        drop(writer);
        server_task.await.unwrap().unwrap();

        // The callback saw exactly the username, wire challenges, and digests.
        let attempts = callbacks.attempts.lock().unwrap();
        assert_eq!(attempts.len(), 2);
        assert_eq!(attempts[0].0, "alice");
        assert_eq!(attempts[0].1, challenge1);
        assert_eq!(attempts[0].2, "0".repeat(32));
        assert_eq!(
            attempts[1],
            ("alice".to_string(), challenge2, good_digest.to_string())
        );
    }

    #[tokio::test]
    async fn test_auth_cram_md5_not_advertised_without_callback_support() {
        // RecordingCallbacks keeps the default supports_cram_md5() == false.
        let callbacks = Arc::new(RecordingCallbacks {
            emails: StdMutex::new(Vec::new()),
        });
        let server = SmtpServer {
            callbacks,
            auth_enabled: true,
            max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
            cmd_timeout: Duration::from_secs(5),
            data_timeout: Duration::from_secs(5),
            hostname: "test.local".to_string(),
        };

        let (client, server_side) = tokio::io::duplex(4096);
        let mut server_stream: Box<dyn SmtpStream> = Box::new(server_side);
        let server_task =
            tokio::spawn(async move { server.handle_client(&mut server_stream).await });

        let (mut reader, mut writer) = tokio::io::split(client);
        let mut buf = vec![0u8; 512];

        let n = reader.read(&mut buf).await.unwrap();
        assert!(String::from_utf8_lossy(&buf[..n]).contains("220"));

        writer.write_all(b"EHLO client.test\r\n").await.unwrap();
        let n = reader.read(&mut buf).await.unwrap();
        let ehlo_reply = String::from_utf8_lossy(&buf[..n]).to_string();
        assert!(ehlo_reply.contains("250-AUTH PLAIN LOGIN\r\n"));
        assert!(!ehlo_reply.contains("CRAM-MD5"));

        // Trying it anyway is rejected without breaking the session.
        writer.write_all(b"AUTH CRAM-MD5\r\n").await.unwrap();
        let n = reader.read(&mut buf).await.unwrap();
        assert!(String::from_utf8_lossy(&buf[..n]).contains("504"));

        // Malformed AUTH PLAIN data gets a 501, and the session stays usable:
        // a well-formed attempt afterwards succeeds (RecordingCallbacks
        // accepts all credentials).
        writer
            .write_all(b"AUTH PLAIN !!!not-base64!!!\r\n")
            .await
            .unwrap();
        let n = reader.read(&mut buf).await.unwrap();
        assert!(String::from_utf8_lossy(&buf[..n]).contains("501"));
        let plain = BASE64_STANDARD.encode("\0user\0pass");
        writer
            .write_all(format!("AUTH PLAIN {}\r\n", plain).as_bytes())
            .await
            .unwrap();
        let n = reader.read(&mut buf).await.unwrap();
        assert!(String::from_utf8_lossy(&buf[..n]).contains("235"));

        writer.write_all(b"QUIT\r\n").await.unwrap();
        let n = reader.read(&mut buf).await.unwrap();
        assert!(String::from_utf8_lossy(&buf[..n]).contains("221"));
        drop(writer);
        server_task.await.unwrap().unwrap();
    }
}
