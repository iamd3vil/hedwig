#![allow(unused_assignments)]

use async_trait::async_trait;
use base64::prelude::*;
use bytes::{Buf, Bytes, BytesMut};
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
    /// The full content of the email, including headers and body. Kept as
    /// raw bytes: message content is opaque to the server and is usually a
    /// zero-copy slice of the receive buffer.
    pub body: Bytes,
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
/// Maximum recipients accepted per message (RFC 5321 requires supporting at
/// least 100; this matches common MTA defaults). Bounding the envelope also
/// bounds every derived delivery-state journal entry in the log queue.
pub const MAX_RECIPIENTS: usize = 1000;
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
        // Reply accumulator, reused for the life of the connection: one
        // write per read iteration without an allocation per command.
        let mut reply = BytesMut::with_capacity(512);
        // Length of data_buffer already searched for the DATA terminator;
        // lets each read scan only the newly received bytes.
        let mut data_scanned: usize = 0;
        // Latched once a message exceeds the size limit, so the shedding
        // that keeps memory bounded cannot make it look small again.
        let mut data_oversized = false;
        // Set when `buf` already holds bytes the client pipelined after an
        // end-of-DATA: they are commands, and blocking on a read before
        // answering them would hang the connection until the idle timeout.
        let mut buffered_commands = false;

        loop {
            let receiving_data = session.state == SessionState::ReceivingData;
            if !buffered_commands {
                let timeout = if receiving_data {
                    self.data_timeout
                } else {
                    self.cmd_timeout
                };
                // During DATA, read straight into the message buffer — no
                // intermediate copy through `buf`.
                let read_target = if receiving_data {
                    &mut data_buffer
                } else {
                    &mut buf
                };
                let n = match tokio::time::timeout(timeout, stream.read_buf(read_target)).await {
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
            }
            buffered_commands = false;

            if receiving_data {
                self.process_data(
                    session,
                    stream,
                    &mut buf,
                    &mut data_buffer,
                    &mut data_scanned,
                    &mut data_oversized,
                )
                .await?;
                buffered_commands = session.state != SessionState::ReceivingData && !buf.is_empty();
                continue;
            }

            // Process every complete command line in buf, batching replies
            // into one write per read (RFC 2920 PIPELINING).
            reply.clear();
            while let Some(cr) = memchr(b'\r', &buf) {
                if cr + 1 >= buf.len() {
                    // Possibly the first half of a CRLF; wait for more data.
                    break;
                }
                if buf[cr + 1] != b'\n' {
                    // A bare CR is illegal in a command line (RFC 5321
                    // 2.3.8), and the byte after it is already here so this
                    // is not a split CRLF. Consume through it and say so:
                    // leaving it in place means every later read re-finds
                    // the same CR and the connection stalls until the idle
                    // timeout, even though the client is waiting on us.
                    let _ = buf.split_to(cr + 1);
                    reply.extend_from_slice(b"500 Syntax error, bare CR not allowed\r\n");
                    continue;
                }
                // Extract the complete line, including CRLF.
                let line = buf.split_to(cr + 2);
                // Remove CRLF.
                let line = &line[..line.len().saturating_sub(2)];
                // Deliberate leniency: surrounding whitespace is trimmed
                // before parsing, so padded commands from sloppy clients
                // (e.g. "STARTTLS \r\n") are accepted.
                let command = match std::str::from_utf8(line) {
                    Ok(s) => s.trim(),
                    Err(err) => {
                        let _ = stream.write_all(&reply).await;
                        return Err(SmtpError::ParseError {
                            message: format!("Invalid UTF-8 sequence: {}", err),
                            span: (0, line.len()).into(),
                        }
                        .into());
                    }
                };

                match parse_command(command, &session.state) {
                    // STARTTLS is handled here rather than in handle_command
                    // because the upgrade must also discard any bytes the
                    // client pipelined after the command (RFC 3207: possible
                    // plaintext injection) — and those live in `buf`.
                    Ok(SmtpCommand::StartTls) => {
                        if !stream.supports_starttls() {
                            reply.extend_from_slice(b"502 STARTTLS not supported\r\n");
                        } else if matches!(
                            session.state,
                            SessionState::ReceivingMailFrom | SessionState::ReceivingRcptTo
                        ) {
                            reply.extend_from_slice(
                                b"503 STARTTLS not allowed during mail transaction\r\n",
                            );
                        } else {
                            // RFC 2920: flush pending replies (plus the 220)
                            // before the handshake bytes take over the wire.
                            reply.extend_from_slice(b"220 Ready to start TLS\r\n");
                            stream.write_all(&reply).await.into_diagnostic()?;
                            reply.clear();
                            buf.clear();
                            data_buffer.clear();
                            data_scanned = 0;
                            data_oversized = false;
                            // Bound the handshake so a client that goes
                            // silent after STARTTLS can't hold the
                            // connection (and its permit) forever.
                            match tokio::time::timeout(self.cmd_timeout, stream.upgrade_to_tls())
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
                        let starttls = stream.supports_starttls();
                        match self
                            .handle_command(session, cmd, starttls, &mut reply)
                            .await
                        {
                            Ok(true) => {
                                stream.write_all(&reply).await.into_diagnostic()?;
                                return Ok(());
                            }
                            Ok(false) => {}
                            Err(e) => {
                                // Deliver replies already owed for earlier
                                // pipelined commands before the error reply.
                                let _ = stream.write_all(&reply).await;
                                return Err(e);
                            }
                        }
                        if session.state == SessionState::ReceivingData {
                            // Remaining buffered bytes are message content,
                            // not commands.
                            break;
                        }
                    }
                    Err(e) => {
                        eprintln!("Parse error: {}", e);
                        reply.extend_from_slice(b"500 Syntax error, command unrecognized\r\n");
                    }
                }
            }
            if !reply.is_empty() {
                stream.write_all(&reply).await.into_diagnostic()?;
            }
            if session.state == SessionState::ReceivingData && !buf.is_empty() {
                // Content the client sent in the same packet as DATA.
                data_buffer.extend_from_slice(&buf);
                buf.clear();
                self.process_data(
                    session,
                    stream,
                    &mut buf,
                    &mut data_buffer,
                    &mut data_scanned,
                    &mut data_oversized,
                )
                .await?;
                buffered_commands = session.state != SessionState::ReceivingData && !buf.is_empty();
            }
        }
    }

    /// Handles bytes accumulated in `data_buffer` during DATA: enforces the
    /// size limit and, once the terminator arrives, unstuffs and delivers
    /// the message.
    async fn process_data(
        &self,
        session: &mut SmtpSession,
        stream: &mut Box<dyn SmtpStream>,
        buf: &mut BytesMut,
        data_buffer: &mut BytesMut,
        data_scanned: &mut usize,
        oversized: &mut bool,
    ) -> Result<()> {
        // Both callers drain `buf` before handing bytes to DATA, so
        // appending leftovers below preserves wire order.
        debug_assert!(buf.is_empty(), "command buffer must be drained during DATA");
        // Once over the limit, stay over it: the shedding below trims the
        // buffer back under `max_message_size`, and without this latch the
        // size check would pass again and the truncated remains would be
        // accepted with a 250.
        *oversized |= data_buffer.len() > self.max_message_size;

        // End of data: `<CRLF>.<CRLF>`, or a lone `.<CRLF>` when the body is
        // empty (RFC 5321 4.1.1.4 — there is no preceding line to end). The
        // empty form is only meaningful while the buffer still starts at the
        // first body byte, which shedding below breaks.
        let end = if !*oversized && data_buffer.starts_with(b".\r\n") {
            Some((0usize, 3usize))
        } else {
            // Only the newly received bytes need to be searched; earlier
            // reads already covered the rest.
            find_data_terminator(data_buffer, *data_scanned)
                .map(|pos| (pos, pos + DATA_TERMINATOR.len()))
        };

        // Enforce message size limit.
        // After rejecting, keep discarding until the DATA terminator
        // (<CRLF>.<CRLF>) so the remaining body bytes aren't
        // misparsed as SMTP commands on this connection.
        if *oversized {
            if let Some((_, consumed)) = end {
                stream.write_line(b"552 5.3.4 Message too big\r\n").await?;
                // Keep whatever followed the terminator: it is the next
                // command group, not part of the rejected message.
                if consumed < data_buffer.len() {
                    buf.extend_from_slice(&data_buffer[consumed..]);
                }
                data_buffer.clear();
                *data_scanned = 0;
                *oversized = false;
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
                *data_scanned = 0;
            } else {
                *data_scanned = data_buffer.len();
            }
            return Ok(());
        }

        match end {
            Some((body_end, consumed)) => {
                // A stuffed dot can only start the message or follow a CRLF;
                // when neither occurs (the overwhelmingly common case) the
                // body is a zero-copy slice of the receive buffer.
                let stuffed = {
                    let raw = &data_buffer[..body_end];
                    raw.starts_with(b".") || memchr::memmem::find(raw, b"\r\n.").is_some()
                };
                session.email.body = if stuffed {
                    let body = Bytes::from(unstuff_dot_lines(&data_buffer[..body_end]));
                    data_buffer.advance(consumed);
                    body
                } else {
                    let body = data_buffer.split_to(body_end).freeze();
                    data_buffer.advance(consumed - body_end);
                    body
                };
                // RFC 2920 allows a command group after the end-of-data dot
                // (Postfix pipelines QUIT there). Those bytes are commands:
                // discarding them leaves the client waiting for a reply that
                // never comes, holding the connection until it times out.
                if !data_buffer.is_empty() {
                    buf.extend_from_slice(data_buffer);
                }
                data_buffer.clear();
                *data_scanned = 0;
                self.callbacks
                    .on_data(std::mem::take(&mut session.email))
                    .await?;
                stream.write_line(b"250 OK\r\n").await?;
                session.state = SessionState::Authenticated;
            }
            None => {
                *data_scanned = data_buffer.len();
            }
        }
        Ok(())
    }

    async fn handle_command(
        &self,
        session: &mut SmtpSession,
        command: SmtpCommand,
        supports_starttls: bool,
        reply: &mut BytesMut,
    ) -> Result<bool> {
        match (&session.state, command) {
            (SessionState::Connected, SmtpCommand::Ehlo(domain)) => {
                self.callbacks.on_ehlo(&domain).await?;
                let mut response = format!("250-{}\r\n", self.hostname);
                response.push_str(&format!("250-SIZE {}\r\n", self.max_message_size));
                // The command loop already handles batched input; advertise
                // it (RFC 2920) so conforming clients stop serializing every
                // round-trip.
                response.push_str("250-PIPELINING\r\n");
                if supports_starttls {
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
                reply.extend_from_slice(response.as_bytes());
                if self.auth_enabled {
                    session.state = SessionState::Greeted;
                } else {
                    session.state = SessionState::Authenticated;
                }
            }
            (SessionState::Greeted, SmtpCommand::AuthPlain(auth_data)) => {
                self.handle_auth_plain(session, auth_data, reply).await?;
            }
            (SessionState::Greeted, SmtpCommand::AuthLogin) => {
                session.state = SessionState::AuthenticatingUsername;
                reply.extend_from_slice(b"334 VXNlcm5hbWU6\r\n");
            }
            (SessionState::Greeted, SmtpCommand::AuthCramMd5) => {
                if !self.callbacks.supports_cram_md5() {
                    reply.extend_from_slice(b"504 Unrecognized authentication type\r\n");
                    return Ok(false);
                }
                let challenge = self.generate_cram_md5_challenge();
                let encoded = BASE64_STANDARD.encode(&challenge);
                session.state = SessionState::AuthenticatingCramMd5(challenge);
                reply.extend_from_slice(format!("334 {}\r\n", encoded).as_bytes());
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
                reply.extend_from_slice(b"501 Authentication cancelled\r\n");
            }
            (
                SessionState::AuthenticatingCramMd5(challenge),
                SmtpCommand::AuthCramMd5Response(response),
            ) => {
                self.handle_auth_cram_md5(session, challenge.clone(), response, reply)
                    .await?;
            }
            (SessionState::AuthenticatingUsername, SmtpCommand::AuthUsername(username)) => {
                match decode_base64(&username) {
                    Ok(decoded_username) => {
                        session.state = SessionState::AuthenticatingPassword(decoded_username);
                        reply.extend_from_slice(b"334 UGFzc3dvcmQ6\r\n");
                    }
                    Err(_) => self.reject_malformed_auth(session, reply),
                }
            }
            (
                SessionState::AuthenticatingPassword(username),
                SmtpCommand::AuthPassword(password),
            ) => {
                self.handle_auth_login(session, username.to_string(), password, reply)
                    .await?;
            }
            (SessionState::Authenticated, SmtpCommand::MailFrom(from_command)) => {
                self.callbacks.on_mail_from(&from_command).await?;
                session.email.from = from_command.address.clone();
                reply.extend_from_slice(b"250 OK\r\n");
                session.state = SessionState::ReceivingMailFrom;
            }
            (SessionState::ReceivingMailFrom, SmtpCommand::RcptTo(to))
            | (SessionState::ReceivingRcptTo, SmtpCommand::RcptTo(to)) => {
                if session.email.to.len() >= MAX_RECIPIENTS {
                    // Transient per RFC 5321 §4.5.3.1.10: the client may
                    // send the remaining recipients in a new transaction.
                    reply.extend_from_slice(b"452 4.5.3 Too many recipients\r\n");
                    session.state = SessionState::ReceivingRcptTo;
                } else {
                    self.callbacks.on_rcpt_to(&to).await?;
                    session.email.to.push(to);
                    reply.extend_from_slice(b"250 OK\r\n");
                    session.state = SessionState::ReceivingRcptTo;
                }
            }
            (SessionState::ReceivingRcptTo, SmtpCommand::MailFrom(from_command)) => {
                // Start a new email transaction
                self.callbacks.on_mail_from(&from_command).await?;
                session.email = Email {
                    from: from_command.address.clone(),
                    to: Vec::with_capacity(1),
                    body: Bytes::new(),
                };
                reply.extend_from_slice(b"250 OK\r\n");
                session.state = SessionState::ReceivingMailFrom;
            }
            (SessionState::ReceivingRcptTo, SmtpCommand::Data) => {
                reply.extend_from_slice(b"354 Start mail input; end with <CRLF>.<CRLF>\r\n");
                session.state = SessionState::ReceivingData;
            }
            (_, SmtpCommand::Quit) => {
                reply.extend_from_slice(b"221 Bye\r\n");
                return Ok(true);
            }
            (_, SmtpCommand::Rset) => {
                // Reset the session state
                session.reset();
                reply.extend_from_slice(b"250 OK\r\n");
            }
            (_, SmtpCommand::Noop) => {
                reply.extend_from_slice(b"250 OK\r\n");
            }
            cmd => {
                if !session.can_accept_mail_commands() {
                    reply.extend_from_slice(b"530 Authentication required\r\n");
                } else {
                    eprintln!("Unknown command: {:?}", cmd);
                    reply.extend_from_slice(b"500 Unknown command\r\n");
                }
            }
        }
        Ok(false)
    }

    /// Rejects a malformed AUTH exchange with 501 and returns the session to
    /// `Greeted`, keeping the connection usable for another attempt instead
    /// of tearing it down.
    fn reject_malformed_auth(&self, session: &mut SmtpSession, reply: &mut BytesMut) {
        session.state = SessionState::Greeted;
        reply.extend_from_slice(b"501 Invalid authentication data\r\n");
    }

    async fn handle_auth_plain(
        &self,
        session: &mut SmtpSession,
        auth_data: String,
        reply: &mut BytesMut,
    ) -> Result<()> {
        let credentials = decode_base64(&auth_data).ok().and_then(|decoded| {
            let parts: Vec<&str> = decoded.split('\0').collect();
            (parts.len() == 3).then(|| (parts[1].to_string(), parts[2].to_string()))
        });
        let Some((username, password)) = credentials else {
            self.reject_malformed_auth(session, reply);
            return Ok(());
        };
        self.handle_authentication(session, &username, &password, reply)
            .await
    }

    async fn handle_auth_login(
        &self,
        session: &mut SmtpSession,
        username: String,
        password: String,
        reply: &mut BytesMut,
    ) -> Result<()> {
        let Ok(decoded_password) = decode_base64(&password) else {
            self.reject_malformed_auth(session, reply);
            return Ok(());
        };
        self.handle_authentication(session, &username, &decoded_password, reply)
            .await
    }

    async fn handle_auth_cram_md5(
        &self,
        session: &mut SmtpSession,
        challenge: String,
        response: String,
        reply: &mut BytesMut,
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
            self.reject_malformed_auth(session, reply);
            return Ok(());
        };
        let result = self
            .callbacks
            .on_auth_cram_md5(&username, &challenge, &digest)
            .await;
        self.finish_authentication(session, result, reply)
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
        reply: &mut BytesMut,
    ) -> Result<()> {
        let result = self.callbacks.on_auth(username, password).await;
        self.finish_authentication(session, result, reply)
    }

    fn finish_authentication(
        &self,
        session: &mut SmtpSession,
        result: Result<bool, SmtpError>,
        reply: &mut BytesMut,
    ) -> Result<()> {
        match result {
            Ok(true) => {
                session.state = SessionState::Authenticated;
                reply.extend_from_slice(b"235 Authentication successful\r\n");
            }
            Ok(false) | Err(_) => {
                session.state = SessionState::Greeted;
                reply.extend_from_slice(b"535 Authentication failed\r\n");
            }
        }
        Ok(())
    }
}

/// Copies one body line into `output`, removing the transparency dot the
/// sender added (RFC 5321 4.5.2). `segment` must start at a line boundary.
fn push_unstuffed_line(output: &mut Vec<u8>, segment: &[u8]) {
    match segment.split_first() {
        Some((b'.', rest)) => output.extend_from_slice(rest),
        _ => output.extend_from_slice(segment),
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
                // CR is not followed by LF; copy the rest and break. It
                // still begins a line, so its stuffing comes off.
                push_unstuffed_line(&mut output, &input[offset..]);
                break;
            }
        } else {
            // The final line: its CRLF was consumed as part of the
            // end-of-data sequence, but it is a line like any other and its
            // transparency dot must come off too.
            push_unstuffed_line(&mut output, &input[offset..]);
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
                body: Bytes::new(),
            },
        }
    }

    fn reset(&mut self) {
        self.email = Email {
            from: String::new(),
            to: Vec::with_capacity(1),
            body: Bytes::new(),
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
    fn test_unstuff_dot_lines_covers_every_line_position() {
        // Nothing to do: returned unchanged.
        assert_eq!(unstuff_dot_lines(b"plain\r\nlines"), b"plain\r\nlines");
        // First, middle and final line, the final one having no CRLF of its
        // own because the end-of-data sequence consumed it.
        assert_eq!(
            unstuff_dot_lines(b".first\r\nmid\r\n..last"),
            b"first\r\nmid\r\n.last"
        );
        // A body that is exactly one stuffed line.
        assert_eq!(unstuff_dot_lines(b".."), b".");
        // Only the leading dot goes; interior dots are content.
        assert_eq!(unstuff_dot_lines(b"..a.b"), b".a.b");
        // Empty input and a lone CRLF are untouched.
        assert_eq!(unstuff_dot_lines(b""), b"");
        assert_eq!(unstuff_dot_lines(b"\r\n"), b"\r\n");
        // A bare CR ends the scan; that trailing segment is still a line.
        assert_eq!(unstuff_dot_lines(b"a\r\n.b\rc"), b"a\r\nb\rc");
    }

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
        String::from_utf8(emails[0].body.to_vec()).expect("body is valid utf8")
    }

    #[tokio::test]
    async fn recipient_count_is_capped_per_message() {
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

        read_reply(&mut reader, "220").await;
        writer.write_all(b"EHLO client.test\r\n").await.unwrap();
        read_reply(&mut reader, "250").await;
        writer
            .write_all(b"MAIL FROM:<a@example.com>\r\n")
            .await
            .unwrap();
        read_reply(&mut reader, "250").await;

        // The first MAX_RECIPIENTS are accepted; the one after gets a 452
        // transient and must NOT abort the session or the transaction.
        for i in 0..MAX_RECIPIENTS {
            writer
                .write_all(format!("RCPT TO:<r{i}@example.org>\r\n").as_bytes())
                .await
                .unwrap();
            read_reply(&mut reader, "250").await;
        }
        writer
            .write_all(b"RCPT TO:<one-too-many@example.org>\r\n")
            .await
            .unwrap();
        read_reply(&mut reader, "452 4.5.3").await;

        // The transaction still completes with the accepted recipients.
        writer.write_all(b"DATA\r\n").await.unwrap();
        read_reply(&mut reader, "354").await;
        writer
            .write_all(b"Subject: capped\r\n\r\nbody\r\n.\r\n")
            .await
            .unwrap();
        read_reply(&mut reader, "250").await;
        writer.write_all(b"QUIT\r\n").await.unwrap();
        drop(writer);
        server_task.await.unwrap().unwrap();

        let emails = callbacks.emails.lock().unwrap();
        assert_eq!(emails.len(), 1);
        assert_eq!(emails[0].to.len(), MAX_RECIPIENTS);
        assert!(!emails[0].to.iter().any(|r| r.contains("one-too-many")));
    }

    /// Drives a session over a duplex stream and returns every byte the
    /// server wrote, given a list of client writes performed after DATA is
    /// acknowledged. Each write goes out as one segment.
    async fn run_pipelined_session(writes: &[&[u8]]) -> (String, Vec<Email>) {
        run_session_with(DEFAULT_MAX_MESSAGE_SIZE, writes).await
    }

    async fn run_session_with(max_message_size: usize, writes: &[&[u8]]) -> (String, Vec<Email>) {
        let callbacks = Arc::new(RecordingCallbacks {
            emails: StdMutex::new(Vec::new()),
        });
        let server = SmtpServer {
            callbacks: callbacks.clone(),
            auth_enabled: false,
            max_message_size,
            cmd_timeout: Duration::from_secs(5),
            data_timeout: Duration::from_secs(5),
            hostname: "test.local".to_string(),
        };
        let (client, server_side) = tokio::io::duplex(65536);
        let mut server_stream: Box<dyn SmtpStream> = Box::new(server_side);
        let server_task =
            tokio::spawn(async move { server.handle_client(&mut server_stream).await });
        let (mut reader, mut writer) = tokio::io::split(client);

        let mut sink = Vec::new();
        let mut chunk = vec![0u8; 4096];
        // Greeting.
        let n = reader.read(&mut chunk).await.unwrap();
        sink.extend_from_slice(&chunk[..n]);
        for w in writes {
            writer.write_all(w).await.unwrap();
            writer.flush().await.unwrap();
            tokio::task::yield_now().await;
        }
        drop(writer);
        // Read until the server closes or stops writing.
        loop {
            match tokio::time::timeout(Duration::from_millis(500), reader.read(&mut chunk)).await {
                Ok(Ok(0)) | Err(_) => break,
                Ok(Ok(n)) => sink.extend_from_slice(&chunk[..n]),
                Ok(Err(_)) => break,
            }
        }
        let _ = tokio::time::timeout(Duration::from_secs(2), server_task).await;
        let emails = callbacks.emails.lock().unwrap().drain(..).collect();
        (String::from_utf8_lossy(&sink).to_string(), emails)
    }

    /// A message over the size limit must be rejected with 552, not
    /// accepted. The shedding path used to trim the buffer below the limit
    /// while discarding the body, so by the time the terminator arrived the
    /// size check passed and the server answered 250 for a body consisting
    /// of the few bytes it happened to keep.
    #[tokio::test]
    async fn test_oversize_message_is_rejected_not_silently_accepted() {
        let big = vec![b'x'; 32 * 1024];
        let mut body = b"Subject: huge\r\n\r\n".to_vec();
        body.extend_from_slice(&big);
        body.extend_from_slice(b"\r\n.\r\n");
        let (replies, emails) = run_session_with(
            1024,
            &[
                b"EHLO client.test\r\n",
                b"MAIL FROM:<a@example.com>\r\nRCPT TO:<b@example.org>\r\nDATA\r\n",
                &body,
                // The session must still be usable afterwards.
                b"MAIL FROM:<c@example.com>\r\nRCPT TO:<d@example.org>\r\nDATA\r\n",
                b"Subject: small\r\n\r\nfits\r\n.\r\nQUIT\r\n",
            ],
        )
        .await;

        assert!(
            replies.contains("552"),
            "oversize message must be refused with 552, got {replies:?}"
        );
        assert_eq!(
            emails.len(),
            1,
            "only the small message may be accepted, got {} -- {replies:?}",
            emails.len()
        );
        assert!(
            emails[0].body.ends_with(b"fits"),
            "the accepted message must be the small one, got {:?}",
            emails[0].body
        );
        assert!(
            replies.contains("221"),
            "session must stay usable: {replies:?}"
        );
    }

    /// RFC 5321 permits an empty message body: the client sends the
    /// end-of-data dot immediately after the 354. There is no preceding CRLF
    /// for the usual <CRLF>.<CRLF> to match, so this used to stall until the
    /// data timeout.
    #[tokio::test]
    async fn test_empty_message_body_is_accepted() {
        let (replies, emails) = run_pipelined_session(&[
            b"EHLO client.test\r\n",
            b"MAIL FROM:<a@example.com>\r\nRCPT TO:<b@example.org>\r\nDATA\r\n",
            b".\r\nQUIT\r\n",
        ])
        .await;

        assert_eq!(emails.len(), 1, "empty body must be accepted: {replies:?}");
        assert!(
            emails[0].body.is_empty(),
            "body must be empty, got {:?}",
            emails[0].body
        );
        assert!(
            replies.contains("221"),
            "session must continue: {replies:?}"
        );
    }

    /// The last body line's CRLF is consumed as part of the end-of-data
    /// sequence, so it used to escape unstuffing: a message whose final line
    /// is "." arrived as "..".
    #[tokio::test]
    async fn test_trailing_stuffed_line_is_unstuffed() {
        let (replies, emails) = run_pipelined_session(&[
            b"EHLO client.test\r\n",
            b"MAIL FROM:<a@example.com>\r\nRCPT TO:<b@example.org>\r\nDATA\r\n",
            // Wire form of a message whose last line is a single ".".
            b"hello\r\n..\r\n.\r\nQUIT\r\n",
        ])
        .await;

        assert_eq!(emails.len(), 1, "message must be accepted: {replies:?}");
        assert_eq!(
            &emails[0].body[..],
            b"hello\r\n.",
            "trailing stuffed dot must be removed, got {:?}",
            emails[0].body
        );
    }

    /// A bare CR is illegal in a command line (RFC 5321 2.3.8). The loop
    /// keyed on CR and treated "not followed by LF" as "wait for more data",
    /// so the same CR was re-found on every read and the connection stalled
    /// until the idle timeout instead of being told it was malformed.
    #[tokio::test]
    async fn test_bare_cr_in_command_does_not_stall() {
        let (replies, _) =
            run_pipelined_session(&[b"EHLO client.test\r\n", b"NOOP\rNOOP\r\n", b"QUIT\r\n"]).await;

        assert!(
            replies.contains("500"),
            "a bare CR must be reported, got {replies:?}"
        );
        assert!(
            replies.contains("221"),
            "the connection must not stall after a bare CR, got {replies:?}"
        );
    }

    /// A client may pipeline a command group after the end-of-DATA dot, and
    /// Postfix does exactly that with QUIT. Those bytes are commands, not
    /// message content: dropping them leaves the client waiting for a reply
    /// that never comes until the idle timeout fires.
    #[tokio::test]
    async fn test_commands_pipelined_after_data_terminator_are_processed() {
        let (replies, emails) = run_pipelined_session(&[
            b"EHLO client.test\r\n",
            b"MAIL FROM:<a@example.com>\r\nRCPT TO:<b@example.org>\r\nDATA\r\n",
            // Body, terminator and QUIT in a single segment.
            b"Subject: pipelined\r\n\r\nbody\r\n.\r\nQUIT\r\n",
        ])
        .await;

        assert_eq!(emails.len(), 1, "message must be accepted: {replies:?}");
        assert!(
            replies.contains("250 OK"),
            "expected 250 for the message, got {replies:?}"
        );
        assert!(
            replies.contains("221"),
            "QUIT pipelined after the terminator must be answered, got {replies:?}"
        );
    }

    /// The same, but the next transaction is pipelined after the dot rather
    /// than QUIT: it must be accepted, not silently dropped.
    #[tokio::test]
    async fn test_transaction_pipelined_after_data_terminator_is_accepted() {
        let (replies, emails) = run_pipelined_session(&[
            b"EHLO client.test\r\n",
            b"MAIL FROM:<a@example.com>\r\nRCPT TO:<b@example.org>\r\nDATA\r\n",
            b"Subject: first\r\n\r\nfirst body\r\n.\r\n              MAIL FROM:<c@example.com>\r\nRCPT TO:<d@example.org>\r\nDATA\r\n",
            b"Subject: second\r\n\r\nsecond body\r\n.\r\nQUIT\r\n",
        ])
        .await;

        assert_eq!(
            emails.len(),
            2,
            "both messages must be accepted, got {} -- {replies:?}",
            emails.len()
        );
        assert!(
            replies.contains("221"),
            "QUIT must be answered: {replies:?}"
        );
    }

    /// PIPELINING must be advertised, since the command loop handles batched
    /// input and clients otherwise serialize every round trip.
    #[tokio::test]
    async fn test_ehlo_advertises_pipelining() {
        let (replies, _) = run_pipelined_session(&[b"EHLO client.test\r\n", b"QUIT\r\n"]).await;
        assert!(
            replies.contains("250-PIPELINING"),
            "EHLO must advertise PIPELINING, got {replies:?}"
        );
    }

    /// Message content is opaque bytes: a body that is not valid UTF-8 must
    /// be accepted and delivered verbatim.
    #[tokio::test]
    async fn test_non_utf8_body_is_accepted_verbatim() {
        let (replies, emails) = run_pipelined_session(&[
            b"EHLO client.test\r\n",
            b"MAIL FROM:<a@example.com>\r\nRCPT TO:<b@example.org>\r\nDATA\r\n",
            b"Subject: binary\r\n\r\nraw \xff\xfe bytes\r\n.\r\nQUIT\r\n",
        ])
        .await;

        assert_eq!(emails.len(), 1, "8-bit body must be accepted: {replies:?}");
        assert!(
            emails[0].body.ends_with(b"raw \xff\xfe bytes"),
            "body must survive verbatim, got {:?}",
            emails[0].body
        );
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
