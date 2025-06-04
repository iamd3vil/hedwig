use async_trait::async_trait;
use base64::prelude::*;
use bytes::{Buf, BytesMut};
use memchr::memchr;
use miette::{bail, Diagnostic, IntoDiagnostic, Result, SourceSpan};
use std::sync::Arc;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use tokio_rustls::{server::TlsStream, TlsAcceptor};

mod parser;
use parser::{parse_command, SmtpCommand};

#[async_trait]
pub trait SmtpStream: AsyncRead + AsyncWrite + Unpin + Send {
    async fn write_line(&mut self, line: &[u8]) -> Result<()> {
        self.write_all(line).await.into_diagnostic()?;
        self.write_all(b"\r\n").await.into_diagnostic()?;
        Ok(())
    }

    async fn upgrade(self: Box<Self>, acceptor: TlsAcceptor) -> Result<Box<dyn SmtpStream>>;
    fn is_encrypted(&self) -> bool;
}

#[async_trait]
impl SmtpStream for TcpStream {
    async fn upgrade(self: Box<Self>, acceptor: TlsAcceptor) -> Result<Box<dyn SmtpStream>> {
        let tls_stream = acceptor.accept(*self).await.into_diagnostic()?;
        Ok(Box::new(tls_stream))
    }

    fn is_encrypted(&self) -> bool {
        false
    }
}

#[async_trait]
impl SmtpStream for TlsStream<TcpStream> {
    async fn upgrade(self: Box<Self>, _acceptor: TlsAcceptor) -> Result<Box<dyn SmtpStream>> {
        bail!(SmtpError::ProtocolError(
            "Cannot STARTTLS on an already encrypted connection".to_string()
        ))
    }

    fn is_encrypted(&self) -> bool {
        true
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

    #[error("Mail rejected: {message}")]
    MailFromDenied { message: String },

    #[error("Mail rejected: {message}")]
    RcptToDenied { message: String },

    #[error("Authentication error")]
    #[diagnostic(code(smtp::auth_error))]
    AuthError,

    #[error("Protocol error: {0}")]
    #[diagnostic(code(smtp::protocol_error))]
    ProtocolError(String),
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
    // TLS acceptor for handling STARTTLS.
    tls_acceptor: Option<TlsAcceptor>,
}

// Added DispatchResult enum definition here
#[derive(Debug)]
enum DispatchResult {
    Ok,
    Quit,
    NeedsTlsUpgrade,
}

impl SmtpServer {
    /// Creates a new SMTP server instance.
    ///
    /// # Arguments
    ///
    /// * `callbacks` - An implementation of `SmtpCallbacks` to handle SMTP events.
    /// * `auth_enabled` - A boolean indicating whether authentication is required.
    /// * `tls_acceptor_for_starttls` - Optional TlsAcceptor for STARTTLS.
    ///
    /// # Returns
    ///
    /// A new `SmtpServer` instance.
    pub fn new<T: SmtpCallbacks + 'static>(
        callbacks: T,
        auth_enabled: bool,
        tls_acceptor_for_starttls: Option<TlsAcceptor>,
    ) -> Self {
        SmtpServer {
            callbacks: Arc::new(callbacks),
            auth_enabled,
            tls_acceptor: tls_acceptor_for_starttls,
        }
    }

    /// Handles a client connection.
    ///
    /// This method processes SMTP commands from the client and manages the SMTP session.
    /// It takes ownership of the initial socket.
    ///
    /// # Arguments
    ///
    /// * `initial_socket` - A `Box<dyn SmtpStream>` representing the client connection.
    ///
    /// # Returns
    ///
    /// A `Result` indicating success or failure of the client handling process.
    pub async fn handle_client(self, initial_socket: Box<dyn SmtpStream>) -> Result<()> {
        let mut current_socket = initial_socket;
        let mut session = SmtpSession::new(current_socket.is_encrypted());

        current_socket
            .write_line(b"220 localhost ESMTP server ready")
            .await?;

        let mut buf = BytesMut::with_capacity(4096); // Buffer for command lines
        let mut data_buffer = BytesMut::new(); // Buffer for DATA content

        loop {
            if session.state == SessionState::ReceivingData {
                let n = current_socket
                    .read_buf(&mut data_buffer)
                    .await
                    .into_diagnostic()?;
                if n == 0 {
                    return Ok(());
                }

                let mut termination_found = false;
                if let Some(pos) = memchr::memmem::find(&data_buffer, b"\r\n.\r\n") {
                    let raw_message_bytes = data_buffer.split_to(pos).freeze();
                    data_buffer.advance(5); // Consume \r\n.\r\n

                    let unstuffed_bytes = unstuff_dot_lines(&raw_message_bytes);
                    session.email.body =
                        String::from_utf8(unstuffed_bytes).map_err(|_| SmtpError::ParseError {
                            message: "Invalid UTF-8 in email body".into(),
                            span: (0, raw_message_bytes.len()).into(),
                        })?;

                    if let Err(_) = self.callbacks.on_data(&session.email).await {
                        // Handle specific SmtpError cases for on_data rejection
                        current_socket.write_line(b"554 Transaction failed").await?;
                        session.reset(); // Reset session for new transaction
                        session.state = if session.auth_required_for_state() || !self.auth_enabled {
                            SessionState::Authenticated
                        } else {
                            SessionState::Greeted
                        };
                    } else {
                        current_socket.write_line(b"250 OK: mail queued").await?;
                    }

                    session.state = if session.auth_required_for_state() || !self.auth_enabled {
                        SessionState::Authenticated
                    } else {
                        SessionState::Greeted
                    };
                    session.email.body.clear();
                    session.email.to.clear(); // From is kept as per some server behaviors for multiple emails in one session

                    termination_found = true;
                }

                if termination_found {
                    if !data_buffer.is_empty() {
                        buf.extend_from_slice(&data_buffer);
                        data_buffer.clear();
                    }
                    continue;
                }
                if data_buffer.len() > 10 * 1024 * 1024 {
                    // 10MB limit
                    current_socket
                        .write_line(
                            b"552 Requested mail action aborted: exceeded storage allocation",
                        )
                        .await?;
                    session.state = SessionState::Authenticated; // Or Greeted
                    data_buffer.clear();
                    // Potentially close connection or wait for RSET/QUIT
                }
            } else {
                if buf.capacity() == 0 {
                    buf.reserve(1024);
                }
                let n = current_socket.read_buf(&mut buf).await.into_diagnostic()?;
                if n == 0 {
                    return Ok(());
                }

                while let Some(cr_pos) = memchr(b'\r', &buf) {
                    if cr_pos + 1 < buf.len() && buf[cr_pos + 1] == b'\n' {
                        let line_bytes = buf.split_to(cr_pos + 2).freeze();
                        let command_str = std::str::from_utf8(&line_bytes[..line_bytes.len() - 2])
                            .map_err(|err| SmtpError::ParseError {
                                message: format!("Invalid UTF-8 sequence: {}", err),
                                span: (0, line_bytes.len() - 2).into(),
                            })?
                            .trim();

                        if command_str.is_empty() {
                            continue;
                        }

                        match parse_command(command_str, &session.state) {
                            Ok(cmd) => {
                                match self
                                    .dispatch_command(&mut session, cmd, &mut current_socket)
                                    .await
                                {
                                    Ok(DispatchResult::Ok) => { /* Continue to next command in buffer or read more */
                                    }
                                    Ok(DispatchResult::Quit) => {
                                        return Ok(());
                                    }
                                    Ok(DispatchResult::NeedsTlsUpgrade) => {
                                        if let Some(ref acceptor) = self.tls_acceptor {
                                            current_socket
                                                .write_line(b"220 Ready to start TLS")
                                                .await?;
                                            // current_socket is consumed by upgrade and a new socket is returned or an error.
                                            match current_socket.upgrade(acceptor.clone()).await {
                                                Ok(upgraded_socket) => {
                                                    current_socket = upgraded_socket; // Assign the new upgraded socket
                                                    session.reset_for_tls();
                                                    buf.clear();
                                                    data_buffer.clear();
                                                    // Continue loop for client to send EHLO on the new TLS stream
                                                }
                                                Err(upgrade_err) => {
                                                    // upgrade_err is miette::Report
                                                    eprintln!("TLS handshake failure: {}. Closing connection.", upgrade_err);
                                                    // Propagate the error; handle_client's caller in main.rs will log it.
                                                    return Err(upgrade_err);
                                                }
                                            }
                                        } else {
                                            // This case should ideally not be reached if dispatch_command ensures
                                            // tls_acceptor.is_some() before returning NeedsTlsUpgrade.
                                            // If it's reached, it implies a logic error in dispatch_command.
                                            eprintln!("Internal Server Error: STARTTLS requested but no acceptor configured, despite dispatch_command signaling upgrade.");
                                            current_socket
                                                .write_line(
                                                    b"454 TLS not available due to server error",
                                                )
                                                .await?;
                                            bail!("Internal server error: Inconsistent STARTTLS state");
                                        }
                                    }
                                    Err(smtp_err) => {
                                        // dispatch_command should ideally send SMTP error replies.
                                        // This block handles errors that weren't translated to replies OR
                                        // cases where we need to send a generic reply based on SmtpError type.
                                        match smtp_err {
                                            SmtpError::MailFromDenied { message } => {
                                                current_socket
                                                    .write_line(
                                                        format!("550 {}", message).as_bytes(),
                                                    )
                                                    .await?;
                                            }
                                            SmtpError::RcptToDenied { message } => {
                                                current_socket
                                                    .write_line(
                                                        format!("550 {}", message).as_bytes(),
                                                    )
                                                    .await?;
                                            }
                                            SmtpError::AuthError => {
                                                current_socket
                                                    .write_line(
                                                        b"535 Authentication credentials invalid",
                                                    )
                                                    .await?;
                                            }
                                            SmtpError::ProtocolError(msg) => {
                                                current_socket
                                                    .write_line(format!("503 {}", msg).as_bytes())
                                                    .await?;
                                            }
                                            SmtpError::ParseError { .. } => {
                                                // Already handled by parse_command presumably with 500
                                                // but if it gets here, means parse_command failed and didn't result in early exit
                                                current_socket
                                                    .write_line(b"500 Syntax error")
                                                    .await?;
                                            }
                                            SmtpError::IoError(_) => {
                                                // IO errors usually mean connection is dead or unusable.
                                                return Err(smtp_err.into()); // Propagate to close handler
                                            }
                                        }
                                        // After sending error, continue processing other commands unless it was fatal IO
                                    }
                                }
                            }
                            Err(parse_err) => {
                                eprintln!("Parse error: {}", parse_err);
                                current_socket
                                    .write_line(b"500 Syntax error, command unrecognized")
                                    .await?;
                            }
                        }
                    } else {
                        break; // Incomplete command in buffer, read more.
                    }
                }
            }
        }
    }

    async fn dispatch_command(
        &self,
        session: &mut SmtpSession,
        command: SmtpCommand,
        stream: &mut Box<dyn SmtpStream>,
    ) -> Result<DispatchResult, SmtpError> {
        match (&session.state, command) {
            (SessionState::Connected, SmtpCommand::Ehlo(domain)) => {
                self.callbacks.on_ehlo(&domain).await?;
                session.ehlo_domain = Some(domain.clone());
                let mut caps = vec![format!("250-localhost Hello {}", domain)];
                if self.tls_acceptor.is_some() && !session.is_tls {
                    caps.push("250-STARTTLS".to_string());
                }
                if self.auth_enabled {
                    caps.push("250-AUTH PLAIN LOGIN".to_string());
                }
                caps.push("250 OK".to_string());
                stream
                    .write_line(caps.join("\r\n").as_bytes())
                    .await
                    .map_err(|e| {
                        SmtpError::IoError(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!("Stream write error: {}", e),
                        ))
                    })?;

                session.state = if self.auth_enabled {
                    SessionState::Greeted
                } else {
                    SessionState::Authenticated
                };
            }
            (_, SmtpCommand::StartTls) => {
                if session.is_tls {
                    stream
                        .write_line(b"503 Bad sequence of commands (already TLS)")
                        .await
                        .map_err(|e| {
                            SmtpError::IoError(std::io::Error::new(
                                std::io::ErrorKind::Other,
                                format!("Stream write error: {}", e),
                            ))
                        })?;
                    return Ok(DispatchResult::Ok);
                }
                if self.tls_acceptor.is_some() {
                    return Ok(DispatchResult::NeedsTlsUpgrade);
                } else {
                    stream
                        .write_line(b"502 STARTTLS not supported")
                        .await
                        .map_err(|e| {
                            SmtpError::IoError(std::io::Error::new(
                                std::io::ErrorKind::Other,
                                format!("Stream write error: {}", e),
                            ))
                        })?;
                }
            }
            (SessionState::Greeted, SmtpCommand::AuthPlain(auth_data)) => {
                match self.handle_auth_plain(session, auth_data, stream).await {
                    Ok(_) => session.state = SessionState::Authenticated,
                    Err(e) => return Err(e),
                }
            }
            (SessionState::Greeted, SmtpCommand::AuthLogin) => {
                session.state = SessionState::AuthenticatingUsername;
                stream.write_line(b"334 VXNlcm5hbWU6").await.map_err(|e| {
                    SmtpError::IoError(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Stream write error: {}", e),
                    ))
                })?;
            }
            (SessionState::AuthenticatingUsername, SmtpCommand::AuthUsername(username)) => {
                let decoded_username = decode_base64(&username)?;
                session.state = SessionState::AuthenticatingPassword(decoded_username);
                stream.write_line(b"334 UGFzc3dvcmQ6").await.map_err(|e| {
                    SmtpError::IoError(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Stream write error: {}", e),
                    ))
                })?;
            }
            (
                SessionState::AuthenticatingPassword(username),
                SmtpCommand::AuthPassword(password),
            ) => {
                match self
                    .handle_auth_login(session, username.to_string(), password, stream)
                    .await
                {
                    Ok(_) => session.state = SessionState::Authenticated,
                    Err(e) => return Err(e),
                }
            }
            (SessionState::Authenticated, SmtpCommand::MailFrom(from))
            | (SessionState::Greeted, SmtpCommand::MailFrom(from))
                if !self.auth_enabled || session.state == SessionState::Authenticated =>
            {
                self.callbacks.on_mail_from(&from).await?;
                session.email.from = from;
                stream.write_line(b"250 OK").await.map_err(|e| {
                    SmtpError::IoError(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Stream write error: {}", e),
                    ))
                })?;
                session.state = SessionState::ReceivingMailFrom;
            }
            (SessionState::ReceivingMailFrom, SmtpCommand::RcptTo(to))
            | (SessionState::ReceivingRcptTo, SmtpCommand::RcptTo(to)) => {
                self.callbacks.on_rcpt_to(&to).await?;
                session.email.to.push(to);
                stream.write_line(b"250 OK").await.map_err(|e| {
                    SmtpError::IoError(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Stream write error: {}", e),
                    ))
                })?;
                session.state = SessionState::ReceivingRcptTo;
            }
            (SessionState::ReceivingRcptTo, SmtpCommand::MailFrom(from)) => {
                session.reset();
                self.callbacks.on_mail_from(&from).await?;
                session.email.from = from;
                stream.write_line(b"250 OK").await.map_err(|e| {
                    SmtpError::IoError(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Stream write error: {}", e),
                    ))
                })?;
                session.state = SessionState::ReceivingMailFrom;
            }
            (SessionState::ReceivingRcptTo, SmtpCommand::Data) => {
                if session.email.to.is_empty() {
                    stream
                        .write_line(b"503 Bad sequence of commands (RCPT TO required first)")
                        .await
                        .map_err(|e| {
                            SmtpError::IoError(std::io::Error::new(
                                std::io::ErrorKind::Other,
                                format!("Stream write error: {}", e),
                            ))
                        })?;
                } else {
                    stream
                        .write_line(b"354 Start mail input; end with <CRLF>.<CRLF>")
                        .await
                        .map_err(|e| {
                            SmtpError::IoError(std::io::Error::new(
                                std::io::ErrorKind::Other,
                                format!("Stream write error: {}", e),
                            ))
                        })?;
                    session.state = SessionState::ReceivingData;
                }
            }
            (_, SmtpCommand::Quit) => {
                stream.write_line(b"221 Bye").await.map_err(|e| {
                    SmtpError::IoError(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Stream write error: {}", e),
                    ))
                })?;
                return Ok(DispatchResult::Quit);
            }
            (_, SmtpCommand::Rset) => {
                session.reset();
                stream.write_line(b"250 OK").await.map_err(|e| {
                    SmtpError::IoError(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Stream write error: {}", e),
                    ))
                })?;
            }
            (_, SmtpCommand::Noop) => {
                stream.write_line(b"250 OK").await.map_err(|e| {
                    SmtpError::IoError(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Stream write error: {}", e),
                    ))
                })?;
            }
            (state, cmd) => {
                if session.ehlo_domain.is_none() && command_requires_ehlo(&cmd) {
                    stream
                        .write_line(b"503 Bad sequence of commands (EHLO first)")
                        .await
                        .map_err(|e| {
                            SmtpError::IoError(std::io::Error::new(
                                std::io::ErrorKind::Other,
                                format!("Stream write error: {}", e),
                            ))
                        })?;
                } else if !session.can_accept_mail_commands()
                    && command_requires_auth(&cmd, self.auth_enabled)
                {
                    stream
                        .write_line(b"530 Authentication required")
                        .await
                        .map_err(|e| {
                            SmtpError::IoError(std::io::Error::new(
                                std::io::ErrorKind::Other,
                                format!("Stream write error: {}", e),
                            ))
                        })?;
                } else {
                    eprintln!("Unhandled command {:?} in state {:?}", cmd, state);
                    stream
                        .write_line(b"500 Unknown command or bad sequence")
                        .await
                        .map_err(|e| {
                            SmtpError::IoError(std::io::Error::new(
                                std::io::ErrorKind::Other,
                                format!("Stream write error: {}", e),
                            ))
                        })?;
                }
            }
        }
        Ok(DispatchResult::Ok)
    }

    async fn handle_auth_plain(
        &self,
        session: &mut SmtpSession,
        auth_data: String,
        stream: &mut Box<dyn SmtpStream>,
    ) -> Result<(), SmtpError> {
        let decoded = decode_base64(&auth_data)?;
        let parts: Vec<&str> = decoded.split('\0').collect();
        if parts.len() != 3 {
            stream
                .write_line(b"501 Syntax error in parameters or arguments")
                .await
                .map_err(|e| {
                    SmtpError::IoError(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Stream write error: {}", e),
                    ))
                })?;
            return Err(SmtpError::AuthError);
        }
        self.handle_authentication(session, parts[1], parts[2], stream)
            .await
    }

    async fn handle_auth_login(
        &self,
        session: &mut SmtpSession,
        username: String,
        password_b64: String,
        stream: &mut Box<dyn SmtpStream>,
    ) -> Result<(), SmtpError> {
        let decoded_password = decode_base64(&password_b64)?;
        self.handle_authentication(session, &username, &decoded_password, stream)
            .await
    }

    async fn handle_authentication(
        &self,
        _session: &mut SmtpSession,
        username: &str,
        password: &str,
        stream: &mut Box<dyn SmtpStream>,
    ) -> Result<(), SmtpError> {
        match self.callbacks.on_auth(username, password).await {
            Ok(true) => {
                stream
                    .write_line(b"235 Authentication successful")
                    .await
                    .map_err(|e| {
                        SmtpError::IoError(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!("Stream write error: {}", e),
                        ))
                    })?;
                Ok(())
            }
            Ok(false) | Err(_) => {
                stream
                    .write_line(b"535 Authentication failed")
                    .await
                    .map_err(|e| {
                        SmtpError::IoError(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!("Stream write error: {}", e),
                        ))
                    })?;
                Err(SmtpError::AuthError)
            }
        }
    }
}

fn command_requires_ehlo(command: &SmtpCommand) -> bool {
    !matches!(
        command,
        SmtpCommand::Ehlo(_) | SmtpCommand::Quit | SmtpCommand::Noop | SmtpCommand::Rset
    )
}

fn command_requires_auth(command: &SmtpCommand, auth_is_enabled: bool) -> bool {
    if !auth_is_enabled {
        return false;
    }
    matches!(command, SmtpCommand::MailFrom(_) | SmtpCommand::RcptTo(_))
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
                if (line_end > offset)
                    && (input[offset] == b'.')
                    && (offset == 0 || input[offset - 1] == b'\n')
                {
                    // Check for dot at start of line
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
    is_tls: bool,
    ehlo_domain: Option<String>,
}

impl SmtpSession {
    fn new(initial_stream_is_encrypted: bool) -> Self {
        SmtpSession {
            state: SessionState::Connected,
            email: Email {
                from: String::new(),
                to: Vec::with_capacity(1),
                body: String::new(),
            },
            is_tls: initial_stream_is_encrypted,
            ehlo_domain: None,
        }
    }

    fn reset(&mut self) {
        let was_authenticated = self.state == SessionState::Authenticated;

        self.email = Email {
            from: String::new(),
            to: Vec::with_capacity(1),
            body: String::new(),
        };

        if was_authenticated {
            self.state = SessionState::Authenticated;
            // self.ehlo_domain is kept because auth is kept
        } else if self.ehlo_domain.is_some() {
            self.state = SessionState::Greeted;
            // self.ehlo_domain is kept because we are just resetting the transaction
        } else {
            self.state = SessionState::Connected;
            self.ehlo_domain = None; // No EHLO was made or it's a full reset
        }
    }

    fn reset_for_tls(&mut self) {
        self.state = SessionState::Connected;
        self.is_tls = true;
        self.ehlo_domain = None; // Client must send EHLO again
        self.email = Email {
            from: String::new(),
            to: Vec::with_capacity(1),
            body: String::new(),
        };
    }

    fn auth_required_for_state(&self) -> bool {
        matches!(
            self.state,
            SessionState::Authenticated
                | SessionState::AuthenticatingPassword(_)
                | SessionState::AuthenticatingUsername
        )
    }

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
    String::from_utf8(BASE64_STANDARD.decode(input).map_err(|e| {
        eprintln!("Base64 decode error: {}", e); // Log the actual error
        SmtpError::AuthError
    })?)
    .map_err(|e| {
        eprintln!("UTF-8 conversion error after base64 decode: {}", e); // Log the actual error
        SmtpError::AuthError
    })
}
