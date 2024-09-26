use base64::prelude::*;
use miette::{Context, Diagnostic, IntoDiagnostic, Result, SourceSpan};
use nom::{
    branch::alt,
    bytes::complete::{tag, take_while1},
    combinator::{map, opt},
    sequence::preceded,
    IResult,
};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[derive(Debug, Error, Diagnostic)]
enum SmtpError {
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
struct Email {
    from: String,
    to: String,
    body: String,
}

#[derive(Debug, PartialEq)]
enum SmtpCommand {
    Ehlo(String),
    AuthPlain(String),
    AuthLogin,
    AuthUsername(String),
    AuthPassword(String),
    MailFrom(String),
    RcptTo(String),
    Data,
    Quit,
}

#[derive(Debug)]
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

    fn can_accept_mail_commands(&self) -> bool {
        matches!(
            self.state,
            SessionState::Authenticated
                | SessionState::ReceivingMailFrom
                | SessionState::ReceivingRcptTo
        )
    }

    async fn handle_command(
        &mut self,
        command: SmtpCommand,
        socket: &mut tokio::net::TcpStream,
    ) -> Result<bool> {
        match (&self.state, command) {
            (SessionState::Connected, SmtpCommand::Ehlo(domain)) => {
                println!("EHLO from {}", domain);
                socket
                    .write_all(b"250-localhost\r\n250-AUTH PLAIN LOGIN\r\n250 OK\r\n")
                    .await
                    .into_diagnostic()?;
                self.state = SessionState::Greeted;
            }
            (SessionState::Greeted, SmtpCommand::AuthPlain(auth_data)) => {
                self.handle_auth_plain(auth_data, socket).await?;
            }
            (SessionState::Greeted, SmtpCommand::AuthLogin) => {
                self.state = SessionState::AuthenticatingUsername;
                socket
                    .write_all(b"334 VXNlcm5hbWU6\r\n")
                    .await
                    .into_diagnostic()?;
            }
            (SessionState::AuthenticatingUsername, SmtpCommand::AuthUsername(username)) => {
                let decoded_username = decode_base64(&username)?;
                self.state = SessionState::AuthenticatingPassword(decoded_username);
                socket
                    .write_all(b"334 UGFzc3dvcmQ6\r\n")
                    .await
                    .into_diagnostic()?;
            }
            (
                SessionState::AuthenticatingPassword(username),
                SmtpCommand::AuthPassword(password),
            ) => {
                self.handle_auth_login(username.to_string(), password, socket)
                    .await?;
            }
            (SessionState::Authenticated, SmtpCommand::MailFrom(from)) => {
                println!("Mail from: {from}");
                self.email.from = from;
                socket.write_all(b"250 OK\r\n").await.into_diagnostic()?;
                self.state = SessionState::ReceivingMailFrom;
            }
            (SessionState::ReceivingMailFrom, SmtpCommand::RcptTo(to)) => {
                println!("Mail to: {to}");
                self.email.to = to;
                socket.write_all(b"250 OK\r\n").await.into_diagnostic()?;
                self.state = SessionState::ReceivingRcptTo;
            }
            (SessionState::ReceivingRcptTo, SmtpCommand::Data) => {
                socket
                    .write_all(b"354 Start mail input; end with <CRLF>.<CRLF>\r\n")
                    .await
                    .into_diagnostic()?;
                self.state = SessionState::ReceivingData;
            }
            (_, SmtpCommand::Quit) => {
                socket.write_all(b"221 Bye\r\n").await.into_diagnostic()?;
                return Ok(true);
            }
            cmd => {
                if !self.can_accept_mail_commands() {
                    println!("Command not allowed before authentication: {:?}", cmd);
                    socket
                        .write_all(b"530 Authentication required\r\n")
                        .await
                        .into_diagnostic()?;
                } else {
                    println!("Unknown command: {:?}", cmd);
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
        &mut self,
        auth_data: String,
        socket: &mut tokio::net::TcpStream,
    ) -> Result<()> {
        let decoded = decode_base64(&auth_data)?;
        let parts: Vec<&str> = decoded.split('\0').collect();
        if parts.len() != 3 {
            return Err(SmtpError::AuthError).into_diagnostic();
        }
        self.handle_authentication(parts[1], parts[2], socket).await
    }

    async fn handle_auth_login(
        &mut self,
        username: String,
        password: String,
        socket: &mut tokio::net::TcpStream,
    ) -> Result<()> {
        let decoded_password = decode_base64(&password)?;
        self.handle_authentication(&username, &decoded_password, socket)
            .await
    }

    async fn handle_authentication(
        &mut self,
        username: &str,
        password: &str,
        socket: &mut tokio::net::TcpStream,
    ) -> Result<()> {
        match authenticate(username, password) {
            Ok(true) => {
                self.state = SessionState::Authenticated;
                socket
                    .write_all(b"235 Authentication successful\r\n")
                    .await
                    .into_diagnostic()?;
            }
            Ok(false) | Err(_) => {
                self.state = SessionState::Greeted;
                socket
                    .write_all(b"535 Authentication failed\r\n")
                    .await
                    .into_diagnostic()?;
            }
        }
        Ok(())
    }

    async fn parse_email_body(&mut self, data: &[u8]) -> Result<()> {
        let mut body = String::new();
        let chunk = String::from_utf8_lossy(&data);
        for line in chunk.lines() {
            println!("line: {line}");
            if line.trim() == "." {
                self.email.body = body;
                println!("Received email: {:?}", self.email);
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

fn decode_base64(input: &str) -> Result<String, SmtpError> {
    String::from_utf8(
        BASE64_STANDARD
            .decode(input)
            .map_err(|_| SmtpError::AuthError)?,
    )
    .map_err(|_| SmtpError::AuthError)
}

async fn handle_client(mut socket: tokio::net::TcpStream) -> Result<()> {
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
        println!("Read {} bytes", n);

        let command = String::from_utf8_lossy(&buffer[..n]).trim().to_string();

        println!("Session state: {:?}", session.state);

        if let SessionState::ReceivingData = session.state {
            session.parse_email_body(&buffer[..n]).await?;
            socket.write_all(b"250 OK\r\n").await.into_diagnostic()?;
            continue;
        }

        match session.parse_command(&command) {
            Ok(cmd) => {
                if session.handle_command(cmd, &mut socket).await? {
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

fn is_alphanumeric(c: char) -> bool {
    c.is_alphanumeric() || c == '.' || c == '-'
}

fn authenticate(username: &str, password: &str) -> Result<bool, SmtpError> {
    // Here you should implement your actual authentication logic
    // For this example, we'll just check if the username and password are "test"
    Ok(username == "test" && password == "test")
}

#[tokio::main]
async fn main() -> Result<()> {
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
        tokio::spawn(async move {
            if let Err(e) = handle_client(socket).await {
                eprintln!("Error handling client: {:#}", e);
            }
        });
    }
}
