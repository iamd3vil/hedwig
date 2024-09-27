use super::*;

#[derive(Debug, PartialEq)]
pub enum SmtpCommand {
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

pub fn parse_command(input: &str, state: &SessionState) -> Result<SmtpCommand, SmtpError> {
    let parse_result: IResult<&str, SmtpCommand> = match state {
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
                preceded(
                    alt((tag("EHLO "), tag("HELO "), tag("ehlo "), tag("helo "))),
                    take_while1(is_alphanumeric),
                ),
                |domain: &str| SmtpCommand::Ehlo(domain.to_string()),
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

fn is_alphanumeric(c: char) -> bool {
    c.is_alphanumeric() || c == '.' || c == '-'
}
