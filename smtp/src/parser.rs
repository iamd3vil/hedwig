use super::*;
use nom::{
    branch::alt,
    bytes::complete::{tag_no_case, take_while1},
    combinator::{map, opt},
    sequence::preceded,
    IResult,
};

/// Represents valid SMTP commands that can be received from a client
#[derive(Debug, PartialEq)]
pub(crate) enum SmtpCommand {
    /// EHLO/HELO command with domain parameter
    Ehlo(String),
    /// AUTH PLAIN command with base64 credentials
    AuthPlain(String),
    /// Initial AUTH LOGIN command
    AuthLogin,
    /// Username input during AUTH LOGIN
    AuthUsername(String),
    /// Password input during AUTH LOGIN
    AuthPassword(String),
    /// MAIL FROM command with email address
    MailFrom(String),
    /// RCPT TO command with email address
    RcptTo(String),
    /// DATA command
    Data,
    /// QUIT command
    Quit,
    /// RSET command
    Rset,
    /// NOOP command
    Noop,
}

/// Parses a raw input string into an SMTP command based on the current session state
pub(crate) fn parse_command(input: &str, state: &SessionState) -> Result<SmtpCommand, SmtpError> {
    let parse_result: IResult<&str, SmtpCommand> = match state {
        SessionState::AuthenticatingUsername => parse_auth_username(input),
        SessionState::AuthenticatingPassword(_) => parse_auth_password(input),
        _ => parse_normal_command(input),
    };

    parse_result
        .map(|(_, cmd)| cmd)
        .map_err(|e| SmtpError::ParseError {
            message: e.to_string(),
            span: (0, input.len()).into(),
        })
}

fn parse_auth_username(input: &str) -> IResult<&str, SmtpCommand> {
    map(take_while1(|c: char| c.is_ascii()), |s: &str| {
        SmtpCommand::AuthUsername(s.to_string())
    })(input)
}

fn parse_auth_password(input: &str) -> IResult<&str, SmtpCommand> {
    map(take_while1(|c: char| c.is_ascii()), |s: &str| {
        SmtpCommand::AuthPassword(s.to_string())
    })(input)
}

fn parse_normal_command(input: &str) -> IResult<&str, SmtpCommand> {
    alt((
        parse_ehlo,
        parse_auth_plain,
        parse_auth_login,
        parse_mail_from,
        parse_rcpt_to,
        parse_simple_command,
    ))(input)
}

fn parse_ehlo(input: &str) -> IResult<&str, SmtpCommand> {
    map(
        preceded(
            alt((tag_no_case("EHLO "), tag_no_case("HELO "))),
            take_while1(is_alphanumeric),
        ),
        |domain: &str| SmtpCommand::Ehlo(domain.to_string()),
    )(input)
}

fn parse_auth_plain(input: &str) -> IResult<&str, SmtpCommand> {
    map(
        preceded(
            tag_no_case("AUTH PLAIN "),
            take_while1(|c: char| c.is_ascii()),
        ),
        |s: &str| SmtpCommand::AuthPlain(s.to_string()),
    )(input)
}

fn parse_auth_login(input: &str) -> IResult<&str, SmtpCommand> {
    map(tag_no_case("AUTH LOGIN"), |_| SmtpCommand::AuthLogin)(input)
}

fn parse_mail_from(input: &str) -> IResult<&str, SmtpCommand> {
    map(
        preceded(tag_no_case("MAIL FROM:"), opt(take_while1(is_alphanumeric))),
        |_| SmtpCommand::MailFrom(input.trim_start_matches("MAIL FROM:").to_string()),
    )(input)
}

fn parse_rcpt_to(input: &str) -> IResult<&str, SmtpCommand> {
    map(
        preceded(tag_no_case("RCPT TO:"), opt(take_while1(is_alphanumeric))),
        |_| SmtpCommand::RcptTo(input.trim_start_matches("RCPT TO:").to_string()),
    )(input)
}

fn parse_simple_command(input: &str) -> IResult<&str, SmtpCommand> {
    alt((
        map(tag_no_case("DATA"), |_| SmtpCommand::Data),
        map(tag_no_case("QUIT"), |_| SmtpCommand::Quit),
        map(tag_no_case("RSET"), |_| SmtpCommand::Rset),
        map(tag_no_case("NOOP"), |_| SmtpCommand::Noop),
    ))(input)
}

/// Checks if a character is valid char.
fn is_alphanumeric(c: char) -> bool {
    c.is_alphanumeric() || c == '.' || c == '-'
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ehlo() {
        assert_eq!(
            parse_command("EHLO example.com", &SessionState::Connected).unwrap(),
            SmtpCommand::Ehlo("example.com".to_string())
        );
        assert_eq!(
            parse_command("ehlo example.com", &SessionState::Connected).unwrap(),
            SmtpCommand::Ehlo("example.com".to_string())
        );

        // Test HELO variant
        assert_eq!(
            parse_command("HELO mail.example.com", &SessionState::Connected).unwrap(),
            SmtpCommand::Ehlo("mail.example.com".to_string())
        );

        // Test with subdomain
        assert_eq!(
            parse_command("EHLO sub.domain.example.com", &SessionState::Connected).unwrap(),
            SmtpCommand::Ehlo("sub.domain.example.com".to_string())
        );
    }

    #[test]
    fn test_auth_commands() {
        // Test AUTH PLAIN
        assert_eq!(
            parse_command("AUTH PLAIN dGVzdAB0ZXN0", &SessionState::Connected).unwrap(),
            SmtpCommand::AuthPlain("dGVzdAB0ZXN0".to_string())
        );

        // Test AUTH LOGIN flow
        assert_eq!(
            parse_command("AUTH LOGIN", &SessionState::Connected).unwrap(),
            SmtpCommand::AuthLogin
        );

        // Test username submission
        assert_eq!(
            parse_command("dXNlcm5hbWU=", &SessionState::AuthenticatingUsername).unwrap(),
            SmtpCommand::AuthUsername("dXNlcm5hbWU=".to_string())
        );

        // Test password submission
        assert_eq!(
            parse_command(
                "cGFzc3dvcmQ=",
                &SessionState::AuthenticatingPassword("user".to_string())
            )
            .unwrap(),
            SmtpCommand::AuthPassword("cGFzc3dvcmQ=".to_string())
        );
    }

    #[test]
    fn test_simple_commands() {
        // Test DATA command
        assert_eq!(
            parse_command("DATA", &SessionState::Connected).unwrap(),
            SmtpCommand::Data
        );

        // Test QUIT command
        assert_eq!(
            parse_command("QUIT", &SessionState::Connected).unwrap(),
            SmtpCommand::Quit
        );

        // Test RSET command
        assert_eq!(
            parse_command("RSET", &SessionState::Connected).unwrap(),
            SmtpCommand::Rset
        );

        // Test NOOP command
        assert_eq!(
            parse_command("NOOP", &SessionState::Connected).unwrap(),
            SmtpCommand::Noop
        );

        // Test case insensitivity
        assert_eq!(
            parse_command("data", &SessionState::Connected).unwrap(),
            SmtpCommand::Data
        );
        assert_eq!(
            parse_command("NoOp", &SessionState::Connected).unwrap(),
            SmtpCommand::Noop
        );
    }

    #[test]
    fn test_invalid_commands() {
        // Test invalid command
        assert!(parse_command("INVALID", &SessionState::Connected).is_err());

        // Test empty command
        assert!(parse_command("", &SessionState::Connected).is_err());

        // Test malformed MAIL FROM
        assert!(parse_command("MAIL FROM", &SessionState::Connected).is_err());

        // Test malformed RCPT TO
        assert!(parse_command("RCPT TO", &SessionState::Connected).is_err());

        // Test malformed AUTH PLAIN
        assert!(parse_command("AUTH PLAIN", &SessionState::Connected).is_err());
    }

    #[test]
    fn test_mail_rcpt_commands() {
        // Test MAIL FROM
        assert_eq!(
            parse_command("MAIL FROM:<user@example.com>", &SessionState::Connected).unwrap(),
            SmtpCommand::MailFrom("<user@example.com>".to_string())
        );

        assert_eq!(
            parse_command("MAIL FROM: <admin@test.com>", &SessionState::Connected).unwrap(),
            SmtpCommand::MailFrom(" <admin@test.com>".to_string())
        );

        // Test RCPT TO
        assert_eq!(
            parse_command("RCPT TO:<recipient@domain.com>", &SessionState::Connected).unwrap(),
            SmtpCommand::RcptTo("<recipient@domain.com>".to_string())
        );

        assert_eq!(
            parse_command(
                "RCPT TO: <multiple@addresses.com>",
                &SessionState::Connected
            )
            .unwrap(),
            SmtpCommand::RcptTo(" <multiple@addresses.com>".to_string())
        );
    }

    #[test]
    fn test_edge_case_domains() {
        // Test domains with hyphens
        assert_eq!(
            parse_command("EHLO my-domain-name.com", &SessionState::Connected).unwrap(),
            SmtpCommand::Ehlo("my-domain-name.com".to_string())
        );

        // Test domains with multiple dots
        assert_eq!(
            parse_command(
                "EHLO very.long.subdomain.example.com",
                &SessionState::Connected
            )
            .unwrap(),
            SmtpCommand::Ehlo("very.long.subdomain.example.com".to_string())
        );

        // Test single-letter domains
        assert_eq!(
            parse_command("EHLO a.b.c", &SessionState::Connected).unwrap(),
            SmtpCommand::Ehlo("a.b.c".to_string())
        );
    }
}
