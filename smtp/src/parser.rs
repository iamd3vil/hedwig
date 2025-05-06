use super::*;
use nom::{
    branch::alt,
    bytes::complete::{tag_no_case, take_while1},
    combinator::{map, rest, verify},
    sequence::preceded,
    IResult, Parser,
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
    StartTls,
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
    })
    .parse(input)
}

fn parse_auth_password(input: &str) -> IResult<&str, SmtpCommand> {
    map(take_while1(|c: char| c.is_ascii()), |s: &str| {
        SmtpCommand::AuthPassword(s.to_string())
    })
    .parse(input)
}

fn parse_normal_command(input: &str) -> IResult<&str, SmtpCommand> {
    alt((
        parse_ehlo,
        parse_auth_plain,
        parse_auth_login,
        parse_mail_from,
        parse_rcpt_to,
        parse_simple_command,
        // Changed this line to be exact
        map(tag_no_case("STARTTLS\r\n"), |_| SmtpCommand::StartTls),
    ))
    .parse(input)
}

fn parse_ehlo(input: &str) -> IResult<&str, SmtpCommand> {
    map(
        preceded(
            alt((tag_no_case("EHLO "), tag_no_case("HELO "))),
            verify(take_while1(is_alphanumeric), |s: &str| s.len() <= 255),
        ),
        |domain: &str| SmtpCommand::Ehlo(domain.to_string()),
    )
    .parse(input)
}

fn parse_auth_plain(input: &str) -> IResult<&str, SmtpCommand> {
    map(
        preceded(
            tag_no_case("AUTH PLAIN "),
            take_while1(|c: char| c.is_ascii()),
        ),
        |s: &str| SmtpCommand::AuthPlain(s.to_string()),
    )
    .parse(input)
}

fn parse_auth_login(input: &str) -> IResult<&str, SmtpCommand> {
    map(tag_no_case("AUTH LOGIN"), |_| SmtpCommand::AuthLogin).parse(input)
}

fn parse_mail_from(input: &str) -> IResult<&str, SmtpCommand> {
    map(
        preceded(tag_no_case("MAIL FROM:"), rest), // Use `rest` to capture everything after the prefix
        |address_part: &str| SmtpCommand::MailFrom(address_part.trim().to_string()), // Trim whitespace from the captured address
    )
    .parse(input)
}

fn parse_rcpt_to(input: &str) -> IResult<&str, SmtpCommand> {
    map(
        preceded(tag_no_case("RCPT TO:"), rest), // Use `rest` to capture everything after the prefix
        |address_part: &str| SmtpCommand::RcptTo(address_part.trim().to_string()), // Trim whitespace from the captured address
    )
    .parse(input)
}

fn parse_simple_command(input: &str) -> IResult<&str, SmtpCommand> {
    alt((
        map(tag_no_case("DATA"), |_| SmtpCommand::Data),
        map(tag_no_case("QUIT"), |_| SmtpCommand::Quit),
        map(tag_no_case("RSET"), |_| SmtpCommand::Rset),
        map(tag_no_case("NOOP"), |_| SmtpCommand::Noop),
    ))
    .parse(input)
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

    // A simplified parse_command for testing these specific parsers directly.
    // Your actual `parse_command` would be more complex and handle dispatching.
    // For these tests, we'll call the specific parsers if we know the command type.
    fn test_parse_command_wrapper(input: &str, _state: &SessionState) -> Result<SmtpCommand> {
        let upper_input = input.to_uppercase();
        let result = if upper_input.starts_with("MAIL FROM:") {
            parse_mail_from(input)
        } else if upper_input.starts_with("RCPT TO:") {
            parse_rcpt_to(input)
        } else {
            // Fallback for other command types if needed for broader test suites,
            // but for this specific test, we only care about MAIL FROM/RCPT TO.
            unimplemented!("This test wrapper only supports MAIL FROM and RCPT TO for now");
        };

        Ok(result
            .map(|(_remaining, cmd)| {
                // In a real scenario, you'd check if _remaining is empty here or in the main parse_command
                cmd
            })
            .unwrap())
    }

    #[test]
    fn test_mail_rcpt_commands() {
        let connected_state = SessionState::Connected; // Or any relevant state

        // Test MAIL FROM
        assert_eq!(
            test_parse_command_wrapper("MAIL FROM:<user@example.com>", &connected_state).unwrap(),
            SmtpCommand::MailFrom("<user@example.com>".to_string())
        );

        // Test MAIL FROM with leading/trailing spaces in the argument part (which trim() should handle)
        assert_eq!(
            test_parse_command_wrapper("MAIL FROM:  <admin@test.com>  ", &connected_state).unwrap(),
            SmtpCommand::MailFrom("<admin@test.com>".to_string())
        );

        // Test case-insensitivity of the command itself
        assert_eq!(
            test_parse_command_wrapper("mail from:<lowercase@example.com>", &connected_state)
                .unwrap(),
            SmtpCommand::MailFrom("<lowercase@example.com>".to_string())
        );

        // Test the problematic case from your description
        assert_eq!(
            test_parse_command_wrapper("mail from:<me@mailtest.alertify.sh>", &connected_state)
                .unwrap(),
            SmtpCommand::MailFrom("<me@mailtest.alertify.sh>".to_string())
        );

        // Test MAIL FROM with no angle brackets (if your server should support this)
        assert_eq!(
            test_parse_command_wrapper("MAIL FROM:user@example.com", &connected_state).unwrap(),
            SmtpCommand::MailFrom("user@example.com".to_string())
        );

        // Test MAIL FROM with empty path (null sender)
        assert_eq!(
            test_parse_command_wrapper("MAIL FROM:<>", &connected_state).unwrap(),
            SmtpCommand::MailFrom("<>".to_string())
        );
        assert_eq!(
            test_parse_command_wrapper("MAIL FROM: <>", &connected_state).unwrap(),
            SmtpCommand::MailFrom("<>".to_string())
        );

        // Test MAIL FROM with only the command (should result in an empty string for the address part)
        assert_eq!(
            test_parse_command_wrapper("MAIL FROM:", &connected_state).unwrap(),
            SmtpCommand::MailFrom("".to_string())
        );
        assert_eq!(
            test_parse_command_wrapper("MAIL FROM: ", &connected_state).unwrap(), // space after colon
            SmtpCommand::MailFrom("".to_string())
        );

        // Test RCPT TO
        assert_eq!(
            test_parse_command_wrapper("RCPT TO:<recipient@domain.com>", &connected_state).unwrap(),
            SmtpCommand::RcptTo("<recipient@domain.com>".to_string())
        );

        // Test RCPT TO with leading/trailing spaces in the argument part
        assert_eq!(
            test_parse_command_wrapper("RCPT TO:  <another@test.com>  ", &connected_state).unwrap(),
            SmtpCommand::RcptTo("<another@test.com>".to_string())
        );

        // Test case-insensitivity of RCPT TO command
        assert_eq!(
            test_parse_command_wrapper("rcpt to:<recipient@example.com>", &connected_state)
                .unwrap(),
            SmtpCommand::RcptTo("<recipient@example.com>".to_string())
        );

        // Test the problematic case for RCPT TO
        assert_eq!(
            test_parse_command_wrapper(
                "rcpt to:<charming.alpaca.noos@letterguard.net>",
                &connected_state
            )
            .unwrap(),
            SmtpCommand::RcptTo("<charming.alpaca.noos@letterguard.net>".to_string())
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

    #[test]
    fn test_starttls_command() {
        // Basic STARTTLS command
        assert_eq!(
            parse_command("STARTTLS\r\n", &SessionState::Connected).unwrap(),
            SmtpCommand::StartTls
        );

        // Case insensitive
        assert_eq!(
            parse_command("starttls\r\n", &SessionState::Connected).unwrap(),
            SmtpCommand::StartTls
        );

        // Should fail without CRLF
        assert!(parse_command("STARTTLS", &SessionState::Connected).is_err());

        // Should fail with parameters
        assert!(parse_command("STARTTLS param\r\n", &SessionState::Connected).is_err());

        // Should fail with extra spaces
        assert!(parse_command("STARTTLS \r\n", &SessionState::Connected).is_err());
        assert!(parse_command(" STARTTLS\r\n", &SessionState::Connected).is_err());
    }

    #[test]
    fn test_command_sequence() {
        // Test typical command sequence
        let commands = [
            (
                "EHLO example.com\r\n",
                SessionState::Connected,
                SmtpCommand::Ehlo("example.com".to_string()),
            ),
            ("STARTTLS\r\n", SessionState::Greeted, SmtpCommand::StartTls),
            (
                "EHLO example.com\r\n",
                SessionState::Connected,
                SmtpCommand::Ehlo("example.com".to_string()),
            ),
            (
                "AUTH LOGIN\r\n",
                SessionState::Greeted,
                SmtpCommand::AuthLogin,
            ),
            (
                "dXNlcg==\r\n",
                SessionState::AuthenticatingUsername,
                SmtpCommand::AuthUsername("dXNlcg==\r\n".to_string()),
            ),
            (
                "cGFzcw==\r\n",
                SessionState::AuthenticatingPassword("user".to_string()),
                SmtpCommand::AuthPassword("cGFzcw==\r\n".to_string()),
            ),
            (
                "MAIL FROM:<sender@example.com>\r\n",
                SessionState::Authenticated,
                SmtpCommand::MailFrom("<sender@example.com>".to_string()), // Include CRLF
            ),
            (
                "RCPT TO:<recipient@example.com>\r\n",
                SessionState::ReceivingMailFrom,
                SmtpCommand::RcptTo("<recipient@example.com>".to_string()), // Include CRLF
            ),
            ("DATA\r\n", SessionState::ReceivingRcptTo, SmtpCommand::Data),
        ];

        for (input, state, expected) in commands {
            assert_eq!(
                parse_command(input, &state).unwrap(),
                expected,
                "Failed to parse '{}' in state {:?}",
                input,
                state
            );
        }
    }

    #[test]
    fn test_state_specific_commands() {
        // Test that AUTH commands are only valid in certain states
        assert!(parse_command("dXNlcg==", &SessionState::Connected).is_err());

        // Fix: Only parse username in AuthenticatingUsername state
        assert!(parse_command("QUIT", &SessionState::Connected).is_ok());
        assert_eq!(
            parse_command("QUIT", &SessionState::Connected).unwrap(),
            SmtpCommand::Quit
        );

        // Test that DATA is parsed in any state
        assert_eq!(
            parse_command("DATA", &SessionState::ReceivingRcptTo).unwrap(),
            SmtpCommand::Data
        );
    }

    #[test]
    fn test_command_boundaries() {
        // Test commands with maximum allowed lengths
        let long_domain = "a".repeat(255); // Maximum domain length
        assert!(parse_command(&format!("EHLO {}", long_domain), &SessionState::Connected).is_ok());

        // Test with very long input that should fail
        let too_long_domain = "a".repeat(256);
        assert!(parse_command(
            &format!("EHLO {}", too_long_domain),
            &SessionState::Connected
        )
        .is_err());
    }
}
