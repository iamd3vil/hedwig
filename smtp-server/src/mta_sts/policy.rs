use std::{fmt, time::Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyMode {
    Enforce,
    Testing,
    None,
}

impl fmt::Display for PolicyMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Enforce => write!(f, "enforce"),
            Self::Testing => write!(f, "testing"),
            Self::None => write!(f, "none"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct MtaStsPolicy {
    pub mode: PolicyMode,
    pub mx_patterns: Vec<String>,
    pub max_age: u64,
}

#[derive(Clone, Debug)]
pub struct CachedPolicy {
    pub policy: MtaStsPolicy,
    pub txt_id: String,
    pub fetched_at: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MtaStsTxtRecord {
    pub id: String,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PolicyParseError {
    #[error("missing required field: {0}")]
    MissingField(&'static str),
    #[error("invalid STS version: {0}")]
    InvalidVersion(String),
    #[error("invalid policy mode: {0}")]
    InvalidMode(String),
    #[error("invalid max_age value: {0}")]
    InvalidMaxAge(String),
}

#[derive(Debug, thiserror::Error)]
#[error("MTA-STS enforce: all MX hosts failed policy validation for domain {domain}")]
pub struct MtaStsEnforcementError {
    pub domain: String,
}

pub fn parse_txt_record(record: &str) -> Result<MtaStsTxtRecord, PolicyParseError> {
    let mut version: Option<String> = None;
    let mut id: Option<String> = None;

    for field in record.split(';') {
        let field = field.trim();
        if field.is_empty() {
            continue;
        }

        let Some((raw_key, raw_value)) = field.split_once('=') else {
            continue;
        };

        let key = raw_key.trim();
        let value = raw_value.trim();

        if key.eq_ignore_ascii_case("v") && version.is_none() {
            version = Some(value.to_string());
            continue;
        }

        if key.eq_ignore_ascii_case("id") && id.is_none() && !value.is_empty() {
            id = Some(value.to_string());
        }
    }

    let version = version.ok_or(PolicyParseError::MissingField("v"))?;
    if version != "STSv1" {
        return Err(PolicyParseError::InvalidVersion(version));
    }

    let id = id.ok_or(PolicyParseError::MissingField("id"))?;
    Ok(MtaStsTxtRecord { id })
}

pub fn parse_policy(policy_body: &str) -> Result<MtaStsPolicy, PolicyParseError> {
    let mut version: Option<String> = None;
    let mut mode: Option<PolicyMode> = None;
    let mut max_age: Option<u64> = None;
    let mut mx_patterns: Vec<String> = Vec::new();

    for line in policy_body.split('\n') {
        let line = line.trim_end_matches('\r').trim();
        if line.is_empty() {
            continue;
        }

        let Some((raw_key, raw_value)) = line.split_once(':') else {
            continue;
        };

        let key = raw_key.trim().to_ascii_lowercase();
        let value = raw_value.trim();

        match key.as_str() {
            "version" if version.is_none() => {
                version = Some(value.to_string());
            }
            "mode" if mode.is_none() => {
                let parsed_mode = match value.to_ascii_lowercase().as_str() {
                    "enforce" => PolicyMode::Enforce,
                    "testing" => PolicyMode::Testing,
                    "none" => PolicyMode::None,
                    _ => return Err(PolicyParseError::InvalidMode(value.to_string())),
                };
                mode = Some(parsed_mode);
            }
            "max_age" if max_age.is_none() => {
                let parsed_max_age = value
                    .parse::<u64>()
                    .map_err(|_| PolicyParseError::InvalidMaxAge(value.to_string()))?;
                // RFC 8461 §3.2: maximum value of 31557600 (~1 year).
                if parsed_max_age > 31_557_600 {
                    return Err(PolicyParseError::InvalidMaxAge(value.to_string()));
                }
                max_age = Some(parsed_max_age);
            }
            "mx" => {
                if !value.is_empty() {
                    mx_patterns.push(value.to_ascii_lowercase());
                }
            }
            _ => {}
        }
    }

    let version = version.ok_or(PolicyParseError::MissingField("version"))?;
    if version != "STSv1" {
        return Err(PolicyParseError::InvalidVersion(version));
    }

    let mode = mode.ok_or(PolicyParseError::MissingField("mode"))?;
    let max_age = max_age.ok_or(PolicyParseError::MissingField("max_age"))?;

    if mode != PolicyMode::None && mx_patterns.is_empty() {
        return Err(PolicyParseError::MissingField("mx"));
    }

    Ok(MtaStsPolicy {
        mode,
        mx_patterns,
        max_age,
    })
}

pub fn mx_matches_pattern(mx_host: &str, pattern: &str) -> bool {
    let normalized_mx = normalize_dns_name(mx_host);
    let normalized_pattern = normalize_dns_name(pattern);

    if let Some(suffix) = normalized_pattern.strip_prefix("*.") {
        if suffix.is_empty() || normalized_mx == suffix {
            return false;
        }

        let expected_suffix = format!(".{suffix}");
        if !normalized_mx.ends_with(&expected_suffix) {
            return false;
        }

        let prefix = &normalized_mx[..normalized_mx.len() - expected_suffix.len()];
        return !prefix.is_empty() && !prefix.contains('.');
    }

    normalized_mx == normalized_pattern
}

pub fn mx_matches_policy(mx_host: &str, policy: &MtaStsPolicy) -> bool {
    policy
        .mx_patterns
        .iter()
        .any(|pattern| mx_matches_pattern(mx_host, pattern))
}

fn normalize_dns_name(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_txt_record_parses_valid_record() {
        let txt = parse_txt_record("v=STSv1; id=20160831085700Z;").unwrap();

        assert_eq!(txt.id, "20160831085700Z");
    }

    #[test]
    fn parse_txt_record_ignores_unknown_fields_and_whitespace() {
        let txt = parse_txt_record(" foo=bar ; v=STSv1 ; id = abc123 ; x=y ;").unwrap();

        assert_eq!(
            txt,
            MtaStsTxtRecord {
                id: "abc123".into()
            }
        );
    }

    #[test]
    fn parse_txt_record_requires_v_field() {
        let err = parse_txt_record("id=abc;").unwrap_err();

        assert_eq!(err, PolicyParseError::MissingField("v"));
    }

    #[test]
    fn parse_txt_record_rejects_invalid_version() {
        let err = parse_txt_record("v=STSv2; id=abc;").unwrap_err();

        assert_eq!(err, PolicyParseError::InvalidVersion("STSv2".into()));
    }

    #[test]
    fn parse_txt_record_requires_id_field() {
        let err = parse_txt_record("v=STSv1;").unwrap_err();

        assert_eq!(err, PolicyParseError::MissingField("id"));
    }

    #[test]
    fn parse_txt_record_rejects_empty_id() {
        let err = parse_txt_record("v=STSv1; id= ;").unwrap_err();

        assert_eq!(err, PolicyParseError::MissingField("id"));
    }

    #[test]
    fn parse_policy_parses_valid_policy_body_with_lf() {
        let policy =
            parse_policy("version: STSv1\nmode: enforce\nmx: MAIL.Example.COM\nmax_age: 86400")
                .unwrap();

        assert_eq!(policy.mode, PolicyMode::Enforce);
        assert_eq!(policy.mx_patterns, vec!["mail.example.com"]);
        assert_eq!(policy.max_age, 86400);
    }

    #[test]
    fn parse_policy_parses_valid_policy_body_with_crlf() {
        let policy = parse_policy(
            "version: STSv1\r\nmode: testing\r\nmx: *.example.com\r\nmax_age: 123\r\n",
        )
        .unwrap();

        assert_eq!(policy.mode, PolicyMode::Testing);
        assert_eq!(policy.mx_patterns, vec!["*.example.com"]);
        assert_eq!(policy.max_age, 123);
    }

    #[test]
    fn parse_policy_requires_version() {
        let err = parse_policy("mode: enforce\nmx: mail.example.com\nmax_age: 10").unwrap_err();

        assert_eq!(err, PolicyParseError::MissingField("version"));
    }

    #[test]
    fn parse_policy_requires_mode() {
        let err = parse_policy("version: STSv1\nmx: mail.example.com\nmax_age: 10").unwrap_err();

        assert_eq!(err, PolicyParseError::MissingField("mode"));
    }

    #[test]
    fn parse_policy_requires_max_age() {
        let err = parse_policy("version: STSv1\nmode: enforce\nmx: mail.example.com").unwrap_err();

        assert_eq!(err, PolicyParseError::MissingField("max_age"));
    }

    #[test]
    fn parse_policy_rejects_invalid_version() {
        let err = parse_policy("version: STSv2\nmode: enforce\nmx: mail.example.com\nmax_age: 10")
            .unwrap_err();

        assert_eq!(err, PolicyParseError::InvalidVersion("STSv2".into()));
    }

    #[test]
    fn parse_policy_rejects_invalid_mode() {
        let err = parse_policy("version: STSv1\nmode: strict\nmx: mail.example.com\nmax_age: 10")
            .unwrap_err();

        assert_eq!(err, PolicyParseError::InvalidMode("strict".into()));
    }

    #[test]
    fn parse_policy_rejects_invalid_max_age() {
        let err =
            parse_policy("version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: soon")
                .unwrap_err();

        assert_eq!(err, PolicyParseError::InvalidMaxAge("soon".into()));
    }

    #[test]
    fn parse_policy_rejects_max_age_exceeding_limit() {
        // RFC 8461 §3.2: max value is 31557600 (~1 year)
        let err = parse_policy(
            "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 31557601",
        )
        .unwrap_err();
        assert_eq!(err, PolicyParseError::InvalidMaxAge("31557601".into()));
    }

    #[test]
    fn parse_policy_accepts_max_age_at_limit() {
        let policy = parse_policy(
            "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 31557600",
        )
        .unwrap();
        assert_eq!(policy.max_age, 31_557_600);
    }

    #[test]
    fn parse_policy_requires_mx_in_enforce_mode() {
        let err = parse_policy("version: STSv1\nmode: enforce\nmax_age: 10").unwrap_err();

        assert_eq!(err, PolicyParseError::MissingField("mx"));
    }

    #[test]
    fn parse_policy_allows_mode_none_without_mx() {
        let policy = parse_policy("version: STSv1\nmode: none\nmax_age: 10").unwrap();

        assert_eq!(policy.mode, PolicyMode::None);
        assert!(policy.mx_patterns.is_empty());
    }

    #[test]
    fn parse_policy_keeps_first_duplicate_non_mx_fields() {
        let policy = parse_policy(
            "version: STSv1\nversion: STSv2\nmode: enforce\nmode: none\nmx: first.example.com\nmax_age: 60\nmax_age: bad",
        )
        .unwrap();

        assert_eq!(policy.mode, PolicyMode::Enforce);
        assert_eq!(policy.max_age, 60);
        assert_eq!(policy.mx_patterns, vec!["first.example.com"]);
    }

    #[test]
    fn parse_policy_ignores_unknown_fields() {
        let policy = parse_policy(
            "version: STSv1\nmode: testing\nmx: mail.example.com\nmax_age: 10\nunknown: value",
        )
        .unwrap();

        assert_eq!(policy.mode, PolicyMode::Testing);
        assert_eq!(policy.max_age, 10);
        assert_eq!(policy.mx_patterns, vec!["mail.example.com"]);
    }

    #[test]
    fn parse_policy_empty_input_reports_missing_version() {
        let err = parse_policy("").unwrap_err();

        assert_eq!(err, PolicyParseError::MissingField("version"));
    }

    #[test]
    fn mx_matches_pattern_matches_exact_case_insensitive_with_trailing_dot() {
        assert!(mx_matches_pattern("MAIL.EXAMPLE.COM.", "mail.example.com"));
        assert!(mx_matches_pattern("mail.example.com", "MAIL.EXAMPLE.COM."));
    }

    #[test]
    fn mx_matches_pattern_matches_single_label_wildcard() {
        assert!(mx_matches_pattern("mail.example.com", "*.example.com"));
        assert!(mx_matches_pattern("mail.example.com.", "*.example.com."));
    }

    #[test]
    fn mx_matches_pattern_wildcard_does_not_match_root_or_multi_label() {
        assert!(!mx_matches_pattern("example.com", "*.example.com"));
        assert!(!mx_matches_pattern("a.b.example.com", "*.example.com"));
    }

    #[test]
    fn mx_matches_pattern_non_matching_cases() {
        assert!(!mx_matches_pattern("mail.example.net", "*.example.com"));
        assert!(!mx_matches_pattern("mail.example.com", "mx.example.com"));
    }

    #[test]
    fn mx_matches_policy_checks_any_pattern() {
        let policy = MtaStsPolicy {
            mode: PolicyMode::Enforce,
            mx_patterns: vec!["mx1.example.com".into(), "*.example.net".into()],
            max_age: 3600,
        };

        assert!(mx_matches_policy("mx1.example.com", &policy));
        assert!(mx_matches_policy("mail.example.net", &policy));
        assert!(!mx_matches_policy("mail.example.org", &policy));
    }

    #[test]
    fn policy_mode_display_outputs_policy_values() {
        assert_eq!(PolicyMode::Enforce.to_string(), "enforce");
        assert_eq!(PolicyMode::Testing.to_string(), "testing");
        assert_eq!(PolicyMode::None.to_string(), "none");
    }

    #[test]
    fn parse_policy_requires_mx_in_testing_mode() {
        let err = parse_policy("version: STSv1\nmode: testing\nmax_age: 10").unwrap_err();
        assert_eq!(err, PolicyParseError::MissingField("mx"));
    }

    #[test]
    fn parse_policy_multiple_mx_lines_accumulate() {
        let body =
            "version: STSv1\nmode: enforce\nmx: a.example.com\nmx: b.example.com\nmax_age: 100";
        let policy = parse_policy(body).unwrap();
        assert_eq!(policy.mx_patterns, vec!["a.example.com", "b.example.com"]);
    }
}
