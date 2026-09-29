use crate::config::{Cfg, CfgDKIM, CfgDkim, DkimKeyType};
use base64::Engine;
use clap::Parser;
use miette::{bail, Context, IntoDiagnostic, Result};
use pkcs8::EncodePrivateKey;
use rand::rngs::OsRng;
use rsa::{
    pkcs8::{EncodePublicKey, LineEnding},
    RsaPrivateKey,
};

pub const DEFAULT_DKIM_KEY_BITS: usize = 2048;

/// Generate DKIM keys based on configuration
pub async fn generate_dkim_keys(config_path: &str, args: DkimGenerateArgs) -> Result<()> {
    let cfg = Cfg::load(config_path).wrap_err("error loading configuration")?;

    let dkim_config = key_generation_config(cfg.server.dkim.as_ref(), args)?;

    match dkim_config.key_type {
        DkimKeyType::Rsa => generate_rsa_keys(&dkim_config).await,
        DkimKeyType::Ed25519 => generate_ed25519_keys(&dkim_config).await,
    }
}

/// Select config defaults without accidentally generating a key for another domain.
fn key_generation_config(config: Option<&CfgDkim>, args: DkimGenerateArgs) -> Result<CfgDKIM> {
    let defaults = match config {
        Some(CfgDkim::Legacy(entry)) => Some(entry),
        Some(CfgDkim::Domains(entries)) => {
            let domain = args.domain.as_deref().ok_or_else(|| {
                miette::miette!("--domain is required with multi-domain DKIM configuration")
            })?;
            entries
                .iter()
                .find(|entry| entry.domain.eq_ignore_ascii_case(domain))
        }
        None => None,
    };
    // Preserve the legacy no-flags behavior, including its configured key type.
    if args.domain.is_none() && args.selector.is_none() && args.private_key.is_none() {
        return defaults.cloned().ok_or_else(|| {
            miette::miette!("DKIM configuration is missing in config file and no flags provided")
        });
    }
    let domain = args
        .domain
        .or_else(|| defaults.map(|v| v.domain.clone()))
        .ok_or_else(|| miette::miette!("Domain is required when not in config file"))?;
    let selector = args
        .selector
        .or_else(|| defaults.map(|v| v.selector.clone()))
        .ok_or_else(|| miette::miette!("Selector is required when not in config file"))?;
    let private_key = args
        .private_key
        .or_else(|| defaults.map(|v| v.private_key.clone()))
        .ok_or_else(|| miette::miette!("Private key path is required when not in config file"))?;
    let key_type = match args.key_type.as_deref() {
        Some("rsa") => DkimKeyType::Rsa,
        Some("ed25519") => DkimKeyType::Ed25519,
        Some(_) => bail!("Invalid key type. Use 'rsa' or 'ed25519'"),
        None if matches!(config, Some(CfgDkim::Domains(_))) => {
            defaults.map(|v| v.key_type.clone()).unwrap_or_default()
        }
        None => DkimKeyType::Rsa,
    };
    Ok(CfgDKIM {
        domain,
        selector,
        private_key,
        key_type,
    })
}

/// Domains are DNS names in ASCII (use A-label/punycode for IDNs).
/// Exact matching deliberately excludes wildcard and parent-domain fallback.
pub(crate) fn normalize_domain(domain: &str) -> Option<String> {
    (domain.len() <= 253
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.as_bytes()[0].is_ascii_alphanumeric()
                && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        }))
    .then(|| domain.to_ascii_lowercase())
}

pub(crate) fn from_domain(body: &[u8]) -> Result<String> {
    let message = mail_parser::MessageParser::default()
        .parse_headers(body)
        .ok_or_else(|| miette::miette!("Invalid message headers"))?;
    if message
        .headers()
        .iter()
        .filter(|h| h.name == mail_parser::HeaderName::From)
        .count()
        != 1
    {
        bail!("Exactly one From header is required");
    }
    let Some(mail_parser::Address::List(addresses)) = message.from() else {
        bail!("From must contain one mailbox");
    };
    if addresses.len() != 1 {
        bail!("From must contain one mailbox");
    }
    let address = addresses[0]
        .address()
        .ok_or_else(|| miette::miette!("Invalid From mailbox"))?;
    let parsed = email_address_parser::EmailAddress::parse(address, None)
        .ok_or_else(|| miette::miette!("Invalid From mailbox"))?;
    let domain =
        normalize_domain(&parsed.domain()).ok_or_else(|| miette::miette!("Invalid From domain"))?;
    // mail-parser deliberately recovers malformed addresses (for example an
    // unclosed angle bracket). Require the raw field to parse as one mailbox
    // too, so recovery cannot turn malformed input into an authorized sender.
    let raw = message
        .headers_raw()
        .find(|(name, _)| name.eq_ignore_ascii_case("From"))
        .map(|(_, value)| value)
        .ok_or_else(|| miette::miette!("Invalid From header"))?;
    let raw_addresses = mailparse::addrparse(raw)
        .into_diagnostic()
        .wrap_err("Invalid From header")?;
    let [mailparse::MailAddr::Single(mailbox)] = raw_addresses.as_slice() else {
        bail!("From must contain one mailbox");
    };
    let raw_address = email_address_parser::EmailAddress::parse(&mailbox.addr, None)
        .ok_or_else(|| miette::miette!("Invalid From mailbox"))?;
    if normalize_domain(&raw_address.domain()).as_ref() != Some(&domain) {
        bail!("Ambiguous From domain");
    }
    Ok(domain)
}

#[derive(Debug, thiserror::Error, miette::Diagnostic)]
#[error("Sending domain {0} is not configured")]
pub(crate) struct UnconfiguredDomain(pub String);

impl crate::reload::RuntimeSnapshot {
    pub(crate) fn signer_for(&self, body: &[u8]) -> Result<Option<&crate::worker::DkimSignerType>> {
        match &self.dkim_domains {
            Some(domains) => {
                let domain = from_domain(body)?;
                domains
                    .get(&domain)
                    .map(Some)
                    .ok_or_else(|| UnconfiguredDomain(domain).into())
            }
            None => Ok(self.dkim_signer.as_ref()),
        }
    }
}

/// Generate RSA DKIM keys
async fn generate_rsa_keys(dkim_config: &CfgDKIM) -> Result<()> {
    let mut rng = OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, DEFAULT_DKIM_KEY_BITS)
        .into_diagnostic()
        .wrap_err("Failed to generate RSA key pair")?;

    let private_key_pem = private_key
        .to_pkcs8_pem(LineEnding::LF)
        .into_diagnostic()
        .wrap_err("Failed to encode private key to PEM")?;

    tokio::fs::write(&dkim_config.private_key, private_key_pem.as_bytes())
        .await
        .into_diagnostic()
        .wrap_err("Failed to write private key")?;

    let public_key = private_key.to_public_key();
    let public_key_der = public_key
        .to_public_key_der()
        .into_diagnostic()
        .wrap_err("Failed to encode public key")?;

    output_dns_record(dkim_config, public_key_der.as_bytes(), "rsa")
}

/// Generate Ed25519 DKIM keys
async fn generate_ed25519_keys(dkim_config: &CfgDKIM) -> Result<()> {
    use ed25519_dalek::SigningKey;
    use pkcs8::{EncodePrivateKey, LineEnding};
    use rand::RngCore;

    let mut rng = OsRng;

    // Generate random bytes for the secret key
    let mut secret_bytes = [0u8; 32];
    rng.fill_bytes(&mut secret_bytes);

    // Create signing key from random bytes
    let signing_key = SigningKey::from_bytes(&secret_bytes);
    let verifying_key = signing_key.verifying_key();

    // Convert directly to PKCS8 PEM using the EncodePrivateKey trait
    let private_key_pem = signing_key
        .to_pkcs8_pem(LineEnding::LF)
        .into_diagnostic()
        .wrap_err("Failed to encode private key to PEM")?;

    tokio::fs::write(&dkim_config.private_key, private_key_pem.as_bytes())
        .await
        .into_diagnostic()
        .wrap_err("Failed to write private key")?;

    output_dns_record(dkim_config, verifying_key.as_bytes(), "ed25519")
}

/// Output DNS record configuration for DKIM
fn output_dns_record(dkim_config: &CfgDKIM, public_key_bytes: &[u8], key_type: &str) -> Result<()> {
    let public_key_base64 = base64::engine::general_purpose::STANDARD.encode(public_key_bytes);
    let dns_record = format!(
        "{}._domainkey.{} IN TXT \"v=DKIM1; k={}; p={}\"",
        dkim_config.selector, dkim_config.domain, key_type, public_key_base64
    );

    println!("DKIM keys generated successfully!");
    println!("Private key saved to: {}", dkim_config.private_key);
    println!("\nAdd the following TXT record to your DNS configuration:");
    println!("{}", dns_record);

    Ok(())
}

/// Command line arguments for DKIM key generation
#[derive(Parser)]
pub struct DkimGenerateArgs {
    /// Domain for DKIM signature
    #[arg(long)]
    pub domain: Option<String>,

    /// DKIM selector
    #[arg(long)]
    pub selector: Option<String>,

    /// Path to save the private key
    #[arg(long)]
    pub private_key: Option<String>,

    /// Key type (rsa or ed25519)
    #[arg(long)]
    pub key_type: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_domain_requires_one_unambiguous_mailbox() {
        for header in [
            "From: Alice <alice@EXAMPLE.com>",
            "From: Alice\r\n <alice@example.com>",
            "From: \"a@b\" <alice@example.com>",
        ] {
            assert_eq!(
                from_domain(format!("{header}\r\nSubject: test\r\n\r\nbody").as_bytes()).unwrap(),
                "example.com"
            );
        }
        for header in [
            "Subject: no from",
            "From: a@example.com\r\nFrom: b@example.com",
            "From: a@example.com, b@example.com",
            "From: friends: a@example.com;",
            "From: invalid",
            "From: <a@example.com",
            "From: a@example.com>",
            "From: a@bad_domain.com",
            "From: a@[127.0.0.1]",
            "From:",
        ] {
            assert!(
                from_domain(format!("{header}\r\n\r\nbody").as_bytes()).is_err(),
                "accepted {header}"
            );
        }
    }

    #[test]
    fn config_formats_and_key_generation_defaults() {
        let entry = CfgDKIM {
            domain: "example.com".into(),
            selector: "one".into(),
            private_key: "one.pem".into(),
            key_type: DkimKeyType::Ed25519,
        };
        let args = |domain| DkimGenerateArgs {
            domain,
            selector: None,
            private_key: None,
            key_type: None,
        };
        let legacy: CfgDkim =
            serde_json::from_value(serde_json::to_value(&entry).unwrap()).unwrap();
        assert!(matches!(legacy, CfgDkim::Legacy(_)));
        assert!(matches!(
            key_generation_config(Some(&legacy), args(None))
                .unwrap()
                .key_type,
            DkimKeyType::Ed25519
        ));
        let multi: CfgDkim = serde_json::from_value(serde_json::json!([entry])).unwrap();
        assert!(matches!(multi, CfgDkim::Domains(_)));
        assert!(key_generation_config(Some(&multi), args(None)).is_err());
        let selected =
            key_generation_config(Some(&multi), args(Some("EXAMPLE.COM".into()))).unwrap();
        assert_eq!(selected.private_key, "one.pem");
        assert!(matches!(selected.key_type, DkimKeyType::Ed25519));
        assert!(key_generation_config(Some(&multi), args(Some("unknown.com".into()))).is_err());
    }
}
