use crate::config::{Cfg, CfgDKIM, DkimKeyType};
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

    let dkim_config =
        if args.domain.is_some() || args.selector.is_some() || args.private_key.is_some() {
            let domain = match args.domain {
                Some(d) => d,
                None => match &cfg.server.dkim {
                    Some(config) => config.domain.clone(),
                    None => bail!("Domain is required when not in config file"),
                },
            };

            let selector = match args.selector {
                Some(s) => s,
                None => match &cfg.server.dkim {
                    Some(config) => config.selector.clone(),
                    None => bail!("Selector is required when not in config file"),
                },
            };

            let private_key = match args.private_key {
                Some(p) => p,
                None => match &cfg.server.dkim {
                    Some(config) => config.private_key.clone(),
                    None => bail!("Private key path is required when not in config file"),
                },
            };

            let key_type = match args.key_type.as_str() {
                "rsa" => DkimKeyType::Rsa,
                "ed25519" => DkimKeyType::Ed25519,
                _ => bail!("Invalid key type. Use 'rsa' or 'ed25519'"),
            };

            CfgDKIM {
                domain,
                selector,
                private_key,
                key_type,
            }
        } else {
            match &cfg.server.dkim {
                Some(config) => config.clone(),
                None => bail!("DKIM configuration is missing in config file and no flags provided"),
            }
        };

    match dkim_config.key_type {
        DkimKeyType::Rsa => generate_rsa_keys(&dkim_config).await,
        DkimKeyType::Ed25519 => generate_ed25519_keys(&dkim_config).await,
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
    #[arg(long, default_value = "rsa")]
    pub key_type: String,
}
