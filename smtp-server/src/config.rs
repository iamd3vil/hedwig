use config::{Config, File};
use miette::{IntoDiagnostic, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;
use tracing::Level;

#[derive(Debug, Deserialize, Clone, Default)]
pub enum FilterType {
    #[serde(rename = "from_domain_filter")]
    #[default]
    FromDomain,
    #[serde(rename = "to_domain_filter")]
    ToDomain,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(rename_all = "kebab-case")]
pub enum FilterAction {
    #[default]
    Allow,
    Deny,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Cfg {
    #[serde(default)]
    pub log: CfgLog,
    pub server: CfgServer,
    pub storage: CfgStorage,
    pub filters: Option<Vec<CfgFilter>>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CfgServer {
    pub listeners: Vec<CfgListener>,
    pub workers: Option<usize>,
    pub max_retries: Option<u32>,
    pub auth: Option<Vec<CfgAuth>>,
    pub dkim: Option<CfgDKIM>,
    pub disable_outbound: Option<bool>,
    pub outbound_local: Option<bool>,
    pub pool_size: Option<u64>,
    pub rate_limits: Option<CfgRateLimits>,
    pub metrics: Option<CfgMetrics>,
    pub health: Option<CfgHealth>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CfgFilter {
    #[serde(rename = "type", default)]
    pub typ: FilterType,
    pub domain: Vec<String>,
    #[serde(default)]
    pub action: FilterAction,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CfgStorage {
    pub storage_type: String,
    pub base_path: String,
    #[serde(default)]
    pub cleanup: Option<CfgCleanup>,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(rename_all = "lowercase")]
pub enum DkimKeyType {
    #[default]
    Rsa,
    Ed25519,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CfgLog {
    pub level: String,
    pub format: String,
}

impl Default for CfgLog {
    fn default() -> Self {
        CfgLog {
            level: Level::INFO.to_string(),
            format: "fmt".to_string(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct CfgDKIM {
    pub domain: String,
    pub selector: String,
    pub private_key: String,

    #[serde(default)]
    pub key_type: DkimKeyType,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CfgAuth {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CfgListener {
    pub addr: String,
    pub tls: Option<CfgTls>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CfgTls {
    pub cert_path: String,
    pub key_path: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CfgMetrics {
    pub bind: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CfgHealth {
    pub bind: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CfgRateLimits {
    #[serde(default)]
    pub enabled: bool,
    pub default_limit: Option<u32>,
    pub domain_limits: Option<HashMap<String, u32>>,
}

/// Configuration for on-disk spool cleanup.
#[derive(Debug, Deserialize, Clone)]
pub struct CfgCleanup {
    #[serde(default, with = "humantime_serde::option")]
    pub deferred_retention: Option<Duration>,
    #[serde(default, with = "humantime_serde::option")]
    pub bounced_retention: Option<Duration>,
    #[serde(default = "default_cleanup_interval", with = "humantime_serde")]
    pub interval: Duration,
}

impl Cfg {
    pub fn load(cfg_path: &str) -> Result<Self> {
        let path = Path::new(cfg_path);

        // For HUML files, deserialize directly without using the config crate
        if path.extension().and_then(|s| s.to_str()) == Some("huml") {
            println!("Loading HUML configuration from {}", cfg_path);
            let huml_content = std::fs::read_to_string(cfg_path).into_diagnostic()?;
            let cfg: Cfg = huml_rs::serde::from_str(&huml_content)
                .map_err(|e| miette::miette!("Failed to parse HUML: {}", e))?;
            return Ok(cfg);
        }

        // For other formats (TOML, JSON), use the config crate
        let settings = Config::builder()
            .add_source(File::with_name(cfg_path))
            .build()
            .into_diagnostic()?;

        let cfg: Cfg = settings.try_deserialize().into_diagnostic()?;

        Ok(cfg)
    }
}

impl CfgRateLimits {
    pub fn to_rate_limit_config(&self) -> crate::worker::rate_limiter::RateLimitConfig {
        crate::worker::rate_limiter::RateLimitConfig {
            enabled: self.enabled,
            default_limit: self.default_limit.unwrap_or(60), // 60 emails per minute default
            domain_limits: self.domain_limits.clone().unwrap_or_default(),
        }
    }
}

impl CfgCleanup {
    pub fn to_cleanup_config(&self) -> crate::storage::CleanupConfig {
        crate::storage::CleanupConfig {
            deferred_retention: self.deferred_retention,
            bounced_retention: self.bounced_retention,
            interval: self.interval,
        }
    }
}

impl CfgStorage {
    pub fn cleanup_config(&self) -> crate::storage::CleanupConfig {
        self.cleanup
            .as_ref()
            .map(|cfg| cfg.to_cleanup_config())
            .unwrap_or_default()
    }
}

/// Default cleanup interval used when the configuration omits an explicit value (1 hour).
fn default_cleanup_interval() -> Duration {
    Duration::from_secs(60 * 60)
}
