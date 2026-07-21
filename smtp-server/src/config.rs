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
    pub queue: Option<CfgQueue>,
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
    pub helo_hostname: Option<String>,
    /// Hostname announced by the inbound listener in the 220 greeting and
    /// EHLO reply. Defaults to the OS hostname.
    pub hostname: Option<String>,
    pub smtp: Option<CfgSmtp>,
    /// Deprecated: use server.smtp.cache_size instead.
    pub pool_size: Option<u64>,
    pub rate_limits: Option<CfgRateLimits>,
    pub metrics: Option<CfgMetrics>,
    pub health: Option<CfgHealth>,
    pub queue_buffer: Option<usize>,
    pub max_connections: Option<usize>,
    pub max_message_size: Option<usize>,
    #[serde(default, with = "humantime_serde::option")]
    pub cmd_timeout: Option<Duration>,
    #[serde(default, with = "humantime_serde::option")]
    pub data_timeout: Option<Duration>,
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

#[derive(Debug, Deserialize, Clone, Default)]
pub struct CfgSmtp {
    /// Number of destination MX transports to keep in the process-wide cache.
    pub cache_size: Option<u64>,
    /// Minimum number of idle connections in each process-wide destination MX pool.
    pub min_idle: Option<u32>,
    /// Maximum number of connections in each process-wide destination MX pool.
    pub max_size: Option<u32>,
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
    /// How TLS is negotiated on this listener: "implicit" wraps the
    /// connection in TLS immediately (e.g. port 465), "starttls" accepts
    /// plaintext and upgrades when the client issues STARTTLS (e.g. port 587).
    #[serde(default)]
    pub mode: TlsMode,
}

#[derive(Debug, Deserialize, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TlsMode {
    #[default]
    Implicit,
    Starttls,
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

/// Configuration for the durable append-log mail queue (see PLAN.md).
///
/// Not yet consumed by the server (the log-queue backend is not wired into
/// the serving path); remove the `allow(dead_code)` once it is.
#[allow(dead_code)]
#[derive(Debug, Deserialize, Clone, Default)]
pub struct CfgQueue {
    /// Number of shards / concurrent append writers (default: 1).
    pub append_writers: Option<u16>,
    /// Bytes of pending (not-yet-durable) append data allowed before backpressure (default: 128 MiB).
    pub pending_append_bytes: Option<u64>,
    /// Target size of each active segment file, per shard (default: 64 MiB).
    pub segment_target_bytes: Option<u64>,
    /// Fraction of dead bytes in a sealed segment that makes it eligible for compaction (default: 0.50).
    pub compaction_dead_ratio: Option<f64>,
    /// Minimum age of a sealed segment before it is eligible for compaction (default: 60s).
    #[serde(default, with = "humantime_serde::option")]
    pub compaction_min_age: Option<Duration>,
    /// Maximum number of compactions allowed to run concurrently (default: 1).
    pub max_concurrent_compactions: Option<usize>,
    /// Minimum free disk space required to accept new mail (default: 1 GiB).
    pub disk_reserve_bytes: Option<u64>,
    /// Bytes of appended data between durability checkpoints (default: 8 MiB).
    pub checkpoint_interval_bytes: Option<u64>,
}

#[allow(dead_code)]
impl CfgQueue {
    pub fn append_writers(&self) -> u16 {
        self.append_writers.unwrap_or(1)
    }

    pub fn pending_append_bytes(&self) -> u64 {
        self.pending_append_bytes.unwrap_or(128 * 1024 * 1024)
    }

    pub fn segment_target_bytes(&self) -> u64 {
        self.segment_target_bytes.unwrap_or(64 * 1024 * 1024)
    }

    pub fn compaction_dead_ratio(&self) -> f64 {
        self.compaction_dead_ratio.unwrap_or(0.50)
    }

    pub fn compaction_min_age(&self) -> Duration {
        self.compaction_min_age.unwrap_or(Duration::from_secs(60))
    }

    pub fn max_concurrent_compactions(&self) -> usize {
        self.max_concurrent_compactions.unwrap_or(1)
    }

    pub fn disk_reserve_bytes(&self) -> u64 {
        self.disk_reserve_bytes.unwrap_or(1024 * 1024 * 1024)
    }

    pub fn checkpoint_interval_bytes(&self) -> u64 {
        self.checkpoint_interval_bytes.unwrap_or(8 * 1024 * 1024)
    }

    /// Validate the resolved configuration. `max_message_size` is the
    /// server's configured (or defaulted) maximum message size in bytes,
    /// since the segment target must be able to hold one worst-case record.
    pub fn validate(&self, max_message_size: usize) -> miette::Result<()> {
        if self.append_writers() < 1 {
            return Err(miette::miette!("queue.append_writers must be at least 1"));
        }

        let ratio = self.compaction_dead_ratio();
        if !(ratio > 0.0 && ratio < 1.0) {
            return Err(miette::miette!(
                "queue.compaction_dead_ratio must be between 0.0 and 1.0 (exclusive), got {ratio}"
            ));
        }

        crate::logqueue::spool::check_segment_sizing(
            self.segment_target_bytes(),
            max_message_size as u64,
        )
        .map_err(miette::Report::new)?;

        Ok(())
    }
}

impl Cfg {
    /// The resolved queue configuration, defaulted if the `[queue]` section
    /// is absent from the loaded configuration.
    #[allow(dead_code)]
    pub fn queue(&self) -> CfgQueue {
        self.queue.clone().unwrap_or_default()
    }

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
            default_limit: self.default_limit,
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

#[cfg(test)]
mod tests {
    use super::*;
    use config::FileFormat;

    /// Smallest configuration that satisfies every required (non-`Option`)
    /// field on `Cfg`, so tests can focus on the `[queue]` section alone.
    const MINIMAL_CFG: &str = r#"
        [server]
        listeners = []

        [storage]
        storage_type = "fs"
        base_path = "/tmp/hedwig-test-spool"
    "#;

    fn parse(toml: &str) -> Cfg {
        let settings = Config::builder()
            .add_source(File::from_str(toml, FileFormat::Toml))
            .build()
            .expect("build config");
        settings.try_deserialize().expect("deserialize config")
    }

    #[test]
    fn queue_defaults_when_section_absent() {
        let cfg = parse(MINIMAL_CFG);
        assert!(cfg.queue.is_none());

        let queue = cfg.queue();
        assert_eq!(queue.append_writers(), 1);
        assert_eq!(queue.pending_append_bytes(), 128 * 1024 * 1024);
        assert_eq!(queue.segment_target_bytes(), 64 * 1024 * 1024);
        assert_eq!(queue.compaction_dead_ratio(), 0.50);
        assert_eq!(queue.compaction_min_age(), Duration::from_secs(60));
        assert_eq!(queue.max_concurrent_compactions(), 1);
        assert_eq!(queue.disk_reserve_bytes(), 1024 * 1024 * 1024);
        assert_eq!(queue.checkpoint_interval_bytes(), 8 * 1024 * 1024);
    }

    #[test]
    fn queue_section_parses_from_toml() {
        let toml = format!(
            r#"{MINIMAL_CFG}
            [queue]
            append_writers = 4
            pending_append_bytes = 1048576
            segment_target_bytes = 16777216
            compaction_dead_ratio = 0.75
            compaction_min_age = "30s"
            max_concurrent_compactions = 2
            disk_reserve_bytes = 2147483648
            checkpoint_interval_bytes = 4194304
            "#
        );
        let cfg = parse(&toml);
        let queue = cfg.queue.expect("queue section present");
        assert_eq!(queue.append_writers(), 4);
        assert_eq!(queue.pending_append_bytes(), 1_048_576);
        assert_eq!(queue.segment_target_bytes(), 16_777_216);
        assert_eq!(queue.compaction_dead_ratio(), 0.75);
        assert_eq!(queue.compaction_min_age(), Duration::from_secs(30));
        assert_eq!(queue.max_concurrent_compactions(), 2);
        assert_eq!(queue.disk_reserve_bytes(), 2_147_483_648);
        assert_eq!(queue.checkpoint_interval_bytes(), 4_194_304);
    }

    #[test]
    fn validate_accepts_defaults() {
        let queue = CfgQueue::default();
        assert!(queue.validate(25 * 1024 * 1024).is_ok());
    }

    #[test]
    fn validate_rejects_dead_ratio_out_of_range() {
        let queue = CfgQueue {
            compaction_dead_ratio: Some(1.5),
            ..CfgQueue::default()
        };
        assert!(queue.validate(25 * 1024 * 1024).is_err());
    }

    #[test]
    fn validate_rejects_segment_smaller_than_max_message_size() {
        let queue = CfgQueue {
            segment_target_bytes: Some(1024),
            ..CfgQueue::default()
        };
        assert!(queue.validate(25 * 1024 * 1024).is_err());
    }
}
