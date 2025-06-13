use config::{Config, File};
use miette::{IntoDiagnostic, Result};
use serde::Deserialize;
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

impl Cfg {
    pub fn load(cfg_path: &str) -> Result<Self> {
        let settings = Config::builder()
            .add_source(File::with_name(cfg_path))
            .build()
            .into_diagnostic()?;

        let cfg: Cfg = settings.try_deserialize().into_diagnostic()?;

        Ok(cfg)
    }
}
