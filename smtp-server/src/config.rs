use config::{Config, File};
use miette::{IntoDiagnostic, Result};
use serde::Deserialize;
use tracing::Level;

#[derive(Debug, Deserialize, Clone)]
pub struct Cfg {
    #[serde(default)]
    pub log: CfgLog,
    pub server: CfgServer,
    pub storage: CfgStorage,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CfgServer {
    pub addr: String,
    pub workers: Option<usize>,
    pub auth: Option<Vec<CfgAuth>>,
    pub dkim: Option<CfgDKIM>,
    pub disable_outbound: Option<bool>,
    pub outbound_local: Option<bool>,
    pub pool_size: Option<u64>,
    pub tls: Option<CfgTls>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CfgStorage {
    pub storage_type: String,
    pub base_path: String,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum DkimKeyType {
    Rsa,
    Ed25519,
}

impl Default for DkimKeyType {
    fn default() -> Self {
        DkimKeyType::Rsa
    }
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
