use config::{Config, File};
use miette::{IntoDiagnostic, Result};
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct Cfg {
    pub server: CfgServer,
    pub storage: CfgStorage,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CfgServer {
    pub addr: String,
    pub workers: Option<usize>,
    pub auth: Option<CfgAuth>,
    pub dkim: Option<CfgDKIM>,
    pub disable_outbound: Option<bool>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CfgStorage {
    pub storage_type: String,
    pub base_path: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CfgDKIM {
    pub domain: String,
    pub selector: String,
    pub private_key: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CfgAuth {
    pub username: String,
    pub password: String,
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
