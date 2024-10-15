use config::{Config, File};
use miette::{IntoDiagnostic, Result};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Cfg {
    pub server: CfgServer,
    pub storage: CfgStorage,
}

#[derive(Debug, Deserialize)]
pub struct CfgServer {
    pub addr: String,
    pub workers: Option<usize>,
    pub dkim: Option<CfgDKIM>,
}

#[derive(Debug, Deserialize)]
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
