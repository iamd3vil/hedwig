//! Atomic preparation and publication of reloadable runtime configuration.

use std::{
    collections::HashMap,
    io::BufReader,
    sync::{Arc, Mutex},
};

use arc_swap::{ArcSwap, Guard};
use miette::{IntoDiagnostic, Result};
use rustls::pki_types::CertificateDer;
use serde_json::Value;
use tokio_rustls::{rustls::ServerConfig, TlsAcceptor};
use tracing::Level;

use crate::{
    callbacks::DomainFilters,
    config::{Cfg, FilterType},
    worker::{DkimSignerType, Worker},
};

pub(crate) struct RuntimeSnapshot {
    cfg: Cfg,
    pub(crate) from_domain_filters: DomainFilters,
    pub(crate) to_domain_filters: DomainFilters,
    pub(crate) auth: HashMap<String, String>,
    pub(crate) dkim_signer: Option<DkimSignerType>,
    tls_acceptors: Vec<Option<TlsAcceptor>>,
    log_level: Level,
}

pub struct RuntimeConfig {
    current: ArcSwap<RuntimeSnapshot>,
    reload_lock: Mutex<()>,
}

#[derive(Debug)]
pub enum ReloadError {
    Unsupported(Vec<String>),
    Preparation(PreparationError),
    LogApply,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparationError {
    pub component: &'static str,
    pub stage: &'static str,
    pub listener_index: Option<usize>,
}

impl PreparationError {
    fn new(component: &'static str, stage: &'static str) -> Self {
        Self {
            component,
            stage,
            listener_index: None,
        }
    }

    fn listener(component: &'static str, stage: &'static str, index: usize) -> Self {
        Self {
            component,
            stage,
            listener_index: Some(index),
        }
    }
}

impl std::fmt::Display for PreparationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.listener_index {
            Some(index) => write!(
                formatter,
                "{} {} for listener {index}",
                self.component, self.stage
            ),
            None => write!(formatter, "{} {}", self.component, self.stage),
        }
    }
}

impl std::error::Error for PreparationError {}
impl miette::Diagnostic for PreparationError {}

impl RuntimeConfig {
    pub fn new(cfg: Cfg) -> Result<Self> {
        Ok(Self {
            current: ArcSwap::from_pointee(RuntimeSnapshot::prepare(cfg)?),
            reload_lock: Mutex::new(()),
        })
    }

    pub(crate) fn load(&self) -> Guard<Arc<RuntimeSnapshot>> {
        self.current.load()
    }

    pub fn tls_acceptor(&self, listener_index: usize) -> Option<TlsAcceptor> {
        self.current.load().tls_acceptors[listener_index].clone()
    }

    pub fn reload(
        &self,
        candidate: Cfg,
        apply_log_level: impl FnOnce(Level) -> Result<()>,
    ) -> std::result::Result<(), ReloadError> {
        // Reads stay lock-free, while writers serialize validation, tracing
        // update, and publication so two API callers cannot commit out of order.
        let _reload_guard = self.reload_lock.lock().map_err(|_| {
            ReloadError::Preparation(PreparationError::new("runtime", "reload lock poisoned"))
        })?;
        let old = self.current.load_full();
        let unsupported = unsupported_changes(&old.cfg, &candidate).map_err(|_| {
            ReloadError::Preparation(PreparationError::new("configuration", "comparison failed"))
        })?;
        if !unsupported.is_empty() {
            return Err(ReloadError::Unsupported(unsupported));
        }
        let prepared =
            Arc::new(RuntimeSnapshot::prepare(candidate).map_err(ReloadError::Preparation)?);
        apply_log_level(prepared.log_level).map_err(|_| ReloadError::LogApply)?;
        self.current.store(prepared);
        Ok(())
    }
}

impl RuntimeSnapshot {
    fn prepare(cfg: Cfg) -> std::result::Result<Self, PreparationError> {
        let log_level = cfg
            .log
            .level
            .parse::<Level>()
            .map_err(|_| PreparationError::new("log.level", "parse"))?;
        let auth = cfg
            .server
            .auth
            .iter()
            .flatten()
            .map(|a| (a.username.clone(), a.password.clone()))
            .collect();
        let dkim_signer = match &cfg.server.dkim {
            Some(dkim) => {
                let key = std::fs::read_to_string(&dkim.private_key)
                    .map_err(|_| PreparationError::new("server.dkim.private_key", "read"))?;
                Some(
                    Worker::create_dkim_signer(dkim, &key)
                        .map_err(|_| PreparationError::new("server.dkim.private_key", "parse"))?,
                )
            }
            None => None,
        };
        let tls_acceptors = cfg
            .server
            .listeners
            .iter()
            .enumerate()
            .map(|(index, listener)| {
                listener
                    .tls
                    .as_ref()
                    .map(|tls| build_tls_acceptor(tls, index))
                    .transpose()
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(Self {
            from_domain_filters: DomainFilters::build(&cfg, |t| {
                matches!(t, FilterType::FromDomain)
            }),
            to_domain_filters: DomainFilters::build(&cfg, |t| matches!(t, FilterType::ToDomain)),
            auth,
            dkim_signer,
            tls_acceptors,
            log_level,
            cfg,
        })
    }
}

fn build_tls_acceptor(
    tls: &crate::config::CfgTls,
    listener_index: usize,
) -> std::result::Result<TlsAcceptor, PreparationError> {
    let cert = std::fs::File::open(&tls.cert_path).map_err(|_| {
        PreparationError::listener("server.listeners.tls.certificate", "read", listener_index)
    })?;
    let key = std::fs::File::open(&tls.key_path).map_err(|_| {
        PreparationError::listener("server.listeners.tls.private_key", "read", listener_index)
    })?;
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut BufReader::new(cert))
        .collect::<std::io::Result<_>>()
        .map_err(|_| {
            PreparationError::listener("server.listeners.tls.certificate", "parse", listener_index)
        })?;
    if certs.is_empty() {
        return Err(PreparationError::listener(
            "server.listeners.tls.certificate",
            "parse",
            listener_index,
        ));
    }
    let key = rustls_pemfile::private_key(&mut BufReader::new(key))
        .map_err(|_| {
            PreparationError::listener("server.listeners.tls.private_key", "parse", listener_index)
        })?
        .ok_or_else(|| {
            PreparationError::listener("server.listeners.tls.private_key", "parse", listener_index)
        })?;
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|_| {
            PreparationError::listener(
                "server.listeners.tls",
                "validate certificate/private key",
                listener_index,
            )
        })?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

fn unsupported_changes(old: &Cfg, new: &Cfg) -> Result<Vec<String>> {
    let old_value = serde_json::to_value(old).into_diagnostic()?;
    let new_value = serde_json::to_value(new).into_diagnostic()?;
    let mut changed = Vec::new();
    collect_changes("", &old_value, &new_value, &mut changed);
    let auth_reloadable = old.server.auth.is_some() == new.server.auth.is_some();
    changed.retain(|path| {
        if path == "log.level" || path == "filters" || path.starts_with("filters[") {
            return false;
        }
        if path == "server.dkim" || path.starts_with("server.dkim.") {
            return false;
        }
        if auth_reloadable && (path == "server.auth" || path.starts_with("server.auth[")) {
            return false;
        }
        if path.starts_with("server.listeners[")
            && (path.ends_with(".tls.cert_path") || path.ends_with(".tls.key_path"))
        {
            return false;
        }
        true
    });
    changed.sort();
    changed.dedup();
    for path in &mut changed {
        if path.starts_with("server.rate_limits.domain_limits.") {
            *path = "server.rate_limits.domain_limits".to_string();
        }
    }
    changed.sort();
    changed.dedup();
    Ok(changed)
}

fn collect_changes(prefix: &str, old: &Value, new: &Value, out: &mut Vec<String>) {
    match (old, new) {
        (Value::Object(a), Value::Object(b)) => {
            let mut keys: Vec<_> = a.keys().chain(b.keys()).collect();
            keys.sort();
            keys.dedup();
            for key in keys {
                let path = if prefix.is_empty() {
                    key.to_string()
                } else {
                    format!("{prefix}.{key}")
                };
                match (a.get(key), b.get(key)) {
                    (Some(x), Some(y)) => collect_changes(&path, x, y, out),
                    _ => out.push(path),
                }
            }
        }
        (Value::Array(a), Value::Array(b)) => {
            for index in 0..a.len().max(b.len()) {
                let path = format!("{prefix}[{index}]");
                match (a.get(index), b.get(index)) {
                    (Some(x), Some(y)) => collect_changes(&path, x, y, out),
                    _ => out.push(path),
                }
            }
        }
        _ if old != new => out.push(prefix.to_string()),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        CfgAuth, CfgDKIM, CfgListener, CfgLog, CfgRateLimits, CfgServer, CfgStorage, CfgTls,
        DkimKeyType, TlsMode,
    };

    fn fixture(path: &str) -> String {
        format!("{}/../dev/certs/{path}", env!("CARGO_MANIFEST_DIR"))
    }

    fn cfg() -> Cfg {
        Cfg {
            log: CfgLog::default(),
            server: CfgServer {
                listeners: vec![CfgListener {
                    addr: "127.0.0.1:2525".into(),
                    tls: None,
                }],
                workers: Some(1),
                max_retries: None,
                auth: Some(vec![CfgAuth {
                    username: "old-user".into(),
                    password: "old-secret".into(),
                }]),
                dkim: None,
                disable_outbound: None,
                outbound_local: None,
                helo_hostname: None,
                hostname: None,
                smtp: None,
                pool_size: None,
                rate_limits: None,
                metrics: None,
                health: None,
                queue_buffer: None,
                max_connections: None,
                max_message_size: None,
                cmd_timeout: None,
                data_timeout: None,
            },
            storage: CfgStorage {
                storage_type: "fs".into(),
                base_path: "/tmp/hedwig-reload-test".into(),
                cleanup: None,
            },
            filters: None,
            queue: None,
        }
    }

    fn assert_snapshot_retained(runtime: &RuntimeConfig, before: &Arc<RuntimeSnapshot>) {
        assert!(Arc::ptr_eq(before, &runtime.current.load_full()));
        assert_eq!(
            runtime.load().auth.get("old-user").map(String::as_str),
            Some("old-secret")
        );
    }

    #[test]
    fn unsupported_changes_name_fields_without_values() {
        let old = cfg();
        let mut new = old.clone();
        new.server.workers = Some(77);
        new.storage.base_path = "/secret/customer/path".into();
        let fields = unsupported_changes(&old, &new).unwrap();
        assert_eq!(fields, vec!["server.workers", "storage.base_path"]);
        let rendered = fields.join(", ");
        assert!(!rendered.contains("77"));
        assert!(!rendered.contains("customer"));
    }

    #[test]
    fn unsupported_map_keys_collapse_to_the_schema_field() {
        let old = cfg();
        let mut new = old.clone();
        new.server.rate_limits = Some(CfgRateLimits {
            enabled: true,
            default_limit: None,
            domain_limits: Some(HashMap::from([(
                "candidate-controlled-secret.test".into(),
                10,
            )])),
        });
        let fields = unsupported_changes(&old, &new).unwrap();
        assert!(fields.contains(&"server.rate_limits".to_string()));
        assert!(!fields.join(",").contains("candidate-controlled"));
    }

    #[test]
    fn auth_presence_change_is_restart_only() {
        let old = cfg();
        let mut new = old.clone();
        new.server.auth = None;
        assert_eq!(
            unsupported_changes(&old, &new).unwrap(),
            vec!["server.auth"]
        );
    }

    #[test]
    fn enabling_auth_is_restart_only() {
        let mut old = cfg();
        old.server.auth = None;
        let new = cfg();
        assert_eq!(
            unsupported_changes(&old, &new).unwrap(),
            vec!["server.auth"]
        );
    }

    #[test]
    fn listener_shape_mode_address_and_log_format_are_restart_only() {
        let mut old = cfg();
        old.server.listeners[0].tls = Some(CfgTls {
            cert_path: fixture("server.pem"),
            key_path: fixture("server-key.pem"),
            mode: TlsMode::Implicit,
        });
        let mut new = old.clone();
        new.log.format = "json".into();
        new.server.listeners[0].addr = "127.0.0.1:2526".into();
        new.server.listeners[0].tls.as_mut().unwrap().mode = TlsMode::Starttls;
        new.server.listeners.push(CfgListener {
            addr: "127.0.0.1:2527".into(),
            tls: None,
        });
        assert_eq!(
            unsupported_changes(&old, &new).unwrap(),
            vec![
                "log.format",
                "server.listeners[0].addr",
                "server.listeners[0].tls.mode",
                "server.listeners[1]",
            ]
        );
    }

    #[test]
    fn password_only_reload_updates_credentials() {
        let runtime = RuntimeConfig::new(cfg()).unwrap();
        let mut new = cfg();
        new.server.auth.as_mut().unwrap()[0].password = "new-secret".into();
        runtime.reload(new, |_| Ok(())).unwrap();
        assert_eq!(
            runtime.load().auth.get("old-user").map(String::as_str),
            Some("new-secret")
        );
    }

    #[test]
    fn unsupported_changes_are_rejected_before_resource_preparation() {
        let runtime = RuntimeConfig::new(cfg()).unwrap();
        let before = runtime.current.load_full();
        let mut new = cfg();
        new.server.workers = Some(99);
        new.server.dkim = Some(CfgDKIM {
            domain: "example.test".into(),
            selector: "new".into(),
            private_key: "/definitely/missing/dkim.pem".into(),
            key_type: DkimKeyType::Rsa,
        });
        let error = runtime.reload(new, |_| Ok(())).unwrap_err();
        assert!(matches!(
            error,
            ReloadError::Unsupported(fields) if fields == vec!["server.workers"]
        ));
        assert_snapshot_retained(&runtime, &before);
    }

    #[test]
    fn log_apply_failure_retains_snapshot() {
        let runtime = RuntimeConfig::new(cfg()).unwrap();
        let before = runtime.current.load_full();
        let mut new = cfg();
        new.log.level = "debug".into();
        let error = runtime.reload(new, |_| Err(miette::miette!("injected log failure")));
        assert!(error.is_err());
        assert_snapshot_retained(&runtime, &before);
    }

    #[test]
    fn invalid_log_level_reports_safe_parse_stage_and_retains_snapshot() {
        let runtime = RuntimeConfig::new(cfg()).unwrap();
        let before = runtime.current.load_full();
        let mut new = cfg();
        new.log.level = "candidate-secret-not-a-level".into();
        assert!(matches!(
            runtime.reload(new, |_| Ok(())),
            Err(ReloadError::Preparation(PreparationError {
                component: "log.level",
                stage: "parse",
                listener_index: None,
            }))
        ));
        assert_snapshot_retained(&runtime, &before);
    }

    #[test]
    fn dkim_preparation_failure_retains_snapshot() {
        let runtime = RuntimeConfig::new(cfg()).unwrap();
        let before = runtime.current.load_full();
        let mut new = cfg();
        new.server.dkim = Some(CfgDKIM {
            domain: "example.test".into(),
            selector: "new".into(),
            private_key: "/definitely/missing/dkim.pem".into(),
            key_type: DkimKeyType::Rsa,
        });
        assert!(matches!(
            runtime.reload(new, |_| Ok(())),
            Err(ReloadError::Preparation(PreparationError {
                component: "server.dkim.private_key",
                stage: "read",
                listener_index: None,
            }))
        ));
        assert_snapshot_retained(&runtime, &before);
    }

    #[test]
    fn dkim_parse_failure_is_distinct_from_read_failure() {
        let key = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(key.path(), "candidate-secret-invalid-pem").unwrap();
        let runtime = RuntimeConfig::new(cfg()).unwrap();
        let before = runtime.current.load_full();
        let mut new = cfg();
        new.server.dkim = Some(CfgDKIM {
            domain: "example.test".into(),
            selector: "new".into(),
            private_key: key.path().to_string_lossy().into_owned(),
            key_type: DkimKeyType::Rsa,
        });
        let error = runtime.reload(new, |_| Ok(())).unwrap_err();
        assert!(matches!(
            error,
            ReloadError::Preparation(PreparationError {
                component: "server.dkim.private_key",
                stage: "parse",
                listener_index: None,
            })
        ));
        assert!(!format!("{error:?}").contains("candidate-secret"));
        assert_snapshot_retained(&runtime, &before);
    }

    #[test]
    fn dkim_rotation_disable_and_reenable_publish_atomically() {
        let mut initial = cfg();
        initial.server.dkim = Some(CfgDKIM {
            domain: "example.test".into(),
            selector: "one".into(),
            private_key: fixture("dkim-private.pem"),
            key_type: DkimKeyType::Rsa,
        });
        let runtime = RuntimeConfig::new(initial.clone()).unwrap();
        let mut rotated = initial.clone();
        rotated.server.dkim.as_mut().unwrap().selector = "two".into();
        runtime.reload(rotated, |_| Ok(())).unwrap();
        assert_eq!(
            runtime.load().cfg.server.dkim.as_ref().unwrap().selector,
            "two"
        );
        let mut disabled = initial.clone();
        disabled.server.dkim = None;
        runtime.reload(disabled, |_| Ok(())).unwrap();
        assert!(runtime.load().dkim_signer.is_none());
        runtime.reload(initial, |_| Ok(())).unwrap();
        assert!(runtime.load().dkim_signer.is_some());
    }

    #[test]
    fn tls_preparation_failure_retains_snapshot() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut initial = cfg();
        initial.server.listeners[0].tls = Some(CfgTls {
            cert_path: fixture("server.pem"),
            key_path: fixture("server-key.pem"),
            mode: TlsMode::Implicit,
        });
        let runtime = RuntimeConfig::new(initial.clone()).unwrap();
        let before = runtime.current.load_full();
        let mut broken = initial;
        broken.server.listeners[0].tls.as_mut().unwrap().cert_path =
            "/definitely/missing/cert.pem".into();
        assert!(matches!(
            runtime.reload(broken, |_| Ok(())),
            Err(ReloadError::Preparation(PreparationError {
                component: "server.listeners.tls.certificate",
                stage: "read",
                listener_index: Some(0),
            }))
        ));
        assert_snapshot_retained(&runtime, &before);
    }

    #[test]
    fn tls_parse_failure_reports_component_stage_and_listener() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut initial = cfg();
        initial.server.listeners[0].tls = Some(CfgTls {
            cert_path: fixture("server.pem"),
            key_path: fixture("server-key.pem"),
            mode: TlsMode::Implicit,
        });
        let runtime = RuntimeConfig::new(initial.clone()).unwrap();
        let before = runtime.current.load_full();
        let cert = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(cert.path(), "candidate-secret-invalid-cert").unwrap();
        initial.server.listeners[0].tls.as_mut().unwrap().cert_path =
            cert.path().to_string_lossy().into_owned();
        let error = runtime.reload(initial, |_| Ok(())).unwrap_err();
        assert!(matches!(
            error,
            ReloadError::Preparation(PreparationError {
                component: "server.listeners.tls.certificate",
                stage: "parse",
                listener_index: Some(0),
            })
        ));
        assert!(!format!("{error:?}").contains("candidate-secret"));
        assert_snapshot_retained(&runtime, &before);
    }
}
