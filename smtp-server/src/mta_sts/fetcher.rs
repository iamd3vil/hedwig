use std::{str, time::Duration};

use hickory_resolver::{
    error::ResolveErrorKind,
    name_server::{GenericConnector, TokioRuntimeProvider},
    AsyncResolver,
};
use miette::{Context, IntoDiagnostic, Result};
use tracing::{debug, warn};

use super::policy::{self, MtaStsPolicy, MtaStsTxtRecord};

const POLICY_FETCH_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_POLICY_SIZE_BYTES: usize = 64 * 1024;

pub struct MtaStsFetcher {
    resolver: AsyncResolver<GenericConnector<TokioRuntimeProvider>>,
    http_client: reqwest::Client,
}

impl MtaStsFetcher {
    pub fn new(resolver: AsyncResolver<GenericConnector<TokioRuntimeProvider>>) -> Self {
        let http_client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(POLICY_FETCH_TIMEOUT)
            .build()
            .expect("building MTA-STS HTTP client");

        Self {
            resolver,
            http_client,
        }
    }

    pub async fn lookup_txt(&self, domain: &str) -> Result<Option<MtaStsTxtRecord>> {
        let query_name = format!("_mta-sts.{domain}");
        debug!(domain = %domain, query_name = %query_name, "looking up MTA-STS TXT record");

        let lookup = match self.resolver.txt_lookup(query_name.as_str()).await {
            Ok(lookup) => lookup,
            Err(error) => {
                if matches!(error.kind(), ResolveErrorKind::NoRecordsFound { .. }) {
                    debug!(domain = %domain, "MTA-STS TXT record not found");
                    return Ok(None);
                }

                return Err(error)
                    .into_diagnostic()
                    .wrap_err_with(|| format!("looking up MTA-STS TXT record for {domain}"));
            }
        };

        let mut valid_records = Vec::new();
        for record in lookup.iter() {
            let mut record_value = String::new();
            for part in record.txt_data() {
                record_value.push_str(&String::from_utf8_lossy(part.as_ref()));
            }

            let record_value = record_value.trim().to_string();
            if record_value.starts_with("v=STSv1;") || record_value.starts_with("v=STSv1 ;") {
                valid_records.push(record_value);
            }
        }

        if valid_records.is_empty() {
            debug!(domain = %domain, "no valid MTA-STS TXT records found");
            return Ok(None);
        }

        if valid_records.len() > 1 {
            warn!(
                domain = %domain,
                count = valid_records.len(),
                "multiple valid MTA-STS TXT records found"
            );
            return Ok(None);
        }

        let record = &valid_records[0];
        match policy::parse_txt_record(record) {
            Ok(parsed) => Ok(Some(parsed)),
            Err(error) => {
                warn!(
                    domain = %domain,
                    record = %record,
                    ?error,
                    "failed to parse MTA-STS TXT record"
                );
                Ok(None)
            }
        }
    }

    pub async fn fetch_policy(&self, domain: &str) -> Result<Option<MtaStsPolicy>> {
        let url = format!("https://mta-sts.{domain}/.well-known/mta-sts.txt");
        debug!(domain = %domain, url = %url, "fetching MTA-STS policy");

        let response = match self.http_client.get(&url).send().await {
            Ok(response) => response,
            Err(error) => {
                warn!(domain = %domain, url = %url, ?error, "failed to fetch MTA-STS policy");
                return Ok(None);
            }
        };

        let status = response.status();
        if status != reqwest::StatusCode::OK {
            warn!(
                domain = %domain,
                url = %url,
                status = %status,
                "MTA-STS policy endpoint returned non-200 status"
            );
            return Ok(None);
        }

        match response.headers().get(reqwest::header::CONTENT_TYPE) {
            Some(value) => match value.to_str() {
                Ok(content_type) if content_type.to_ascii_lowercase().starts_with("text/plain") => {
                }
                Ok(content_type) => {
                    warn!(
                        domain = %domain,
                        url = %url,
                        content_type = %content_type,
                        "MTA-STS policy served with non-text/plain content type"
                    );
                }
                Err(error) => {
                    warn!(
                        domain = %domain,
                        url = %url,
                        ?error,
                        "MTA-STS policy returned invalid Content-Type header"
                    );
                }
            },
            None => {
                warn!(
                    domain = %domain,
                    url = %url,
                    "MTA-STS policy response missing Content-Type header"
                );
            }
        }

        // Pre-check Content-Length to avoid downloading oversized responses.
        if let Some(content_length) = response.content_length() {
            if content_length as usize > MAX_POLICY_SIZE_BYTES {
                warn!(
                    domain = %domain,
                    url = %url,
                    content_length,
                    max_size = MAX_POLICY_SIZE_BYTES,
                    "MTA-STS policy Content-Length exceeds size limit, skipping download"
                );
                return Ok(None);
            }
        }

        let body = match response.bytes().await {
            Ok(body) => body,
            Err(error) => {
                warn!(domain = %domain, url = %url, ?error, "failed to read MTA-STS policy body");
                return Ok(None);
            }
        };

        // Also check actual body size (Content-Length may be absent or wrong).
        if body.len() > MAX_POLICY_SIZE_BYTES {
            warn!(
                domain = %domain,
                url = %url,
                size = body.len(),
                max_size = MAX_POLICY_SIZE_BYTES,
                "MTA-STS policy body exceeds size limit"
            );
            return Ok(None);
        }

        let policy_body = match str::from_utf8(&body) {
            Ok(policy_body) => policy_body,
            Err(error) => {
                warn!(
                    domain = %domain,
                    url = %url,
                    ?error,
                    "MTA-STS policy body is not valid UTF-8"
                );
                return Ok(None);
            }
        };

        match policy::parse_policy(policy_body) {
            Ok(policy) => Ok(Some(policy)),
            Err(error) => {
                warn!(domain = %domain, url = %url, ?error, "failed to parse MTA-STS policy");
                Ok(None)
            }
        }
    }
}
