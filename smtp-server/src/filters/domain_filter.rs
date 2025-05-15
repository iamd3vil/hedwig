use super::{FilterOutcome, MailFromFilter, RcptToFilter};
use crate::callbacks::extract_domain_from_path; // Assuming this path
use crate::config::FilterAction;
use async_trait::async_trait; // Assuming this path

pub struct DomainFilterImpl {
    domains: Vec<String>,
    action: FilterAction,
    filter_type_name: &'static str, // e.g., "from_domain_filter" or "to_domain_filter"
}

impl DomainFilterImpl {
    pub fn new(domains: Vec<String>, action: FilterAction, filter_type_name: &'static str) -> Self {
        Self {
            domains,
            action,
            filter_type_name,
        }
    }

    fn check_domain(&self, email_path: &str) -> FilterOutcome {
        let domain = match extract_domain_from_path(email_path) {
            Some(d) if !d.is_empty() => d,
            _ => {
                // If no domain can be extracted, and a wildcard "*" is not present in the domains list,
                // then this path cannot match any specific domain.
                if !self.domains.iter().any(|d| d == "*") {
                    return match self.action {
                        FilterAction::Allow => {
                            // If we are in an allow-list mode, and the path has no domain, it cannot be explicitly allowed.
                            // Denying here is a safer default.
                            FilterOutcome::Deny(format!(
                                "Address '{}' does not contain a domain for {} filter.",
                                email_path, self.filter_type_name
                            ))
                        }
                        FilterAction::Deny => {
                            // If we are in a deny-list mode, and the path has no domain, it cannot be explicitly denied.
                            // Allowing (or Neutral) here means it doesn't hit a deny rule.
                            FilterOutcome::Allow // Or Neutral, depending on how strictly "Deny" lists should work.
                        }
                    };
                }
                // If "*" is in domains, let the main logic handle it.
                String::new() // Effectively an empty domain for wildcard matching.
            }
        };

        let matched = self.domains.iter().any(|d| d == &domain || d == "*");

        match self.action {
            FilterAction::Allow => {
                if matched {
                    FilterOutcome::Allow
                } else {
                    FilterOutcome::Deny(format!(
                        "Domain '{}' (from path '{}') is not in the allowed list for {} filter.",
                        domain, email_path, self.filter_type_name
                    ))
                }
            }
            FilterAction::Deny => {
                if matched {
                    FilterOutcome::Deny(format!(
                        "Domain '{}' (from path '{}') is in the denied list for {} filter.",
                        domain, email_path, self.filter_type_name
                    ))
                } else {
                    FilterOutcome::Allow
                }
            }
        }
    }
}

#[async_trait]
impl MailFromFilter for DomainFilterImpl {
    async fn filter_mail_from(&self, from: &str) -> FilterOutcome {
        self.check_domain(from)
    }

    fn name(&self) -> &'static str {
        self.filter_type_name
    }
}

#[async_trait]
impl RcptToFilter for DomainFilterImpl {
    async fn filter_rcpt_to(&self, to: &str) -> FilterOutcome {
        self.check_domain(to)
    }

    fn name(&self) -> &'static str {
        self.filter_type_name
    }
}
