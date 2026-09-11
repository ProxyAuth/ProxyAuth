//! Configuration for automatic Let's Encrypt certificate renewal
//! (`certbot_renew: true` in `routes.yml`) — see the `acme` module for
//! the actual renewal mechanism.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AcmeConfig {
    /// How often (in seconds) ProxyAuth checks every `certbot_renew:
    /// true` vhost's certificate to decide whether it needs renewing.
    /// This is a check interval, not a renewal interval — most checks
    /// find nothing due and do nothing. Defaults to hourly (3600).
    #[serde(default = "default_check_interval_secs")]
    pub check_interval_secs: u64,

    /// Renew when the current certificate has this many days or fewer
    /// left before it expires. Let's Encrypt certificates are valid
    /// for 90 days; 30 is the widely-used convention (matches
    /// Certbot's own default) — renewing this early leaves comfortable
    /// margin for a failed attempt or two before anything is actually
    /// at risk of expiring.
    #[serde(default = "default_renew_before_days")]
    pub renew_before_days: i64,

    /// The ACME directory URL to use. Defaults to Let's Encrypt
    /// **production**. Point this at
    /// `"https://acme-staging-v02.api.letsencrypt.org/directory"`
    /// while testing this feature — Let's Encrypt's production
    /// environment has strict rate limits (a handful of certificates
    /// per registered domain per week) and issues certificates that
    /// aren't trusted any differently in staging, so there's no
    /// upside to testing against production first.
    #[serde(default = "default_directory_url")]
    pub directory_url: String,

    /// Contact email given to Let's Encrypt for the ACME account
    /// (expiry reminders, and how they'd reach you about an issue
    /// with your account). Optional — Let's Encrypt doesn't require
    /// one — but recommended.
    #[serde(default)]
    pub contact_email: Option<String>,

    /// Where the ACME account's credentials (its private key, issued
    /// once and reused for every future order — *not* the TLS
    /// certificate itself) are persisted between restarts. Without
    /// this, every restart would register a brand new Let's Encrypt
    /// account, which is wasteful and, at high enough frequency, is
    /// itself something Let's Encrypt rate-limits.
    #[serde(default = "default_account_credentials_path")]
    pub account_credentials_path: String,
}

impl Default for AcmeConfig {
    fn default() -> Self {
        Self {
            check_interval_secs: default_check_interval_secs(),
            renew_before_days: default_renew_before_days(),
            directory_url: default_directory_url(),
            contact_email: None,
            account_credentials_path: default_account_credentials_path(),
        }
    }
}

fn default_check_interval_secs() -> u64 {
    3600
}

fn default_renew_before_days() -> i64 {
    30
}

fn default_directory_url() -> String {
    "https://acme-v02.api.letsencrypt.org/directory".to_string()
}

fn default_account_credentials_path() -> String {
    "/etc/proxyauth/acme/account.json".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_documented_values() {
        let cfg = AcmeConfig::default();
        assert_eq!(cfg.check_interval_secs, 3600);
        assert_eq!(cfg.renew_before_days, 30);
        assert_eq!(
            cfg.directory_url,
            "https://acme-v02.api.letsencrypt.org/directory"
        );
        assert!(cfg.contact_email.is_none());
        assert_eq!(
            cfg.account_credentials_path,
            "/etc/proxyauth/acme/account.json"
        );
    }

    #[test]
    fn deserializes_from_empty_object() {
        let cfg: AcmeConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(cfg.check_interval_secs, 3600);
    }

    #[test]
    fn deserializes_staging_override() {
        let json = r#"{"directory_url": "https://acme-staging-v02.api.letsencrypt.org/directory"}"#;
        let cfg: AcmeConfig = serde_json::from_str(json).unwrap();
        assert!(cfg.directory_url.contains("staging"));
        // Everything else still falls back to its own default.
        assert_eq!(cfg.renew_before_days, 30);
    }
}
