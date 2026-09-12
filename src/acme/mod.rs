//! Periodic scan: for every `routes.yml` vhost with `certbot_renew:
//! true`, checks whether its certificate is due for renewal (missing
//! entirely, or within `AcmeConfig.renew_before_days` of expiring) and
//! runs `renew::renew_certificate` for it if so.

pub mod challenge;
pub mod renew;

use crate::config::acme::AcmeConfig;
use crate::config::config::RouteRule;
use std::collections::HashMap;
use std::path::PathBuf;
use tracing::{error, info, warn};

/// One vhost that opted into automatic renewal, with the cert/key
/// paths its `vhost_cert` points at.
pub struct ManagedVhost {
    /// Every DNS name this one certificate has to cover, in
    /// `routes.yml` order.
    ///
    /// This was a single `String`, which quietly broke any vhost group
    /// listing more than one name: `collect_managed_vhosts` produced
    /// one entry per name, each pointing at the *same* `vhost_cert`
    /// path, so each issued its own single-SAN certificate into that
    /// path and overwrote the previous one. The file ended up holding
    /// a certificate valid for whichever name happened to be renewed
    /// last, and every other name in the group was left uncovered —
    /// the equivalent of running certbot once per `-d` instead of once
    /// with every `-d` together. It also burned one ACME order per
    /// name, which counts against Let's Encrypt's rate limits.
    pub names: Vec<String>,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

impl ManagedVhost {
    /// The name this certificate is identified by in logs and CLI
    /// output. Never empty in practice — both collectors only ever
    /// build a `ManagedVhost` from at least one name.
    pub fn primary(&self) -> &str {
        self.names.first().map(String::as_str).unwrap_or("<unnamed>")
    }

    /// Every name, for messages where knowing the full SAN set
    /// matters more than brevity.
    pub fn display_names(&self) -> String {
        self.names.join(", ")
    }
}

/// Outcome of one `check_and_maybe_renew` call — lets a caller (the
/// periodic task, or `proxyauth certbot renew`) report the result its
/// own way. The periodic task logs via `tracing`, which — since
/// `"local"` writes straight to `/var/log/proxyauth/proxyauth.log`
/// rather than stdout — an interactive CLI invocation wouldn't show at
/// all on its own; the CLI handler prints this outcome directly
/// instead, on top of (not instead of) the same `tracing` calls.
pub enum RenewOutcome {
    /// Not due yet, `renew_before_days` not reached — carries how many
    /// days are actually left. Never produced when `force: true` was
    /// passed to `check_and_maybe_renew`.
    NotDue { days_left: i64 },
    Renewed,
    Failed(String),
}

/// Collects every distinct vhost across `routes` that has
/// `certbot_renew: true` on at least one of its routes, together with
/// the `vhost_cert` cert/key paths configured for it (also possibly on
/// a *different* route sharing the same vhost — mirrors
/// `tls::load_vhost_resolvers`'s own lookup, which already handles
/// vhost/cert config living on separate route entries).
///
/// A vhost with `certbot_renew: true` but no usable `vhost_cert`
/// (missing entirely, or missing the `cert`/`key` keys) is skipped
/// with a warning — there's nowhere to write a renewed certificate to,
/// and more importantly nothing watching that path to hot-reload it,
/// so silently proceeding would renew a certificate nobody ever
/// actually starts using.
pub fn collect_managed_vhosts(routes: &[RouteRule]) -> Vec<ManagedVhost> {
    let mut wants_renewal: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut cert_paths: HashMap<String, (String, String)> = HashMap::new();

    for rule in routes {
        if rule.vhost.is_empty() {
            continue;
        }
        if rule.certbot_renew {
            for host in &rule.vhost {
                wants_renewal.insert(host.to_ascii_lowercase());
            }
        }
        if let (Some(cert), Some(key)) =
            (rule.vhost_cert.get("cert"), rule.vhost_cert.get("key"))
        {
            for host in &rule.vhost {
                cert_paths
                    .entry(host.to_ascii_lowercase())
                    .or_insert_with(|| (cert.clone(), key.clone()));
            }
        }
    }

    // Grouped by destination cert/key path, not by name: the path is
    // what defines one issuance unit. Two names writing into the same
    // `fullchain.pem` must end up on one certificate carrying both as
    // SANs — issuing one certificate per name into a shared path meant
    // each overwrote the last.
    //
    // Names are kept in `routes.yml` order (`wants_renewal` is walked
    // via `routes`, not via the set) so the certificate's primary name
    // is stable across runs rather than varying with hash iteration
    // order.
    let mut grouped: Vec<((String, String), Vec<String>)> = Vec::new();
    for rule in routes {
        for host in &rule.vhost {
            let host = host.to_ascii_lowercase();
            if !wants_renewal.contains(&host) {
                continue;
            }
            let Some(paths) = cert_paths.get(&host) else {
                continue;
            };
            match grouped.iter_mut().find(|(p, _)| p == paths) {
                Some((_, names)) => {
                    if !names.contains(&host) {
                        names.push(host);
                    }
                }
                None => grouped.push((paths.clone(), vec![host])),
            }
        }
    }

    for vhost in &wants_renewal {
        if !cert_paths.contains_key(vhost) {
            warn!(
                "acme: {vhost} has certbot_renew: true but no vhost_cert (cert/key) configured for it anywhere in routes.yml — nothing to renew into, skipping. Set vhost_cert for this vhost to e.g. /etc/proxyauth/cert/{vhost}/fullchain.pem and .../privkey.pem."
            );
        }
    }

    grouped
        .into_iter()
        .map(|((cert, key), names)| ManagedVhost {
            names,
            cert_path: PathBuf::from(cert),
            key_path: PathBuf::from(key),
        })
        .collect()
}

/// Every name in `routes` whose `vhost_cert` points at `cert_path` —
/// i.e. every name that must appear on that one certificate. Used by
/// `proxyauth certbot renew <vhost>`, so naming a single member of a
/// group still renews the whole group: reissuing just that one name
/// would overwrite the shared file with a certificate no longer
/// covering its siblings, which is the very bug grouping exists to
/// prevent.
pub fn names_sharing_cert(routes: &[RouteRule], cert_path: &std::path::Path) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for rule in routes {
        let Some(cert) = rule.vhost_cert.get("cert") else {
            continue;
        };
        if std::path::Path::new(cert) != cert_path {
            continue;
        }
        for host in &rule.vhost {
            let host = host.to_ascii_lowercase();
            if !names.contains(&host) {
                names.push(host);
            }
        }
    }
    names
}

/// Every distinct vhost across `routes` that has a usable `vhost_cert`
/// (both `cert` and `key`), **regardless of `certbot_renew`** — unlike
/// `collect_managed_vhosts`, this also includes vhosts whose
/// certificate is managed manually or by an external tool. Used by
/// `proxyauth certbot check all`, which is read-only and has no reason
/// to limit itself to only ACME-managed vhosts the way renewal does.
pub fn collect_all_vhost_certs(routes: &[RouteRule]) -> Vec<ManagedVhost> {
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut out = Vec::new();

    for rule in routes {
        if rule.vhost.is_empty() {
            continue;
        }
        let Some((cert, key)) = rule.vhost_cert.get("cert").zip(rule.vhost_cert.get("key"))
        else {
            continue;
        };
        for host in &rule.vhost {
            let host = host.to_ascii_lowercase();
            if !seen.insert(host.clone()) {
                continue;
            }
            // Same grouping as `collect_managed_vhosts`: names sharing
            // a cert path are one certificate, so they are one entry
            // here too rather than N identical-looking lines in
            // `certbot check all`.
            match out
                .iter_mut()
                .find(|mv: &&mut ManagedVhost| mv.cert_path == PathBuf::from(cert))
            {
                Some(mv) => mv.names.push(host),
                None => out.push(ManagedVhost {
                    names: vec![host],
                    cert_path: PathBuf::from(cert),
                    key_path: PathBuf::from(key),
                }),
            }
        }
    }
    out
}

/// Days left before `cert_path`'s certificate expires. `None` if the
/// file doesn't exist yet (the very first certificate for a brand new
/// vhost hasn't been issued — treated as "renewal due immediately",
/// same as an expired one) or can't be parsed (also treated as due,
/// with a warning, rather than silently never renewing a broken file).
pub fn days_until_expiry(cert_path: &std::path::Path) -> Option<i64> {
    let bytes = std::fs::read(cert_path).ok()?;
    let (_, pem) = x509_parser::pem::parse_x509_pem(&bytes).ok()?;
    let cert = pem.parse_x509().ok()?;
    let not_after = cert.validity().not_after;
    let now = x509_parser::time::ASN1Time::now();
    Some((not_after.timestamp() - now.timestamp()) / 86400)
}

/// A snapshot of the useful bits of an X.509 certificate, for
/// `proxyauth certbot check` — everything a human wants to see at a
/// glance without reaching for `openssl x509 -text` themselves.
pub struct CertInfo {
    pub subject: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub days_left: i64,
    pub serial: String,
    pub san: Vec<String>,
}

/// Reads and parses the certificate at `cert_path`. `Err` covers both
/// "no file there at all" and "file there but not a valid
/// certificate" — both are just "nothing readable to report on" from
/// the caller's point of view, with the underlying reason in the
/// message for whichever one it actually was.
pub fn read_cert_info(cert_path: &std::path::Path) -> Result<CertInfo, String> {
    let bytes = std::fs::read(cert_path)
        .map_err(|e| format!("failed to read {}: {e}", cert_path.display()))?;
    let (_, pem) = x509_parser::pem::parse_x509_pem(&bytes)
        .map_err(|e| format!("failed to parse {} as PEM: {e}", cert_path.display()))?;
    let cert = pem
        .parse_x509()
        .map_err(|e| format!("failed to parse {} as X.509: {e}", cert_path.display()))?;

    let not_after = cert.validity().not_after;
    let now = x509_parser::time::ASN1Time::now();
    let days_left = (not_after.timestamp() - now.timestamp()) / 86400;

    let san = match cert.subject_alternative_name() {
        Ok(Some(ext)) => ext
            .value
            .general_names
            .iter()
            .map(|n| n.to_string())
            .collect(),
        _ => Vec::new(),
    };

    Ok(CertInfo {
        subject: cert.subject().to_string(),
        issuer: cert.issuer().to_string(),
        not_before: cert.validity().not_before.to_string(),
        not_after: not_after.to_string(),
        days_left,
        serial: cert.raw_serial_as_string(),
        san,
    })
}

/// Finds the `vhost_cert` cert/key paths configured for `vhost`,
/// across every route (not just ones with `certbot_renew: true` —
/// unlike `collect_managed_vhosts`, used by the periodic scan). A
/// manual `proxyauth certbot renew <vhost>` invocation is itself
/// sufficient intent to renew; it doesn't require `certbot_renew: true`
/// to *also* be set on that vhost, so this also works for someone who
/// wants ACME-issued certificates but prefers only ever triggering
/// renewal by hand.
pub fn find_vhost_cert_paths(
    routes: &[RouteRule],
    vhost: &str,
) -> Option<(std::path::PathBuf, std::path::PathBuf)> {
    let vhost = vhost.to_ascii_lowercase();
    for rule in routes {
        if !rule.vhost.iter().any(|h| h.to_ascii_lowercase() == vhost) {
            continue;
        }
        if let (Some(cert), Some(key)) =
            (rule.vhost_cert.get("cert"), rule.vhost_cert.get("key"))
        {
            return Some((std::path::PathBuf::from(cert), std::path::PathBuf::from(key)));
        }
    }
    None
}

/// Checks one managed vhost and renews it if due (or unconditionally,
/// if `force` is set). Never panics — a single vhost's renewal failing
/// (a Let's Encrypt outage, a transient network error, a
/// misconfiguration) must never stop every *other* vhost's check in
/// the same scan, and must never take down the periodic task itself;
/// callers get the outcome back instead of an `Err` to propagate.
pub async fn check_and_maybe_renew(
    vhost: &ManagedVhost,
    acme_cfg: &AcmeConfig,
    force: bool,
) -> RenewOutcome {
    if !force {
        match days_until_expiry(&vhost.cert_path) {
            Some(days) if days > acme_cfg.renew_before_days => {
                return RenewOutcome::NotDue { days_left: days };
            }
            Some(days) => {
                info!(
                    "acme: {} has {days} day(s) left (renew_before_days: {}), renewing",
                    vhost.display_names(),
                    acme_cfg.renew_before_days
                );
            }
            None => {
                info!(
                    "acme: {} has no existing/readable certificate at {} — issuing one",
                    vhost.display_names(),
                    vhost.cert_path.display()
                );
            }
        }
    } else {
        info!("acme: {} — forced renewal requested", vhost.display_names());
    }

    match renew::renew_certificate(&vhost.names, &vhost.cert_path, &vhost.key_path, acme_cfg).await
    {
        Ok(()) => {
            info!("acme: renewal succeeded for {}", vhost.display_names());
            RenewOutcome::Renewed
        }
        Err(e) => {
            error!(
                "acme: renewal FAILED for {} — the currently valid certificate keeps being used: {e}",
                vhost.display_names()
            );
            RenewOutcome::Failed(e)
        }
    }
}


/// Runs one full scan over every `certbot_renew: true` vhost in
/// `routes`, immediately (not on a timer) — used both by the periodic
/// task below and available for a manual on-demand trigger if one is
/// ever wired up (e.g. a CLI command or admin endpoint).
pub async fn run_scan(routes: &[RouteRule], acme_cfg: &AcmeConfig) {
    let managed = collect_managed_vhosts(routes);
    if managed.is_empty() {
        return;
    }
    for vhost in &managed {
        // Outcome already logged inside check_and_maybe_renew via
        // tracing — the periodic scan itself has nothing further to
        // do with it.
        let _ = check_and_maybe_renew(vhost, acme_cfg, false).await;
    }
}

/// Spawns the periodic scan, running every `acme_cfg.check_interval_secs`
/// (default hourly). `routes`/`acme_cfg` are read once here and moved
/// into the task — matching this codebase's existing periodic-task
/// pattern (e.g. the database refresh tasks), not intended to observe
/// a `routes.yml`/`config.json` change without a restart, same as
/// everything else in config today except TLS certificates themselves.
pub fn spawn_periodic_scan(routes: std::sync::Arc<Vec<RouteRule>>, acme_cfg: AcmeConfig) {
    tokio::spawn(async move {
        let mut ticker =
            tokio::time::interval(std::time::Duration::from_secs(acme_cfg.check_interval_secs.max(1)));
        ticker.tick().await; // first tick fires immediately; skip it, run_scan below covers startup
        run_scan(&routes, &acme_cfg).await; // check once right at startup too, don't wait a full interval
        loop {
            ticker.tick().await;
            run_scan(&routes, &acme_cfg).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap as StdHashMap;

    fn rule(vhost: &[&str], certbot_renew: bool, cert_kv: Option<(&str, &str)>) -> RouteRule {
        // `prefix` is RouteRule's one genuinely required field (no
        // serde default) — every other field does have one, but this
        // helper still needs to supply *something* for `prefix`
        // specifically.
        let mut r: RouteRule = serde_json::from_str(r#"{"prefix": "/"}"#)
            .expect("RouteRule must deserialize given just prefix — every other field has a serde default");
        r.vhost = vhost.iter().map(|s| s.to_string()).collect();
        r.certbot_renew = certbot_renew;
        if let Some((cert, key)) = cert_kv {
            let mut m = StdHashMap::new();
            m.insert("cert".to_string(), cert.to_string());
            m.insert("key".to_string(), key.to_string());
            r.vhost_cert = m;
        }
        r
    }

    #[test]
    fn collects_vhost_with_rew_and_cert_on_same_route() {
        let routes = vec![rule(
            &["a.example.com"],
            true,
            Some(("/etc/proxyauth/cert/a.example.com/fullchain.pem", "/etc/proxyauth/cert/a.example.com/privkey.pem")),
        )];
        let managed = collect_managed_vhosts(&routes);
        assert_eq!(managed.len(), 1);
        assert_eq!(managed[0].names, vec!["a.example.com".to_string()]);
    }

    #[test]
    fn collects_vhost_with_rew_and_cert_on_different_routes() {
        // certbot_renew on one route, vhost_cert on another — both for
        // the same vhost, mirroring how vhost_cert lookups already
        // work elsewhere in this codebase.
        let routes = vec![
            rule(&["b.example.com"], true, None),
            rule(
                &["b.example.com"],
                false,
                Some(("/etc/proxyauth/cert/b.example.com/fullchain.pem", "/etc/proxyauth/cert/b.example.com/privkey.pem")),
            ),
        ];
        let managed = collect_managed_vhosts(&routes);
        assert_eq!(managed.len(), 1);
        assert_eq!(managed[0].names, vec!["b.example.com".to_string()]);
    }

    #[test]
    fn skips_rew_without_any_cert_path() {
        let routes = vec![rule(&["c.example.com"], true, None)];
        let managed = collect_managed_vhosts(&routes);
        assert!(managed.is_empty(), "no vhost_cert anywhere -> nothing to manage");
    }

    #[test]
    fn ignores_cert_without_rew() {
        // vhost_cert alone (no certbot_renew: true anywhere) must NOT
        // opt a vhost into automatic renewal — that would silently
        // start managing certificates for vhosts an operator never
        // asked ProxyAuth to touch.
        let routes = vec![rule(
            &["d.example.com"],
            false,
            Some(("/etc/proxyauth/cert/d.example.com/fullchain.pem", "/etc/proxyauth/cert/d.example.com/privkey.pem")),
        )];
        let managed = collect_managed_vhosts(&routes);
        assert!(managed.is_empty());
    }

    #[test]
    fn dedupes_same_vhost_listed_on_multiple_rew_routes() {
        let routes = vec![
            rule(
                &["e.example.com"],
                true,
                Some(("/etc/proxyauth/cert/e.example.com/fullchain.pem", "/etc/proxyauth/cert/e.example.com/privkey.pem")),
            ),
            rule(&["e.example.com"], true, None),
        ];
        let managed = collect_managed_vhosts(&routes);
        assert_eq!(managed.len(), 1, "the same vhost must not be scanned twice");
    }

    #[test]
    fn days_until_expiry_none_for_missing_file() {
        assert_eq!(days_until_expiry(std::path::Path::new("/nonexistent/path.pem")), None);
    }

    #[test]
    fn find_vhost_cert_paths_finds_configured_vhost() {
        let routes = vec![rule(
            &["f.example.com"],
            false, // certbot_renew NOT set — must still be found by name
            Some(("/etc/proxyauth/cert/f.example.com/fullchain.pem", "/etc/proxyauth/cert/f.example.com/privkey.pem")),
        )];
        let found = find_vhost_cert_paths(&routes, "f.example.com");
        assert!(found.is_some());
        let (cert, key) = found.unwrap();
        assert_eq!(cert, std::path::PathBuf::from("/etc/proxyauth/cert/f.example.com/fullchain.pem"));
        assert_eq!(key, std::path::PathBuf::from("/etc/proxyauth/cert/f.example.com/privkey.pem"));
    }

    #[test]
    fn find_vhost_cert_paths_is_case_insensitive() {
        let routes = vec![rule(
            &["G.Example.com"],
            false,
            Some(("/cert/g/fullchain.pem", "/cert/g/privkey.pem")),
        )];
        assert!(find_vhost_cert_paths(&routes, "g.example.com").is_some());
        assert!(find_vhost_cert_paths(&routes, "G.EXAMPLE.COM").is_some());
    }

    #[test]
    fn find_vhost_cert_paths_none_for_unknown_vhost() {
        let routes = vec![rule(
            &["h.example.com"],
            false,
            Some(("/cert/h/fullchain.pem", "/cert/h/privkey.pem")),
        )];
        assert_eq!(find_vhost_cert_paths(&routes, "not-configured.example.com"), None);
    }

    #[test]
    fn find_vhost_cert_paths_none_without_vhost_cert() {
        let routes = vec![rule(&["i.example.com"], false, None)];
        assert_eq!(find_vhost_cert_paths(&routes, "i.example.com"), None);
    }

    #[test]
    fn collect_all_vhost_certs_includes_manually_managed() {
        // certbot_renew: false, but vhost_cert IS configured — must
        // still show up here (unlike collect_managed_vhosts).
        let routes = vec![rule(
            &["j.example.com"],
            false,
            Some(("/cert/j/fullchain.pem", "/cert/j/privkey.pem")),
        )];
        let all = collect_all_vhost_certs(&routes);
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].names, vec!["j.example.com".to_string()]);
    }

    #[test]
    fn group_with_several_names_becomes_one_certificate() {
        // Regression: this used to produce two ManagedVhost entries
        // pointing at the same cert path, so each issued its own
        // single-SAN certificate and overwrote the other. One entry
        // carrying both names is what makes a single multi-SAN
        // certificate get issued.
        let routes = vec![rule(
            &["example.com", "www.example.com"],
            true,
            Some(("/cert/example/fullchain.pem", "/cert/example/privkey.pem")),
        )];
        let managed = collect_managed_vhosts(&routes);
        assert_eq!(managed.len(), 1);
        assert_eq!(
            managed[0].names,
            vec!["example.com".to_string(), "www.example.com".to_string()]
        );
        assert_eq!(managed[0].primary(), "example.com");
    }

    #[test]
    fn distinct_cert_paths_stay_separate() {
        let routes = vec![
            rule(&["one.example.com"], true, Some(("/cert/one/fullchain.pem", "/cert/one/privkey.pem"))),
            rule(&["two.example.com"], true, Some(("/cert/two/fullchain.pem", "/cert/two/privkey.pem"))),
        ];
        let managed = collect_managed_vhosts(&routes);
        assert_eq!(managed.len(), 2);
    }

    #[test]
    fn collect_all_vhost_certs_excludes_vhost_without_cert() {
        let routes = vec![rule(&["k.example.com"], false, None)];
        assert!(collect_all_vhost_certs(&routes).is_empty());
    }

    #[test]
    fn collect_all_vhost_certs_dedupes() {
        let routes = vec![
            rule(
                &["l.example.com"],
                true,
                Some(("/cert/l/fullchain.pem", "/cert/l/privkey.pem")),
            ),
            rule(
                &["l.example.com"],
                false,
                Some(("/cert/l-other/fullchain.pem", "/cert/l-other/privkey.pem")),
            ),
        ];
        let all = collect_all_vhost_certs(&routes);
        assert_eq!(all.len(), 1, "the same vhost must not appear twice");
    }

    #[test]
    fn read_cert_info_none_for_missing_file() {
        assert!(read_cert_info(std::path::Path::new("/nonexistent/cert.pem")).is_err());
    }
}
