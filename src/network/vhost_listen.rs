//! Port d'écoute et protocole HTTP choisis par vhost.
//!
//! ```yaml
//! vhosts:
//!   - vhost: ["api.example.com"]
//!     port: 8443        # défaut : `port` de config.json
//!     protocol: h2      # h1 | h2 | auto (défaut : auto)
//!     routes: [...]
//! ```
//!
//! * **Port** — ProxyAuth ouvre un socket par port distinct (port de
//!   `config.json` + chaque `port` de vhost), sur chacune des adresses
//!   `host` de `config.json`. Un vhost n'est servi **que** sur son port :
//!   la même requête arrivant sur un autre port reçoit
//!   `421 Misdirected Request`, et un port dédié ne sert que les vhosts
//!   qui l'ont déclaré. Sans `port`, un vhost reste sur le port par
//!   défaut, comme avant.
//! * **Protocole** — en TLS, l'ALPN proposé au client dépend du nom SNI :
//!   `h1` n'annonce que `http/1.1`, `h2` que `h2`, `auto` les deux. En
//!   clair (sans TLS), un port dont tous les vhosts imposent le même
//!   protocole n'accepte que celui-là. Dans tous les cas, une requête
//!   arrivée dans le mauvais protocole reçoit
//!   `505 HTTP Version Not Supported`.

use crate::AppState;
use crate::config::config::RouteRule;
use crate::hyper_web::dev::{Middleware, Next, ServiceFuture, ServiceRequest};
use crate::hyper_web::http::Version;
use crate::hyper_web::server::ConnProtocol;
use crate::hyper_web::{HttpResponse, web};
use crate::network::proxy::{find_vhost_route, normalize_host, request_host, vhost_entry_matches};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use tracing::warn;

/// Protocole HTTP servi pour un vhost.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum HttpProtocol {
    /// HTTP/1.1 et HTTP/2 (négocié).
    #[default]
    Auto,
    /// HTTP/1.1 uniquement.
    #[serde(alias = "http1", alias = "http/1.1", alias = "h1.1")]
    H1,
    /// HTTP/2 uniquement.
    #[serde(alias = "http2", alias = "http/2")]
    H2,
}

impl HttpProtocol {
    pub fn alpn(self) -> Vec<Vec<u8>> {
        match self {
            HttpProtocol::Auto => vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            HttpProtocol::H1 => vec![b"http/1.1".to_vec()],
            HttpProtocol::H2 => vec![b"h2".to_vec()],
        }
    }

    pub fn accepts(self, version: Version) -> bool {
        match self {
            HttpProtocol::Auto => true,
            HttpProtocol::H1 => version != Version::HTTP_2 && version != Version::HTTP_3,
            HttpProtocol::H2 => version == Version::HTTP_2,
        }
    }

    fn conn(self) -> ConnProtocol {
        match self {
            HttpProtocol::Auto => ConnProtocol::Auto,
            HttpProtocol::H1 => ConnProtocol::Http1,
            HttpProtocol::H2 => ConnProtocol::Http2,
        }
    }
}

/// Port effectif d'une route.
pub fn route_port(rule: &RouteRule, default_port: u16) -> u16 {
    rule.port.unwrap_or(default_port)
}

/// Protocole effectif d'une route.
pub fn route_protocol(rule: &RouteRule) -> HttpProtocol {
    rule.protocol.unwrap_or_default()
}

/// Plan d'écoute calculé à partir de `routes.yml` et `config.json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenPlan {
    /// Ports à ouvrir, port par défaut en premier.
    pub ports: Vec<u16>,
    /// Protocole imposé au niveau connexion, par port (TLS exclu : là,
    /// c'est l'ALPN par SNI qui décide).
    pub conn_protocol: BTreeMap<u16, ConnProtocol>,
}

impl ListenPlan {
    pub fn build(routes: &[RouteRule], default_port: u16) -> Self {
        // Hôte (normalisé) → (port, protocole) ; le premier qui le
        // déclare l'emporte, les incohérences sont signalées.
        let mut seen: BTreeMap<String, (u16, HttpProtocol, String)> = BTreeMap::new();
        for r in routes {
            if r.vhost.is_empty() {
                if r.port.is_some() || r.protocol.is_some() {
                    warn!(
                        "routes.yml: route `{}` has `port`/`protocol` but no `vhost` — ignored, catch-all routes stay on the default port",
                        r.prefix
                    );
                }
                continue;
            }
            let port = route_port(r, default_port);
            let proto = route_protocol(r);
            for h in &r.vhost {
                let h = h.to_ascii_lowercase();
                match seen.get(&h) {
                    Some((p, pr, first)) if (*p, *pr) != (port, proto) => warn!(
                        "routes.yml: vhost `{h}`: route `{}` sets port {port}/{proto:?} but route `{first}` already set {p}/{pr:?} — keeping the first",
                        r.prefix
                    ),
                    Some(_) => {}
                    None => {
                        seen.insert(h, (port, proto, r.prefix.clone()));
                    }
                }
            }
        }

        let mut ports = vec![default_port];
        let extra: BTreeSet<u16> = seen
            .values()
            .map(|(p, _, _)| *p)
            .filter(|p| *p != default_port)
            .collect();
        ports.extend(extra);

        let mut conn_protocol = BTreeMap::new();
        for &port in &ports {
            let mut protos: BTreeSet<HttpProtocol> = seen
                .values()
                .filter(|(p, _, _)| *p == port)
                .map(|(_, pr, _)| *pr)
                .collect();
            // Le port par défaut sert aussi les routes sans vhost, en auto.
            if port == default_port && routes.iter().any(|r| r.vhost.is_empty()) {
                protos.insert(HttpProtocol::Auto);
            }
            let cp = if protos.len() == 1 {
                protos.into_iter().next().unwrap().conn()
            } else {
                ConnProtocol::Auto
            };
            conn_protocol.insert(port, cp);
        }

        ListenPlan {
            ports,
            conn_protocol,
        }
    }
}

/// Protocole d'un nom SNI (TLS), même résolution que le routage :
/// nom exact d'abord, puis joker `*.domaine`.
pub fn protocol_for_sni(routes: &[RouteRule], sni: Option<&str>) -> HttpProtocol {
    let Some(sni) = sni else {
        return HttpProtocol::Auto;
    };
    let host = normalize_host(sni);
    let exact = routes
        .iter()
        .find(|r| r.vhost.iter().any(|v| !v.starts_with("*.") && vhost_entry_matches(v, &host)));
    let rule = exact.or_else(|| {
        routes
            .iter()
            .find(|r| r.vhost.iter().any(|v| vhost_entry_matches(v, &host)))
    });
    rule.map(route_protocol).unwrap_or_default()
}

/// Garde de port et de protocole, à enregistrer avec `App::wrap`.
pub struct VhostListenGuard {
    pub state: web::Data<AppState>,
}

impl Middleware for VhostListenGuard {
    fn call(&self, req: ServiceRequest, next: Next) -> ServiceFuture {
        let default_port = self.state.config.port;
        let local_port = req.local_addr().map(|a| a.port());
        let host = request_host(req.request());
        let route = find_vhost_route(host.as_deref(), &self.state.routes.routes);

        // Port attendu pour ce Host : celui de son vhost, sinon le défaut.
        let expected = route.map(|r| route_port(r, default_port)).unwrap_or(default_port);
        // Le défi ACME HTTP-01 (port 80, écouteur séparé) n'est pas concerné ;
        // `local_port` absent = requête de test.
        if let Some(lp) = local_port {
            if lp != expected && !is_acme_challenge(req.path()) {
                let res = HttpResponse::build(crate::hyper_web::http::StatusCode::MISDIRECTED_REQUEST)
                    .body("421 Misdirected Request");
                return Box::pin(async move { Ok(req.into_response(res)) });
            }
        }

        let proto = route.map(route_protocol).unwrap_or_default();
        if !proto.accepts(req.version()) {
            let res = HttpResponse::build(crate::hyper_web::http::StatusCode::HTTP_VERSION_NOT_SUPPORTED)
                .body(match proto {
                    HttpProtocol::H2 => "505 HTTP Version Not Supported: this host is served over HTTP/2 only",
                    _ => "505 HTTP Version Not Supported: this host is served over HTTP/1.1 only",
                });
            return Box::pin(async move { Ok(req.into_response(res)) });
        }

        next.call(req)
    }
}

fn is_acme_challenge(path: &str) -> bool {
    path.starts_with("/.well-known/acme-challenge/")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(vhost: &[&str], port: Option<u16>, proto: Option<HttpProtocol>) -> RouteRule {
        let mut r: RouteRule = serde_json::from_str(r#"{"prefix": "/"}"#).unwrap();
        r.vhost = vhost.iter().map(|s| s.to_string()).collect();
        r.port = port;
        r.protocol = proto;
        r
    }

    #[test]
    fn plan_collects_ports_and_protocols() {
        let routes = vec![
            rule(&["a.example.com"], None, None),
            rule(&["b.example.com"], Some(8443), Some(HttpProtocol::H2)),
            rule(&["c.example.com"], Some(9000), Some(HttpProtocol::H1)),
            rule(&["d.example.com"], Some(9000), Some(HttpProtocol::H2)),
        ];
        let plan = ListenPlan::build(&routes, 443);
        assert_eq!(plan.ports, vec![443, 8443, 9000]);
        assert_eq!(plan.conn_protocol[&443], ConnProtocol::Auto);
        assert_eq!(plan.conn_protocol[&8443], ConnProtocol::Http2);
        assert_eq!(plan.conn_protocol[&9000], ConnProtocol::Auto);
    }

    #[test]
    fn sni_resolution_prefers_exact_then_wildcard() {
        let routes = vec![
            rule(&["*.example.com"], None, Some(HttpProtocol::H1)),
            rule(&["api.example.com"], None, Some(HttpProtocol::H2)),
        ];
        assert_eq!(protocol_for_sni(&routes, Some("api.example.com")), HttpProtocol::H2);
        assert_eq!(protocol_for_sni(&routes, Some("www.example.com")), HttpProtocol::H1);
        assert_eq!(protocol_for_sni(&routes, Some("other.org")), HttpProtocol::Auto);
        assert_eq!(protocol_for_sni(&routes, None), HttpProtocol::Auto);
    }

    #[test]
    fn protocol_parsing() {
        let p: HttpProtocol = serde_yaml::from_str("h2").unwrap();
        assert_eq!(p, HttpProtocol::H2);
        let p: HttpProtocol = serde_yaml::from_str("http1").unwrap();
        assert_eq!(p, HttpProtocol::H1);
        assert!(HttpProtocol::H1.accepts(Version::HTTP_11));
        assert!(!HttpProtocol::H1.accepts(Version::HTTP_2));
        assert!(!HttpProtocol::H2.accepts(Version::HTTP_11));
    }
}
