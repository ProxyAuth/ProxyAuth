//! En-têtes de sécurité automatiques (`"discovery-csp": "auto"`).
//!
//! ```json
//! { "discovery-csp": "auto" }
//! ```
//!
//! Avec `auto`, ProxyAuth ajoute à chaque réponse servie **en HTTPS** un
//! socle d'en-têtes qui protègent n'importe quel site sans le casser :
//!
//! | En-tête | Valeur | Contre |
//! |---|---|---|
//! | `Content-Security-Policy` | `frame-ancestors 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; upgrade-insecure-requests` | clickjacking, injection de `<base>`, plugins, formulaires détournés, contenu mixte |
//! | `X-Frame-Options` | `SAMEORIGIN` | clickjacking (anciens navigateurs) |
//! | `X-Content-Type-Options` | `nosniff` | XSS par détournement du type MIME |
//! | `Referrer-Policy` | `strict-origin-when-cross-origin` | fuite d'URL (jetons, chemins) vers d'autres sites |
//! | `Strict-Transport-Security` | `max-age=31536000` | retour forcé en HTTP, cookies interceptés |
//! | `Cross-Origin-Opener-Policy` | `same-origin-allow-popups` | attaques entre fenêtres (tabnabbing, XS-Leaks) |
//! | `X-XSS-Protection` | `0` | désactive le filtre XSS des anciens navigateurs, lui-même exploitable |
//!
//! La politique CSP ne restreint volontairement **ni les scripts ni les
//! styles** (`script-src`, `style-src`…) : ce sont eux qui cassent les
//! applications existantes (scripts inline, CDN). Elle verrouille ce qui
//! ne sert à aucun site légitime : être encadré par un autre site, changer
//! la base des URL, charger des plugins, envoyer un formulaire ailleurs.
//!
//! Règles :
//! * **HTTPS seulement** : rien n'est ajouté sur une connexion en clair
//!   (HSTS n'y a pas de sens, et un site en HTTP n'est pas encore à
//!   protéger de cette façon).
//! * **Le backend garde la main** : un en-tête que la réponse porte déjà
//!   n'est jamais remplacé ni doublé. Une application qui envoie sa
//!   propre CSP (par exemple pour autoriser un partenaire à l'encadrer)
//!   n'est pas touchée, et si cette CSP règle `frame-ancestors`, aucun
//!   `X-Frame-Options` n'est ajouté pour la contredire.
//! * Un vhost peut se désactiver (`discovery-csp: off` dans routes.yml),
//!   ou l'activer seul quand config.json ne le fait pas.

use crate::AppState;
use crate::hyper_web::dev::{Middleware, Next, ServiceFuture, ServiceRequest};
use crate::hyper_web::http::header::{self, HeaderMap, HeaderName, HeaderValue};
use crate::hyper_web::web;
use crate::network::proxy::{find_vhost_route, request_host};
use serde::{Deserialize, Serialize};

/// Valeur de `discovery-csp`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DiscoveryCsp {
    /// Socle d'en-têtes de sécurité sur toutes les réponses HTTPS.
    Auto,
    /// Rien n'est ajouté (défaut).
    #[default]
    Off,
}

/// Le socle appliqué par `auto`.
pub const BASELINE_CSP: &str = "frame-ancestors 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; upgrade-insecure-requests";

fn baseline() -> [(HeaderName, HeaderValue); 7] {
    [
        (
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(BASELINE_CSP),
        ),
        (
            header::X_FRAME_OPTIONS,
            HeaderValue::from_static("SAMEORIGIN"),
        ),
        (
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ),
        (
            header::REFERRER_POLICY,
            HeaderValue::from_static("strict-origin-when-cross-origin"),
        ),
        (
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000"),
        ),
        (
            HeaderName::from_static("cross-origin-opener-policy"),
            HeaderValue::from_static("same-origin-allow-popups"),
        ),
        (header::X_XSS_PROTECTION, HeaderValue::from_static("0")),
    ]
}

/// Ajoute à `headers` les en-têtes du socle qui n'y sont pas déjà.
/// Renvoie le nombre d'en-têtes ajoutés.
pub fn apply_baseline(headers: &mut HeaderMap) -> usize {
    // L'application règle elle-même qui peut l'encadrer (`frame-ancestors`
    // dans sa CSP) : ne pas y ajouter un X-Frame-Options qui la
    // contredirait sur les anciens navigateurs.
    let app_sets_framing = headers
        .get_all(header::CONTENT_SECURITY_POLICY)
        .iter()
        .chain(
            headers
                .get_all(header::CONTENT_SECURITY_POLICY_REPORT_ONLY)
                .iter(),
        )
        .filter_map(|v| v.to_str().ok())
        .any(|v| v.to_ascii_lowercase().contains("frame-ancestors"));
    let mut added = 0;
    for (name, value) in baseline() {
        if name == header::X_FRAME_OPTIONS && app_sets_framing {
            continue;
        }
        // `Content-Security-Policy-Report-Only` posé par l'application :
        // elle est en train de régler sa propre CSP, on la laisse faire.
        if name == header::CONTENT_SECURITY_POLICY
            && headers.contains_key(header::CONTENT_SECURITY_POLICY_REPORT_ONLY)
        {
            continue;
        }
        if !headers.contains_key(&name) {
            headers.insert(name, value);
            added += 1;
        }
    }
    added
}

/// Réglage effectif pour une requête : celui du vhost, sinon config.json.
pub fn mode_for(state: &AppState, host: Option<&str>) -> DiscoveryCsp {
    find_vhost_route(host, &state.routes.routes)
        .and_then(|r| r.discovery_csp)
        .or(state.config.discovery_csp)
        .unwrap_or_default()
}

/// Middleware, à enregistrer avec `App::wrap`.
pub struct SecurityHeaders {
    pub state: web::Data<AppState>,
}

impl Middleware for SecurityHeaders {
    fn call(&self, req: ServiceRequest, next: Next) -> ServiceFuture {
        // HTTPS seulement : la connexion elle-même est en TLS.
        if !req.app_config().secure() {
            return next.call(req);
        }
        let host = request_host(req.request());
        if mode_for(&self.state, host.as_deref()) != DiscoveryCsp::Auto {
            return next.call(req);
        }
        let fut = next.call(req);
        Box::pin(async move {
            let mut res = fut.await?;
            apply_baseline(res.headers_mut());
            Ok(res)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adds_the_whole_baseline_to_a_bare_response() {
        let mut h = HeaderMap::new();
        assert_eq!(apply_baseline(&mut h), 7);
        assert_eq!(h[header::CONTENT_SECURITY_POLICY], BASELINE_CSP);
        assert_eq!(h[header::X_FRAME_OPTIONS], "SAMEORIGIN");
        assert_eq!(h[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
        assert_eq!(h[header::STRICT_TRANSPORT_SECURITY], "max-age=31536000");
        assert!(BASELINE_CSP.contains("frame-ancestors 'self'"));
        assert!(
            !BASELINE_CSP.contains("script-src"),
            "scripts are never restricted"
        );
    }

    #[test]
    fn never_overrides_what_the_backend_sent() {
        let mut h = HeaderMap::new();
        h.insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static("frame-ancestors https://partner.example"),
        );
        h.insert(
            header::X_FRAME_OPTIONS,
            HeaderValue::from_static("ALLOW-FROM https://partner.example"),
        );
        h.insert(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=63072000; includeSubDomains"),
        );
        assert_eq!(apply_baseline(&mut h), 4);
        assert_eq!(h.get_all(header::CONTENT_SECURITY_POLICY).iter().count(), 1);
        assert_eq!(
            h[header::X_FRAME_OPTIONS],
            "ALLOW-FROM https://partner.example"
        );
        assert_eq!(
            h[header::CONTENT_SECURITY_POLICY],
            "frame-ancestors https://partner.example"
        );
        assert_eq!(
            h[header::STRICT_TRANSPORT_SECURITY],
            "max-age=63072000; includeSubDomains"
        );
    }

    #[test]
    fn no_x_frame_options_when_the_app_sets_frame_ancestors() {
        let mut h = HeaderMap::new();
        h.insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static("frame-ancestors https://partner.example"),
        );
        apply_baseline(&mut h);
        assert!(
            !h.contains_key(header::X_FRAME_OPTIONS),
            "would contradict the app's own framing rule"
        );
        assert!(h.contains_key(header::X_CONTENT_TYPE_OPTIONS));
    }

    #[test]
    fn report_only_policy_is_respected() {
        let mut h = HeaderMap::new();
        h.insert(
            header::CONTENT_SECURITY_POLICY_REPORT_ONLY,
            HeaderValue::from_static("default-src 'self'"),
        );
        apply_baseline(&mut h);
        assert!(!h.contains_key(header::CONTENT_SECURITY_POLICY));
        assert!(h.contains_key(header::X_FRAME_OPTIONS));
    }

    #[test]
    fn parses_config_values() {
        assert_eq!(
            serde_json::from_str::<DiscoveryCsp>(r#""auto""#).unwrap(),
            DiscoveryCsp::Auto
        );
        assert_eq!(
            serde_json::from_str::<DiscoveryCsp>(r#""off""#).unwrap(),
            DiscoveryCsp::Off
        );
        assert!(serde_json::from_str::<DiscoveryCsp>(r#""strict""#).is_err());
    }
}
