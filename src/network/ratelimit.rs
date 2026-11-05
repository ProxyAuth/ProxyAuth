//! Limitation de débit par vhost — implémentation propre à ProxyAuth.
//!
//! Remplace actix-governor (et le crate `governor`) : même algorithme
//! (GCRA, « Generic Cell Rate Algorithm »), mais configuré par vhost dans
//! `routes.yml` au lieu de `ratelimit_auth`/`ratelimit_proxy` dans
//! `config.json`, et branché comme middleware de la couche hyper
//! (`crate::hyper_web`).
//!
//! # Configuration (`routes.yml`)
//!
//! ```yaml
//! vhosts:
//!   - vhost: ["app.example.com"]
//!     ratelimit:
//!       limit_req_per_sec: 5   # débit soutenu : 5 requêtes / seconde
//!       burst: 5               # rafale tolérée (défaut : = débit)
//!       timeout: 10            # blocage de 10 s après un dépassement (0 = aucun)
//!       key: ip                # ip (défaut) | user
//!       auth:                  # facultatif : plus strict sur /auth & co
//!         limit_request: 10    # 10 requêtes…
//!         period: 60           # …par fenêtre de 60 s
//!         timeout: 300
//!     routes:
//!       - prefix: /
//!         target: http://127.0.0.1:3000
//! ```
//!
//! Deux façons d'exprimer le débit, exclusives :
//! * `limit_req_per_sec: N` — N requêtes par seconde ;
//! * `limit_request: N` + `period: S` — N requêtes par fenêtre de S
//!   secondes (`period` vaut 60 par défaut).
//!
//! Le bloc peut être posé sur un groupe `vhosts:` (hérité par toutes ses
//! routes, avec **un seul compteur partagé** pour le vhost) ou sur une
//! route précise (compteur propre à cette configuration).
//!
//! # Fonctionnement
//!
//! Chaque clé (IP du client, ou utilisateur du jeton puis IP) a une
//! « heure d'arrivée théorique » (TAT). Une requête avance la TAT d'un
//! intervalle d'émission `T = période / N` ; elle est acceptée tant que
//! la TAT ne dépasse pas « maintenant + burst × T ». C'est exactement le
//! modèle de `governor` : `burst` requêtes d'un coup, puis une toutes les
//! `T`. Avec `timeout`, une clé qui dépasse est en plus bloquée pendant
//! `timeout` secondes — chaque requête refusée pendant le blocage ne le
//! prolonge pas.
//!
//! L'IP utilisée est celle de `proxy::client_ip`, qui ne fait confiance à
//! `X-Forwarded-For` que derrière un proxy déclaré
//! (`trust_proxy_forward_for`) : un client ne peut pas se fabriquer une
//! clé neuve à chaque requête.

use crate::AppState;
use crate::config::config::RouteRule;
use crate::hyper_web::dev::{Middleware, Next, ServiceFuture, ServiceRequest};
use crate::hyper_web::http::StatusCode;
use crate::hyper_web::http::header::{self, ContentType, HeaderValue};
use crate::hyper_web::{HttpResponse, web};
use crate::network::proxy::{client_ip, find_vhost_route, match_route_idx, request_host};
use crate::token::security::extract_token_user;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};
use tracing::warn;

/// Chemins servis par ProxyAuth lui-même où se joue l'authentification :
/// ceux que l'ancien `ratelimit_auth` protégeait.
pub const AUTH_PATHS: &[&str] = &[
    "/auth",
    "/refresh_token",
    "/reset-password",
    "/auth/registry",
    "/adm/auth/totp/get",
];

// ─── Configuration ───────────────────────────────────────────────────

/// Ce qui identifie « un client » pour le compteur.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitKey {
    /// Adresse IP du client (défaut).
    #[default]
    Ip,
    /// Utilisateur du jeton (Bearer ou cookie de session) si valide,
    /// sinon l'IP — comme l'ancien limiteur « proxy ».
    User,
}

/// Bloc `ratelimit:` d'un vhost ou d'une route.
#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimitConfig {
    /// N requêtes par seconde.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit_req_per_sec: Option<u32>,

    /// N requêtes par fenêtre de `period` secondes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit_request: Option<u32>,

    /// Fenêtre de `limit_request`, en secondes (défaut 60).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub period: Option<u64>,

    /// Rafale tolérée ; par défaut égale au nombre de requêtes de la
    /// fenêtre.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub burst: Option<u32>,

    /// Durée de blocage (secondes) après un dépassement ; 0 = aucun
    /// blocage supplémentaire.
    #[serde(default)]
    pub timeout: u64,

    #[serde(default)]
    pub key: RateLimitKey,

    /// Limite spécifique aux chemins d'authentification ([`AUTH_PATHS`]).
    /// Absente : ces chemins suivent la limite générale.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<Box<RateLimitConfig>>,
}

/// Paramètres validés, prêts pour [`Limiter`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Quota {
    /// Requêtes autorisées par fenêtre.
    pub count: u32,
    pub period: Duration,
    pub burst: u32,
    pub block: Duration,
}

impl RateLimitConfig {
    /// Valide et normalise. `Err` décrit le problème en clair.
    pub fn quota(&self) -> Result<Quota, String> {
        let (count, period) = match (self.limit_req_per_sec, self.limit_request) {
            (Some(_), Some(_)) => {
                return Err(
                    "`limit_req_per_sec` and `limit_request` are mutually exclusive — pick one"
                        .into(),
                );
            }
            (Some(n), None) => {
                if self.period.is_some() {
                    return Err("`period` only applies to `limit_request`".into());
                }
                (n, Duration::from_secs(1))
            }
            (None, Some(n)) => (n, Duration::from_secs(self.period.unwrap_or(60))),
            (None, None) => {
                return Err("set either `limit_req_per_sec` or `limit_request`".into());
            }
        };
        if count == 0 {
            return Err(
                "the request count must be at least 1 (remove the block to disable rate limiting)"
                    .into(),
            );
        }
        if period.is_zero() {
            return Err("`period` must be at least 1 second".into());
        }
        let burst = self.burst.unwrap_or(count);
        if burst == 0 {
            return Err("`burst` must be at least 1".into());
        }
        Ok(Quota {
            count,
            period,
            burst,
            block: Duration::from_secs(self.timeout),
        })
    }

    /// Description d'une ligne pour le démarrage.
    pub fn describe(&self) -> String {
        match self.quota() {
            Ok(q) => {
                let rate = if self.limit_req_per_sec.is_some() {
                    format!("{}/s", q.count)
                } else {
                    format!("{}/{}s", q.count, q.period.as_secs())
                };
                let mut s = format!("{rate} burst {}", q.burst);
                if !q.block.is_zero() {
                    s.push_str(&format!(" timeout {}s", q.block.as_secs()));
                }
                if self.key == RateLimitKey::User {
                    s.push_str(" key=user");
                }
                s
            }
            Err(e) => format!("invalid ({e})"),
        }
    }
}

// ─── Limiteur GCRA ───────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
struct KeyState {
    /// Heure d'arrivée théorique, en ns depuis `Limiter::start`.
    tat: u64,
    /// Fin du blocage `timeout`, en ns depuis `Limiter::start`.
    blocked_until: u64,
}

/// Résultat d'une vérification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow { remaining: u32 },
    Deny { retry_after: Duration },
}

/// Un compteur (une configuration), partagé par tous les workers.
#[derive(Debug)]
pub struct Limiter {
    quota: Quota,
    emission_ns: u64,
    tolerance_ns: u64,
    block_ns: u64,
    start: Instant,
    states: DashMap<String, KeyState>,
}

impl Limiter {
    pub fn new(quota: Quota) -> Self {
        let emission_ns = (quota.period.as_nanos() / u128::from(quota.count)).max(1) as u64;
        Limiter {
            quota,
            emission_ns,
            tolerance_ns: emission_ns.saturating_mul(u64::from(quota.burst)),
            block_ns: quota.block.as_nanos().min(u128::from(u64::MAX)) as u64,
            start: Instant::now(),
            states: DashMap::new(),
        }
    }

    pub fn quota(&self) -> Quota {
        self.quota
    }

    fn now_ns(&self) -> u64 {
        self.start.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64
    }

    pub fn check(&self, key: &str) -> Decision {
        self.check_at(key, self.now_ns())
    }

    /// Cœur de l'algorithme, à horloge explicite (testable).
    pub fn check_at(&self, key: &str, now: u64) -> Decision {
        let mut st = self.states.entry(key.to_owned()).or_insert(KeyState {
            tat: now,
            blocked_until: 0,
        });

        if st.blocked_until > now {
            return Decision::Deny {
                retry_after: Duration::from_nanos(st.blocked_until - now),
            };
        }

        let new_tat = st.tat.max(now).saturating_add(self.emission_ns);
        let allowed_from = new_tat.saturating_sub(self.tolerance_ns);
        if allowed_from > now {
            let mut wait = allowed_from - now;
            if self.block_ns > 0 {
                st.blocked_until = now.saturating_add(self.block_ns);
                wait = wait.max(self.block_ns);
            }
            return Decision::Deny {
                retry_after: Duration::from_nanos(wait),
            };
        }

        st.tat = new_tat;
        let used = new_tat - now;
        let remaining = (self.tolerance_ns.saturating_sub(used) / self.emission_ns) as u32;
        Decision::Allow { remaining }
    }

    /// Oublie les clés revenues à l'état neuf (ni dette, ni blocage).
    pub fn purge(&self) {
        let now = self.now_ns();
        self.states
            .retain(|_, st| st.tat > now || st.blocked_until > now);
        self.states.shrink_to_fit();
    }

    #[allow(dead_code)] // tests et diagnostic
    pub fn tracked_keys(&self) -> usize {
        self.states.len()
    }
}

// ─── Table des limiteurs (construite au démarrage) ───────────────────

#[derive(Debug, Clone)]
struct Entry {
    limiter: Arc<Limiter>,
    key: RateLimitKey,
}

#[derive(Debug, Clone)]
struct RouteLimits {
    general: Entry,
    auth: Option<Entry>,
}

/// Limiteurs par route, résolus une fois à partir de `routes.yml`.
///
/// Les routes d'un même groupe `vhosts:` portent la même configuration
/// héritée : elles partagent donc le même [`Limiter`] — un seul compteur
/// pour tout le vhost. Une route qui définit sa propre configuration a
/// le sien.
#[derive(Debug, Default)]
pub struct RateLimiters {
    /// Index de route → limites.
    by_route: Vec<Option<RouteLimits>>,
    /// Tous les compteurs distincts (pour la purge et le résumé).
    all: Vec<Arc<Limiter>>,
}

impl RateLimiters {
    /// Construit la table. Une configuration invalide est refusée avec un
    /// message citant la route : mieux vaut ne pas démarrer que de servir
    /// un vhost qu'on croit protégé et qui ne l'est pas.
    pub fn from_routes(routes: &[RouteRule]) -> Result<Self, String> {
        let mut shared: HashMap<(Vec<String>, String), Arc<Limiter>> = HashMap::new();
        let mut all = Vec::new();
        let mut by_route = Vec::with_capacity(routes.len());

        let mut make =
            |rule: &RouteRule, cfg: &RateLimitConfig, what: &str| -> Result<Entry, String> {
                let quota = cfg.quota().map_err(|e| {
                    format!(
                        "routes.yml: route `{}` (vhost {:?}): ratelimit{what}: {e}",
                        rule.prefix, rule.vhost
                    )
                })?;
                let id = (
                    rule.vhost.clone(),
                    format!("{what}|{quota:?}|{:?}", cfg.key),
                );
                let limiter = shared
                    .entry(id)
                    .or_insert_with(|| {
                        let l = Arc::new(Limiter::new(quota));
                        all.push(l.clone());
                        l
                    })
                    .clone();
                Ok(Entry {
                    limiter,
                    key: cfg.key,
                })
            };

        for rule in routes {
            let Some(cfg) = rule.ratelimit.as_ref() else {
                by_route.push(None);
                continue;
            };
            let general = make(rule, cfg, "")?;
            let auth = match cfg.auth.as_deref() {
                Some(a) => {
                    if a.auth.is_some() {
                        return Err(format!(
                            "routes.yml: route `{}`: `ratelimit.auth` cannot contain another `auth`",
                            rule.prefix
                        ));
                    }
                    Some(make(rule, a, ".auth")?)
                }
                None => None,
            };
            by_route.push(Some(RouteLimits { general, auth }));
        }

        Ok(RateLimiters { by_route, all })
    }

    pub fn is_empty(&self) -> bool {
        self.all.is_empty()
    }

    /// Lance la purge périodique des clés inactives (sur le runtime
    /// courant). Sans elle, chaque IP jamais revue resterait en mémoire.
    pub fn spawn_purge(self: &Arc<Self>, every: Duration) {
        let weak: Weak<Self> = Arc::downgrade(self);
        if let Ok(h) = tokio::runtime::Handle::try_current() {
            h.spawn(async move {
                let mut tick = tokio::time::interval(every);
                tick.tick().await;
                loop {
                    tick.tick().await;
                    let Some(this) = weak.upgrade() else { break };
                    for l in &this.all {
                        l.purge();
                    }
                }
            });
        }
    }

    /// Lignes de résumé pour le démarrage.
    pub fn describe(routes: &[RouteRule]) -> Vec<String> {
        let mut seen = std::collections::HashSet::new();
        let mut out = Vec::new();
        for r in routes {
            let Some(cfg) = &r.ratelimit else { continue };
            let label = if r.vhost.is_empty() {
                "(catch-all)".to_string()
            } else {
                r.vhost.join(", ")
            };
            let mut line = format!("ratelimit {label}: {}", cfg.describe());
            if let Some(a) = &cfg.auth {
                line.push_str(&format!(" | auth: {}", a.describe()));
            }
            if seen.insert(line.clone()) {
                out.push(line);
            }
        }
        out
    }

    /// Limite applicable à cette requête : celle de la route qui la
    /// servira, sinon (chemins propres à ProxyAuth comme `/auth`) celle
    /// du vhost.
    fn resolve(&self, routes: &[RouteRule], path: &str, host: Option<&str>) -> Option<&Entry> {
        let idx = match_route_idx(path, host, routes)
            .or_else(|| {
                let r = find_vhost_route(host, routes)?;
                routes.iter().position(|x| std::ptr::eq(x, r))
            })
            // Hôte sans vhost dédié, chemin propre à ProxyAuth (`/auth`…) :
            // première route « catch-all » limitée. Un autre chemin qu'aucune
            // route ne sert (sonde sur `/`, 404) ne consomme le quota de
            // personne — une route sans `vhost` ne limite que son préfixe.
            .or_else(|| {
                AUTH_PATHS.contains(&path).then_some(())?;
                routes
                    .iter()
                    .position(|r| r.vhost.is_empty() && r.ratelimit.is_some())
            })?;
        let limits = self.by_route.get(idx)?.as_ref()?;
        if AUTH_PATHS.contains(&path) {
            Some(limits.auth.as_ref().unwrap_or(&limits.general))
        } else {
            Some(&limits.general)
        }
    }
}

// ─── Middleware hyper ────────────────────────────────────────────────

/// Middleware de limitation de débit, à enregistrer avec
/// `App::wrap(VhostRateLimit { .. })`.
pub struct VhostRateLimit {
    pub state: web::Data<AppState>,
    pub limiters: Arc<RateLimiters>,
}

fn key_for(req: &ServiceRequest, state: &AppState, kind: RateLimitKey, ip: &str) -> String {
    match kind {
        RateLimitKey::Ip => ip.to_string(),
        RateLimitKey::User => {
            let from_bearer = req
                .headers()
                .get(header::AUTHORIZATION)
                .and_then(|h| h.to_str().ok())
                .and_then(|s| s.strip_prefix("Bearer "))
                .and_then(|t| extract_token_user(t, &state.config, ip.to_string()).ok());
            let user = from_bearer.or_else(|| {
                let cookie = req.cookie("session_token")?;
                extract_token_user(cookie.value(), &state.config, ip.to_string()).ok()
            });
            match user {
                Some(u) => format!("user:{u}"),
                None => ip.to_string(),
            }
        }
    }
}

/// Réponse 429 (même corps JSON que l'ancien limiteur).
pub fn too_many_requests(retry_after: Duration, quota: Quota) -> HttpResponse {
    let secs = retry_after.as_secs() + u64::from(retry_after.subsec_nanos() > 0);
    HttpResponse::TooManyRequests()
        .content_type(ContentType::json())
        .insert_header((header::RETRY_AFTER, secs))
        .insert_header(("x-ratelimit-limit", quota.burst))
        .insert_header(("x-ratelimit-remaining", 0u32))
        .insert_header(("x-ratelimit-after", secs))
        .body(format!(
            r#"{{"code":429, "error": "TooManyRequests", "message": "Too Many Requests", "after": {secs}}}"#
        ))
}

impl Middleware for VhostRateLimit {
    fn call(&self, req: ServiceRequest, next: Next) -> ServiceFuture {
        if self.limiters.is_empty() {
            return next.call(req);
        }
        let state = &self.state;
        let host = request_host(req.request());
        let Some(entry) = self
            .limiters
            .resolve(&state.routes.routes, req.path(), host.as_deref())
        else {
            return next.call(req);
        };

        let Some(ip) = client_ip(req.request(), &state.config) else {
            // Sans IP on ne peut pas compter : on refuse plutôt que de
            // laisser passer sans limite.
            let res = HttpResponse::InternalServerError().body("Unable to determine client IP");
            return Box::pin(async move { Ok(req.into_response(res)) });
        };
        let ip = ip.to_string();
        let key = key_for(&req, state, entry.key, &ip);
        let quota = entry.limiter.quota();

        match entry.limiter.check(&key) {
            Decision::Allow { remaining } => {
                let fut = next.call(req);
                Box::pin(async move {
                    let mut res = fut.await?;
                    let h = res.headers_mut();
                    h.insert("x-ratelimit-limit", HeaderValue::from(quota.burst));
                    h.insert("x-ratelimit-remaining", HeaderValue::from(remaining));
                    Ok(res)
                })
            }
            Decision::Deny { retry_after } => {
                let user_agent = req
                    .headers()
                    .get(header::USER_AGENT)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("-");
                warn!(
                    client_ip = %ip,
                    key = %key,
                    method = %req.method(),
                    host = %host.as_deref().unwrap_or("-"),
                    path = %req.path(),
                    user_agent = %user_agent,
                    retry_after_secs = retry_after.as_secs(),
                    "Rate limit exceeded (429)"
                );
                let res = too_many_requests(retry_after, quota);
                debug_assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
                Box::pin(async move { Ok(req.into_response(res)) })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(yaml: &str) -> RateLimitConfig {
        serde_yaml::from_str(yaml).unwrap()
    }

    const S: u64 = 1_000_000_000;

    #[test]
    fn catch_all_route_limits_its_prefix_and_login_paths_only() {
        let routes: crate::config::config::RouteConfig = serde_yaml::from_str(
            r#"
routes:
  - prefix: "/app"
    target: "http://127.0.0.1:1"
    ratelimit:
      limit_req_per_sec: 1
      burst: 5
      auth:
        limit_req_per_sec: 1
        burst: 3
"#,
        )
        .unwrap();
        let routes = routes.expand_vhost_groups().routes;
        let rl = RateLimiters::from_routes(&routes).unwrap();
        let general = rl
            .resolve(&routes, "/app/x", Some("localhost"))
            .map(|e| Arc::as_ptr(&e.limiter));
        let auth = rl
            .resolve(&routes, "/auth", Some("localhost"))
            .map(|e| Arc::as_ptr(&e.limiter));
        assert!(
            general.is_some() && auth.is_some() && general != auth,
            "route and auth limits are distinct"
        );
        assert!(
            rl.resolve(&routes, "/", Some("localhost")).is_none(),
            "a path no route serves must not consume the route's quota"
        );
        assert!(rl.resolve(&routes, "/other", None).is_none());
    }

    #[test]
    fn per_second_with_burst() {
        let q = cfg("limit_req_per_sec: 5\nburst: 5").quota().unwrap();
        let l = Limiter::new(q);
        for i in 0..5 {
            assert!(
                matches!(l.check_at("a", 0), Decision::Allow { .. }),
                "req {i}"
            );
        }
        assert!(matches!(l.check_at("a", 0), Decision::Deny { .. }));
        // Une autre clé a son propre compteur.
        assert!(matches!(
            l.check_at("b", 0),
            Decision::Allow { remaining: 4 }
        ));
        // 200 ms plus tard : une place s'est libérée (T = 200 ms).
        assert!(matches!(l.check_at("a", S / 5), Decision::Allow { .. }));
        assert!(matches!(l.check_at("a", S / 5), Decision::Deny { .. }));
    }

    #[test]
    fn limit_request_over_period() {
        let q = cfg("limit_request: 3\nperiod: 60").quota().unwrap();
        assert_eq!(q.burst, 3);
        let l = Limiter::new(q);
        for _ in 0..3 {
            assert!(matches!(l.check_at("a", 0), Decision::Allow { .. }));
        }
        match l.check_at("a", 0) {
            Decision::Deny { retry_after } => assert_eq!(retry_after, Duration::from_secs(20)),
            d => panic!("{d:?}"),
        }
        assert!(matches!(l.check_at("a", 20 * S), Decision::Allow { .. }));
    }

    #[test]
    fn timeout_blocks_after_exceeding() {
        let q = cfg("limit_req_per_sec: 1\nburst: 1\ntimeout: 10")
            .quota()
            .unwrap();
        let l = Limiter::new(q);
        assert!(matches!(l.check_at("a", 0), Decision::Allow { .. }));
        match l.check_at("a", 0) {
            Decision::Deny { retry_after } => assert_eq!(retry_after, Duration::from_secs(10)),
            d => panic!("{d:?}"),
        }
        // Le débit seul l'aurait relâché après 1 s ; le blocage tient 10 s.
        assert!(matches!(l.check_at("a", 2 * S), Decision::Deny { .. }));
        assert!(matches!(l.check_at("a", 10 * S), Decision::Allow { .. }));
    }

    #[test]
    fn invalid_configs_are_rejected() {
        assert!(cfg("burst: 5").quota().is_err());
        assert!(
            cfg("limit_req_per_sec: 5\nlimit_request: 5")
                .quota()
                .is_err()
        );
        assert!(cfg("limit_req_per_sec: 0").quota().is_err());
        assert!(cfg("limit_req_per_sec: 5\nperiod: 10").quota().is_err());
        assert!(serde_yaml::from_str::<RateLimitConfig>("limit_req_per_sc: 5").is_err());
    }

    #[test]
    fn purge_forgets_idle_keys() {
        let l = Limiter::new(cfg("limit_req_per_sec: 1000").quota().unwrap());
        l.check_at("a", 0);
        assert_eq!(l.tracked_keys(), 1);
        std::thread::sleep(Duration::from_millis(5));
        l.purge();
        assert_eq!(l.tracked_keys(), 0);
    }
}
