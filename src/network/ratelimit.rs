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
//!       key: ip                # ip (défaut) | user | user_ip | cookie | cookie_ip
//!       # cookie_name: "app_session"   # avec key: cookie
//!       # ip_ceiling: { limit_req_per_sec: 50, burst: 100 }   # plafond par IP
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
    /// Utilisateur **et** IP : un compteur par couple (utilisateur, IP)
    /// pour les requêtes authentifiées, l'IP seule pour les autres.
    ///
    /// Derrière une même IP (NAT d'entreprise, opérateur mobile, proxy),
    /// chaque utilisateur connecté a son propre compteur : un client
    /// bruyant ne bloque pas ses voisins. Et un même compte utilisé depuis
    /// plusieurs endroits n'a pas un seul compteur partagé — un jeton volé
    /// et rejoué ailleurs ne vide pas le quota du titulaire légitime.
    /// Aussi accepté : `ip_user`.
    #[serde(alias = "ip_user")]
    UserIp,
    /// Valeur d'un cookie choisi (`cookie_name`), par exemple le cookie de
    /// session d'une application : un compteur par session. Sans ce
    /// cookie, l'IP.
    ///
    /// La valeur vient du client : un client qui en change à chaque
    /// requête obtient chaque fois un compteur neuf. Associez-la à
    /// `ip_ceiling`, qui plafonne l'adresse quelles que soient les valeurs.
    /// La valeur n'est jamais stockée telle quelle : seule son empreinte
    /// (BLAKE3) sert de clé et apparaît dans les journaux.
    Cookie,
    /// Cookie **et** IP, avec un plafond par IP intégré : la forme simple
    /// et sûre de `cookie`.
    ///
    /// * Un compteur par couple (valeur du cookie, IP) : chaque session a
    ///   le sien, et un cookie volé rejoué depuis une autre IP ne vide pas
    ///   le quota de la vraie session.
    /// * Un plafond par IP, toujours présent : `ip_ceiling` s'il est écrit,
    ///   sinon [`IMPLICIT_CEILING_FACTOR`] fois la limite du bloc. Un client
    ///   qui change de cookie à chaque requête est arrêté par ce plafond.
    ///
    /// Aussi accepté : `ip_cookie`.
    #[serde(alias = "ip_cookie")]
    CookieIp,
}

/// Plafond par IP implicite de `key: cookie_ip`, en multiple de la limite
/// du bloc. Une limite identique à celle d'une session ferait partager un
/// seul quota à toutes les sessions d'une même IP — exactement `key: ip`.
/// Dix fois laisse une dizaine de sessions actives derrière un NAT avant
/// que le plafond ne joue ; `ip_ceiling` permet de régler autrement.
pub const IMPLICIT_CEILING_FACTOR: u32 = 10;

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

    /// Nom du cookie dont la valeur sert de clé, avec `key: cookie`.
    /// Aussi accepté : `custom_cookie`.
    #[serde(
        default,
        alias = "custom_cookie",
        skip_serializing_if = "Option::is_none"
    )]
    pub cookie_name: Option<String>,

    /// Plafond par IP, vérifié en plus de la clé : toutes les requêtes
    /// d'une adresse, quels que soient leurs cookies ou utilisateurs, ne
    /// dépassent jamais ce débit. Mêmes champs de débit que le bloc
    /// (`limit_req_per_sec` ou `limit_request` + `period`, `burst`,
    /// `timeout`) ; il compte toujours par IP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_ceiling: Option<Box<RateLimitConfig>>,

    /// Pénalité progressive : chaque récidive multiplie `timeout`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub penalty: Option<PenaltyConfig>,

    /// Coût des requêtes : une archive peut valoir 10 requêtes simples.
    /// La première règle qui correspond s'applique ; sinon 1.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub costs: Vec<CostRule>,

    /// Limites resserrées quand le processeur sature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adaptive: Option<AdaptiveConfig>,

    /// Rempli par `expand_vhost_groups` quand une route hérite le bloc de
    /// son groupe `vhosts:` (index du groupe). Les routes d'un même groupe
    /// partagent alors un compteur ; une route qui écrit son propre bloc
    /// (`None`) a toujours le sien, même avec des valeurs identiques.
    #[serde(skip)]
    pub inherited_from_group: Option<usize>,
}

/// `bandwidth_max:` — plafond **global** d'un vhost ou d'une route : tous
/// clients confondus, au plus `request_per_second` requêtes par seconde.
/// Le surplus reçoit `static_page` (statut 503, `Retry-After: 1`) au lieu
/// d'atteindre le backend.
///
/// ```yaml
/// bandwidth_max:                 # aussi accepté : bandwith_max
///   request_per_second: 500      # ou requests_per_second
///   burst: 1000                  # facultatif, défaut = request_per_second
///   static_page: "/var/www/busy.html"
/// ```
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BandwidthMax {
    #[serde(alias = "requests_per_second", alias = "limit_req_per_sec")]
    pub request_per_second: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub burst: Option<u32>,
    #[serde(alias = "page")]
    pub static_page: String,
    /// Adresses soumises au plafond (IP ou réseau CIDR). Vide : toutes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ip_filtered: Vec<String>,
    /// Adresses jamais soumises au plafond, ni comptées : réseau interne,
    /// supervision… Prioritaire sur `ip_filtered`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ip_nofiltered: Vec<String>,
    /// Chemins jamais soumis au plafond, ni comptés (regex sur le chemin) :
    /// fichiers statiques, page de surplus elle-même, sondes de santé…
    /// Aussi accepté : `excludes`, `exclude_regex`.
    #[serde(
        default,
        alias = "excludes",
        alias = "exclude_regex",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub exclude: Vec<String>,
    /// Rempli par `expand_vhost_groups` quand la route hérite le bloc de
    /// son groupe : tout le vhost partage alors un seul plafond.
    #[serde(skip)]
    pub inherited_from_group: Option<usize>,
}

/// Un plafond global : son compteur et la page servie au surplus.
#[derive(Debug)]
struct Cap {
    limiter: Arc<Limiter>,
    page: Arc<CapPage>,
    rps: u32,
    filtered: Vec<ipnet::IpNet>,
    nofiltered: Vec<ipnet::IpNet>,
    exclude: Vec<regex::Regex>,
}

impl Cap {
    /// Le chemin est exclu du plafond (une regex de `exclude` y correspond).
    fn excludes(&self, path: &str) -> bool {
        self.exclude.iter().any(|re| re.is_match(path))
    }

    /// Le plafond s'applique-t-il à ce client ? Les adresses de
    /// `ip_nofiltered` passent toujours, sans être comptées ; sinon celles
    /// de `ip_filtered` (toutes si la liste est vide). Sans IP connue, le
    /// plafond s'applique.
    fn applies_to(&self, ip: Option<std::net::IpAddr>) -> bool {
        let Some(ip) = ip else { return true };
        if self.nofiltered.iter().any(|n| n.contains(&ip)) {
            return false;
        }
        self.filtered.is_empty() || self.filtered.iter().any(|n| n.contains(&ip))
    }
}

/// Une adresse ou un réseau CIDR (`10.0.0.1`, `192.168.0.0/24`, `::1`,
/// `fe80::/64`).
fn parse_net(entry: &str) -> Result<ipnet::IpNet, String> {
    let e = entry.trim();
    e.parse::<ipnet::IpNet>()
        .or_else(|_| e.parse::<std::net::IpAddr>().map(ipnet::IpNet::from))
        .map_err(|_| {
            format!(
                "{entry:?} is not an IP address or a CIDR network (e.g. 192.168.0.0/24, fe80::/64)"
            )
        })
}

/// La page de surplus, gardée en mémoire et relue si le fichier change
/// (vérifié au plus toutes les 5 s) : elle est servie précisément quand
/// le serveur est le plus chargé.
#[derive(Debug)]
struct CapPage {
    path: std::path::PathBuf,
    content_type: String,
    cached: std::sync::Mutex<(bytes::Bytes, Option<std::time::SystemTime>, Instant)>,
}

impl CapPage {
    fn load(path: &str) -> Result<Self, String> {
        let p = std::path::PathBuf::from(path);
        let body =
            std::fs::read(&p).map_err(|e| format!("cannot read `static_page` {path}: {e}"))?;
        let mtime = std::fs::metadata(&p).and_then(|m| m.modified()).ok();
        Ok(Self {
            content_type: crate::network::proxy::guess_content_type(&p).to_string(),
            path: p,
            cached: std::sync::Mutex::new((bytes::Bytes::from(body), mtime, Instant::now())),
        })
    }

    fn body(&self) -> bytes::Bytes {
        let mut c = self.cached.lock().unwrap_or_else(|e| e.into_inner());
        if c.2.elapsed() >= Duration::from_secs(5) {
            c.2 = Instant::now();
            let mtime = std::fs::metadata(&self.path)
                .and_then(|m| m.modified())
                .ok();
            if mtime != c.1 {
                if let Ok(b) = std::fs::read(&self.path) {
                    c.0 = bytes::Bytes::from(b);
                    c.1 = mtime;
                }
            }
        }
        c.0.clone()
    }
}

/// `penalty:` — le blocage d'une récidive dure `timeout × factor^n`
/// (n = récidives précédentes), plafonné à `max`. Les récidives sont
/// oubliées après `forget_after` secondes sans dépassement.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PenaltyConfig {
    #[serde(default = "default_penalty_factor")]
    pub factor: u32,
    /// Plafond du blocage, en secondes.
    #[serde(default = "default_penalty_max")]
    pub max: u64,
    /// Oubli des récidives, en secondes.
    #[serde(default = "default_penalty_forget")]
    pub forget_after: u64,
}
fn default_penalty_factor() -> u32 {
    2
}
fn default_penalty_max() -> u64 {
    3600
}
fn default_penalty_forget() -> u64 {
    600
}

/// Une règle de `costs:` : `regex` (sur le chemin) et/ou `methods`.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CostRule {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub regex: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<String>,
    pub cost: u32,
}

/// `adaptive:` — au-delà de `cpu_threshold` % d'occupation processeur, le
/// coût de chaque requête augmente, jusqu'à `1 / min_factor` à 100 %.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdaptiveConfig {
    #[serde(default = "default_cpu_threshold")]
    pub cpu_threshold: u32,
    #[serde(default = "default_min_factor")]
    pub min_factor: f64,
}
fn default_cpu_threshold() -> u32 {
    75
}
fn default_min_factor() -> f64 {
    0.25
}

impl AdaptiveConfig {
    /// Facteur de débit (1 = normal) pour une occupation `cpu` en %.
    pub fn factor(&self, cpu: u32) -> f64 {
        let thr = self.cpu_threshold.min(99) as f64;
        let cpu = (cpu.min(100)) as f64;
        if cpu <= thr {
            return 1.0;
        }
        let over = (cpu - thr) / (100.0 - thr);
        (1.0 - over * (1.0 - self.min_factor)).clamp(self.min_factor, 1.0)
    }
}

/// Paramètres validés, prêts pour [`Limiter`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Quota {
    /// Requêtes autorisées par fenêtre.
    pub count: u32,
    pub period: Duration,
    pub burst: u32,
    pub block: Duration,
    /// Pénalité progressive : 1 = sans (le blocage dure toujours `block`).
    pub penalty_factor: u32,
    pub penalty_max: Duration,
    pub penalty_forget: Duration,
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
        let (penalty_factor, penalty_max, penalty_forget) = match &self.penalty {
            None => (1, Duration::ZERO, Duration::ZERO),
            Some(p) => {
                if self.timeout == 0 {
                    return Err(
                        "`penalty` multiplies `timeout`: set a `timeout` (seconds) first".into(),
                    );
                }
                if p.factor < 2 {
                    return Err("`penalty.factor` must be at least 2".into());
                }
                if p.max < self.timeout {
                    return Err("`penalty.max` must be at least `timeout`".into());
                }
                if p.forget_after == 0 {
                    return Err("`penalty.forget_after` must be at least 1 second".into());
                }
                (
                    p.factor,
                    Duration::from_secs(p.max),
                    Duration::from_secs(p.forget_after),
                )
            }
        };
        for c in &self.costs {
            if c.cost == 0 {
                return Err("a `costs` entry must have `cost` of at least 1".into());
            }
            if c.cost > burst {
                return Err(format!(
                    "a `costs` entry costs {} but `burst` is {burst}: such a request could never pass — raise `burst`",
                    c.cost
                ));
            }
            if c.regex.is_none() && c.methods.is_empty() {
                return Err("a `costs` entry needs a `regex`, `methods`, or both".into());
            }
            if let Some(r) = &c.regex {
                regex::Regex::new(r).map_err(|e| format!("invalid `costs` regex {r:?}: {e}"))?;
            }
        }
        if let Some(a) = &self.adaptive {
            if !(1..=99).contains(&a.cpu_threshold) {
                return Err("`adaptive.cpu_threshold` must be between 1 and 99 (%)".into());
            }
            if !(a.min_factor > 0.0 && a.min_factor <= 1.0) {
                return Err("`adaptive.min_factor` must be in (0, 1]".into());
            }
        }
        Ok(Quota {
            count,
            period,
            burst,
            block: Duration::from_secs(self.timeout),
            penalty_factor,
            penalty_max,
            penalty_forget,
        })
    }

    /// Description d'une ligne pour le démarrage.
    /// Le bloc ne fixe aucune limite générale (ni `limit_req_per_sec` ni
    /// `limit_request`) : seulement, peut-être, un bloc `auth`.
    pub fn has_general_limit(&self) -> bool {
        self.limit_req_per_sec.is_some() || self.limit_request.is_some()
    }

    pub fn describe(&self) -> String {
        if !self.has_general_limit() {
            return "routes unlimited".into();
        }
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
                if q.penalty_factor > 1 {
                    s.push_str(&format!(
                        " penalty x{} up to {}s",
                        q.penalty_factor,
                        q.penalty_max.as_secs()
                    ));
                }
                if !self.costs.is_empty() {
                    s.push_str(&format!(" costs {}", self.costs.len()));
                }
                if let Some(a) = &self.adaptive {
                    s.push_str(&format!(" adaptive >{}% cpu", a.cpu_threshold));
                }
                match self.key {
                    RateLimitKey::Ip => {}
                    RateLimitKey::User => s.push_str(" key=user"),
                    RateLimitKey::UserIp => s.push_str(" key=user_ip"),
                    RateLimitKey::Cookie => s.push_str(&format!(
                        " key=cookie({})",
                        self.cookie_name.as_deref().unwrap_or("?")
                    )),
                    RateLimitKey::CookieIp => s.push_str(&format!(
                        " key=cookie_ip({})",
                        self.cookie_name.as_deref().unwrap_or("?")
                    )),
                }
                if let Some(c) = &self.ip_ceiling {
                    s.push_str(&format!(" ip_ceiling {}", c.describe()));
                } else if self.key == RateLimitKey::CookieIp {
                    let rate = if self.limit_req_per_sec.is_some() {
                        format!("{}/s", q.count.saturating_mul(IMPLICIT_CEILING_FACTOR))
                    } else {
                        format!(
                            "{}/{}s",
                            q.count.saturating_mul(IMPLICIT_CEILING_FACTOR),
                            q.period.as_secs()
                        )
                    };
                    s.push_str(&format!(
                        " ip_ceiling {rate} burst {} (implicit, x{IMPLICIT_CEILING_FACTOR})",
                        q.burst.saturating_mul(IMPLICIT_CEILING_FACTOR)
                    ));
                } else if self.key == RateLimitKey::Cookie {
                    s.push_str(" — WARNING: no ip_ceiling, a client can send a new cookie value per request to get a fresh counter");
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
    /// Blocages déjà subis (pénalité progressive).
    strikes: u32,
    /// Dernier blocage, en ns depuis `Limiter::start`.
    last_strike: u64,
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

    #[allow(dead_code)] // tests et diagnostic ; le middleware pèse ses requêtes
    pub fn check(&self, key: &str) -> Decision {
        self.check_at(key, self.now_ns())
    }

    /// Requête de poids `weight` (coût × charge ; 1.0 = une requête).
    pub fn check_weighted(&self, key: &str, weight: f64) -> Decision {
        self.check_weighted_at(key, self.now_ns(), weight)
    }

    /// Cœur de l'algorithme, à horloge explicite (testable).
    #[allow(dead_code)] // tests
    pub fn check_at(&self, key: &str, now: u64) -> Decision {
        self.check_weighted_at(key, now, 1.0)
    }

    /// Durée du blocage d'une `strikes`-ième récidive.
    fn block_for(&self, strikes: u32) -> u64 {
        if self.quota.penalty_factor <= 1 {
            return self.block_ns;
        }
        let max = self.quota.penalty_max.as_nanos().min(u128::from(u64::MAX)) as u64;
        let mut b = self.block_ns;
        for _ in 0..strikes {
            b = b.saturating_mul(u64::from(self.quota.penalty_factor));
            if b >= max {
                return max;
            }
        }
        b.min(max)
    }

    pub fn check_weighted_at(&self, key: &str, now: u64, weight: f64) -> Decision {
        // Poids d'une requête en « temps de bucket ». Plafonné à la
        // tolérance : un bucket plein laisse toujours passer une requête,
        // même très chère ou sous forte charge.
        let increment = ((self.emission_ns as f64) * weight.max(0.0))
            .round()
            .clamp(1.0, self.tolerance_ns.max(self.emission_ns) as f64)
            as u64;
        let mut st = self.states.entry(key.to_owned()).or_insert(KeyState {
            tat: now,
            blocked_until: 0,
            strikes: 0,
            last_strike: 0,
        });

        if st.blocked_until > now {
            return Decision::Deny {
                retry_after: Duration::from_nanos(st.blocked_until - now),
            };
        }

        let new_tat = st.tat.max(now).saturating_add(increment);
        let allowed_from = new_tat.saturating_sub(self.tolerance_ns);
        if allowed_from > now {
            let mut wait = allowed_from - now;
            if self.block_ns > 0 {
                // Pénalité progressive : les récidives anciennes sont
                // oubliées, les récentes allongent le blocage.
                let forget = self
                    .quota
                    .penalty_forget
                    .as_nanos()
                    .min(u128::from(u64::MAX)) as u64;
                if st.strikes > 0 && now.saturating_sub(st.last_strike) > forget {
                    st.strikes = 0;
                }
                let block = self.block_for(st.strikes);
                st.strikes = st.strikes.saturating_add(1);
                st.last_strike = now;
                st.blocked_until = now.saturating_add(block);
                wait = wait.max(block);
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
        let forget = self
            .quota
            .penalty_forget
            .as_nanos()
            .min(u128::from(u64::MAX)) as u64;
        self.states.retain(|_, st| {
            st.tat > now
                || st.blocked_until > now
                // Une récidive récente doit être retenue pour la suivante.
                || (st.strikes > 0 && now.saturating_sub(st.last_strike) <= forget)
        });
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
    /// Règles de coût compilées : (regex, méthodes, coût).
    costs: Arc<Vec<(Option<regex::Regex>, Vec<String>, u32)>>,
    adaptive: Option<AdaptiveConfig>,
    /// Nom du cookie, pour `key: cookie`.
    cookie: Option<Arc<str>>,
    /// Plafond par IP (`ip_ceiling`), vérifié avant la clé.
    ceiling: Option<Arc<Limiter>>,
}

#[derive(Debug, Clone)]
struct RouteLimits {
    /// `None` : bloc limité aux chemins de connexion (`auth` seul).
    general: Option<Entry>,
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
    /// Index de route → plafond global (`bandwidth_max`).
    caps_by_route: Vec<Option<Arc<Cap>>>,
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

        let mut make = |index: usize,
                        rule: &RouteRule,
                        cfg: &RateLimitConfig,
                        group: Option<usize>,
                        what: &str|
         -> Result<Entry, String> {
            let quota = cfg.quota().map_err(|e| {
                format!(
                    "routes.yml: route `{}` (vhost {:?}): ratelimit{what}: {e}",
                    rule.prefix, rule.vhost
                )
            })?;
            // Portée du compteur : le groupe `vhosts:` dont le bloc est
            // hérité (compteur partagé par ses routes), ou la route
            // elle-même quand elle a écrit son propre bloc.
            let scope = match group {
                Some(g) => format!("group#{g}"),
                None => format!("route#{index}"),
            };
            let id = (
                rule.vhost.clone(),
                format!(
                    "{scope}|{what}|{quota:?}|{:?}|{:?}",
                    cfg.key, cfg.cookie_name
                ),
            );
            let where_ = || {
                format!(
                    "routes.yml: route `{}` (vhost {:?}): ratelimit{what}",
                    rule.prefix, rule.vhost
                )
            };
            let cookie_kind = matches!(cfg.key, RateLimitKey::Cookie | RateLimitKey::CookieIp);
            let cookie = match (cookie_kind, cfg.cookie_name.as_deref()) {
                (true, Some(name)) if valid_cookie_name(name) => Some(Arc::<str>::from(name)),
                (true, Some(name)) => {
                    return Err(format!(
                        "{}: `cookie_name` {name:?} is not a valid cookie name",
                        where_()
                    ));
                }
                (true, None) => {
                    return Err(format!(
                        "{}: `key: {}` needs `cookie_name`",
                        where_(),
                        if cfg.key == RateLimitKey::Cookie {
                            "cookie"
                        } else {
                            "cookie_ip"
                        }
                    ));
                }
                (false, Some(_)) => {
                    return Err(format!(
                        "{}: `cookie_name` only applies to `key: cookie` and `key: cookie_ip`",
                        where_()
                    ));
                }
                (false, None) => None,
            };
            let ceiling = match cfg.ip_ceiling.as_deref() {
                // `cookie_ip` sans plafond écrit : plafond implicite.
                None if cfg.key == RateLimitKey::CookieIp => {
                    let q = Quota {
                        count: quota.count.saturating_mul(IMPLICIT_CEILING_FACTOR),
                        burst: quota.burst.saturating_mul(IMPLICIT_CEILING_FACTOR),
                        ..quota
                    };
                    let cid = (id.0.clone(), format!("{}|ceiling|{q:?}", id.1));
                    Some(
                        shared
                            .entry(cid)
                            .or_insert_with(|| {
                                let l = Arc::new(Limiter::new(q));
                                all.push(l.clone());
                                l
                            })
                            .clone(),
                    )
                }
                None => None,
                Some(c) => {
                    if c.auth.is_some()
                        || c.ip_ceiling.is_some()
                        || c.cookie_name.is_some()
                        || c.key != RateLimitKey::Ip
                    {
                        return Err(format!(
                            "{}: `ip_ceiling` takes only rate fields (limit_req_per_sec / limit_request, period, burst, timeout): it always counts per IP",
                            where_()
                        ));
                    }
                    let q = c
                        .quota()
                        .map_err(|e| format!("{}.ip_ceiling: {e}", where_()))?;
                    let cid = (id.0.clone(), format!("{}|ceiling|{q:?}", id.1));
                    Some(
                        shared
                            .entry(cid)
                            .or_insert_with(|| {
                                let l = Arc::new(Limiter::new(q));
                                all.push(l.clone());
                                l
                            })
                            .clone(),
                    )
                }
            };
            let limiter = shared
                .entry(id)
                .or_insert_with(|| {
                    let l = Arc::new(Limiter::new(quota));
                    all.push(l.clone());
                    l
                })
                .clone();
            let costs = cfg
                .costs
                .iter()
                .map(|c| {
                    let re = c.regex.as_deref().map(regex::Regex::new).transpose();
                    re.map(|re| {
                        (
                            re,
                            c.methods
                                .iter()
                                .map(|m| m.to_ascii_uppercase())
                                .collect::<Vec<_>>(),
                            c.cost,
                        )
                    })
                    .map_err(|e| format!("{}: invalid `costs` regex: {e}", where_()))
                })
                .collect::<Result<Vec<_>, String>>()?;
            if cfg.adaptive.is_some() {
                start_cpu_sampler();
            }
            Ok(Entry {
                limiter,
                key: cfg.key,
                costs: Arc::new(costs),
                adaptive: cfg.adaptive.clone(),
                cookie,
                ceiling,
            })
        };

        for (index, rule) in routes.iter().enumerate() {
            let Some(cfg) = rule.ratelimit.as_ref() else {
                by_route.push(None);
                continue;
            };
            let group = cfg.inherited_from_group;
            // Un bloc qui ne contient que `auth:` limite les chemins de
            // connexion sans limiter les routes elles-mêmes. Un bloc vide
            // (ni limite générale ni `auth`) reste une erreur : il ne
            // protégerait rien, ce qui n'est sûrement pas l'intention.
            let general = if cfg.has_general_limit() {
                Some(make(index, rule, cfg, group, "")?)
            } else if cfg.auth.is_some() {
                if cfg.burst.is_some() || cfg.timeout != 0 || cfg.period.is_some() {
                    return Err(format!(
                        "routes.yml: route `{}` (vhost {:?}): ratelimit: `burst`, `period` and `timeout` need `limit_req_per_sec` or `limit_request` — put them inside `auth:` to limit only the login paths",
                        rule.prefix, rule.vhost
                    ));
                }
                None
            } else {
                return Err(format!(
                    "routes.yml: route `{}` (vhost {:?}): ratelimit: set `limit_req_per_sec` or `limit_request`, or an `auth:` block",
                    rule.prefix, rule.vhost
                ));
            };
            let auth = match cfg.auth.as_deref() {
                Some(a) => {
                    if a.auth.is_some() {
                        return Err(format!(
                            "routes.yml: route `{}`: `ratelimit.auth` cannot contain another `auth`",
                            rule.prefix
                        ));
                    }
                    Some(make(index, rule, a, group, ".auth")?)
                }
                None => None,
            };
            by_route.push(Some(RouteLimits { general, auth }));
        }

        // Plafonds globaux : un par groupe `vhosts:` (routes qui héritent),
        // ou par route qui écrit le sien.
        let mut caps: HashMap<String, Arc<Cap>> = HashMap::new();
        let mut caps_by_route = Vec::with_capacity(routes.len());
        for (index, rule) in routes.iter().enumerate() {
            let Some(bw) = rule.bandwidth_max.as_ref() else {
                caps_by_route.push(None);
                continue;
            };
            let place = format!(
                "routes.yml: route `{}` (vhost {:?}): bandwidth_max",
                rule.prefix, rule.vhost
            );
            if bw.request_per_second == 0 {
                return Err(format!("{place}: `request_per_second` must be at least 1"));
            }
            let scope = match bw.inherited_from_group {
                Some(g) => format!("group#{g}"),
                None => format!("route#{index}"),
            };
            let cap = match caps.get(&scope) {
                Some(c) => c.clone(),
                None => {
                    let quota = Quota {
                        count: bw.request_per_second,
                        period: Duration::from_secs(1),
                        burst: bw.burst.unwrap_or(bw.request_per_second).max(1),
                        block: Duration::ZERO,
                        penalty_factor: 1,
                        penalty_max: Duration::ZERO,
                        penalty_forget: Duration::ZERO,
                    };
                    let page = Arc::new(
                        CapPage::load(&bw.static_page).map_err(|e| format!("{place}: {e}"))?,
                    );
                    let limiter = Arc::new(Limiter::new(quota));
                    all.push(limiter.clone());
                    let nets = |list: &[String],
                                field: &str|
                     -> Result<Vec<ipnet::IpNet>, String> {
                        list.iter()
                            .map(|e| parse_net(e).map_err(|err| format!("{place}.{field}: {err}")))
                            .collect()
                    };
                    let c = Arc::new(Cap {
                        limiter,
                        page,
                        rps: bw.request_per_second,
                        filtered: nets(&bw.ip_filtered, "ip_filtered")?,
                        nofiltered: nets(&bw.ip_nofiltered, "ip_nofiltered")?,
                        exclude: bw
                            .exclude
                            .iter()
                            .map(|r| {
                                regex::Regex::new(r).map_err(|e| {
                                    format!("{place}.exclude: invalid regex {r:?}: {e}")
                                })
                            })
                            .collect::<Result<Vec<_>, String>>()?,
                    });
                    caps.insert(scope, c.clone());
                    c
                }
            };
            caps_by_route.push(Some(cap));
        }

        Ok(RateLimiters {
            by_route,
            caps_by_route,
            all,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.all.is_empty()
    }

    /// Plafond global applicable : celui de la route, sinon (chemin
    /// qu'aucune route ne sert) celui du vhost. Les défis ACME n'y sont
    /// jamais soumis : un renouvellement de certificat ne doit pas échouer
    /// parce que le site est saturé.
    fn resolve_cap(
        &self,
        routes: &[RouteRule],
        path: &str,
        host: Option<&str>,
    ) -> Option<&Arc<Cap>> {
        if path.starts_with("/.well-known/acme-challenge/") {
            return None;
        }
        let idx = match_route_idx(path, host, routes).or_else(|| {
            let r = find_vhost_route(host, routes)?;
            routes.iter().position(|x| {
                x.vhost == r.vhost
                    && x.bandwidth_max
                        .as_ref()
                        .is_some_and(|b| b.inherited_from_group.is_some())
            })
        })?;
        self.caps_by_route
            .get(idx)?
            .as_ref()
            // Chemin exclu : ni plafonné, ni compté.
            .filter(|c| !c.excludes(path))
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
            let label = if r.vhost.is_empty() {
                "(catch-all)".to_string()
            } else {
                r.vhost.join(", ")
            };
            if let Some(bw) = &r.bandwidth_max {
                let line = format!(
                    "bandwidth_max {label}{}: {} req/s{} → {} (503){}{}",
                    if bw.inherited_from_group.is_some() {
                        String::new()
                    } else {
                        format!(" {}", r.prefix)
                    },
                    bw.request_per_second,
                    bw.burst.map(|b| format!(" burst {b}")).unwrap_or_default(),
                    bw.static_page,
                    if bw.ip_filtered.is_empty() {
                        String::new()
                    } else {
                        format!(", only {}", bw.ip_filtered.join(" "))
                    },
                    if bw.ip_nofiltered.is_empty() {
                        String::new()
                    } else {
                        format!(", never {}", bw.ip_nofiltered.join(" "))
                    }
                ) + &if bw.exclude.is_empty() {
                    String::new()
                } else {
                    format!(", paths excluded: {}", bw.exclude.join(" "))
                };
                if seen.insert(line.clone()) {
                    out.push(line);
                }
            }
            let Some(cfg) = &r.ratelimit else { continue };
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
            // Chemin qu'aucune route ne sert sur ce vhost (`/auth`…) : la
            // limite du vhost, c'est-à-dire celle héritée de son groupe
            // `vhosts:` — pas celle qu'une route a fixée pour son seul chemin.
            .or_else(|| {
                let r = find_vhost_route(host, routes)?;
                routes
                    .iter()
                    .position(|x| {
                        x.vhost == r.vhost
                            && x.ratelimit
                                .as_ref()
                                .is_some_and(|c| c.inherited_from_group.is_some())
                    })
                    .or_else(|| routes.iter().position(|x| std::ptr::eq(x, r)))
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
            limits.auth.as_ref().or(limits.general.as_ref())
        } else {
            limits.general.as_ref()
        }
    }
}

// ─── Middleware hyper ────────────────────────────────────────────────

/// La page de surplus de `bandwidth_max`.
fn over_capacity_response(cap: &Cap) -> HttpResponse {
    HttpResponse::ServiceUnavailable()
        .insert_header((header::CONTENT_TYPE, cap.page.content_type.as_str()))
        .insert_header((header::RETRY_AFTER, "1"))
        .insert_header((header::CACHE_CONTROL, "no-store"))
        .insert_header(("x-bandwidth-max", cap.rps.to_string()))
        .body(cap.page.body())
}

/// Route sans `ratelimit` mais avec `bandwidth_max` : seul le plafond.
fn over_capacity_or_next(
    cap: Arc<Cap>,
    req: ServiceRequest,
    next: Next,
    host: Option<&str>,
) -> ServiceFuture {
    match cap.limiter.check("*") {
        Decision::Allow { .. } => next.call(req),
        Decision::Deny { .. } => {
            tracing::warn!(
                host = %host.unwrap_or("-"),
                path = %req.path(),
                limit = cap.rps,
                "bandwidth_max reached: request served the static page (503)"
            );
            Box::pin(async move { Ok(req.into_response(over_capacity_response(&cap))) })
        }
    }
}

/// Middleware de limitation de débit, à enregistrer avec
/// `App::wrap(VhostRateLimit { .. })`.
pub struct VhostRateLimit {
    pub state: web::Data<AppState>,
    pub limiters: Arc<RateLimiters>,
}

impl Entry {
    /// Coût de la requête (première règle de `costs` qui correspond, sinon
    /// 1), divisé par le facteur de charge (`adaptive`).
    fn weight(&self, method: &str, path: &str) -> (f64, u32, f64) {
        let cost = self
            .costs
            .iter()
            .find(|(re, methods, _)| {
                re.as_ref().is_none_or(|re| re.is_match(path))
                    && (methods.is_empty() || methods.iter().any(|m| m == method))
            })
            .map(|(_, _, c)| *c)
            .unwrap_or(1);
        let factor = self
            .adaptive
            .as_ref()
            .map(|a| a.factor(cpu_percent()))
            .unwrap_or(1.0);
        (f64::from(cost) / factor, cost, factor)
    }
}

static CPU_PERCENT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
static CPU_SAMPLER: std::sync::Once = std::sync::Once::new();

/// Occupation du processeur de la machine (toutes les cœurs), en %,
/// mesurée chaque seconde depuis `/proc/stat`.
pub fn cpu_percent() -> u32 {
    CPU_PERCENT.load(std::sync::atomic::Ordering::Relaxed)
}

/// Démarré une seule fois, et seulement si un bloc utilise `adaptive`.
fn start_cpu_sampler() {
    CPU_SAMPLER.call_once(|| {
        let _ = std::thread::Builder::new()
            .name("ratelimit-cpu".into())
            .spawn(|| {
                let read = || -> Option<(u64, u64)> {
                    let stat = std::fs::read_to_string("/proc/stat").ok()?;
                    let line = stat.lines().next()?;
                    let v: Vec<u64> = line
                        .split_whitespace()
                        .skip(1)
                        .filter_map(|x| x.parse().ok())
                        .collect();
                    if v.len() < 4 {
                        return None;
                    }
                    let idle = v[3] + v.get(4).copied().unwrap_or(0); // idle + iowait
                    Some((v.iter().sum(), idle))
                };
                let mut prev = read();
                loop {
                    std::thread::sleep(Duration::from_secs(1));
                    let cur = read();
                    if let (Some((t0, i0)), Some((t1, i1))) = (prev, cur) {
                        let total = t1.saturating_sub(t0);
                        let idle = i1.saturating_sub(i0);
                        if total > 0 {
                            let busy = ((total - idle.min(total)) * 100 / total) as u32;
                            CPU_PERCENT.store(busy, std::sync::atomic::Ordering::Relaxed);
                        }
                    }
                    prev = cur;
                }
            });
    });
}

/// Utilisateur du jeton présenté (Bearer, sinon cookie de session), s'il
/// est valide.
fn token_user(req: &ServiceRequest, state: &AppState, ip: &str) -> Option<String> {
    let from_bearer = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .and_then(|t| extract_token_user(t, &state.config, ip.to_string()).ok());
    from_bearer.or_else(|| {
        let cookie = req.cookie("session_token")?;
        extract_token_user(cookie.value(), &state.config, ip.to_string()).ok()
    })
}

fn key_for(req: &ServiceRequest, state: &AppState, entry: &Entry, ip: &str) -> String {
    let user = match entry.key {
        RateLimitKey::Ip => return ip.to_string(),
        RateLimitKey::Cookie | RateLimitKey::CookieIp => {
            let value = entry
                .cookie
                .as_deref()
                .and_then(|name| req.cookie(name))
                .map(|c| c.value().to_string());
            let key = cookie_key(value.as_deref(), ip);
            // cookie_ip : la même session depuis une autre IP est un autre
            // compteur. Sans cookie, `cookie_key` a déjà rendu l'IP seule.
            return if entry.key == RateLimitKey::CookieIp && key != ip {
                format!("{key}|ip:{ip}")
            } else {
                key
            };
        }
        RateLimitKey::User | RateLimitKey::UserIp => token_user(req, state, ip),
    };
    compose_key(entry.key, user.as_deref(), ip)
}

/// Clé pour `key: cookie` : l'empreinte de la valeur (jamais la valeur
/// elle-même, qui peut être un identifiant de session), sinon l'IP.
fn cookie_key(value: Option<&str>, ip: &str) -> String {
    match value.map(str::trim).filter(|v| !v.is_empty()) {
        Some(v) => {
            let hash = blake3::hash(v.as_bytes());
            format!("cookie:{}", &hash.to_hex()[..32])
        }
        None => ip.to_string(),
    }
}

/// Nom de cookie acceptable (RFC 6265 : un « token » HTTP).
fn valid_cookie_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

/// La clé du compteur, à partir de l'utilisateur (s'il y en a un) et de
/// l'IP. Les préfixes séparent les espaces de clés : un nom d'utilisateur
/// ne peut jamais tomber sur la clé d'une IP, ni l'inverse.
fn compose_key(kind: RateLimitKey, user: Option<&str>, ip: &str) -> String {
    match (kind, user) {
        (RateLimitKey::Ip | RateLimitKey::Cookie | RateLimitKey::CookieIp, _) | (_, None) => {
            ip.to_string()
        }
        (RateLimitKey::User, Some(u)) => format!("user:{u}"),
        (RateLimitKey::UserIp, Some(u)) => format!("user:{u}|ip:{ip}"),
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
        let cap = self
            .limiters
            .resolve_cap(&state.routes.routes, req.path(), host.as_deref())
            .cloned();
        let Some(entry) = self
            .limiters
            .resolve(&state.routes.routes, req.path(), host.as_deref())
        else {
            return match cap {
                Some(cap) => {
                    let ip = client_ip(req.request(), &state.config);
                    if cap.applies_to(ip) {
                        over_capacity_or_next(cap, req, next, host.as_deref())
                    } else {
                        next.call(req)
                    }
                }
                None => next.call(req),
            };
        };

        let Some(ip) = client_ip(req.request(), &state.config) else {
            // Sans IP on ne peut pas compter : on refuse plutôt que de
            // laisser passer sans limite.
            let res = HttpResponse::InternalServerError().body("Unable to determine client IP");
            return Box::pin(async move { Ok(req.into_response(res)) });
        };
        let ip_addr = ip;
        let ip = ip.to_string();
        // Le plafond global ne concerne pas les adresses exemptées.
        let cap = cap.filter(|c| c.applies_to(Some(ip_addr)));
        // Poids de la requête : son coût (`costs`), divisé par le facteur
        // de charge (`adaptive`). 1.0 pour une requête ordinaire au calme.
        let (weight, cost, load_factor) = entry.weight(req.method().as_str(), req.path());
        // Plafond par IP d'abord : quelles que soient les clés présentées,
        // une adresse ne dépasse jamais ce débit.
        let (key, decision, quota) = match &entry.ceiling {
            Some(c) => match c.check_weighted(&ip, weight) {
                Decision::Allow { .. } => {
                    let key = key_for(&req, state, entry, &ip);
                    let d = entry.limiter.check_weighted(&key, weight);
                    (key, d, entry.limiter.quota())
                }
                deny => (format!("ip_ceiling:{ip}"), deny, c.quota()),
            },
            None => {
                let key = key_for(&req, state, entry, &ip);
                let d = entry.limiter.check_weighted(&key, weight);
                (key, d, entry.limiter.quota())
            }
        };

        match decision {
            // Le plafond global ne compte que les requêtes que la limite
            // par client aurait laissées passer : un client déjà refusé ne
            // consomme pas la capacité des autres.
            Decision::Allow { .. }
                if cap
                    .as_ref()
                    .is_some_and(|c| !matches!(c.limiter.check("*"), Decision::Allow { .. })) =>
            {
                let cap = cap.expect("checked above");
                Box::pin(async move { Ok(req.into_response(over_capacity_response(&cap))) })
            }
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
                    cost = cost,
                    load_factor = %format!("{load_factor:.2}"),
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
    fn a_route_with_its_own_block_has_its_own_counter() {
        let routes: crate::config::config::RouteConfig = serde_yaml::from_str(
            r#"
vhosts:
  - vhost: ["app.example.com"]
    ratelimit: { limit_req_per_sec: 10, burst: 20 }
    routes:
      - { prefix: "/", target: "http://127.0.0.1:1" }
      - { prefix: "/docs", target: "http://127.0.0.1:1" }
      - prefix: "/search"
        target: "http://127.0.0.1:1"
        ratelimit: { limit_req_per_sec: 10, burst: 20 }   # same values, own block
      - prefix: "/export"
        target: "http://127.0.0.1:1"
        ratelimit: { limit_req_per_sec: 10, burst: 20 }
"#,
        )
        .unwrap();
        let routes = routes.expand_vhost_groups().routes;
        let rl = RateLimiters::from_routes(&routes).unwrap();
        let host = Some("app.example.com");
        let id = |path: &str| {
            rl.resolve(&routes, path, host)
                .map(|e| Arc::as_ptr(&e.limiter))
        };

        assert!(id("/").is_some());
        assert_eq!(
            id("/"),
            id("/docs/x"),
            "routes inheriting the group share one counter"
        );
        assert_ne!(
            id("/search"),
            id("/"),
            "an own block is separate, even with identical values"
        );
        assert_ne!(
            id("/search"),
            id("/export"),
            "two own blocks are separate from each other"
        );
        assert_eq!(
            id("/auth"),
            id("/"),
            "login paths follow the vhost's (group) limit"
        );
    }

    #[test]
    fn auth_only_block_limits_login_paths_and_not_routes() {
        let routes: crate::config::config::RouteConfig = serde_yaml::from_str(
            r#"
vhosts:
  - vhost: ["app.example.com"]
    ratelimit:
      auth:
        limit_req_per_sec: 10
        burst: 3
        timeout: 300
        key: ip
    routes:
      - { prefix: "/", target: "http://127.0.0.1:1" }
"#,
        )
        .unwrap();
        let routes = routes.expand_vhost_groups().routes;
        let rl = RateLimiters::from_routes(&routes).unwrap();
        let host = Some("app.example.com");
        assert!(
            rl.resolve(&routes, "/", host).is_none(),
            "routes are not limited"
        );
        assert!(rl.resolve(&routes, "/page", host).is_none());
        assert!(
            rl.resolve(&routes, "/auth", host).is_some(),
            "login paths are"
        );
        assert!(rl.resolve(&routes, "/refresh_token", host).is_some());

        // Nothing at all, or route settings without a rate: refused.
        for bad in ["{}", "{ burst: 5, auth: { limit_req_per_sec: 1 } }"] {
            let yaml = format!(
                "routes:\n  - {{ prefix: \"/\", target: \"http://127.0.0.1:1\", ratelimit: {bad} }}\n"
            );
            let r: crate::config::config::RouteConfig = serde_yaml::from_str(&yaml).unwrap();
            let r = r.expand_vhost_groups().routes;
            assert!(
                RateLimiters::from_routes(&r).is_err(),
                "{bad} must be refused"
            );
        }
    }

    #[test]
    fn cookie_key_and_ip_ceiling() {
        let ip = "203.0.113.7";
        // Same value, same counter; different values, different counters.
        assert_eq!(
            cookie_key(Some("abc"), ip),
            cookie_key(Some("abc"), "198.51.100.1")
        );
        assert_ne!(cookie_key(Some("abc"), ip), cookie_key(Some("abd"), ip));
        // No cookie, or an empty one: the IP.
        assert_eq!(cookie_key(None, ip), ip);
        assert_eq!(cookie_key(Some("  "), ip), ip);
        // The raw value never appears in the key (it may be a session id).
        assert!(!cookie_key(Some("secret-session-123"), ip).contains("secret"));

        let build = |yaml: &str| {
            let r: crate::config::config::RouteConfig = serde_yaml::from_str(yaml).unwrap();
            let r = r.expand_vhost_groups().routes;
            RateLimiters::from_routes(&r).map(|rl| (rl, r))
        };
        let ok = build(
            r#"
routes:
  - prefix: "/"
    target: "http://127.0.0.1:1"
    ratelimit:
      limit_req_per_sec: 1
      burst: 2
      key: cookie
      custom_cookie: "app_session"
      ip_ceiling: { limit_req_per_sec: 5, burst: 10 }
"#,
        );
        let (rl, routes) = ok.expect("valid cookie block");
        let e = rl.resolve(&routes, "/x", None).expect("limited");
        assert_eq!(e.key, RateLimitKey::Cookie);
        assert_eq!(e.cookie.as_deref(), Some("app_session"));
        let ceiling = e.ceiling.as_ref().expect("ceiling built");
        // Rotating cookie values cannot get past the ceiling: 10 then refused.
        let allowed = (0..30)
            .filter(|_| matches!(ceiling.check(ip), Decision::Allow { .. }))
            .count();
        assert_eq!(allowed, 10);

        for bad in [
            "{ limit_req_per_sec: 1, key: cookie }", // no cookie_name
            "{ limit_req_per_sec: 1, cookie_name: \"a\" }", // cookie_name without key: cookie
            "{ limit_req_per_sec: 1, key: cookie, cookie_name: \"a b\" }", // invalid name
            "{ limit_req_per_sec: 1, ip_ceiling: { limit_req_per_sec: 1, key: user } }", // ceiling is per IP
            "{ limit_req_per_sec: 1, ip_ceiling: { burst: 3 } }", // ceiling without a rate
        ] {
            let yaml = format!(
                "routes:\n  - {{ prefix: \"/\", target: \"http://127.0.0.1:1\", ratelimit: {bad} }}\n"
            );
            assert!(build(&yaml).is_err(), "{bad} must be refused");
        }
    }

    #[test]
    fn cookie_ip_has_a_ceiling_built_in() {
        let build = |yaml: &str| {
            let r: crate::config::config::RouteConfig = serde_yaml::from_str(yaml).unwrap();
            let r = r.expand_vhost_groups().routes;
            RateLimiters::from_routes(&r).map(|rl| (rl, r))
        };
        let (rl, routes) = build(
            r#"
routes:
  - prefix: "/"
    target: "http://127.0.0.1:1"
    ratelimit: { limit_req_per_sec: 1, burst: 3, key: cookie_ip, cookie_name: "sid" }
"#,
        )
        .expect("valid");
        let e = rl.resolve(&routes, "/", None).unwrap();
        assert_eq!(e.key, RateLimitKey::CookieIp);
        let ceiling = e.ceiling.as_ref().expect("implicit ceiling");
        assert_eq!(ceiling.quota().burst, 3 * IMPLICIT_CEILING_FACTOR);
        assert_eq!(ceiling.quota().count, IMPLICIT_CEILING_FACTOR);
        // An explicit ip_ceiling replaces the implicit one.
        let (rl, routes) = build(
            r#"
routes:
  - prefix: "/"
    target: "http://127.0.0.1:1"
    ratelimit:
      limit_req_per_sec: 1
      burst: 3
      key: ip_cookie
      cookie_name: "sid"
      ip_ceiling: { limit_req_per_sec: 7, burst: 9 }
"#,
        )
        .expect("valid");
        assert_eq!(
            rl.resolve(&routes, "/", None)
                .unwrap()
                .ceiling
                .as_ref()
                .unwrap()
                .quota()
                .burst,
            9
        );
        // cookie_name is required.
        assert!(build("routes:\n  - { prefix: \"/\", target: \"http://127.0.0.1:1\", ratelimit: { limit_req_per_sec: 1, key: cookie_ip } }\n").is_err());
    }

    #[test]
    fn key_kinds() {
        let parse = |k: &str| -> RateLimitConfig {
            serde_yaml::from_str(&format!("limit_req_per_sec: 1\nkey: {k}")).unwrap()
        };
        assert_eq!(parse("ip").key, RateLimitKey::Ip);
        assert_eq!(parse("user").key, RateLimitKey::User);
        assert_eq!(parse("user_ip").key, RateLimitKey::UserIp);
        assert_eq!(parse("ip_user").key, RateLimitKey::UserIp);

        let ip = "203.0.113.7";
        // Anonymous: the IP, whatever the kind.
        for k in [RateLimitKey::Ip, RateLimitKey::User, RateLimitKey::UserIp] {
            assert_eq!(compose_key(k, None, ip), ip);
        }
        // Two users behind one IP: separate counters with user and user_ip.
        assert_ne!(
            compose_key(RateLimitKey::UserIp, Some("alice"), ip),
            compose_key(RateLimitKey::UserIp, Some("bob"), ip)
        );
        // One user from two IPs: one counter with user, two with user_ip.
        assert_eq!(
            compose_key(RateLimitKey::User, Some("alice"), ip),
            compose_key(RateLimitKey::User, Some("alice"), "198.51.100.9")
        );
        assert_ne!(
            compose_key(RateLimitKey::UserIp, Some("alice"), ip),
            compose_key(RateLimitKey::UserIp, Some("alice"), "198.51.100.9")
        );
        // A username that looks like an IP never shares the IP's counter.
        assert_ne!(compose_key(RateLimitKey::UserIp, Some(ip), ip), ip);
        assert_eq!(compose_key(RateLimitKey::Ip, Some("alice"), ip), ip);
    }

    #[test]
    fn bandwidth_max_is_one_counter_for_the_whole_vhost() {
        let dir = std::env::temp_dir().join(format!("pa-bw-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let page = dir.join("busy.html");
        std::fs::write(&page, "<h1>busy</h1>").unwrap();
        let yaml = format!(
            r#"
vhosts:
  - vhost: ["app.example.com"]
    bandwith_max:                       # the spelling from the request works too
      request_per_second: 3
      static_page: "{}"
    routes:
      - {{ prefix: "/", target: "http://127.0.0.1:1" }}
      - {{ prefix: "/api", target: "http://127.0.0.1:1" }}
"#,
            page.display()
        );
        let routes: crate::config::config::RouteConfig = serde_yaml::from_str(&yaml).unwrap();
        let routes = routes.expand_vhost_groups().routes;
        let rl = RateLimiters::from_routes(&routes).unwrap();
        assert!(!rl.is_empty());
        let host = Some("app.example.com");
        let a = rl.resolve_cap(&routes, "/", host).unwrap();
        let b = rl.resolve_cap(&routes, "/api/x", host).unwrap();
        assert!(
            Arc::ptr_eq(a, b),
            "routes inheriting the vhost share one cap"
        );
        assert!(
            rl.resolve_cap(&routes, "/.well-known/acme-challenge/t", host)
                .is_none()
        );
        // 3 requests pass, whatever path or client; the 4th gets the page.
        for _ in 0..3 {
            assert!(matches!(a.limiter.check("*"), Decision::Allow { .. }));
        }
        assert!(matches!(b.limiter.check("*"), Decision::Deny { .. }));
        assert_eq!(&a.page.body()[..], b"<h1>busy</h1>");
        assert_eq!(a.page.content_type, "text/html; charset=utf-8");
        // Who is subject to the cap.
        let ip = |s: &str| Some(s.parse::<std::net::IpAddr>().unwrap());
        assert!(a.applies_to(ip("203.0.113.9")), "no lists: everyone");
        let filtered_yaml = yaml.replace(
            "      static_page:",
            "      ip_filtered: [\"0.0.0.0/0\", \"::/0\"]\n      ip_nofiltered: [\"192.168.0.0/24\", \"fe80::/64\", \"10.1.2.3\"]\n      static_page:",
        );
        let routes2: crate::config::config::RouteConfig =
            serde_yaml::from_str(&filtered_yaml).unwrap();
        let routes2 = routes2.expand_vhost_groups().routes;
        let rl2 = RateLimiters::from_routes(&routes2).unwrap();
        let c = rl2.resolve_cap(&routes2, "/", host).unwrap();
        assert!(
            c.applies_to(ip("203.0.113.9")),
            "an outside address is capped"
        );
        assert!(c.applies_to(ip("2001:db8::1")));
        assert!(
            !c.applies_to(ip("192.168.0.42")),
            "the internal network never is"
        );
        assert!(!c.applies_to(ip("fe80::1234")));
        assert!(!c.applies_to(ip("10.1.2.3")), "a single address works too");
        assert!(c.applies_to(None), "unknown address: capped");
        // Only some addresses capped.
        let only = yaml.replace(
            "      static_page:",
            "      ip_filtered: [\"203.0.113.0/24\"]\n      static_page:",
        );
        let r3: crate::config::config::RouteConfig = serde_yaml::from_str(&only).unwrap();
        let r3 = r3.expand_vhost_groups().routes;
        let rl3 = RateLimiters::from_routes(&r3).unwrap();
        let c3 = rl3.resolve_cap(&r3, "/", host).unwrap();
        assert!(c3.applies_to(ip("203.0.113.7")) && !c3.applies_to(ip("198.51.100.1")));
        // Invalid entries stop startup — `fe80::00::00/64` has two `::`.
        let bad_net = yaml.replace(
            "      static_page:",
            "      ip_nofiltered: [\"fe80::00::00/64\"]\n      static_page:",
        );
        let r4: crate::config::config::RouteConfig = serde_yaml::from_str(&bad_net).unwrap();
        let err = RateLimiters::from_routes(&r4.expand_vhost_groups().routes).unwrap_err();
        assert!(
            err.contains("ip_nofiltered") && err.contains("fe80::00::00/64"),
            "{err}"
        );
        // Excluded paths: never capped, never counted.
        let ex = yaml.replace(
            "      static_page:",
            "      exclude: ['\\.(css|js|png|svg|woff2)$', '^/healthz$']\n      static_page:",
        );
        let r5: crate::config::config::RouteConfig = serde_yaml::from_str(&ex).unwrap();
        let r5 = r5.expand_vhost_groups().routes;
        let rl5 = RateLimiters::from_routes(&r5).unwrap();
        assert!(rl5.resolve_cap(&r5, "/static/app.js", host).is_none());
        assert!(rl5.resolve_cap(&r5, "/img/logo.png", host).is_none());
        assert!(rl5.resolve_cap(&r5, "/healthz", host).is_none());
        assert!(
            rl5.resolve_cap(&r5, "/page", host).is_some(),
            "other paths are still capped"
        );
        let bad_re = yaml.replace(
            "      static_page:",
            "      exclude: ['(']\n      static_page:",
        );
        let r6: crate::config::config::RouteConfig = serde_yaml::from_str(&bad_re).unwrap();
        assert!(
            RateLimiters::from_routes(&r6.expand_vhost_groups().routes)
                .unwrap_err()
                .contains("exclude")
        );
        // A missing page stops startup.
        let bad = yaml.replace("busy.html", "missing.html");
        let routes: crate::config::config::RouteConfig = serde_yaml::from_str(&bad).unwrap();
        assert!(RateLimiters::from_routes(&routes.expand_vhost_groups().routes).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    const SEC: u64 = 1_000_000_000;

    #[test]
    fn progressive_penalty_grows_then_is_forgotten() {
        let q = cfg("limit_req_per_sec: 1\nburst: 1\ntimeout: 10\npenalty: { factor: 3, max: 60, forget_after: 300 }")
            .quota()
            .unwrap();
        let l = Limiter::new(q);
        let deny_secs = |d: Decision| match d {
            Decision::Deny { retry_after } => retry_after.as_secs(),
            Decision::Allow { .. } => 0,
        };
        let mut t = 0;
        assert!(matches!(l.check_at("k", t), Decision::Allow { .. }));
        // 1st offence: 10 s; 2nd: 30 s; 3rd: 90 s capped at 60 s.
        assert_eq!(deny_secs(l.check_at("k", t)), 10);
        t += 11 * SEC;
        assert!(matches!(l.check_at("k", t), Decision::Allow { .. }));
        assert_eq!(deny_secs(l.check_at("k", t)), 30);
        t += 31 * SEC;
        assert!(matches!(l.check_at("k", t), Decision::Allow { .. }));
        assert_eq!(deny_secs(l.check_at("k", t)), 60);
        // Requests refused during a block do not extend it.
        assert_eq!(deny_secs(l.check_at("k", t + SEC)), 59);
        // Quiet for longer than forget_after: back to the base timeout.
        t += 400 * SEC;
        assert!(matches!(l.check_at("k", t), Decision::Allow { .. }));
        assert_eq!(deny_secs(l.check_at("k", t)), 10);
        // Without penalty: always the same timeout.
        let plain = Limiter::new(
            cfg("limit_req_per_sec: 1\nburst: 1\ntimeout: 10")
                .quota()
                .unwrap(),
        );
        for i in 0..3u64 {
            let at = i * 11 * SEC;
            assert!(matches!(plain.check_at("k", at), Decision::Allow { .. }));
            assert_eq!(deny_secs(plain.check_at("k", at)), 10);
        }
    }

    #[test]
    fn expensive_requests_use_more_of_the_bucket() {
        let l = Limiter::new(cfg("limit_req_per_sec: 1\nburst: 10").quota().unwrap());
        // A request costing 4 uses four tokens: two pass, the third does not.
        assert!(matches!(
            l.check_weighted_at("k", 0, 4.0),
            Decision::Allow { .. }
        ));
        assert!(matches!(
            l.check_weighted_at("k", 0, 4.0),
            Decision::Allow { .. }
        ));
        assert!(matches!(
            l.check_weighted_at("k", 0, 4.0),
            Decision::Deny { .. }
        ));
        // Two plain requests still fit in what is left.
        assert!(matches!(
            l.check_weighted_at("k", 0, 1.0),
            Decision::Allow { .. }
        ));
        assert!(matches!(
            l.check_weighted_at("k", 0, 1.0),
            Decision::Allow { .. }
        ));
        assert!(matches!(
            l.check_weighted_at("k", 0, 1.0),
            Decision::Deny { .. }
        ));
        // A full bucket always admits one request, however heavy.
        let l = Limiter::new(cfg("limit_req_per_sec: 1\nburst: 2").quota().unwrap());
        assert!(matches!(
            l.check_weighted_at("k", 0, 50.0),
            Decision::Allow { .. }
        ));
    }

    #[test]
    fn cost_rules_and_adaptive_factor() {
        let c = cfg(r#"
limit_req_per_sec: 5
burst: 20
costs:
  - { regex: '\.(zip|tar\.gz)$', cost: 10 }
  - { methods: ["post", "PUT"], cost: 2 }
adaptive: { cpu_threshold: 70, min_factor: 0.25 }
"#);
        c.quota().unwrap();
        let routes: crate::config::config::RouteConfig = serde_yaml::from_str(
            r#"
routes:
  - prefix: "/"
    target: "http://127.0.0.1:1"
    ratelimit:
      limit_req_per_sec: 5
      burst: 20
      costs:
        - { regex: '\.(zip|tar\.gz)$', cost: 10 }
        - { methods: ["post", "PUT"], cost: 2 }
"#,
        )
        .unwrap();
        let routes = routes.expand_vhost_groups().routes;
        let rl = RateLimiters::from_routes(&routes).unwrap();
        let e = rl.resolve(&routes, "/x", None).unwrap();
        assert_eq!(e.weight("GET", "/repo/archive/main.zip").1, 10);
        assert_eq!(e.weight("GET", "/repo/archive/main.tar.gz").1, 10);
        assert_eq!(e.weight("POST", "/form").1, 2);
        assert_eq!(e.weight("GET", "/page").1, 1);

        let a = AdaptiveConfig {
            cpu_threshold: 70,
            min_factor: 0.25,
        };
        assert_eq!(a.factor(50), 1.0);
        assert_eq!(a.factor(70), 1.0);
        assert!(
            (a.factor(85) - 0.625).abs() < 1e-9,
            "halfway: halfway between 1 and 0.25"
        );
        assert_eq!(a.factor(100), 0.25);

        for bad in [
            "limit_req_per_sec: 1\nburst: 5\ncosts: [{ regex: 'x', cost: 6 }]", // cost > burst
            "limit_req_per_sec: 1\ncosts: [{ cost: 2 }]", // no regex nor methods
            "limit_req_per_sec: 1\npenalty: { factor: 2 }", // penalty without timeout
            "limit_req_per_sec: 1\ntimeout: 10\npenalty: { factor: 1 }", // factor < 2
            "limit_req_per_sec: 1\nadaptive: { cpu_threshold: 100 }", // threshold out of range
            "limit_req_per_sec: 1\nadaptive: { min_factor: 0 }", // factor out of range
        ] {
            assert!(cfg(bad).quota().is_err(), "{bad} must be refused");
        }
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
