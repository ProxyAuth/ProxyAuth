//! Anti-bot par preuve de travail (`antibot:`).
//!
//! ```yaml
//! vhosts:
//!   - vhost: ["git.example.com"]
//!     antibot:
//!       random_difficulty: [3, 4]            # ou difficulty: 4
//!       random_algorithm: ["slow", "fast", "sha512"]   # ou algorithm: fast
//!       min_start: 2s                        # attente avant le calcul…
//!       max_start: 5s                        # …tirée entre 2 et 5 s
//!       webgl: true                          # rendu WebGL exigé
//!       reject_software_gl: false            # refuser SwiftShader / llvmpipe
//!       reject_headless: true                # webdriver, fenêtre 0×0
//!       static_page: "/var/www/abuse.html"   # page à soi, avec {{ script }}
//!       load_levels:                         # plus de trafic, plus de travail
//!         - { request: 1000, period: 10, difficulty: 5 }
//!         - { request: 5000, period: 10, difficulty: 6 }
//!       cookie_ttl: 604800
//!       only_browsers: true
//!       exclude: ['\.(css|js|png|svg|woff2)$']
//!       ip_nofiltered: ["192.168.0.0/24"]
//! ```
//!
//! # Déroulement
//!
//! Un navigateur sans laissez-passer reçoit une page qui :
//! 1. vérifie l'environnement : contexte sécurisé, `navigator.webdriver`,
//!    taille de la fenêtre (une fenêtre 0×0 trahit un navigateur piloté) ;
//! 2. attend le délai tiré entre `min_start` et `max_start` (un compte à
//!    rebours s'affiche) — le serveur refuse toute solution arrivée avant ;
//! 3. effectue un rendu WebGL : quatre passes d'un shader dont la couleur
//!    dépend du challenge, relues pixel par pixel ;
//! 4. cherche un `nonce` tel que `hash(challenge + nonce)` commence par
//!    `difficulty` zéros hexadécimaux, avec une barre de progression ;
//! 5. envoie le tout à `/.proxyauth/antibot/pass`, qui pose un cookie signé.
//!
//! # Algorithmes
//!
//! | `algorithm` | Hash | Calcul côté navigateur |
//! |---|---|---|
//! | `fast` | SHA-256 | tous les cœurs (jusqu'à 8) |
//! | `slow` | SHA-256 | un seul cœur : plus long, pour un même `difficulty` |
//! | `sha256` | SHA-256 | tous les cœurs |
//! | `sha512` | SHA-512 | tous les cœurs |
//!
//! # Ce que le WebGL prouve, et ce qu'il ne prouve pas
//!
//! Il prouve qu'un moteur WebGL a réellement exécuté un shader : un script
//! sans moteur graphique ne peut pas produire la réponse sans réimplémenter
//! le calcul. Il ne prouve **pas** qu'une carte graphique physique est
//! présente : Chrome sans interface utilise un rendu logiciel (SwiftShader).
//! `reject_software_gl` refuse ces rendus d'après le nom annoncé par le
//! navigateur — un indice, falsifiable par un robot déterminé. Même chose
//! pour la taille de fenêtre et `webdriver`. Le coût du calcul, lui, ne se
//! contourne pas.
//!
//! # Sans état côté serveur
//!
//! Le challenge est un MAC de tous ses paramètres (horodatage, difficulté,
//! algorithme, délai, options, IP, navigateur) : ni forgé, ni rejoué
//! ailleurs, ni assoupli. Le laissez-passer est `expiration . MAC`.

use std::hash::BuildHasher;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use hyper::header::{self, HeaderValue};
use serde::{Deserialize, Deserializer, Serialize};

use crate::AppState;
use crate::config::config::RouteRule;
use crate::hyper_web::HttpResponse;
use crate::hyper_web::dev::{Middleware, Next, ServiceFuture, ServiceRequest};
use crate::hyper_web::web;
use crate::network::proxy::{client_ip, find_vhost_route, match_route_idx, request_host};

/// Chemin où le navigateur envoie sa solution.
pub const PASS_PATH: &str = "/.proxyauth/antibot/pass";
const COOKIE: &str = "proxyauth_antibot";
const CHALLENGE_MAX_AGE_MS: u64 = 30 * 60 * 1000;

const FLAG_WEBGL: u8 = 1;
const FLAG_REJECT_SOFTWARE_GL: u8 = 2;
const FLAG_REJECT_HEADLESS: u8 = 4;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Algorithm {
    #[default]
    Fast,
    Slow,
    Sha256,
    Sha512,
}

impl Algorithm {
    fn name(self) -> &'static str {
        match self {
            Algorithm::Fast => "fast",
            Algorithm::Slow => "slow",
            Algorithm::Sha256 => "sha256",
            Algorithm::Sha512 => "sha512",
        }
    }
    fn parse(s: &str) -> Option<Self> {
        match s {
            "fast" => Some(Algorithm::Fast),
            "slow" => Some(Algorithm::Slow),
            "sha256" => Some(Algorithm::Sha256),
            "sha512" => Some(Algorithm::Sha512),
            _ => None,
        }
    }
    fn webcrypto(self) -> &'static str {
        match self {
            Algorithm::Sha512 => "SHA-512",
            _ => "SHA-256",
        }
    }
    /// `slow` : un seul cœur côté navigateur.
    fn single_thread(self) -> bool {
        self == Algorithm::Slow
    }
    fn digest(self, data: &[u8]) -> Vec<u8> {
        let alg = match self {
            Algorithm::Sha512 => &ring::digest::SHA512,
            _ => &ring::digest::SHA256,
        };
        ring::digest::digest(alg, data).as_ref().to_vec()
    }
}

/// Un palier de charge : si le vhost a reçu au moins `request` requêtes
/// pendant les `period` dernières secondes, la difficulté passe à
/// `difficulty` (au minimum).
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LoadLevel {
    pub request: u64,
    #[serde(default = "default_period")]
    pub period: u64,
    #[serde(deserialize_with = "de_u8_loose")]
    pub difficulty: u8,
}
fn default_period() -> u64 {
    10
}

/// `antibot:` sur un vhost (hérité par ses routes) ou sur une route.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AntiBotConfig {
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Zéros hexadécimaux exigés en tête du hash (1 à 8).
    #[serde(default = "default_difficulty", deserialize_with = "de_u8_loose")]
    pub difficulty: u8,
    /// Une difficulté tirée au hasard pour chaque visiteur.
    #[serde(
        default,
        deserialize_with = "de_u8_list_loose",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub random_difficulty: Vec<u8>,
    #[serde(default)]
    pub algorithm: Algorithm,
    /// Un algorithme tiré au hasard pour chaque visiteur.
    #[serde(
        default,
        alias = "random_algorithme",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub random_algorithm: Vec<Algorithm>,
    /// Attente minimale avant le calcul (`2`, `"2s"`, `"1500ms"`).
    #[serde(default, deserialize_with = "de_seconds")]
    pub min_start: f64,
    /// Attente maximale ; défaut = `min_start`.
    #[serde(default = "neg", deserialize_with = "de_seconds")]
    pub max_start: f64,
    /// Exiger un rendu WebGL.
    #[serde(default = "yes")]
    pub webgl: bool,
    /// Refuser les rendus logiciels (SwiftShader, llvmpipe…).
    #[serde(default)]
    pub reject_software_gl: bool,
    /// Refuser `navigator.webdriver` et les fenêtres de taille nulle.
    #[serde(default = "yes")]
    pub reject_headless: bool,
    /// Page à soi, avec `{{ script }}` (et `{{ title }}`).
    #[serde(default, alias = "page", skip_serializing_if = "Option::is_none")]
    pub static_page: Option<String>,
    /// Difficulté selon le trafic du vhost.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub load_levels: Vec<LoadLevel>,
    /// Validité du laissez-passer, en secondes.
    #[serde(default = "default_cookie_ttl")]
    pub cookie_ttl: u64,
    /// Ne défier que les User-Agent « Mozilla » (les navigateurs).
    #[serde(default = "yes")]
    pub only_browsers: bool,
    #[serde(
        default,
        alias = "excludes",
        alias = "exclude_regex",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub exclude: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ip_nofiltered: Vec<String>,
}

fn yes() -> bool {
    true
}
fn neg() -> f64 {
    -1.0
}
fn default_difficulty() -> u8 {
    4
}
fn default_cookie_ttl() -> u64 {
    7 * 24 * 3600
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Loose {
    N(f64),
    S(String),
}

fn loose_u8(v: Loose) -> Result<u8, String> {
    match v {
        Loose::N(n) if n >= 0.0 && n <= 255.0 && n.fract() == 0.0 => Ok(n as u8),
        Loose::S(s) => s
            .trim()
            .parse::<u8>()
            .map_err(|_| format!("{s:?} is not a number")),
        Loose::N(n) => Err(format!("{n} is not a small whole number")),
    }
}
fn de_u8_loose<'de, D: Deserializer<'de>>(d: D) -> Result<u8, D::Error> {
    loose_u8(Loose::deserialize(d)?).map_err(serde::de::Error::custom)
}
fn de_u8_list_loose<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    Vec::<Loose>::deserialize(d)?
        .into_iter()
        .map(loose_u8)
        .collect::<Result<_, _>>()
        .map_err(serde::de::Error::custom)
}
/// Secondes : `2`, `2.5`, `"2s"`, `"1500ms"`.
fn de_seconds<'de, D: Deserializer<'de>>(d: D) -> Result<f64, D::Error> {
    match Loose::deserialize(d)? {
        Loose::N(n) => Ok(n),
        Loose::S(s) => {
            let t = s.trim();
            let (num, mult) = if let Some(v) = t.strip_suffix("ms") {
                (v, 0.001)
            } else if let Some(v) = t.strip_suffix('s') {
                (v, 1.0)
            } else {
                (t, 1.0)
            };
            num.trim().parse::<f64>().map(|n| n * mult).map_err(|_| {
                serde::de::Error::custom(format!("{s:?} is not a duration (e.g. 2s, 1500ms)"))
            })
        }
    }
}

// ───────────────────────────────────────────── traffic counter

/// Requêtes reçues par seconde, sur les 60 dernières secondes.
#[derive(Debug)]
struct Traffic {
    buckets: Mutex<[(u64, u64); 60]>,
}

impl Traffic {
    fn new() -> Self {
        Self {
            buckets: Mutex::new([(0, 0); 60]),
        }
    }
    fn record(&self, sec: u64) {
        let mut b = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        let slot = &mut b[(sec % 60) as usize];
        if slot.0 != sec {
            *slot = (sec, 0);
        }
        slot.1 += 1;
    }
    /// Requêtes des `period` dernières secondes (seconde en cours comprise).
    fn count(&self, sec: u64, period: u64) -> u64 {
        let b = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        let from = sec.saturating_sub(period.saturating_sub(1));
        b.iter()
            .filter(|(s, _)| *s >= from && *s <= sec)
            .map(|(_, c)| c)
            .sum()
    }
}

// ───────────────────────────────────────────── page

/// La page servie, gardée en mémoire et relue si le fichier change.
#[derive(Debug)]
struct Page {
    path: Option<std::path::PathBuf>,
    cached: Mutex<(String, Option<SystemTime>, Instant)>,
}

impl Page {
    fn load(path: Option<&str>) -> Result<Self, String> {
        let Some(path) = path else {
            return Ok(Self {
                path: None,
                cached: Mutex::new((DEFAULT_PAGE.to_string(), None, Instant::now())),
            });
        };
        let p = std::path::PathBuf::from(path);
        let html = std::fs::read_to_string(&p)
            .map_err(|e| format!("cannot read `static_page` {path}: {e}"))?;
        if !html.contains("{{ script }}") && !html.contains("{{script}}") {
            return Err(format!(
                "`static_page` {path} has no {{{{ script }}}} tag: the check would never run"
            ));
        }
        let mtime = std::fs::metadata(&p).and_then(|m| m.modified()).ok();
        Ok(Self {
            path: Some(p),
            cached: Mutex::new((html, mtime, Instant::now())),
        })
    }
    fn html(&self) -> String {
        let mut c = self.cached.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(p) = &self.path {
            if c.2.elapsed() >= Duration::from_secs(5) {
                c.2 = Instant::now();
                let mtime = std::fs::metadata(p).and_then(|m| m.modified()).ok();
                if mtime != c.1 {
                    if let Ok(h) = std::fs::read_to_string(p) {
                        if h.contains("{{ script }}") || h.contains("{{script}}") {
                            c.0 = h;
                            c.1 = mtime;
                        }
                    }
                }
            }
        }
        c.0.clone()
    }
}

// ───────────────────────────────────────────── registry

#[derive(Debug)]
struct Rule {
    cfg: AntiBotConfig,
    exclude: Vec<regex::Regex>,
    nofiltered: Vec<ipnet::IpNet>,
    traffic: Arc<Traffic>,
    page: Arc<Page>,
}

impl Rule {
    fn flags(&self) -> u8 {
        (if self.cfg.webgl { FLAG_WEBGL } else { 0 })
            | (if self.cfg.reject_software_gl {
                FLAG_REJECT_SOFTWARE_GL
            } else {
                0
            })
            | (if self.cfg.reject_headless {
                FLAG_REJECT_HEADLESS
            } else {
                0
            })
    }

    /// Paramètres tirés pour un visiteur : difficulté (relevée par les
    /// paliers de charge), algorithme et délai de démarrage en ms.
    fn draw(&self, sec: u64) -> (u8, Algorithm, u64) {
        let r = random_u64();
        let mut d = if self.cfg.random_difficulty.is_empty() {
            self.cfg.difficulty
        } else {
            self.cfg.random_difficulty[(r % self.cfg.random_difficulty.len() as u64) as usize]
        };
        for level in &self.cfg.load_levels {
            if self.traffic.count(sec, level.period) >= level.request {
                d = d.max(level.difficulty);
            }
        }
        let a = if self.cfg.random_algorithm.is_empty() {
            self.cfg.algorithm
        } else {
            self.cfg.random_algorithm[((r >> 16) % self.cfg.random_algorithm.len() as u64) as usize]
        };
        let (lo, hi) = (
            self.cfg.min_start,
            self.cfg.max_start.max(self.cfg.min_start),
        );
        let frac = ((r >> 32) % 10_001) as f64 / 10_000.0;
        let start_ms = ((lo + (hi - lo) * frac) * 1000.0).round() as u64;
        (d.min(8), a, start_ms)
    }
}

fn random_u64() -> u64 {
    std::collections::hash_map::RandomState::new().hash_one(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    )
}

struct Registry {
    by_route: Vec<Option<Arc<Rule>>>,
    key: [u8; 32],
}

static REGISTRY: OnceLock<Registry> = OnceLock::new();

fn validate(cfg: &AntiBotConfig, place: &str) -> Result<(), String> {
    let d_ok = |d: u8| (1..=8).contains(&d);
    if !d_ok(cfg.difficulty) {
        return Err(format!("{place}: `difficulty` must be between 1 and 8"));
    }
    if let Some(d) = cfg.random_difficulty.iter().find(|d| !d_ok(**d)) {
        return Err(format!(
            "{place}: `random_difficulty` value {d} must be between 1 and 8"
        ));
    }
    if cfg.cookie_ttl < 60 {
        return Err(format!("{place}: `cookie_ttl` must be at least 60 seconds"));
    }
    if cfg.min_start < 0.0 || cfg.min_start > 60.0 {
        return Err(format!(
            "{place}: `min_start` must be between 0 and 60 seconds"
        ));
    }
    if cfg.max_start >= 0.0 && (cfg.max_start < cfg.min_start || cfg.max_start > 60.0) {
        return Err(format!(
            "{place}: `max_start` must be at least `min_start` and at most 60 seconds"
        ));
    }
    for l in &cfg.load_levels {
        if !d_ok(l.difficulty) {
            return Err(format!(
                "{place}: a `load_levels` difficulty must be between 1 and 8"
            ));
        }
        if l.request == 0 || !(1..=60).contains(&l.period) {
            return Err(format!(
                "{place}: a `load_levels` entry needs `request` ≥ 1 and `period` between 1 and 60 seconds"
            ));
        }
    }
    Ok(())
}

/// Valide et compile les blocs `antibot:` ; `Err` arrête le démarrage.
pub fn init(routes: &[RouteRule], secret: &str) -> Result<Vec<String>, String> {
    let mut by_route = Vec::with_capacity(routes.len());
    let mut summary = Vec::new();
    // Une règle (et un compteur de trafic) par vhost et configuration.
    let mut shared: std::collections::HashMap<String, Arc<Rule>> = std::collections::HashMap::new();
    for r in routes {
        let Some(cfg) = r.antibot.as_ref().filter(|c| c.enabled) else {
            by_route.push(None);
            continue;
        };
        let place = format!(
            "routes.yml: route `{}` (vhost {:?}): antibot",
            r.prefix, r.vhost
        );
        validate(cfg, &place)?;
        let scope = format!(
            "{}|{}",
            r.vhost.join(","),
            serde_json::to_string(cfg).unwrap_or_default()
        );
        if let Some(rule) = shared.get(&scope) {
            by_route.push(Some(rule.clone()));
            continue;
        }
        let exclude = cfg
            .exclude
            .iter()
            .map(|x| {
                regex::Regex::new(x)
                    .map_err(|e| format!("{place}.exclude: invalid regex {x:?}: {e}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let nofiltered = cfg
            .ip_nofiltered
            .iter()
            .map(|e| {
                let e = e.trim();
                e.parse::<ipnet::IpNet>()
                    .or_else(|_| e.parse::<IpAddr>().map(ipnet::IpNet::from))
                    .map_err(|_| {
                        format!(
                            "{place}.ip_nofiltered: {e:?} is not an IP address or a CIDR network"
                        )
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let page =
            Arc::new(Page::load(cfg.static_page.as_deref()).map_err(|e| format!("{place}: {e}"))?);
        let label = if r.vhost.is_empty() {
            "(catch-all)".to_string()
        } else {
            r.vhost.join(", ")
        };
        let diffs = if cfg.random_difficulty.is_empty() {
            cfg.difficulty.to_string()
        } else {
            format!("{:?}", cfg.random_difficulty)
        };
        let algs: Vec<&str> = if cfg.random_algorithm.is_empty() {
            vec![cfg.algorithm.name()]
        } else {
            cfg.random_algorithm.iter().map(|a| a.name()).collect()
        };
        summary.push(format!(
            "antibot {label}: difficulty {diffs}, {}, start {}–{}s{}{}{}, {} load levels, pass {}s",
            algs.join("/"),
            cfg.min_start,
            cfg.max_start.max(cfg.min_start),
            if cfg.webgl { ", webgl" } else { "" },
            if cfg.reject_headless {
                ", no headless"
            } else {
                ""
            },
            if cfg.static_page.is_some() {
                ", custom page"
            } else {
                ""
            },
            cfg.load_levels.len(),
            cfg.cookie_ttl
        ));
        let rule = Arc::new(Rule {
            cfg: cfg.clone(),
            exclude,
            nofiltered,
            traffic: Arc::new(Traffic::new()),
            page,
        });
        shared.insert(scope, rule.clone());
        by_route.push(Some(rule));
    }
    let key = blake3::derive_key("proxyauth antibot v1", secret.as_bytes());
    let _ = REGISTRY.set(Registry { by_route, key });
    Ok(summary)
}

fn registry() -> Option<&'static Registry> {
    REGISTRY
        .get()
        .filter(|r| r.by_route.iter().any(Option::is_some))
}

fn resolve(
    reg: &'static Registry,
    routes: &[RouteRule],
    path: &str,
    host: Option<&str>,
) -> Option<&'static Rule> {
    let idx = match_route_idx(path, host, routes).or_else(|| {
        let r = find_vhost_route(host, routes)?;
        routes
            .iter()
            .position(|x| x.vhost == r.vhost && x.antibot.is_some())
    })?;
    reg.by_route.get(idx)?.as_deref()
}

// ───────────────────────────────────────────── crypto helpers

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn mac(key: &[u8; 32], data: &str) -> String {
    blake3::keyed_hash(key, data.as_bytes())
        .to_hex()
        .to_string()
}

fn ct_eq(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq;
    a.len() == b.len() && bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

fn user_agent(req: &ServiceRequest) -> String {
    req.headers()
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

/// Le challenge : MAC de tous ses paramètres et du client.
#[allow(clippy::too_many_arguments)]
pub fn challenge_for(
    key: &[u8; 32],
    ts_ms: u64,
    d: u8,
    alg: Algorithm,
    ttl: u64,
    start_ms: u64,
    flags: u8,
    ip: &str,
    ua: &str,
) -> String {
    mac(
        key,
        &format!(
            "challenge|{ts_ms}|{d}|{}|{ttl}|{start_ms}|{flags}|{ip}|{ua}",
            alg.name()
        ),
    )
}

/// Le hash commence-t-il par `difficulty` zéros hexadécimaux ?
pub fn meets_difficulty(hash: &[u8], difficulty: u8) -> bool {
    let full = usize::from(difficulty / 2);
    hash.len() > full
        && hash[..full].iter().all(|b| *b == 0)
        && (difficulty % 2 == 0 || hash[full] >> 4 == 0)
}

/// Les 12 octets que le rendu WebGL doit produire pour ce challenge : le
/// shader calcule `(octet × 7 + décalage) mod 256` pour quatre triplets
/// d'octets du challenge (voir le fragment shader de la page).
pub fn expected_webgl(challenge: &str) -> Option<String> {
    let bytes = hex::decode(challenge.get(..24)?).ok()?;
    let mut out = Vec::with_capacity(12);
    for k in 0..4u32 {
        let offs = [k * 31, k * 17 + 3, k * 13 + 11];
        for c in 0..3 {
            out.push(((u32::from(bytes[(k * 3) as usize + c]) * 7 + offs[c]) % 256) as u8);
        }
    }
    Some(hex::encode(out))
}

fn software_renderer(r: &str) -> bool {
    let r = r.to_ascii_lowercase();
    [
        "swiftshader",
        "llvmpipe",
        "softpipe",
        "software",
        "mesa offscreen",
    ]
    .iter()
    .any(|s| r.contains(s))
}

fn pass_cookie(key: &[u8; 32], expires: u64, ua: &str) -> String {
    format!("{expires}.{}", mac(key, &format!("pass|{expires}|{ua}")))
}

/// Le cookie présenté est-il un laissez-passer valide pour ce navigateur ?
pub fn pass_is_valid(key: &[u8; 32], value: &str, ua: &str) -> bool {
    let Some((exp, sig)) = value.split_once('.') else {
        return false;
    };
    let Ok(expires) = exp.parse::<u64>() else {
        return false;
    };
    expires > now_ms() / 1000 && ct_eq(sig, &mac(key, &format!("pass|{expires}|{ua}")))
}

fn safe_redirect(target: &str) -> String {
    if target.starts_with('/')
        && !target.starts_with("//")
        && !target.contains('\\')
        && !target.contains('\n')
    {
        target.to_string()
    } else {
        "/".to_string()
    }
}

fn query_param(query: &str, name: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == name).then(|| percent_decode(v))
    })
}

/// Décodage `application/x-www-form-urlencoded` (`+` et `%XX`).
fn percent_decode(v: &str) -> String {
    let bytes = v.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => {
                match u8::from_str_radix(
                    std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("zz"),
                    16,
                ) {
                    Ok(b) => {
                        out.push(b);
                        i += 2;
                    }
                    Err(_) => out.push(b'%'),
                }
            }
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ───────────────────────────────────────────── middleware

pub struct AntiBot {
    pub state: web::Data<AppState>,
}

impl Middleware for AntiBot {
    fn call(&self, req: ServiceRequest, next: Next) -> ServiceFuture {
        let Some(reg) = registry() else {
            return next.call(req);
        };
        let path = req.path().to_string();
        if path == PASS_PATH {
            let res = verify_pass(reg, &req, &self.state);
            return Box::pin(async move { Ok(req.into_response(res)) });
        }
        let host = request_host(req.request());
        let Some(rule) = resolve(reg, &self.state.routes.routes, &path, host.as_deref()) else {
            return next.call(req);
        };
        // Le trafic du vhost, pour `load_levels`.
        rule.traffic.record(now_ms() / 1000);

        if path.starts_with("/.well-known/")
            || path == "/robots.txt"
            || path == "/favicon.ico"
            || rule.exclude.iter().any(|re| re.is_match(&path))
        {
            return next.call(req);
        }
        let ip = client_ip(req.request(), &self.state.config);
        if ip.is_some_and(|ip| rule.nofiltered.iter().any(|n| n.contains(&ip))) {
            return next.call(req);
        }
        if req.headers().contains_key(header::AUTHORIZATION) {
            return next.call(req);
        }
        let ua = user_agent(&req);
        if rule.cfg.only_browsers && !ua.contains("Mozilla") {
            return next.call(req);
        }
        if req
            .cookie(COOKIE)
            .is_some_and(|c| pass_is_valid(&reg.key, c.value(), &ua))
        {
            return next.call(req);
        }
        let method = req.method().clone();
        let res = if method == hyper::Method::GET || method == hyper::Method::HEAD {
            let ip_s = ip.map(|i| i.to_string()).unwrap_or_default();
            challenge_page(reg, rule, &ip_s, &ua, &req)
        } else {
            HttpResponse::Forbidden()
                .insert_header((header::CONTENT_TYPE, "application/json"))
                .insert_header((header::CACHE_CONTROL, "no-store"))
                .body(r#"{"error":"antibot_challenge_required","message":"Load a page of this site in a browser first."}"#)
        };
        Box::pin(async move { Ok(req.into_response(res)) })
    }
}

fn verify_pass(
    reg: &'static Registry,
    req: &ServiceRequest,
    state: &web::Data<AppState>,
) -> HttpResponse {
    let q = req.query_string();
    let ip = client_ip(req.request(), &state.config)
        .map(|i| i.to_string())
        .unwrap_or_default();
    let ua = user_agent(req);
    let redirect = safe_redirect(&query_param(q, "redir").unwrap_or_default());

    let outcome = (|| -> Result<u64, &'static str> {
        let p = |n: &str| query_param(q, n).ok_or("missing parameter");
        let ts: u64 = p("ts")?.parse().map_err(|_| "bad ts")?;
        let d: u8 = p("d")?.parse().map_err(|_| "bad difficulty")?;
        let alg = Algorithm::parse(&p("a")?).ok_or("bad algorithm")?;
        let ttl: u64 = p("ttl")?.parse().map_err(|_| "bad ttl")?;
        let start: u64 = p("s")?.parse().map_err(|_| "bad start")?;
        let flags: u8 = p("f")?.parse().map_err(|_| "bad flags")?;
        let challenge = p("challenge")?;
        let nonce: u64 = p("nonce")?.parse().map_err(|_| "bad nonce")?;
        let t = now_ms();
        if !(1..=8).contains(&d) || ts > t + 60_000 || t.saturating_sub(ts) > CHALLENGE_MAX_AGE_MS {
            return Err("challenge expired");
        }
        if !ct_eq(
            &challenge,
            &challenge_for(&reg.key, ts, d, alg, ttl, start, flags, &ip, &ua),
        ) {
            return Err("challenge not issued to this client");
        }
        // Le délai de démarrage est imposé : une solution arrivée avant n'a
        // pas attendu, quelle que soit sa justesse.
        if t < ts + start {
            return Err("solved before the start delay");
        }
        if flags & FLAG_REJECT_HEADLESS != 0 {
            if query_param(q, "wd").as_deref() == Some("1") {
                return Err("automated browser (navigator.webdriver)");
            }
            let w: u32 = query_param(q, "w")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            let h: u32 = query_param(q, "h")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            if w == 0 || h == 0 {
                return Err("window of size zero");
            }
        }
        if flags & FLAG_WEBGL != 0 {
            let got = query_param(q, "wg").unwrap_or_default();
            if !expected_webgl(&challenge).is_some_and(|e| ct_eq(&got, &e)) {
                return Err("WebGL rendering missing or wrong");
            }
            if flags & FLAG_REJECT_SOFTWARE_GL != 0
                && software_renderer(&query_param(q, "r").unwrap_or_default())
            {
                return Err("software WebGL renderer");
            }
        }
        let hash = alg.digest(format!("{challenge}{nonce}").as_bytes());
        if !meets_difficulty(&hash, d) {
            return Err("proof of work not met");
        }
        Ok(ttl)
    })();

    match outcome {
        Ok(ttl) => {
            let expires = now_ms() / 1000 + ttl;
            let cookie = format!(
                "{COOKIE}={}; Path=/; Max-Age={ttl}; HttpOnly; SameSite=Lax{}",
                pass_cookie(&reg.key, expires, &ua),
                if req.app_config().secure() {
                    "; Secure"
                } else {
                    ""
                }
            );
            tracing::info!(client_ip = %ip, "antibot: challenge solved, pass issued for {ttl}s");
            HttpResponse::Found()
                .insert_header((header::LOCATION, redirect))
                .insert_header((header::SET_COOKIE, cookie))
                .insert_header((header::CACHE_CONTROL, "no-store"))
                .finish()
        }
        Err(reason) => {
            tracing::warn!(client_ip = %ip, user_agent = %ua, reason = reason, "antibot: solution refused");
            HttpResponse::Forbidden()
                .insert_header((header::CONTENT_TYPE, "text/html; charset=utf-8"))
                .insert_header((header::CACHE_CONTROL, "no-store"))
                .insert_header(("x-antibot-reason", reason))
                .body(format!(
                    "<!doctype html><meta charset=utf-8><title>Vérification échouée</title>\
                     <body style=\"font-family:system-ui;max-width:32rem;margin:4rem auto;padding:0 1rem\">\
                     <h1>Vérification échouée</h1><p>La vérification a expiré ou n'a pas pu être validée.</p>\
                     <p><a href=\"{}\">Réessayer</a></p>",
                    crate::network::proxy::html_escape(&redirect)
                ))
        }
    }
}

fn challenge_page(
    reg: &'static Registry,
    rule: &Rule,
    ip: &str,
    ua: &str,
    req: &ServiceRequest,
) -> HttpResponse {
    let ts = now_ms();
    let (d, alg, start_ms) = rule.draw(ts / 1000);
    let flags = rule.flags();
    let ttl = rule.cfg.cookie_ttl;
    let challenge = challenge_for(&reg.key, ts, d, alg, ttl, start_ms, flags, ip, ua);
    let redir = match req.query_string() {
        "" => req.path().to_string(),
        q => format!("{}?{q}", req.path()),
    };
    let params = serde_json::json!({
        "challenge": challenge, "ts": ts, "d": d, "a": alg.name(), "algo": alg.webcrypto(),
        "single": alg.single_thread(), "ttl": ttl, "s": start_ms, "f": flags,
        "webgl": flags & FLAG_WEBGL != 0, "redir": redir, "pass": PASS_PATH,
    });
    let params = params.to_string().replace("</", "<\\/");
    let script = SCRIPT_HTML.replace("__PARAMS__", &params);
    let body = rule
        .page
        .html()
        .replace("{{ script }}", &script)
        .replace("{{script}}", &script)
        .replace("{{ title }}", TITLE)
        .replace("{{title}}", TITLE);
    let mut res = HttpResponse::Ok()
        .insert_header((header::CONTENT_TYPE, "text/html; charset=utf-8"))
        .insert_header((header::CACHE_CONTROL, "no-store"))
        .insert_header(("x-robots-tag", "noindex, nofollow"))
        .body(body);
    res.headers_mut()
        .insert("x-proxyauth-antibot", HeaderValue::from_static("challenge"));
    res
}

const TITLE: &str = "Vérification de votre navigateur";

/// Ce que `{{ script }}` insère : l'état, la barre de progression et le
/// script (WebGL, compte à rebours, calcul réparti sur les cœurs).
const SCRIPT_HTML: &str = r##"<div class="centered-div" id="pa-antibot">
  <p id="status">Préparation de la vérification…</p>
  <div id="progress" style="display:block"><div class="bar-inner" id="pa-fill"></div></div>
  <p id="pa-stats" style="font:12px/1.4 monospace;opacity:.75;margin:0">&nbsp;</p>
  <noscript><p class="error-code">JavaScript est nécessaire pour terminer cette vérification.</p></noscript>
</div>
<script>
(function () {
  const P = __PARAMS__;
  const $ = (id) => document.getElementById(id);
  const say = (t) => { $("status").textContent = t; };
  const fail = (t) => { say(t); $("status").style.color = "#ff6868"; };
  const pct = (p, extra) => { $("pa-fill").style.width = p.toFixed(1) + "%"; if (extra !== undefined) $("pa-stats").textContent = extra; };

  if (!window.crypto || !crypto.subtle || !window.Worker) { fail("Cette vérification nécessite un navigateur récent en HTTPS."); return; }
  const w = window.innerWidth || 0, h = window.innerHeight || 0;
  const wd = navigator.webdriver ? 1 : 0;

  // ── Rendu WebGL : 4 passes d'un shader dont la couleur dépend du challenge.
  let wg = "", renderer = "";
  function webgl() {
    const c = document.createElement("canvas"); c.width = c.height = 16;
    const gl = c.getContext("webgl", { preserveDrawingBuffer: true, antialias: false }) || c.getContext("experimental-webgl");
    if (!gl) return false;
    const dbg = gl.getExtension("WEBGL_debug_renderer_info");
    renderer = String(dbg ? gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER));
    const sh = (t, s) => { const x = gl.createShader(t); gl.shaderSource(x, s); gl.compileShader(x); return x; };
    const prog = gl.createProgram();
    gl.attachShader(prog, sh(gl.VERTEX_SHADER, "attribute vec2 p;void main(){gl_Position=vec4(p,0.0,1.0);}"));
    gl.attachShader(prog, sh(gl.FRAGMENT_SHADER,
      "precision highp float;uniform vec3 u;uniform float k;" +
      "void main(){vec3 v=mod(u*7.0+vec3(k*31.0,k*17.0+3.0,k*13.0+11.0),256.0);gl_FragColor=vec4(v/255.0,1.0);}"));
    gl.linkProgram(prog);
    if (!gl.getProgramParameter(prog, gl.LINK_STATUS)) return false;
    gl.useProgram(prog);
    const buf = gl.createBuffer(); gl.bindBuffer(gl.ARRAY_BUFFER, buf);
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 3, -1, -1, 3]), gl.STATIC_DRAW);
    const loc = gl.getAttribLocation(prog, "p"); gl.enableVertexAttribArray(loc); gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0);
    const uu = gl.getUniformLocation(prog, "u"), uk = gl.getUniformLocation(prog, "k");
    const px = new Uint8Array(4), out = [];
    for (let k = 0; k < 4; k++) {
      const b = (i) => parseInt(P.challenge.substr((k * 3 + i) * 2, 2), 16);
      gl.uniform3f(uu, b(0), b(1), b(2)); gl.uniform1f(uk, k);
      gl.viewport(0, 0, 16, 16); gl.drawArrays(gl.TRIANGLES, 0, 3);
      gl.readPixels(8, 8, 1, 1, gl.RGBA, gl.UNSIGNED_BYTE, px);
      out.push(px[0], px[1], px[2]);
    }
    wg = out.map((x) => x.toString(16).padStart(2, "0")).join("");
    return true;
  }

  // ── Preuve de travail.
  function work() {
    const expected = Math.pow(16, P.d);
    const threads = P.single ? 1 : Math.max(1, Math.min(navigator.hardwareConcurrency || 2, 8));
    const src = `
      onmessage = async (e) => {
        const { challenge, d, algo, start, step } = e.data;
        const enc = new TextEncoder(), full = Math.floor(d / 2), half = d % 2;
        let nonce = start, done = 0;
        for (;;) {
          const h = new Uint8Array(await crypto.subtle.digest(algo, enc.encode(challenge + nonce)));
          let ok = true;
          for (let i = 0; i < full; i++) if (h[i] !== 0) { ok = false; break; }
          if (ok && half && (h[full] >> 4) !== 0) ok = false;
          if (ok) { postMessage({ found: nonce, done }); return; }
          nonce += step; done++;
          if (done === 512) { postMessage({ progress: done }); done = 0; }
        }
      };`;
    const url = URL.createObjectURL(new Blob([src], { type: "text/javascript" }));
    const workers = []; let total = 0, finished = false; const t0 = performance.now();
    say("Vérification en cours (difficulté " + P.d + ", " + P.a + ", " + threads + (threads > 1 ? " cœurs" : " cœur") + ")…");
    for (let i = 0; i < threads; i++) {
      const wk = new Worker(url);
      wk.onmessage = (e) => {
        if (finished) return;
        if (e.data.progress) {
          total += e.data.progress;
          const s = (performance.now() - t0) / 1000;
          pct(Math.min(99, (1 - Math.exp(-total / expected)) * 100),
              total.toLocaleString() + " hashes · " + (s > 0.2 ? Math.round(total / s).toLocaleString() + " H/s" : "–"));
          return;
        }
        if (e.data.found !== undefined) {
          finished = true; total += e.data.done;
          workers.forEach((x) => x.terminate());
          pct(100, total.toLocaleString() + " hashes");
          say("Vérifié — redirection…");
          const q = new URLSearchParams({ challenge: P.challenge, ts: P.ts, d: P.d, a: P.a, ttl: P.ttl, s: P.s, f: P.f,
            nonce: e.data.found, redir: P.redir, wg: wg, r: renderer, w: w, h: h, wd: wd,
            elapsed: Math.round(performance.now() - t0) });
          location.replace(P.pass + "?" + q.toString());
        }
      };
      wk.onerror = () => fail("La vérification n'a pas pu s'exécuter dans ce navigateur.");
      wk.postMessage({ challenge: P.challenge, d: P.d, algo: P.algo, start: i, step: threads });
      workers.push(wk);
    }
  }

  if (P.webgl && !webgl()) { fail("Cette vérification nécessite WebGL, désactivé ou indisponible dans ce navigateur."); return; }
  // ── Délai de démarrage, imposé par le serveur.
  const begin = performance.now();
  (function tick() {
    const left = P.s - (performance.now() - begin);
    if (left <= 0) { pct(0, ""); work(); return; }
    say("Démarrage de la vérification dans " + Math.ceil(left / 1000) + " s…");
    pct(0, "");
    setTimeout(tick, Math.min(250, left));
  })();
})();
</script>"##;

/// Page par défaut, au style de ProxyAuth. `{{ title }}` et `{{ script }}`
/// sont remplacés à chaque envoi.
const DEFAULT_PAGE: &str = r##"<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex,nofollow">
<meta name="theme-color" content="#0a0b09">
<meta name="color-scheme" content="dark">
<title>{{ title }}</title>
<style>
:root { --background:#0a0b09; --surface:#11130f; --surface-light:#191c16; --border:#292e24; --accent:#d7ff45; --blue:#83d2ff; --text:#f0f2e9; --muted:#92978a; }
* { box-sizing:border-box; }
html { min-height:100%; background:var(--background); }
body { margin:0; min-height:100vh; color:var(--text); background:radial-gradient(ellipse at 50% 40%, #202817 0%, transparent 55%), var(--background); font-family:Inter, system-ui, sans-serif; }
.proxy-shell { min-height:100vh; display:flex; flex-direction:column; }
.proxy-header { min-height:76px; padding:0 7%; display:flex; align-items:center; justify-content:space-between; gap:16px; border-bottom:1px solid var(--border); }
.brand { display:flex; align-items:center; gap:12px; font-size:21px; font-weight:750; letter-spacing:-1px; }
.brand-mark { width:34px; height:34px; display:grid; place-items:center; background:var(--accent); color:#0a0b09; border-radius:8px; font-weight:900; }
.brand-accent { color:var(--accent); }
.security-label, .eyebrow, .encrypted { font-family:monospace; font-size:11px; letter-spacing:1.5px; }
.security-label { color:var(--muted); }
.status-dot { display:inline-block; width:7px; height:7px; margin-right:7px; border-radius:50%; background:var(--accent); box-shadow:0 0 10px var(--accent); animation:proxy-pulse 1.8s infinite; }
.proxy-main { flex:1; display:grid; place-items:center; padding:55px 20px; }
.verification-card { width:100%; max-width:620px; padding:42px; background:rgba(17,19,15,.94); border:1px solid var(--border); border-radius:16px; box-shadow:0 25px 90px #0008; }
.card-top { display:flex; justify-content:space-between; align-items:center; gap:12px; }
.eyebrow { color:var(--accent); }
.encrypted { color:var(--blue); font-size:10px; }
.icon-container { margin:38px 0 24px; }
.shield { width:58px; height:58px; display:grid; place-items:center; color:var(--accent); background:#d7ff4512; border:1px solid #d7ff4540; border-radius:16px; font-size:28px; }
h1 { margin:0 0 16px; font-size:clamp(25px,5vw,34px); letter-spacing:-1.2px; line-height:1.2; }
.description { max-width:490px; color:var(--muted); font-size:15px; line-height:1.8; }
.challenge-container { margin-top:32px; padding:20px; background:var(--surface-light); border:1px solid var(--border); border-radius:10px; overflow-wrap:anywhere; }
.footer-info { display:flex; justify-content:space-between; align-items:center; gap:12px; flex-wrap:wrap; margin-top:35px; padding-top:22px; border-top:1px solid var(--border); font-family:monospace; font-size:10px; letter-spacing:1px; color:var(--muted); }
.footer-info strong { color:var(--text); }
.proxy-footer { padding:22px 7%; display:flex; justify-content:space-between; gap:15px; border-top:1px solid var(--border); color:var(--muted); font-family:monospace; font-size:10px; }
.proxy-footer a { color:var(--blue); text-decoration:none; }
.proxy-footer a:hover { color:var(--accent); }
.centered-div { text-align:center; }
#status { max-width:430px; margin:18px auto; color:var(--muted); font-size:14px; font-variant-numeric:tabular-nums; }
#progress { display:none; width:min(100%,340px); height:9px; margin:25px auto; border:1px solid #d7ff4540; border-radius:20px; overflow:hidden; background:#080a07; }
.bar-inner { width:0; height:100%; border-radius:inherit; background:linear-gradient(90deg,var(--accent),var(--blue)); box-shadow:0 0 16px #d7ff4559; transition:width .25s ease-in; }
.error-code { max-width:100%; padding:15px; overflow-x:auto; border:1px solid var(--border); border-radius:10px; background:#080a07; color:#ff6868; text-align:left; }
@keyframes proxy-pulse { 0%,100% { opacity:1; } 50% { opacity:.35; } }
@media (max-width:600px) { .proxy-header { padding:0 20px; } .security-label { font-size:9px; } .verification-card { padding:25px 20px; } .proxy-footer { flex-direction:column; padding:20px; } }
@media (prefers-reduced-motion: reduce) { *, *::before, *::after { animation-duration:.01ms !important; transition-duration:.01ms !important; } }
</style>
</head>
<body id="top">
<div class="proxy-shell">
  <header class="proxy-header">
    <div class="brand"><span class="brand-mark">P</span><span>Proxy<span class="brand-accent">Auth</span></span></div>
    <span class="security-label"><span class="status-dot"></span>SECURITY GATEWAY</span>
  </header>
  <main class="proxy-main">
    <section class="verification-card">
      <div class="card-top"><span class="eyebrow">ACCESS CONTROL / 01</span><span class="encrypted">TLS SECURED</span></div>
      <div class="icon-container"><div class="shield" aria-hidden="true">✓</div></div>
      <h1 id="title">{{ title }}</h1>
      <p class="description">Nous vérifions que votre connexion provient d'un navigateur légitime avant de vous donner accès à cette ressource.</p>
      <div class="challenge-container">
        {{ script }}
      </div>
      <div class="footer-info"><span>PROTECTED BY</span><strong>PROXYAUTH</strong></div>
    </section>
  </main>
  <footer class="proxy-footer">
    <span>ProxyAuth Security Infrastructure</span>
    <span><a href="https://proxyauth.app">ProxyAuth</a></span>
  </footer>
</div>
</body>
</html>
"##;

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [7; 32];

    #[test]
    fn difficulty_counts_hex_zeros() {
        assert!(meets_difficulty(&[0x00, 0x00, 0x0f], 4));
        assert!(!meets_difficulty(&[0x00, 0x01, 0x00], 4));
        assert!(meets_difficulty(&[0x00, 0x0a], 3));
        assert!(!meets_difficulty(&[0x00, 0x1a], 3));
    }

    #[test]
    fn challenge_binds_every_parameter() {
        let base = challenge_for(
            &KEY,
            1000,
            4,
            Algorithm::Fast,
            3600,
            2000,
            7,
            "203.0.113.9",
            "Mozilla/5.0",
        );
        for other in [
            challenge_for(
                &KEY,
                1001,
                4,
                Algorithm::Fast,
                3600,
                2000,
                7,
                "203.0.113.9",
                "Mozilla/5.0",
            ),
            challenge_for(
                &KEY,
                1000,
                3,
                Algorithm::Fast,
                3600,
                2000,
                7,
                "203.0.113.9",
                "Mozilla/5.0",
            ),
            challenge_for(
                &KEY,
                1000,
                4,
                Algorithm::Slow,
                3600,
                2000,
                7,
                "203.0.113.9",
                "Mozilla/5.0",
            ),
            challenge_for(
                &KEY,
                1000,
                4,
                Algorithm::Fast,
                3600,
                0,
                7,
                "203.0.113.9",
                "Mozilla/5.0",
            ),
            challenge_for(
                &KEY,
                1000,
                4,
                Algorithm::Fast,
                3600,
                2000,
                0,
                "203.0.113.9",
                "Mozilla/5.0",
            ),
            challenge_for(
                &KEY,
                1000,
                4,
                Algorithm::Fast,
                3600,
                2000,
                7,
                "198.51.100.1",
                "Mozilla/5.0",
            ),
            challenge_for(
                &KEY,
                1000,
                4,
                Algorithm::Fast,
                3600,
                2000,
                7,
                "203.0.113.9",
                "curl/8",
            ),
        ] {
            assert_ne!(base, other);
        }
        // A real solution, as the browser finds it, for every algorithm.
        for alg in [
            Algorithm::Fast,
            Algorithm::Slow,
            Algorithm::Sha256,
            Algorithm::Sha512,
        ] {
            let c = challenge_for(&KEY, 1000, 2, alg, 3600, 0, 0, "ip", "ua");
            assert!(
                (0u64..1_000_000)
                    .any(|n| meets_difficulty(&alg.digest(format!("{c}{n}").as_bytes()), 2))
            );
        }
    }

    #[test]
    fn webgl_expectation_matches_the_shader_formula() {
        // challenge bytes 00 01 02 | 03 04 05 | ...
        let c = "000102030405060708090a0b".to_string() + &"0".repeat(40);
        let e = hex::decode(expected_webgl(&c).unwrap()).unwrap();
        // k = 0: (b*7 + 0, b*7 + 3, b*7 + 11)
        assert_eq!(&e[0..3], &[0, 7 + 3, 14 + 11]);
        // k = 1: b = 3,4,5 → (21+31, 28+20, 35+24)
        assert_eq!(&e[3..6], &[52, 48, 59]);
        assert_eq!(e.len(), 12);
        assert!(expected_webgl("short").is_none());
        assert!(software_renderer("Google SwiftShader") && software_renderer("llvmpipe (LLVM 15)"));
        assert!(!software_renderer("ANGLE (NVIDIA GeForce RTX 3060)"));
    }

    #[test]
    fn pass_cookie_is_bound_and_expires() {
        let ua = "Mozilla/5.0 test";
        let good = pass_cookie(&KEY, now_ms() / 1000 + 60, ua);
        assert!(pass_is_valid(&KEY, &good, ua));
        assert!(!pass_is_valid(&KEY, &good, "Mozilla/5.0 other"));
        assert!(!pass_is_valid(
            &KEY,
            &pass_cookie(&KEY, now_ms() / 1000 - 1, ua),
            ua
        ));
        let (_, sig) = good.split_once('.').unwrap();
        assert!(!pass_is_valid(
            &KEY,
            &format!("{}.{sig}", now_ms() / 1000 + 999_999),
            ua
        ));
    }

    #[test]
    fn redirects_and_query_decoding() {
        assert_eq!(safe_redirect("/repo/src?x=1"), "/repo/src?x=1");
        assert_eq!(safe_redirect("//evil.example/"), "/");
        assert_eq!(safe_redirect("https://evil.example/"), "/");
        assert_eq!(percent_decode("%2Frepo%3Fx%3D1"), "/repo?x=1");
        assert_eq!(percent_decode("100%"), "100%");
    }

    #[test]
    fn config_random_choices_start_delay_and_load_levels() {
        let c: AntiBotConfig = serde_yaml::from_str(
            r#"{ random_difficulty: ["3", 4], random_algorithme: [slow, fast, sha512],
                 min_start: 2s, max_start: "5s",
                 load_levels: [{ request: 10, period: 5, difficulty: "6" }] }"#,
        )
        .unwrap();
        assert_eq!(c.random_difficulty, vec![3, 4]);
        assert_eq!(
            c.random_algorithm,
            vec![Algorithm::Slow, Algorithm::Fast, Algorithm::Sha512]
        );
        assert_eq!((c.min_start, c.max_start), (2.0, 5.0));
        validate(&c, "t").unwrap();
        let rule = Rule {
            cfg: c,
            exclude: vec![],
            nofiltered: vec![],
            traffic: Arc::new(Traffic::new()),
            page: Arc::new(Page::load(None).unwrap()),
        };
        let mut seen_d = std::collections::HashSet::new();
        let mut seen_a = std::collections::HashSet::new();
        for _ in 0..200 {
            let (d, a, s) = rule.draw(1000);
            assert!((2000..=5000).contains(&s), "start {s} ms");
            seen_d.insert(d);
            seen_a.insert(a);
        }
        assert_eq!(
            seen_d,
            [3u8, 4].into_iter().collect(),
            "both difficulties drawn"
        );
        assert_eq!(seen_a.len(), 3, "all three algorithms drawn");
        // Under load: 10 requests within 5 s raise the difficulty to 6.
        for _ in 0..10 {
            rule.traffic.record(1000);
        }
        assert!((0..50).all(|_| rule.draw(1000).0 == 6));
        // Ten seconds later the load has passed.
        assert!(rule.draw(1010).0 < 6);

        for bad in [
            "{ difficulty: 9 }",
            "{ random_difficulty: [0] }",
            "{ min_start: 5, max_start: 2 }",
            "{ min_start: 120 }",
            "{ load_levels: [{ request: 0, difficulty: 5 }] }",
            "{ load_levels: [{ request: 5, period: 120, difficulty: 5 }] }",
        ] {
            let c: AntiBotConfig = serde_yaml::from_str(bad).unwrap();
            assert!(validate(&c, "t").is_err(), "{bad} must be refused");
        }
        assert!(serde_yaml::from_str::<AntiBotConfig>("{ algorithm: md5 }").is_err());
    }

    #[test]
    fn default_page_has_the_tags() {
        assert!(DEFAULT_PAGE.contains("{{ script }}") && DEFAULT_PAGE.contains("{{ title }}"));
        assert!(SCRIPT_HTML.contains("__PARAMS__"));
    }
}
