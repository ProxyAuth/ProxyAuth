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
/// Difficulté maximale : 20 zéros hexadécimaux (80 bits).
pub const MAX_DIFFICULTY: u8 = 20;

/// Hashes à calculer en moyenne pour une difficulté : 16^d.
pub fn expected_hashes(d: u8) -> f64 {
    16f64.powi(i32::from(d))
}
const CHALLENGE_MAX_AGE_MS: u64 = 30 * 60 * 1000;

const FLAG_WEBGL: u8 = 1;
const FLAG_REJECT_SOFTWARE_GL: u8 = 2;
const FLAG_REJECT_HEADLESS: u8 = 4;
const FLAG_SCALE_WORKERS: u8 = 8;

/// Bits ajoutés pour `w` workers : log2(w) arrondi par défaut, au plus 8.
/// Chaque bit double le travail : un client à 8 workers a 3 bits de plus
/// qu'un client à 1 worker, et met donc à peu près le même temps.
pub fn worker_bits(w: u32) -> u32 {
    (31 - w.max(1).leading_zeros()).min(8)
}

/// Le hash commence-t-il par `bits` bits nuls ?
pub fn meets_bits(hash: &[u8], bits: u32) -> bool {
    let full = (bits / 8) as usize;
    let rem = bits % 8;
    hash.len() > full
        && hash[..full].iter().all(|b| *b == 0)
        && (rem == 0 || hash[full] >> (8 - rem) == 0)
}

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

/// `client_cores` : tous les cœurs, ou une fraction.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub enum CoreUsage {
    #[default]
    Full,
    /// Diviseur ≥ 2 : `cœurs / n − 1`, au moins 1.
    Divide(u8),
}

impl<'de> Deserialize<'de> for CoreUsage {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        match Loose::deserialize(d)? {
            Loose::S(s)
                if matches!(
                    s.trim().to_ascii_lowercase().as_str(),
                    "full" | "all" | "max"
                ) =>
            {
                Ok(CoreUsage::Full)
            }
            other => {
                let n = loose_u8(other).map_err(serde::de::Error::custom)?;
                if (2..=16).contains(&n) {
                    Ok(CoreUsage::Divide(n))
                } else {
                    Err(serde::de::Error::custom(format!(
                        "`client_cores` is `full` or a divisor between 2 and 16, not {n}"
                    )))
                }
            }
        }
    }
}

impl CoreUsage {
    /// Ce que le navigateur reçoit : 0 = tous les cœurs, sinon le diviseur.
    fn divisor(self) -> u8 {
        match self {
            CoreUsage::Full => 0,
            CoreUsage::Divide(n) => n,
        }
    }

    /// Le calcul que fait la page, pour un nombre de cœurs donné (le
    /// JavaScript fait le même ; sert aux tests et à la documentation).
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn threads(self, cores: u32) -> u32 {
        match self {
            CoreUsage::Full => cores.max(1),
            CoreUsage::Divide(n) => (cores / u32::from(n)).saturating_sub(1).max(1),
        }
    }
}

/// `hostname_check_limit` : `request` requêtes en `period` secondes, sur le
/// vhost (défaut) ou tout le serveur (`scope: server`).
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostnameCheckLimit {
    pub request: u64,
    #[serde(default = "default_period")]
    pub period: u64,
    #[serde(default)]
    pub scope: LoadScope,
}

/// `gpu_check` : une recherche de nonce sur la carte graphique.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GpuCheck {
    /// `auto` (WebGPU, sinon WebGL 2), `webgpu`, `webgl2`.
    #[serde(default)]
    pub mode: GpuMode,
    /// Bits nuls exigés : 2^bits essais en moyenne (28 ≈ 268 millions).
    #[serde(default = "default_gpu_bits")]
    pub bits: u8,
    /// Temps accordé au navigateur ; au-delà, il abandonne (`timeout`).
    #[serde(default = "default_gpu_budget", deserialize_with = "de_seconds")]
    pub budget: f64,
    /// En dessous de ce temps, mesuré par le serveur, la carte compte
    /// comme un vrai GPU (`hardware`) ; au-dessus, `slow`.
    #[serde(default = "default_gpu_budget", deserialize_with = "de_seconds")]
    pub hardware_under: f64,
    /// Que faire d'un client **sans vrai GPU** (`software`, `slow`,
    /// `timeout`, `invalid`, `unavailable`) : `allow` (le laisser, simple
    /// signal), `harder` (preuve de travail alourdie de `software_extra`
    /// crans), `detect` (le laisser, mais compter une détection), `refuse`.
    #[serde(default)]
    pub on_software: OnSoftware,
    /// Crans de difficulté ajoutés avec `harder` (1 à 4 ; chaque cran ×16).
    #[serde(default = "default_software_extra")]
    pub software_extra: u8,
    /// Montée en puissance sous une vague de clients sans vrai GPU : au-delà
    /// de `request` en `period` secondes, `on_software` et/ou
    /// `software_extra` passent à la valeur du palier (le plus sévère des
    /// paliers atteints l'emporte), au moins `software_hold` secondes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub software_levels: Vec<SoftwareLevel>,
    /// Durée minimale d'une montée en puissance après le dernier
    /// dépassement (défaut 60 s).
    #[serde(default = "default_software_hold", deserialize_with = "de_seconds_u64")]
    pub software_hold: u64,
}
fn default_software_hold() -> u64 {
    60
}

/// `lockdown:` — sous un trafic extrême, tout client qui se présente comme
/// un navigateur doit le prouver entièrement, sans les exceptions
/// habituelles. Chaque mesure de `refuse` peut être choisie ; par défaut,
/// toutes.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LockdownConfig {
    /// Requêtes en `period` secondes au-delà desquelles le verrouillage
    /// s'active.
    pub request: u64,
    #[serde(default = "default_period")]
    pub period: u64,
    /// Trafic compté : ce vhost (défaut) ou tout le serveur.
    #[serde(default)]
    pub scope: LoadScope,
    /// Durée minimale du verrouillage après le dernier dépassement.
    #[serde(default = "default_lockdown_hold", deserialize_with = "de_seconds_u64")]
    pub hold: u64,
    /// Ce qui est refusé pendant le verrouillage (défaut : tout).
    #[serde(default = "all_lockdown_rules")]
    pub refuse: Vec<LockdownRule>,
    /// Ce que `request` compte (comme dans `load_levels`).
    #[serde(default)]
    pub count: LevelCount,
}
fn default_lockdown_hold() -> u64 {
    120
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LockdownRule {
    /// Pas de vraie carte graphique à l'épreuve GPU (avec `gpu_check`).
    NoGpu,
    /// Rendu WebGL logiciel annoncé (SwiftShader, llvmpipe, WARP).
    SoftwareRenderer,
    /// Pas de rendu WebGL valide.
    NoWebgl,
    /// `navigator.webdriver`, fenêtre 0×0.
    Headless,
    /// Les clients qui ne s'annoncent pas comme navigateurs : refusés au
    /// lieu de passer (`only_browsers`).
    NonBrowsers,
    /// Les robots vérifiés par nom d'hôte ne sont plus exemptés.
    Crawlers,
    /// Les laissez-passer délivrés avant le verrouillage sont redemandés.
    OldPasses,
}

fn all_lockdown_rules() -> Vec<LockdownRule> {
    use LockdownRule::*;
    vec![
        NoGpu,
        SoftwareRenderer,
        NoWebgl,
        Headless,
        NonBrowsers,
        Crawlers,
        OldPasses,
    ]
}

/// L'état du verrouillage d'un vhost.
#[derive(Debug)]
pub struct LockdownState {
    cfg: LockdownConfig,
    until: std::sync::atomic::AtomicU64,
    started: std::sync::atomic::AtomicU64,
}

impl LockdownState {
    fn new(cfg: LockdownConfig) -> Self {
        Self {
            cfg,
            until: Default::default(),
            started: Default::default(),
        }
    }
    fn active(&self, sec: u64) -> bool {
        self.until.load(std::sync::atomic::Ordering::Relaxed) > sec
    }
    fn refuses(&self, sec: u64, r: LockdownRule) -> bool {
        self.active(sec) && self.cfg.refuse.contains(&r)
    }
    /// Réévalue d'après le trafic compté, et journalise les changements.
    fn update(&self, sec: u64, vhost_traffic: &Traffic, vhost_software: Option<&Traffic>) {
        use std::sync::atomic::Ordering;
        let none = Traffic::new();
        let traffic = match (self.cfg.count, self.cfg.scope) {
            (LevelCount::Requests, LoadScope::Vhost) => vhost_traffic,
            (LevelCount::Requests, LoadScope::Server) => server_traffic(),
            (LevelCount::Software, LoadScope::Vhost) => vhost_software.unwrap_or(&none),
            (LevelCount::Software, LoadScope::Server) => server_software(),
        };
        let was = self.active(sec);
        if traffic.count(sec, self.cfg.period) >= self.cfg.request {
            if !was {
                self.started.store(sec, Ordering::Relaxed);
                tracing::warn!(
                    "antibot: LOCKDOWN — more than {} requests in {}s: every client must prove it is a real browser ({}), for at least {}s",
                    self.cfg.request,
                    self.cfg.period,
                    self.cfg
                        .refuse
                        .iter()
                        .map(|r| format!("{r:?}"))
                        .collect::<Vec<_>>()
                        .join(", "),
                    self.cfg.hold
                );
            }
            self.until.store(sec + self.cfg.hold, Ordering::Relaxed);
        } else if !was && self.started.load(Ordering::Relaxed) != 0 {
            self.started.store(0, Ordering::Relaxed);
            tracing::info!("antibot: lockdown over");
        }
    }
}

/// Un palier de `software_levels`.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SoftwareLevel {
    /// Clients sans vrai GPU vus pendant `period` secondes.
    pub request: u64,
    #[serde(default = "default_period")]
    pub period: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_software: Option<OnSoftware>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub software_extra: Option<u8>,
    /// Compter sur ce vhost (défaut) ou sur tout le serveur.
    #[serde(default)]
    pub scope: LoadScope,
    /// `software` ici (les clients sans vrai GPU) ; `requests` pour les
    /// paliers venus de `load_levels`.
    #[serde(default = "count_software")]
    pub count: LevelCount,
}
fn count_software() -> LevelCount {
    LevelCount::Software
}

impl OnSoftware {
    /// Du plus doux au plus sévère.
    fn severity(self) -> u8 {
        match self {
            OnSoftware::Allow => 0,
            OnSoftware::Detect => 1,
            OnSoftware::Harder => 2,
            OnSoftware::Refuse => 3,
        }
    }
    fn name(self) -> &'static str {
        match self {
            OnSoftware::Allow => "allow",
            OnSoftware::Detect => "detect",
            OnSoftware::Harder => "harder",
            OnSoftware::Refuse => "refuse",
        }
    }
    fn parse(s: &str) -> Option<Self> {
        match s {
            "allow" => Some(OnSoftware::Allow),
            "detect" => Some(OnSoftware::Detect),
            "harder" => Some(OnSoftware::Harder),
            "refuse" => Some(OnSoftware::Refuse),
            _ => None,
        }
    }
}

/// Clients sans vrai GPU vus par tout le serveur (`scope: server`).
static SERVER_SOFTWARE: OnceLock<Traffic> = OnceLock::new();
fn server_software() -> &'static Traffic {
    SERVER_SOFTWARE.get_or_init(Traffic::new)
}

/// L'état de `on_software` d'un vhost : compteur des clients sans vrai GPU
/// et montée en puissance en cours.
#[derive(Debug)]
pub struct SoftwareGuard {
    cfg: GpuCheck,
    /// `gpu_check.software_levels` et les paliers de `load_levels` qui
    /// fixent `on_software` / `software_extra`.
    levels: Vec<SoftwareLevel>,
    /// Les requêtes du vhost (paliers `count: requests`).
    requests: Arc<Traffic>,
    seen: Traffic,
    /// Décision imposée jusqu'à `until` (secondes Unix).
    escalated: Mutex<Option<(OnSoftware, u8, u64)>>,
}

impl SoftwareGuard {
    fn new(cfg: GpuCheck, load_levels: &[LoadLevel], requests: Arc<Traffic>) -> Self {
        let mut levels = cfg.software_levels.clone();
        levels.extend(
            load_levels
                .iter()
                .filter(|l| l.on_software.is_some() || l.software_extra.is_some())
                .map(|l| SoftwareLevel {
                    request: l.request,
                    period: l.period,
                    on_software: l.on_software,
                    software_extra: l.software_extra,
                    scope: l.scope,
                    count: l.count,
                }),
        );
        Self {
            cfg,
            levels,
            requests,
            seen: Traffic::new(),
            escalated: Mutex::new(None),
        }
    }

    /// Compte un client sans vrai GPU.
    fn record(&self, sec: u64) {
        self.seen.record(sec);
        server_software().record(sec);
    }

    /// Le mode et les crans en vigueur maintenant.
    fn decision(&self, sec: u64) -> (OnSoftware, u8) {
        let (mut mode, mut extra) = (self.cfg.on_software, self.cfg.software_extra);
        let mut reached = false;
        for l in &self.levels {
            let traffic = match (l.count, l.scope) {
                (LevelCount::Software, LoadScope::Vhost) => &self.seen,
                (LevelCount::Software, LoadScope::Server) => server_software(),
                (LevelCount::Requests, LoadScope::Vhost) => &*self.requests,
                (LevelCount::Requests, LoadScope::Server) => server_traffic(),
            };
            if traffic.count(sec, l.period) >= l.request {
                reached = true;
                if let Some(m) = l.on_software.filter(|m| m.severity() > mode.severity()) {
                    mode = m;
                }
                if let Some(x) = l.software_extra {
                    extra = extra.max(x);
                }
            }
        }
        let mut esc = self.escalated.lock().unwrap_or_else(|e| e.into_inner());
        if reached {
            let changed = esc
                .map(|(m, x, until)| until <= sec || m != mode || x != extra)
                .unwrap_or(true);
            if changed {
                tracing::warn!(
                    "antibot: wave of clients without a real GPU — on_software now {} (software_extra {extra}) for at least {}s",
                    mode.name(),
                    self.cfg.software_hold
                );
            }
            *esc = Some((mode, extra, sec + self.cfg.software_hold));
            return (mode, extra);
        }
        match *esc {
            Some((m, x, until)) if until > sec => (m, x),
            Some(_) => {
                *esc = None;
                tracing::info!(
                    "antibot: the wave is over — on_software back to {}",
                    self.cfg.on_software.name()
                );
                (self.cfg.on_software, self.cfg.software_extra)
            }
            None => (mode, extra),
        }
    }
}
fn default_software_extra() -> u8 {
    2
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum OnSoftware {
    #[default]
    Allow,
    Harder,
    Detect,
    Refuse,
}

/// Le résultat de l'épreuve GPU ne montre pas une vraie carte graphique.
pub fn no_hardware_gpu(class: &str) -> bool {
    matches!(
        class,
        "software" | "slow" | "timeout" | "invalid" | "unavailable" | "not run"
    )
}
fn default_gpu_bits() -> u8 {
    28
}
fn default_gpu_budget() -> f64 {
    2.0
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum GpuMode {
    #[default]
    Auto,
    Webgpu,
    Webgl2,
}

impl GpuMode {
    fn name(self) -> &'static str {
        match self {
            GpuMode::Auto => "auto",
            GpuMode::Webgpu => "webgpu",
            GpuMode::Webgl2 => "webgl2",
        }
    }
}

/// Le hachage de l'épreuve GPU : 32 tours d'un mélangeur d'entiers 32 bits.
/// Le même code tourne en WGSL (WebGPU), en GLSL (WebGL 2) et ici, où une
/// seule évaluation suffit à vérifier une solution.
pub fn gpu_hash(seed: u32, n: u32) -> u32 {
    let mut x = seed ^ n;
    for i in 0..32u32 {
        x ^= x >> 16;
        x = x.wrapping_mul(0x7feb_352d);
        x ^= x >> 15;
        x = x.wrapping_mul(0x846c_a68b);
        x ^= x >> 16;
        x = x.wrapping_add(0x9e37_79b9u32.wrapping_add(i));
    }
    x
}

pub fn gpu_meets(h: u32, bits: u8) -> bool {
    bits == 0 || (h >> (32 - u32::from(bits.min(31)))) == 0
}

/// Langue des pages de l'anti-bot.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Language {
    #[default]
    #[serde(alias = "french", alias = "français")]
    Fr,
    #[serde(alias = "english")]
    En,
}

/// Les textes d'une langue.
pub struct Texts {
    pub html_lang: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub preparing: &'static str,
    pub noscript: &'static str,
    pub need_https: &'static str,
    pub need_webgl: &'static str,
    pub gpu: &'static str,
    pub starting: &'static str,
    pub running: &'static str,
    pub core: &'static str,
    pub cores: &'static str,
    pub done: &'static str,
    pub worker_failed: &'static str,
    pub failed_title: &'static str,
    pub failed_body: &'static str,
    pub retry: &'static str,
    pub banned_title: &'static str,
    pub banned_body: &'static str,
}

impl Language {
    pub fn texts(self) -> &'static Texts {
        match self {
            Language::Fr => &Texts {
                html_lang: "fr",
                title: "Vérification de votre navigateur",
                description: "Nous vérifions que votre connexion provient d'un navigateur légitime avant de vous donner accès à cette ressource.",
                preparing: "Préparation de la vérification…",
                noscript: "JavaScript est nécessaire pour terminer cette vérification.",
                need_https: "Cette vérification nécessite un navigateur récent en HTTPS.",
                need_webgl: "Cette vérification nécessite WebGL, désactivé ou indisponible dans ce navigateur.",
                gpu: "Veuillez patienter…",
                starting: "Démarrage de la vérification dans {s} s…",
                running: "Vérification en cours (difficulté {d}, {a}, {n} {cores})…",
                core: "cœur",
                cores: "cœurs",
                done: "Vérifié — redirection…",
                worker_failed: "La vérification n'a pas pu s'exécuter dans ce navigateur.",
                failed_title: "Vérification échouée",
                failed_body: "La vérification a expiré ou n'a pas pu être validée.",
                retry: "Réessayer",
                banned_title: "Accès bloqué",
                banned_body: "Trop de tentatives automatisées ont été détectées depuis votre adresse. Réessayez plus tard.",
            },
            Language::En => &Texts {
                html_lang: "en",
                title: "Checking your browser",
                description: "We are making sure your connection comes from a genuine browser before giving you access to this resource.",
                preparing: "Preparing the check…",
                noscript: "JavaScript is required to complete this check.",
                need_https: "This check needs a recent browser over HTTPS.",
                need_webgl: "This check needs WebGL, which is disabled or unavailable in this browser.",
                gpu: "Please wait…",
                starting: "Starting the check in {s} s…",
                running: "Checking (difficulty {d}, {a}, {n} {cores})…",
                core: "core",
                cores: "cores",
                done: "Verified — redirecting…",
                worker_failed: "The check could not run in this browser.",
                failed_title: "Verification failed",
                failed_body: "The check expired or could not be verified.",
                retry: "Try again",
                banned_title: "Access blocked",
                banned_body: "Too many automated attempts were detected from your address. Please try again later.",
            },
        }
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
    /// Difficulté minimale à ce palier ; défaut : inchangée.
    #[serde(default, deserialize_with = "de_opt_u8_loose")]
    pub difficulty: Option<u8>,
    /// Âge maximal d'un laissez-passer à ce palier, en secondes : sous
    /// forte charge, les visiteurs dont le passage est plus ancien sont
    /// redéfiés, et les nouveaux reçoivent un cookie de cette durée.
    /// Aussi accepté : `cookie_time_challenge`.
    #[serde(
        default,
        alias = "cookie_time_challenge",
        deserialize_with = "de_opt_seconds_u64"
    )]
    pub cookie_ttl: Option<u64>,
    /// Trafic compté : celui du vhost (`vhost`, défaut) ou de **tout le
    /// serveur**, tous vhosts confondus (`server`).
    #[serde(default)]
    pub scope: LoadScope,
    /// Cœurs du visiteur utilisés sous cette charge (`full`, `2`, `3`…),
    /// à la place de `client_cores`.
    #[serde(
        default,
        alias = "cpu_usage",
        alias = "cores",
        skip_serializing_if = "Option::is_none"
    )]
    pub client_cores: Option<CoreUsage>,
    /// Ce palier déclenche le verrouillage : `true` (toutes les règles,
    /// 120 s), ou `{ hold, refuse }`. Un seul palier peut le faire.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lockdown: Option<LockdownSpec>,
    /// À ce palier, `gpu_check.on_software` devient au moins celui-ci.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_software: Option<OnSoftware>,
    /// À ce palier, `gpu_check.software_extra` devient au moins celui-ci.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub software_extra: Option<u8>,
    /// Ce que `request` compte : `requests` (défaut) ou `software`.
    #[serde(default)]
    pub count: LevelCount,
}

/// Ce qu'un palier compte : toutes les requêtes (défaut), ou les clients
/// sans vrai GPU à l'épreuve `gpu_check` (`software`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LevelCount {
    #[default]
    Requests,
    Software,
}

/// `lockdown:` dans un palier de `load_levels`.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum LockdownSpec {
    On(bool),
    Rules {
        #[serde(default = "default_lockdown_hold", deserialize_with = "de_seconds_u64")]
        hold: u64,
        #[serde(default = "all_lockdown_rules")]
        refuse: Vec<LockdownRule>,
    },
}

impl LoadLevel {
    /// Le verrouillage que ce palier déclenche, avec son seuil.
    fn lockdown_config(&self) -> Option<LockdownConfig> {
        let (hold, refuse) = match self.lockdown.as_ref()? {
            LockdownSpec::On(false) => return None,
            LockdownSpec::On(true) => (default_lockdown_hold(), all_lockdown_rules()),
            LockdownSpec::Rules { hold, refuse } => (*hold, refuse.clone()),
        };
        Some(LockdownConfig {
            request: self.request,
            period: self.period,
            scope: self.scope,
            hold,
            refuse,
            count: self.count,
        })
    }
}
fn default_period() -> u64 {
    10
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LoadScope {
    #[default]
    Vhost,
    Server,
}

/// Toutes les requêtes du serveur, tous vhosts confondus
/// (`scope: server`).
static SERVER_TRAFFIC: OnceLock<Traffic> = OnceLock::new();
fn server_traffic() -> &'static Traffic {
    SERVER_TRAFFIC.get_or_init(Traffic::new)
}

/// `ban:` — une adresse détectée au moins `after` fois en `period`
/// secondes est bloquée (`403`) pendant `duration` secondes, sur tout le
/// vhost.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BanConfig {
    #[serde(default = "default_ban_after", alias = "detections")]
    pub after: u32,
    #[serde(default = "default_ban_period", deserialize_with = "de_seconds_u64")]
    pub period: u64,
    #[serde(default = "default_ban_duration", deserialize_with = "de_seconds_u64")]
    pub duration: u64,
    /// Fichier où les détections et bannissements sont gardés : sauvegardé
    /// toutes les 30 s, à l'arrêt et après `proxyauth antibot unban`, relu
    /// au démarrage. Sans lui, un redémarrage remet tout à zéro.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store: Option<String>,
    /// Fichier texte des adresses bannies en ce moment, au format de
    /// `ip_blocklists` : une IP par ligne, précédée d'un commentaire `#`
    /// (date du bannissement, vhost, raisons). Réécrit dès qu'il change ;
    /// un bannissement expiré ou levé en sort. Chargé automatiquement avec
    /// `antibots_auto: true` (config.json), ou par n'importe quelle source
    /// `ip_blocklists`, y compris sur d'autres serveurs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub export: Option<String>,
}
fn default_ban_after() -> u32 {
    100
}
fn default_ban_period() -> u64 {
    600
}
fn default_ban_duration() -> u64 {
    3600
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
    /// Durée de vie de la clé AES d'une vérification, en secondes : le
    /// script doit être chargé et la solution envoyée dans ce délai, une
    /// seule fois. Aussi accepté : `key_lifetime`.
    #[serde(
        default = "default_key_ttl",
        alias = "key_lifetime",
        deserialize_with = "de_seconds_u64"
    )]
    pub key_ttl: u64,
    /// Ajuster la difficulté au nombre de workers du visiteur : un bit de
    /// plus (travail ×2) à chaque doublement, pour que chacun attende à
    /// peu près autant. `difficulty` est alors celle d'un client à un seul
    /// worker. Activé par défaut.
    #[serde(default = "yes")]
    pub scale_with_workers: bool,
    /// Cœurs du visiteur utilisés pour le calcul : `full` (tous, défaut),
    /// ou un diviseur `n` → `cœurs / n − 1` (au moins 1). `2` sur une
    /// machine à 8 cœurs en utilise 3, `3` en utilise 1. L'algorithme
    /// `slow` reste toujours sur un seul cœur.
    #[serde(default, alias = "cpu_usage", alias = "cores")]
    pub client_cores: CoreUsage,
    /// Deuxième épreuve, sur la carte graphique (WebGPU, sinon WebGL 2) :
    /// mesurée par le serveur et journalisée (`gpu_check`). Un signal, pas
    /// une barrière : personne n'est refusé sur ce seul critère.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu_check: Option<GpuCheck>,
    /// Verrouillage sous trafic extrême (voir [`LockdownConfig`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lockdown: Option<LockdownConfig>,
    /// Langue des pages (vérification, échec, blocage) : `fr` ou `en`.
    #[serde(default, alias = "lang")]
    pub language: Language,
    /// Page à soi, avec `{{ script }}` (et `{{ title }}`).
    #[serde(default, alias = "page", skip_serializing_if = "Option::is_none")]
    pub static_page: Option<String>,
    /// Difficulté selon le trafic du vhost.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub load_levels: Vec<LoadLevel>,
    /// Seuil d'activation : l'anti-bot ne défie personne tant que le vhost
    /// reçoit moins de `request` requêtes par `period` secondes. Sans
    /// `request`, il est toujours actif.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request: Option<u64>,
    /// Fenêtre du seuil, en secondes (1 à 60).
    #[serde(default = "default_period")]
    pub period: u64,
    /// Une fois déclenché, l'anti-bot reste actif au moins `hold` secondes
    /// après le dernier dépassement (défaut : 60), pour ne pas s'éteindre
    /// et se rallumer au rythme des vagues d'une attaque.
    #[serde(default = "default_hold", deserialize_with = "de_seconds_u64")]
    pub hold: u64,
    /// Journal CSV des détections : date, vhost, IP, User-Agent, raison
    /// (en anglais), chemin. Créé s'il n'existe pas, en ajout sinon.
    #[serde(default, alias = "log", skip_serializing_if = "Option::is_none")]
    pub detection_log: Option<String>,
    /// Bannir une adresse après trop de détections.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ban: Option<BanConfig>,
    /// Laisser passer sans défi toute requête qui porte un en-tête
    /// `Authorization`. **Désactivé par défaut** : n'importe quel client
    /// peut ajouter `Authorization: x` — c'était une porte ouverte. À
    /// n'activer que pour un backend d'API dont les clients s'annoncent
    /// comme navigateurs.
    #[serde(default)]
    pub trust_authorization: bool,
    /// Écrire dans `detection_log` chaque requête qui **passe sans défi**,
    /// avec la raison (`passed without challenge: …`) — pour comprendre
    /// pourquoi un client n'a pas eu la page. Une ligne par client, raison
    /// et chemin et par minute ; rien n'est compté pour le bannissement.
    #[serde(default)]
    pub log_bypass: bool,
    /// Écrire aussi les vérifications **réussies** dans `detection_log`
    /// (raison `passed`), avec les mêmes informations sur le navigateur.
    #[serde(default)]
    pub log_passes: bool,
    /// Validité du laissez-passer : secondes, ou `"30m"`, `"12h"`, `"7d"`.
    /// Aussi accepté : `cookie_time_challenge`.
    #[serde(
        default = "default_cookie_ttl",
        alias = "cookie_time_challenge",
        deserialize_with = "de_seconds_u64"
    )]
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
    /// Domaines dont les machines ne sont jamais défiées, d'après le DNS
    /// inverse **confirmé** de l'adresse (`googlebot.com`, `search.msn.com`).
    /// Un `*.` en tête est accepté et ignoré.
    #[serde(
        default,
        alias = "hostnames_nofiltered",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub hostname_nofiltered: Vec<String>,
    /// Attente maximale d'une résolution DNS de `hostname_nofiltered`
    /// avant de servir quand même la page de vérification : `300ms` par
    /// défaut. La résolution continue en arrière-plan et son résultat est
    /// mis en cache pour la requête suivante.
    #[serde(default = "default_dns_timeout", deserialize_with = "de_seconds")]
    pub dns_timeout: f64,
    /// Au-delà de ce trafic, la vérification par nom d'hôte est coupée :
    /// plus aucune résolution DNS, et tout client passe par les autres
    /// règles de l'anti-bot. Sous une attaque venant de milliers d'adresses,
    /// cela évite des milliers de résolutions. Aussi accepté :
    /// `hostname_disable_above`.
    #[serde(
        default,
        alias = "hostname_disable_above",
        skip_serializing_if = "Option::is_none"
    )]
    pub hostname_check_limit: Option<HostnameCheckLimit>,
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
fn default_dns_timeout() -> f64 {
    0.3
}
fn default_key_ttl() -> u64 {
    120
}
fn default_hold() -> u64 {
    60
}
fn de_seconds_u64<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
    de_seconds(d).map(|s| s.max(0.0).round() as u64)
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
fn de_opt_u8_loose<'de, D: Deserializer<'de>>(d: D) -> Result<Option<u8>, D::Error> {
    loose_u8(Loose::deserialize(d)?)
        .map(Some)
        .map_err(serde::de::Error::custom)
}
fn de_opt_seconds_u64<'de, D: Deserializer<'de>>(d: D) -> Result<Option<u64>, D::Error> {
    de_seconds(d).map(|s| Some(s.max(0.0).round() as u64))
}
fn de_u8_list_loose<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    Vec::<Loose>::deserialize(d)?
        .into_iter()
        .map(loose_u8)
        .collect::<Result<_, _>>()
        .map_err(serde::de::Error::custom)
}
/// Secondes : `2`, `2.5`, `"2s"`, `"1500ms"`, `"10m"`, `"1h"`, `"7d"`.
fn de_seconds<'de, D: Deserializer<'de>>(d: D) -> Result<f64, D::Error> {
    match Loose::deserialize(d)? {
        Loose::N(n) => Ok(n),
        Loose::S(s) => {
            let t = s.trim();
            let (num, mult) = if let Some(v) = t.strip_suffix("ms") {
                (v, 0.001)
            } else if let Some(v) = t.strip_suffix('s') {
                (v, 1.0)
            } else if let Some(v) = t.strip_suffix('m') {
                (v, 60.0)
            } else if let Some(v) = t.strip_suffix('h') {
                (v, 3600.0)
            } else if let Some(v) = t.strip_suffix('d') {
                (v, 86400.0)
            } else {
                (t, 1.0)
            };
            num.trim().parse::<f64>().map(|n| n * mult).map_err(|_| {
                serde::de::Error::custom(format!(
                    "{s:?} is not a duration (e.g. 2s, 1500ms, 10m, 1h, 7d)"
                ))
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

// ───────────────────────────────────────────── reverse DNS

/// Le nom d'hôte correspond-il à l'un des domaines ? `googlebot.com`
/// couvre `crawl-66-249-66-1.googlebot.com` et `googlebot.com`, pas
/// `evilgooglebot.com`.
pub fn hostname_matches(host: &str, domains: &[String]) -> bool {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    domains.iter().any(|d| {
        let d = d
            .trim()
            .trim_start_matches("*.")
            .trim_end_matches('.')
            .to_ascii_lowercase();
        !d.is_empty() && (h == d || h.ends_with(&format!(".{d}")))
    })
}

/// DNS inverse confirmé (FCrDNS) : le nom donné par le PTR de l'adresse
/// doit appartenir à un domaine autorisé **et** se résoudre lui-même vers
/// cette adresse. Sans la seconde étape, n'importe qui pourrait nommer son
/// adresse `crawl.googlebot.com`.
pub fn verify_hostname(
    ip: IpAddr,
    domains: &[String],
    reverse: impl Fn(IpAddr) -> Option<String>,
    forward: impl Fn(&str) -> Vec<IpAddr>,
) -> Option<String> {
    let name = reverse(ip)?;
    (hostname_matches(&name, domains) && forward(&name).contains(&ip)).then_some(name)
}

/// PTR de l'adresse, par le résolveur du système (`getnameinfo`).
fn reverse_dns(ip: IpAddr) -> Option<String> {
    let mut host = [0 as libc::c_char; 1025];
    let rc = match ip {
        IpAddr::V4(v4) => {
            let sin = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: 0,
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(v4.octets()),
                },
                sin_zero: [0; 8],
            };
            // SAFETY: structure initialisée, tampon de sortie de taille
            // annoncée ; getnameinfo n'écrit pas au-delà.
            unsafe {
                libc::getnameinfo(
                    (&sin as *const libc::sockaddr_in).cast(),
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                    host.as_mut_ptr(),
                    host.len() as libc::socklen_t,
                    std::ptr::null_mut(),
                    0,
                    libc::NI_NAMEREQD,
                )
            }
        }
        IpAddr::V6(v6) => {
            let mut sin6: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
            sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sin6.sin6_addr = libc::in6_addr {
                s6_addr: v6.octets(),
            };
            // SAFETY: comme ci-dessus.
            unsafe {
                libc::getnameinfo(
                    (&sin6 as *const libc::sockaddr_in6).cast(),
                    std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                    host.as_mut_ptr(),
                    host.len() as libc::socklen_t,
                    std::ptr::null_mut(),
                    0,
                    libc::NI_NAMEREQD,
                )
            }
        }
    };
    if rc != 0 {
        return None;
    }
    // SAFETY: getnameinfo a écrit une chaîne terminée par NUL.
    let name = unsafe { std::ffi::CStr::from_ptr(host.as_ptr()) };
    name.to_str().ok().map(str::to_owned)
}

fn forward_dns(name: &str) -> Vec<IpAddr> {
    use std::net::ToSocketAddrs;
    (name, 0)
        .to_socket_addrs()
        .map(|it| it.map(|a| a.ip()).collect())
        .unwrap_or_default()
}

/// Résultats mis en cache une heure (cinq minutes en cas d'échec) : une
/// adresse n'est résolue qu'une fois.
static DNS_CACHE: OnceLock<dashmap::DashMap<IpAddr, (Option<String>, u64)>> = OnceLock::new();
/// Au plus 32 résolutions en même temps : une attaque depuis des milliers
/// d'adresses ne monopolise pas les threads ; au-delà, pas d'exemption.
static DNS_SLOTS: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();

/// Robot vérifié par son nom ? La requête attend au plus `wait` ; une
/// résolution plus lente **continue en arrière-plan** et met elle-même son
/// résultat en cache, pour la requête suivante. Avant, la requête attendait
/// jusqu'à 3 s — la page de vérification arrivait alors avec 3 s de retard
/// pour chaque nouvelle adresse au DNS lent — et un délai dépassé était
/// mémorisé 5 minutes comme un échec.
async fn hostname_allowed(
    ip: IpAddr,
    domains: &'static [String],
    wait: Duration,
) -> Option<String> {
    let cache = DNS_CACHE.get_or_init(dashmap::DashMap::new);
    let sec = now_ms() / 1000;
    if let Some(hit) = cache.get(&ip).filter(|e| e.1 > sec) {
        return hit.0.clone();
    }
    let slots = DNS_SLOTS
        .get_or_init(|| Arc::new(tokio::sync::Semaphore::new(32)))
        .clone();
    let Ok(permit) = slots.try_acquire_owned() else {
        return None;
    };
    if cache.len() > 100_000 {
        cache.retain(|_, e| e.1 > sec);
    }
    // Une seule résolution par adresse : en attendant, l'adresse compte
    // comme non vérifiée (au plus 10 s).
    cache.insert(ip, (None, sec + 10));
    let lookup = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let result = verify_hostname(ip, domains, reverse_dns, forward_dns);
        let now = now_ms() / 1000;
        if let Some(c) = DNS_CACHE.get() {
            c.insert(
                ip,
                (
                    result.clone(),
                    now + if result.is_some() { 3600 } else { 300 },
                ),
            );
        }
        result
    });
    match tokio::time::timeout(wait, lookup).await {
        Ok(Ok(r)) => r,
        _ => None,
    }
}

// ───────────────────────────────────────────── detections

/// Une ligne CSV : chaque champ entre guillemets, guillemets doublés,
/// retours à la ligne retirés (un User-Agent ne peut pas casser le fichier).
fn csv_line(fields: &[&str]) -> String {
    let mut line = fields
        .iter()
        .map(|f| format!("\"{}\"", f.replace(['\r', '\n'], " ").replace('"', "\"\"")))
        .collect::<Vec<_>>()
        .join(",");
    line.push('\n');
    line
}

const CSV_HEADER: &str = "timestamp,host,ip,user_agent,reason,path,gpu,renderer,vendor,webgl_version,viewport,screen,pixel_ratio,cores,webdriver,language,platform,timezone,difficulty,algorithm,solve_ms,workers,bits,server_ms,gpu_check,gpu_api,gpu_ms,gpu_adapter,proxyauth_version\n";

/// Ce que le navigateur a rapporté en envoyant sa solution. Vide pour les
/// détections faites sans solution (page redemandée, POST…).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ClientInfo {
    pub renderer: String,
    pub vendor: String,
    pub webgl_version: String,
    pub viewport: String,
    pub screen: String,
    pub pixel_ratio: String,
    pub cores: String,
    pub webdriver: String,
    pub language: String,
    pub platform: String,
    pub timezone: String,
    pub difficulty: String,
    pub algorithm: String,
    pub solve_ms: String,
    /// Workers lancés par le navigateur (annoncés avec la solution).
    pub workers: String,
    /// Bits exigés : 4 × difficulté + bits des workers.
    pub bits: String,
    /// Temps mesuré **par le serveur**, de l'envoi de la page de défi à la
    /// réception de la solution (délai de démarrage compris) — contrairement
    /// à `solve_ms`, mesuré par le navigateur, il ne peut pas être falsifié.
    pub server_ms: String,
    /// Épreuve GPU, mesurée par le serveur : `hardware`, `slow`, `timeout`,
    /// `unavailable`, `invalid`, ou vide sans `gpu_check`.
    pub gpu_check: String,
    pub gpu_api: String,
    pub gpu_ms: String,
    /// Fabricant / architecture annoncés par WebGPU (`nvidia/pascal`).
    pub gpu_adapter: String,
}

impl ClientInfo {
    /// Lu depuis la requête de solution ; chaque valeur est bornée à 200
    /// caractères (elle vient du client).
    fn from_query(q: &str) -> Self {
        let g = |n: &str| {
            query_param(q, n)
                .map(|v| v.chars().take(200).collect())
                .unwrap_or_default()
        };
        let pair = |a: &str, b: &str| {
            let (x, y): (String, String) = (g(a), g(b));
            if x.is_empty() && y.is_empty() {
                String::new()
            } else {
                format!("{x}x{y}")
            }
        };
        Self {
            renderer: g("r"),
            vendor: g("v"),
            webgl_version: g("gv"),
            viewport: pair("w", "h"),
            screen: pair("sw", "sh"),
            pixel_ratio: g("dpr"),
            cores: g("c"),
            webdriver: match g("wd").as_str() {
                "1" => "yes".into(),
                "0" => "no".into(),
                _ => String::new(),
            },
            language: g("l"),
            platform: g("p"),
            timezone: g("tz"),
            difficulty: g("d"),
            algorithm: g("a"),
            solve_ms: g("elapsed"),
            workers: g("wk"),
            bits: String::new(),
            server_ms: String::new(),
            gpu_check: g("gpu_check"),
            gpu_api: g("gpu_api"),
            gpu_ms: g("gpu_ms"),
            gpu_adapter: g("ga"),
        }
    }

    /// `hardware`, `software` (SwiftShader, llvmpipe…), `none` (pas de
    /// WebGL), ou vide si le navigateur n'a rien envoyé.
    fn gpu(&self) -> &'static str {
        if self.renderer.is_empty() {
            if self.viewport.is_empty() { "" } else { "none" }
        } else if software_renderer(&self.renderer) {
            "software"
        } else {
            "hardware"
        }
    }
}

/// Écrit le journal CSV dans un thread à part, par blocs : une rafale de
/// détections pendant une attaque ne ralentit pas les requêtes.
fn csv_writer(path: String) -> std::sync::mpsc::Sender<String> {
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    let _ = std::thread::Builder::new()
        .name("antibot-log".into())
        .spawn(move || {
            use std::io::Write;
            // Ouvert au premier événement, donc après l'abandon des
            // privilèges root : le fichier appartient à `run_user`.
            let mut out: Option<std::io::BufWriter<std::fs::File>> = None;
            loop {
                match rx.recv_timeout(Duration::from_secs(1)) {
                    Ok(line) => {
                        if out.is_none() {
                            let mut opts = std::fs::OpenOptions::new();
                            opts.create(true).append(true);
                            #[cfg(unix)]
                            {
                                use std::os::unix::fs::OpenOptionsExt;
                                opts.mode(0o640);
                            }
                            match opts.open(&path) {
                                Ok(f) => {
                                    let empty = f.metadata().map(|m| m.len() == 0).unwrap_or(false);
                                    let mut w = std::io::BufWriter::new(f);
                                    if empty {
                                        let _ = w.write_all(CSV_HEADER.as_bytes());
                                    }
                                    out = Some(w);
                                }
                                Err(e) => {
                                    tracing::error!(
                                        "antibot: cannot open detection log {path}: {e}"
                                    );
                                    continue;
                                }
                            }
                        }
                        if let Some(w) = out.as_mut() {
                            // Tout ce qui attend est écrit d'un bloc, puis le
                            // tampon est vidé : une ligne est sur le disque
                            // aussitôt, même si la suivante arrive avant la
                            // seconde d'inactivité (qui seule vidait le tampon
                            // auparavant — sous un flot continu, rien n'était
                            // écrit, et un arrêt perdait tout).
                            let _ = w.write_all(line.as_bytes());
                            while let Ok(more) = rx.try_recv() {
                                let _ = w.write_all(more.as_bytes());
                            }
                            let _ = w.flush();
                        }
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                        if let Some(w) = out.as_mut() {
                            let _ = w.flush();
                        }
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                        if let Some(w) = out.as_mut() {
                            let _ = w.flush();
                        }
                        return;
                    }
                }
            }
        });
    tx
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Offender {
    window_start: u64,
    count: u32,
    banned_until: u64,
    /// Détections de la fenêtre par raison (8 raisons distinctes au plus).
    reasons: Vec<(String, u32)>,
    /// Résumé figé au moment du bannissement (`proxyauth antibot list`).
    ban_reason: String,
    /// Début du bannissement (secondes Unix).
    #[serde(default)]
    banned_at: u64,
}

impl Offender {
    fn new(sec: u64) -> Self {
        Self {
            window_start: sec,
            count: 0,
            banned_until: 0,
            reasons: Vec::new(),
            ban_reason: String::new(),
            banned_at: 0,
        }
    }

    /// Raison principale, puis les autres : `POST request without a pass ×3, window of size zero ×1`.
    fn summary(&self) -> String {
        let mut r = self.reasons.clone();
        r.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        r.iter()
            .map(|(reason, n)| format!("{reason} ×{n}"))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Détections d'un vhost : journal CSV et bannissements.
#[derive(Debug)]
struct Detector {
    /// Le vhost (pour `proxyauth antibot list`).
    label: String,
    log: Option<Mutex<std::sync::mpsc::Sender<String>>>,
    ban: Option<BanConfig>,
    offenders: dashmap::DashMap<IpAddr, Offender>,
    /// Lignes identiques (adresse, raison, chemin) écrites au plus une fois
    /// par minute : (dernière écriture, répétitions tues depuis).
    recent: dashmap::DashMap<u64, (u64, u32)>,
}

const CSV_REPEAT_WINDOW: u64 = 60;

impl Detector {
    /// Bannie en ce moment ? Renvoie la fin du bannissement.
    fn banned_until(&self, ip: IpAddr, sec: u64) -> Option<u64> {
        self.offenders
            .get(&ip)
            .map(|o| o.banned_until)
            .filter(|u| *u > sec)
    }

    #[allow(clippy::too_many_arguments)]
    fn write(&self, host: &str, ip: &str, ua: &str, reason: &str, path: &str, info: &ClientInfo) {
        if let Some(tx) = &self.log {
            let ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
            let line = csv_line(&[
                &ts,
                host,
                ip,
                ua,
                reason,
                path,
                info.gpu(),
                &info.renderer,
                &info.vendor,
                &info.webgl_version,
                &info.viewport,
                &info.screen,
                &info.pixel_ratio,
                &info.cores,
                &info.webdriver,
                &info.language,
                &info.platform,
                &info.timezone,
                &info.difficulty,
                &info.algorithm,
                &info.solve_ms,
                &info.workers,
                &info.bits,
                &info.server_ms,
                &info.gpu_check,
                &info.gpu_api,
                &info.gpu_ms,
                &info.gpu_adapter,
                crate::VERSION,
            ]);
            let _ = tx.lock().unwrap_or_else(|e| e.into_inner()).send(line);
        }
    }

    /// Une ligne au journal, sans compter pour le bannissement.
    fn note(&self, host: &str, ip: Option<IpAddr>, ua: &str, reason: &str, path: &str) {
        let ip_s = ip.map(|i| i.to_string()).unwrap_or_default();
        self.write(host, &ip_s, ua, reason, path, &ClientInfo::default());
    }

    /// Une vérification réussie (`log_passes`).
    fn passed(&self, host: &str, ip: &str, ua: &str, path: &str, info: &ClientInfo) {
        self.write(host, ip, ua, "passed", path, info);
    }

    /// Une détection : écrite au journal, comptée pour le bannissement.
    fn detect(&self, sec: u64, host: &str, ip: Option<IpAddr>, ua: &str, reason: &str, path: &str) {
        self.detect_with(sec, host, ip, ua, reason, path, &ClientInfo::default());
    }

    /// Comme [`detect`](Self::detect), avec ce que le navigateur a envoyé.
    #[allow(clippy::too_many_arguments)]
    fn detect_with(
        &self,
        sec: u64,
        host: &str,
        ip: Option<IpAddr>,
        ua: &str,
        reason: &str,
        path: &str,
        info: &ClientInfo,
    ) {
        let ip_s = ip.map(|i| i.to_string()).unwrap_or_default();
        self.log_once(sec, host, &ip_s, ua, reason, path, info);
        self.count_for_ban(sec, host, ip, &ip_s, ua, reason, path);
    }

    /// Une requête passée sans défi (`log_bypass`) : journalisée une fois
    /// par minute, jamais comptée.
    fn bypass(&self, sec: u64, host: &str, ip: Option<IpAddr>, ua: &str, why: &str, path: &str) {
        let ip_s = ip.map(|i| i.to_string()).unwrap_or_default();
        self.log_once(
            sec,
            host,
            &ip_s,
            ua,
            &format!("passed without challenge: {why}"),
            path,
            &ClientInfo::default(),
        );
    }

    /// Le journal ne répète pas la même ligne plus d'une fois par minute ;
    /// la suivante indique combien ont été tues.
    #[allow(clippy::too_many_arguments)]
    fn log_once(
        &self,
        sec: u64,
        host: &str,
        ip_s: &str,
        ua: &str,
        reason: &str,
        path: &str,
        info: &ClientInfo,
    ) {
        if self.log.is_some() {
            if self.recent.len() > 100_000 {
                self.recent
                    .retain(|_, (t, _)| sec.saturating_sub(*t) < CSV_REPEAT_WINDOW);
            }
            let h = blake3::hash(format!("{ip_s}\n{reason}\n{path}").as_bytes());
            let k = u64::from_le_bytes(h.as_bytes()[..8].try_into().unwrap_or([0; 8]));
            let mut e = self.recent.entry(k).or_insert((0, 0));
            if e.0 != 0 && sec.saturating_sub(e.0) < CSV_REPEAT_WINDOW {
                e.1 += 1;
            } else {
                let reason = if e.1 > 0 {
                    format!("{reason} (+{} identical in the previous minute)", e.1)
                } else {
                    reason.to_string()
                };
                *e = (sec, 0);
                drop(e);
                self.write(host, ip_s, ua, &reason, path, info);
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn count_for_ban(
        &self,
        sec: u64,
        host: &str,
        ip: Option<IpAddr>,
        ip_s: &str,
        ua: &str,
        reason: &str,
        path: &str,
    ) {
        let (Some(ban), Some(ip)) = (&self.ban, ip) else {
            return;
        };
        let mut o = self
            .offenders
            .entry(ip)
            .or_insert_with(|| Offender::new(sec));
        if o.banned_until > sec {
            return;
        }
        if sec.saturating_sub(o.window_start) >= ban.period {
            o.window_start = sec;
            o.count = 0;
            o.reasons.clear();
        }
        o.count += 1;
        if let Some(i) = o.reasons.iter().position(|(r, _)| r == reason) {
            o.reasons[i].1 += 1;
        } else if o.reasons.len() < 8 {
            o.reasons.push((reason.to_string(), 1));
        }
        if o.count >= ban.after {
            o.banned_until = sec + ban.duration;
            o.ban_reason = o.summary();
            o.banned_at = sec;
            let detections = o.count;
            drop(o);
            tracing::warn!(client_ip = %ip, host = %host, "antibot: address banned for {}s after {detections} detections", ban.duration);
            self.write(
                host,
                ip_s,
                ua,
                &format!(
                    "banned for {}s after {detections} detections in {}s",
                    ban.duration, ban.period
                ),
                path,
                &ClientInfo::default(),
            );
        }
    }

    /// Oublie les adresses ni bannies, ni récemment détectées.
    fn purge(&self, sec: u64) {
        let period = self.ban.as_ref().map(|b| b.period).unwrap_or(0);
        self.offenders
            .retain(|_, o| o.banned_until > sec || sec.saturating_sub(o.window_start) < period);
    }
}

// ───────────────────────────────────────────── per-challenge key and script

/// Préfixe de l'URL du script de vérification (`<jeton>.js`).
pub const JS_PREFIX: &str = "/.proxyauth/antibot/js/";

/// Une vérification en cours : sa clé AES, ses paramètres, son client.
struct Pending {
    key: [u8; 32],
    params: String,
    ip: String,
    ua: String,
    created: u64,
    key_ttl: u64,
    served: bool,
    /// Épreuve GPU : graine, bits, début de la mesure (ms), résultat.
    gpu: Option<GpuPending>,
}

struct GpuPending {
    seed: u32,
    bits: u8,
    hardware_under_ms: u64,
    started: Option<u64>,
    result: Option<(&'static str, String, u64)>,
    /// Bits ajoutés à la preuve de travail (`on_software: harder`).
    penalty_bits: u32,
    /// Le mode retenu à la fin de l'épreuve (paliers compris).
    decision: OnSoftware,
    guard: Arc<SoftwareGuard>,
    lockdown: Option<Arc<LockdownState>>,
}

static PENDING: OnceLock<dashmap::DashMap<String, Pending>> = OnceLock::new();
fn pending() -> &'static dashmap::DashMap<String, Pending> {
    PENDING.get_or_init(dashmap::DashMap::new)
}

fn random_bytes<const N: usize>() -> [u8; N] {
    use ring::rand::SecureRandom;
    let mut b = [0u8; N];
    let _ = ring::rand::SystemRandom::new().fill(&mut b);
    b
}

/// Enregistre une vérification ; renvoie son jeton et sa clé.
#[cfg(test)]
fn register_pending(params: String, ip: &str, ua: &str, key_ttl: u64) -> (String, [u8; 32]) {
    register_pending_with(params, ip, ua, key_ttl, None)
}

#[cfg(test)]
fn register_pending_with(
    params: String,
    ip: &str,
    ua: &str,
    key_ttl: u64,
    gpu: Option<&Arc<SoftwareGuard>>,
) -> (String, [u8; 32]) {
    register_pending_full(params, ip, ua, key_ttl, gpu, None)
}

fn register_pending_full(
    params: String,
    ip: &str,
    ua: &str,
    key_ttl: u64,
    gpu: Option<&Arc<SoftwareGuard>>,
    lockdown: Option<&Arc<LockdownState>>,
) -> (String, [u8; 32]) {
    let map = pending();
    let sec = now_ms() / 1000;
    if map.len() > 100_000 {
        map.retain(|_, p| sec.saturating_sub(p.created) <= p.key_ttl);
        if map.len() > 100_000 {
            // Sous une attaque : on repart de zéro plutôt que de grossir.
            map.clear();
        }
    }
    let token = hex::encode(random_bytes::<16>());
    let key = random_bytes::<32>();
    let gpu = gpu
        .map(|guard| (guard, &guard.cfg))
        .map(|(guard, g)| GpuPending {
            seed: u32::from_le_bytes(random_bytes::<4>()),
            bits: g.bits,
            hardware_under_ms: (g.hardware_under * 1000.0) as u64,
            started: None,
            result: None,
            penalty_bits: 0,
            decision: OnSoftware::Allow,
            guard: guard.clone(),
            lockdown: lockdown.cloned(),
        });
    map.insert(
        token.clone(),
        Pending {
            key,
            params,
            ip: ip.to_string(),
            ua: ua.to_string(),
            created: sec,
            key_ttl,
            served: false,
            gpu,
        },
    );
    (token, key)
}

/// Le script d'une vérification, une seule fois, au même client, dans le
/// délai de la clé.
fn serve_script(token: &str, ip: &str, ua: &str) -> Option<String> {
    use base64::Engine;
    let sec = now_ms() / 1000;
    let mut p = pending().get_mut(token)?;
    if p.served || p.ip != ip || p.ua != ua || sec.saturating_sub(p.created) > p.key_ttl {
        return None;
    }
    p.served = true;
    let key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(p.key);
    let worker = serde_json::to_string(WORKER_JS)
        .unwrap_or_default()
        .replace("</", "<\\/");
    Some(
        MAIN_JS
            .replace("__PARAMS__", &p.params)
            .replace("__KEY__", &key)
            .replace("__TOKEN__", token)
            .replace("__WORKER__", &worker),
    )
}

/// Préfixe des deux points d'entrée de l'épreuve GPU.
pub const GPU_PREFIX: &str = "/.proxyauth/antibot/gpu/";

/// Début de l'épreuve GPU : la graine n'est révélée qu'à cet instant, et
/// le serveur démarre son chronomètre. Une seule fois par vérification.
fn gpu_start(token: &str, ip: &str, ua: &str) -> Option<String> {
    let mut p = pending().get_mut(token)?;
    if p.ip != ip || p.ua != ua || !p.served {
        return None;
    }
    let g = p.gpu.as_mut()?;
    if g.started.is_some() {
        return None;
    }
    g.started = Some(now_ms());
    Some(serde_json::json!({ "seed": g.seed, "bits": g.bits }).to_string())
}

/// Fin de l'épreuve GPU : temps mesuré par le serveur et classement.
fn gpu_done(token: &str, ip: &str, ua: &str, q: &str) -> Option<&'static str> {
    let mut p = pending().get_mut(token)?;
    if p.ip != ip || p.ua != ua {
        return None;
    }
    let g = p.gpu.as_mut()?;
    if g.result.is_some() {
        return None;
    }
    let api: String = query_param(q, "api")
        .unwrap_or_default()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .take(16)
        .collect();
    let class = match (
        g.started,
        query_param(q, "n").and_then(|n| n.parse::<i64>().ok()),
    ) {
        (None, _) => "unavailable",
        (Some(_), None) | (Some(_), Some(-1)) => "timeout",
        (Some(_), Some(n))
            if !(0..=i64::from(u32::MAX)).contains(&n)
                || !gpu_meets(gpu_hash(g.seed, n as u32), g.bits) =>
        {
            "invalid"
        }
        (Some(t0), Some(_)) => {
            if now_ms().saturating_sub(t0) <= g.hardware_under_ms {
                "hardware"
            } else {
                "slow"
            }
        }
    };
    let ms = g.started.map(|t0| now_ms().saturating_sub(t0)).unwrap_or(0);
    // Le navigateur dit lui-même faire le rendu en logiciel.
    let reported = format!(
        "{} {}",
        query_param(q, "r").unwrap_or_default(),
        query_param(q, "ga").unwrap_or_default()
    );
    let class = if matches!(class, "hardware" | "slow") && software_renderer(&reported) {
        "software"
    } else {
        class
    };
    g.result = Some((class, api, ms));
    if no_hardware_gpu(class) {
        // Compté, puis décision du moment : sous une vague, les paliers
        // durcissent `on_software` pour tous les clients sans vrai GPU.
        let sec = now_ms() / 1000;
        g.guard.record(sec);
        let (mode, extra) = g.guard.decision(sec);
        // Verrouillage : pas de vrai GPU, pas de passage.
        let mode = if g
            .lockdown
            .as_ref()
            .is_some_and(|l| l.refuses(sec, LockdownRule::NoGpu))
        {
            OnSoftware::Refuse
        } else {
            mode
        };
        g.decision = mode;
        g.penalty_bits = if mode == OnSoftware::Harder {
            4 * u32::from(extra)
        } else {
            0
        };
    }
    Some(class)
}

/// Classement GPU retenu : celui du serveur, ou `software` si le navigateur
/// annonce un rendu logiciel.
fn effective_gpu_class(q: &str) -> String {
    let class = query_param(q, "gpu_check").unwrap_or_default();
    let reported = format!(
        "{} {}",
        query_param(q, "r").unwrap_or_default(),
        query_param(q, "ga").unwrap_or_default()
    );
    if matches!(class.as_str(), "hardware" | "slow") && software_renderer(&reported) {
        "software".into()
    } else {
        class
    }
}

/// Les bits supplémentaires que le navigateur doit maintenant chercher.
fn gpu_penalty(token: &str) -> u32 {
    pending()
        .get(token)
        .and_then(|p| p.gpu.as_ref().map(|g| g.penalty_bits))
        .unwrap_or(0)
}

/// Déchiffre une solution (AES-256-GCM, le jeton en données associées).
pub fn open_sealed(key: &[u8; 32], token: &str, iv_b64: &str, c_b64: &str) -> Option<String> {
    use base64::Engine;
    use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
    let b = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let iv: [u8; 12] = b.decode(iv_b64).ok()?.try_into().ok()?;
    let mut data = b.decode(c_b64).ok()?;
    let k = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key).ok()?);
    let plain = k
        .open_in_place(
            Nonce::assume_unique_for_key(iv),
            Aad::from(token.as_bytes()),
            &mut data,
        )
        .ok()?;
    String::from_utf8(plain.to_vec()).ok()
}

/// Retire la vérification (usage unique) et déchiffre sa solution ; renvoie
/// les champs sous forme de chaîne de requête, lue ensuite comme avant.
fn take_solution(q: &str, ip: &str, ua: &str) -> Result<String, &'static str> {
    let token = query_param(q, "t").ok_or("unencrypted solution")?;
    let (_, p) = pending()
        .remove(&token)
        .ok_or("unknown or already used challenge key")?;
    if p.ip != ip || p.ua != ua {
        return Err("challenge key issued to another client");
    }
    if !p.served {
        return Err("challenge script was never loaded");
    }
    if (now_ms() / 1000).saturating_sub(p.created) > p.key_ttl {
        return Err("challenge key expired");
    }
    let plain = open_sealed(
        &p.key,
        &token,
        &query_param(q, "iv").unwrap_or_default(),
        &query_param(q, "c").unwrap_or_default(),
    )
    .ok_or("solution could not be decrypted")?;
    let mut map: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(&plain).map_err(|_| "solution could not be decrypted")?;
    // Le résultat GPU vient du serveur, jamais du client.
    for k in [
        "gpu_check",
        "gpu_api",
        "gpu_ms",
        "gpu_penalty_bits",
        "gpu_decision",
    ] {
        map.remove(k);
    }
    if let Some(g) = &p.gpu {
        let (class, api, ms) = g.result.clone().unwrap_or(("not run", String::new(), 0));
        map.insert("gpu_check".into(), class.into());
        map.insert("gpu_api".into(), api.into());
        map.insert(
            "gpu_ms".into(),
            if ms > 0 {
                ms.to_string()
            } else {
                String::new()
            }
            .into(),
        );
        map.insert("gpu_penalty_bits".into(), g.penalty_bits.to_string().into());
        map.insert("gpu_decision".into(), g.decision.name().into());
    }
    Ok(map
        .iter()
        .map(|(k, v)| {
            let v = v
                .as_str()
                .map(str::to_string)
                .unwrap_or_else(|| v.to_string());
            format!("{}={}", percent_encode(k), percent_encode(&v))
        })
        .collect::<Vec<_>>()
        .join("&"))
}

fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

// ───────────────────────────────────────────── persistence of bans

/// Une adresse dans le fichier `ban.store`.
#[derive(Serialize, Deserialize)]
struct StoredOffender {
    vhost: String,
    ip: IpAddr,
    #[serde(flatten)]
    offender: Offender,
}

#[derive(Serialize, Deserialize)]
struct StoreFile {
    version: u32,
    saved: u64,
    offenders: Vec<StoredOffender>,
}

/// Les détecteurs qui partagent ce fichier.
fn detectors_of(path: &str) -> Vec<Arc<Detector>> {
    all_detectors()
        .into_iter()
        .filter(|d| d.ban.as_ref().and_then(|b| b.store.as_deref()) == Some(path))
        .collect()
}

/// Écrit l'état de ces détecteurs (adresses bannies ou dans leur fenêtre
/// de comptage) : fichier temporaire puis renommage, droits 0600.
fn save_store(path: &str, detectors: &[Arc<Detector>]) -> std::io::Result<usize> {
    let sec = now_ms() / 1000;
    let mut offenders = Vec::new();
    for d in detectors {
        let period = d.ban.as_ref().map(|b| b.period).unwrap_or(0);
        for e in d.offenders.iter() {
            if e.banned_until > sec || sec.saturating_sub(e.window_start) < period {
                offenders.push(StoredOffender {
                    vhost: d.label.clone(),
                    ip: *e.key(),
                    offender: e.value().clone(),
                });
            }
        }
    }
    let n = offenders.len();
    let body = serde_json::to_vec(&StoreFile {
        version: 1,
        saved: sec,
        offenders,
    })?;
    let tmp = format!("{path}.tmp");
    {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        use std::io::Write;
        let mut f = opts.open(&tmp)?;
        f.write_all(&body)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(n)
}

/// Sauvegarde tous les fichiers `ban.store` (arrêt, unban, tâche de fond).
pub fn save_all_stores() {
    let mut paths: Vec<String> = all_detectors()
        .iter()
        .filter_map(|d| d.ban.as_ref().and_then(|b| b.store.clone()))
        .collect();
    paths.sort();
    paths.dedup();
    for p in paths {
        if let Err(e) = save_store(&p, &detectors_of(&p)) {
            tracing::warn!("antibot: cannot save bans to {p}: {e}");
        }
    }
}

/// Relit un fichier `ban.store` dans les détecteurs des vhosts qu'il
/// nomme. Les dates sont absolues : un bannissement reprend avec le temps
/// qu'il lui restait, une fenêtre de comptage là où elle en était.
fn load_store(path: &str, detectors: &[Arc<Detector>]) -> (usize, usize) {
    let Ok(bytes) = std::fs::read(path) else {
        return (0, 0);
    };
    let Ok(file) = serde_json::from_slice::<StoreFile>(&bytes) else {
        tracing::warn!("antibot: {path} is not a ban store, ignored");
        return (0, 0);
    };
    let sec = now_ms() / 1000;
    let (mut banned, mut counting) = (0, 0);
    for so in file.offenders {
        let Some(d) = detectors.iter().find(|d| d.label == so.vhost) else {
            continue;
        };
        let period = d.ban.as_ref().map(|b| b.period).unwrap_or(0);
        if so.offender.banned_until > sec {
            banned += 1;
        } else if sec.saturating_sub(so.offender.window_start) < period {
            counting += 1;
        } else {
            continue;
        }
        d.offenders.insert(so.ip, so.offender);
    }
    (banned, counting)
}

// ───────────────────────────────────────────── export of bans (ip_blocklists format)

fn iso(sec: u64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(sec as i64, 0)
        .map(|d| d.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        .unwrap_or_default()
}

/// Le contenu du fichier `ban.export` : seulement les bannissements en
/// cours. La durée restante n'y figure pas — elle reste gérée par
/// l'anti-bot (et `ban.store`) ; quand elle s'achève, l'IP sort du fichier.
fn export_text(detectors: &[Arc<Detector>], sec: u64) -> String {
    let mut bans: Vec<(u64, String, IpAddr, String)> = Vec::new();
    for d in detectors {
        for e in d.offenders.iter() {
            if e.banned_until > sec {
                bans.push((e.banned_at, d.label.clone(), *e.key(), e.ban_reason.clone()));
            }
        }
    }
    bans.sort_by(|a, b| a.0.cmp(&b.0).then(a.2.cmp(&b.2)));
    bans.dedup_by(|a, b| a.2 == b.2);
    let mut out = format!(
        "# ProxyAuth anti-bot bans — {} address(es)\n# Format: ip_blocklists (one IP per line). Loaded with \"antibots_auto\": true.\n",
        bans.len()
    );
    for (at, vhost, ip, reason) in bans {
        let reason = reason.replace(['\n', '\r'], " ");
        out.push_str(&format!(
            "\n# {} · {vhost} · {}\n{ip}\n",
            if at > 0 { iso(at) } else { "-".into() },
            if reason.is_empty() { "-" } else { &reason }
        ));
    }
    out
}

static EXPORTED: OnceLock<Mutex<std::collections::HashMap<String, String>>> = OnceLock::new();

/// Réécrit les fichiers `ban.export` dont le contenu a changé
/// (atomiquement, mode 0644). Appelé toutes les 5 s, et aussitôt après
/// `unban`.
pub fn write_exports() {
    let sec = now_ms() / 1000;
    let mut paths: Vec<String> = all_detectors()
        .iter()
        .filter_map(|d| d.ban.as_ref().and_then(|b| b.export.clone()))
        .collect();
    paths.sort();
    paths.dedup();
    let last = EXPORTED.get_or_init(Default::default);
    for path in paths {
        let ds: Vec<Arc<Detector>> = all_detectors()
            .into_iter()
            .filter(|d| d.ban.as_ref().and_then(|b| b.export.as_deref()) == Some(path.as_str()))
            .collect();
        let text = export_text(&ds, sec);
        let mut l = last.lock().unwrap_or_else(|e| e.into_inner());
        // L'en-tête ne change qu'avec la liste : on compare tout.
        if l.get(&path) == Some(&text) {
            continue;
        }
        let tmp = format!("{path}.tmp");
        let res = (|| -> std::io::Result<()> {
            use std::io::Write;
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o644);
            }
            let mut f = opts.open(&tmp)?;
            f.write_all(text.as_bytes())?;
            f.sync_all()?;
            std::fs::rename(&tmp, &path)
        })();
        match res {
            Ok(()) => {
                l.insert(path, text);
            }
            Err(e) => tracing::warn!("antibot: cannot write {path}: {e}"),
        }
    }
}

/// Les fichiers `ban.export` de ces routes (pour `antibots_auto`).
pub fn export_paths(routes: &[RouteRule]) -> Vec<String> {
    let mut v: Vec<String> = routes
        .iter()
        .filter_map(|r| r.antibot.as_ref()?.ban.as_ref()?.export.clone())
        .collect();
    v.sort();
    v.dedup();
    v
}

// ───────────────────────────────────────────── administration

/// Une adresse bannie, pour `proxyauth antibot list`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BanInfo {
    pub vhost: String,
    pub ip: String,
    pub remaining_secs: u64,
    pub detections: u32,
    /// Ce qui a conduit au bannissement, raison principale en tête.
    #[serde(default)]
    pub reason: String,
}

fn all_detectors() -> Vec<Arc<Detector>> {
    let Some(reg) = REGISTRY.get() else {
        return Vec::new();
    };
    let mut out: Vec<Arc<Detector>> = Vec::new();
    for rule in reg.by_route.iter().flatten() {
        if !out.iter().any(|d| Arc::ptr_eq(d, &rule.detector)) {
            out.push(rule.detector.clone());
        }
    }
    out
}

/// Lève le bannissement d'une adresse sur tous les vhosts, et oublie ses
/// détections. Renvoie les vhosts où elle était bannie.
pub fn unban(ip: IpAddr) -> Vec<String> {
    let sec = now_ms() / 1000;
    let mut lifted = Vec::new();
    for d in all_detectors() {
        if let Some((_, o)) = d.offenders.remove(&ip) {
            if o.banned_until > sec {
                lifted.push(d.label.clone());
                d.write(
                    &d.label,
                    &ip.to_string(),
                    "",
                    "unbanned by an administrator (proxyauth antibot unban)",
                    "",
                    &ClientInfo::default(),
                );
                tracing::warn!(client_ip = %ip, vhost = %d.label, "antibot: address unbanned by an administrator");
            }
        }
    }
    if !lifted.is_empty() {
        save_all_stores();
        write_exports();
    }
    lifted
}

/// Adresses bannies en ce moment, tous vhosts confondus.
pub fn bans() -> Vec<BanInfo> {
    let sec = now_ms() / 1000;
    let mut out = Vec::new();
    for d in all_detectors() {
        for e in d.offenders.iter() {
            if e.banned_until > sec {
                out.push(BanInfo {
                    vhost: d.label.clone(),
                    ip: e.key().to_string(),
                    remaining_secs: e.banned_until - sec,
                    detections: e.count,
                    reason: e.ban_reason.clone(),
                });
            }
        }
    }
    out.sort_by(|a, b| a.vhost.cmp(&b.vhost).then(a.ip.cmp(&b.ip)));
    out
}

// ───────────────────────────────────────────── registry

#[derive(Debug)]
struct Rule {
    cfg: AntiBotConfig,
    exclude: Vec<regex::Regex>,
    nofiltered: Vec<ipnet::IpNet>,
    traffic: Arc<Traffic>,
    page: Arc<Page>,
    /// Fin de l'activation déclenchée par le seuil (secondes Unix).
    active_until: std::sync::atomic::AtomicU64,
    detector: Arc<Detector>,
    /// Première page de défi servie à chaque navigateur (adresse +
    /// empreinte du User-Agent), dans la fenêtre de 30 minutes.
    challenged: dashmap::DashMap<(IpAddr, [u8; 8]), u64>,
    /// La vérification par nom d'hôte est-elle coupée (pour journaliser
    /// le changement d'état une seule fois) ?
    hostname_off: std::sync::atomic::AtomicBool,
    /// `gpu_check.on_software` et ses paliers.
    software: Option<Arc<SoftwareGuard>>,
    /// `lockdown`.
    lockdown: Option<Arc<LockdownState>>,
}

impl Rule {
    /// Une page de défi a-t-elle déjà été servie à cette adresse dans les
    /// 30 dernières minutes (durée de vie d'un challenge) ? Enregistre
    /// celle-ci.
    fn challenged_recently(&self, ip: IpAddr, ua: &str, sec: u64) -> bool {
        let window = CHALLENGE_MAX_AGE_MS / 1000;
        if self.challenged.len() > 100_000 {
            self.challenged
                .retain(|_, t| sec.saturating_sub(*t) < window);
        }
        // Par navigateur (adresse + User-Agent) : plusieurs personnes
        // derrière une même adresse ne se comptent pas les unes les autres.
        let key = (
            ip,
            blake3::hash(ua.as_bytes()).as_bytes()[..8]
                .try_into()
                .unwrap_or([0; 8]),
        );
        // Délai de grâce : le temps d'attendre et de calculer, plus les
        // pages ouvertes en même temps. Seule une nouvelle demande après ce
        // délai, sans avoir résolu entre-temps, est suspecte.
        let grace = self.cfg.max_start.max(self.cfg.min_start).max(0.0) as u64 + 30;
        match self.challenged.get(&key).map(|t| *t) {
            Some(first) if sec.saturating_sub(first) < window => sec.saturating_sub(first) > grace,
            _ => {
                self.challenged.insert(key, sec);
                false
            }
        }
    }

    /// L'anti-bot défie-t-il en ce moment ? Toujours sans seuil ; avec un
    /// seuil, dès qu'il est atteint et pendant `hold` secondes ensuite.
    fn active(&self, sec: u64) -> bool {
        use std::sync::atomic::Ordering;
        let Some(threshold) = self.cfg.request else {
            return true;
        };
        if self.traffic.count(sec, self.cfg.period) >= threshold {
            let until = sec + self.cfg.hold.max(1);
            let prev = self.active_until.fetch_max(until, Ordering::Relaxed);
            if prev <= sec {
                tracing::warn!(
                    threshold = threshold,
                    period = self.cfg.period,
                    "antibot: traffic threshold reached, challenge enabled for at least {}s",
                    self.cfg.hold
                );
            }
            return true;
        }
        self.active_until.load(Ordering::Relaxed) > sec
    }

    /// Cœurs du visiteur à utiliser : ceux du dernier palier atteint qui en
    /// fixe, sinon `client_cores`.
    fn client_cores(&self, sec: u64) -> CoreUsage {
        self.cfg
            .load_levels
            .iter()
            .filter(|l| l.client_cores.is_some() && self.level_reached(l, sec))
            .filter_map(|l| l.client_cores)
            .last()
            .unwrap_or(self.cfg.client_cores)
    }

    /// La vérification par nom d'hôte est-elle active ? Coupée tant que le
    /// trafic dépasse `hostname_check_limit` ; le journal note chaque
    /// passage de l'un à l'autre.
    fn hostname_check_enabled(&self, sec: u64) -> bool {
        use std::sync::atomic::Ordering;
        let Some(limit) = &self.cfg.hostname_check_limit else {
            return true;
        };
        let traffic = match limit.scope {
            LoadScope::Vhost => &*self.traffic,
            LoadScope::Server => server_traffic(),
        };
        let over = traffic.count(sec, limit.period) >= limit.request;
        if self.hostname_off.swap(over, Ordering::Relaxed) != over {
            if over {
                tracing::warn!(
                    "antibot: more than {} requests in {}s — hostname check (reverse DNS) turned off, every client goes through the other rules",
                    limit.request,
                    limit.period
                );
            } else {
                tracing::info!(
                    "antibot: traffic back under {} requests in {}s — hostname check turned on again",
                    limit.request,
                    limit.period
                );
            }
        }
        !over
    }

    /// Le palier est-il atteint, d'après le trafic qu'il compte ?
    fn level_reached(&self, level: &LoadLevel, sec: u64) -> bool {
        let traffic = match (level.count, level.scope) {
            (LevelCount::Requests, LoadScope::Vhost) => &*self.traffic,
            (LevelCount::Requests, LoadScope::Server) => server_traffic(),
            (LevelCount::Software, LoadScope::Vhost) => match &self.software {
                Some(g) => &g.seen,
                None => return false,
            },
            (LevelCount::Software, LoadScope::Server) => server_software(),
        };
        traffic.count(sec, level.period) >= level.request
    }

    /// Les contrôles de la page, durcis pendant un verrouillage.
    fn flags_at(&self, sec: u64) -> u8 {
        let lock = |r| self.lockdown.as_ref().is_some_and(|l| l.refuses(sec, r));
        (if self.cfg.webgl || lock(LockdownRule::NoWebgl) || lock(LockdownRule::SoftwareRenderer) {
            FLAG_WEBGL
        } else {
            0
        }) | (if self.cfg.reject_software_gl || lock(LockdownRule::SoftwareRenderer) {
            FLAG_REJECT_SOFTWARE_GL
        } else {
            0
        }) | (if self.cfg.reject_headless || lock(LockdownRule::Headless) {
            FLAG_REJECT_HEADLESS
        } else {
            0
        }) | (if self.cfg.scale_with_workers {
            FLAG_SCALE_WORKERS
        } else {
            0
        })
    }

    /// Paramètres tirés pour un visiteur : difficulté (relevée par les
    /// paliers de charge), algorithme et délai de démarrage en ms.
    /// Âge maximal d'un laissez-passer en ce moment : le plus court des
    /// paliers atteints, sinon `cookie_ttl`.
    fn pass_max_age(&self, sec: u64) -> u64 {
        self.cfg
            .load_levels
            .iter()
            .filter(|l| l.cookie_ttl.is_some() && self.level_reached(l, sec))
            .filter_map(|l| l.cookie_ttl)
            .min()
            .unwrap_or(self.cfg.cookie_ttl)
            .min(self.cfg.cookie_ttl)
    }

    fn draw(&self, sec: u64) -> (u8, Algorithm, u64) {
        let r = random_u64();
        let mut d = if self.cfg.random_difficulty.is_empty() {
            self.cfg.difficulty
        } else {
            self.cfg.random_difficulty[(r % self.cfg.random_difficulty.len() as u64) as usize]
        };
        for level in &self.cfg.load_levels {
            if self.level_reached(level, sec) {
                if let Some(ld) = level.difficulty {
                    d = d.max(ld);
                }
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
        (d.min(MAX_DIFFICULTY), a, start_ms)
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
    let d_ok = |d: u8| (1..=MAX_DIFFICULTY).contains(&d);
    if !d_ok(cfg.difficulty) {
        return Err(format!(
            "{place}: `difficulty` must be between 1 and {MAX_DIFFICULTY}"
        ));
    }
    if let Some(d) = cfg.random_difficulty.iter().find(|d| !d_ok(**d)) {
        return Err(format!(
            "{place}: `random_difficulty` value {d} must be between 1 and {MAX_DIFFICULTY}"
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
    if let Some(l) = &cfg.hostname_check_limit {
        if l.request == 0 || !(1..=60).contains(&l.period) {
            return Err(format!(
                "{place}: `hostname_check_limit` needs `request` ≥ 1 and `period` between 1 and 60 seconds"
            ));
        }
    }
    let level_lockdowns = cfg
        .load_levels
        .iter()
        .filter(|l| l.lockdown_config().is_some())
        .count();
    if level_lockdowns > 1 || (level_lockdowns == 1 && cfg.lockdown.is_some()) {
        return Err(format!(
            "{place}: only one lockdown — one `load_levels` entry with `lockdown`, or the `lockdown` block"
        ));
    }
    if let Some(LockdownSpec::Rules { refuse, .. }) =
        cfg.load_levels.iter().find_map(|l| l.lockdown.as_ref())
    {
        if refuse.is_empty() {
            return Err(format!("{place}: a lockdown `refuse` list is empty"));
        }
    }
    if let Some(l) = &cfg.lockdown {
        if l.request == 0 || !(1..=60).contains(&l.period) {
            return Err(format!(
                "{place}: `lockdown` needs `request` ≥ 1 and `period` between 1 and 60 seconds"
            ));
        }
        if l.refuse.is_empty() {
            return Err(format!(
                "{place}: `lockdown.refuse` is empty — remove `lockdown` instead"
            ));
        }
    }
    if let Some(g) = &cfg.gpu_check {
        if !(16..=31).contains(&g.bits) {
            return Err(format!(
                "{place}: `gpu_check.bits` must be between 16 and 31"
            ));
        }
        for l in &g.software_levels {
            if l.request == 0 || !(1..=60).contains(&l.period) {
                return Err(format!(
                    "{place}: a `software_levels` entry needs `request` ≥ 1 and `period` between 1 and 60 seconds"
                ));
            }
            if l.on_software.is_none() && l.software_extra.is_none() {
                return Err(format!(
                    "{place}: a `software_levels` entry needs `on_software`, `software_extra`, or both"
                ));
            }
            if l.software_extra.is_some_and(|x| !(1..=4).contains(&x)) {
                return Err(format!(
                    "{place}: a `software_levels` software_extra must be between 1 and 4"
                ));
            }
        }
        if !(1..=4).contains(&g.software_extra) {
            return Err(format!(
                "{place}: `gpu_check.software_extra` must be between 1 and 4"
            ));
        }
        if !(0.2..=30.0).contains(&g.budget) || !(0.05..=30.0).contains(&g.hardware_under) {
            return Err(format!(
                "{place}: `gpu_check.budget` and `hardware_under` must be between 0.2 and 30 seconds"
            ));
        }
    }
    if !(0.01..=5.0).contains(&cfg.dns_timeout) {
        return Err(format!(
            "{place}: `dns_timeout` must be between 10ms and 5s"
        ));
    }
    if !(10..=3600).contains(&cfg.key_ttl) {
        return Err(format!(
            "{place}: `key_ttl` must be between 10 and 3600 seconds"
        ));
    }
    if let Some(b) = &cfg.ban {
        if let Some(export) = &b.export {
            let dir = std::path::Path::new(export)
                .parent()
                .filter(|d| !d.as_os_str().is_empty());
            if dir.is_some_and(|d| !d.is_dir()) {
                return Err(format!(
                    "{place}: the directory of `ban.export` {export} does not exist"
                ));
            }
        }
        if let Some(store) = &b.store {
            let dir = std::path::Path::new(store)
                .parent()
                .filter(|d| !d.as_os_str().is_empty());
            if dir.is_some_and(|d| !d.is_dir()) {
                return Err(format!(
                    "{place}: the directory of `ban.store` {store} does not exist"
                ));
            }
        }
        if b.after == 0 || b.period == 0 || b.duration == 0 {
            return Err(format!(
                "{place}: `ban` needs `after`, `period` and `duration` of at least 1"
            ));
        }
    }
    if cfg
        .detection_log
        .as_deref()
        .is_some_and(|p| p.trim().is_empty())
    {
        return Err(format!("{place}: `detection_log` is empty"));
    }
    if let Some(r) = cfg.request {
        if r == 0 || !(1..=60).contains(&cfg.period) {
            return Err(format!(
                "{place}: the activation threshold needs `request` ≥ 1 and `period` between 1 and 60 seconds"
            ));
        }
    }
    for l in &cfg.load_levels {
        if l.difficulty.is_some_and(|d| !d_ok(d)) {
            return Err(format!(
                "{place}: a `load_levels` difficulty must be between 1 and {MAX_DIFFICULTY}"
            ));
        }
        if l.cookie_ttl.is_some_and(|t| t < 60) {
            return Err(format!(
                "{place}: a `load_levels` cookie_time_challenge must be at least 60 seconds"
            ));
        }
        if (l.on_software.is_some()
            || l.software_extra.is_some()
            || l.count == LevelCount::Software)
            && cfg.gpu_check.is_none()
        {
            return Err(format!(
                "{place}: a `load_levels` entry with `on_software`, `software_extra` or `count: software` needs `gpu_check`"
            ));
        }
        if l.software_extra.is_some_and(|x| !(1..=4).contains(&x)) {
            return Err(format!(
                "{place}: a `load_levels` software_extra must be between 1 and 4"
            ));
        }
        if l.difficulty.is_none()
            && l.cookie_ttl.is_none()
            && l.client_cores.is_none()
            && l.lockdown.is_none()
            && l.on_software.is_none()
            && l.software_extra.is_none()
        {
            return Err(format!(
                "{place}: a `load_levels` entry needs a `difficulty`, a `cookie_time_challenge`, a `client_cores`, a `lockdown`, an `on_software` or a `software_extra`"
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
    let mut writers: std::collections::HashMap<String, std::sync::mpsc::Sender<String>> =
        std::collections::HashMap::new();
    let mut detectors: Vec<Arc<Detector>> = Vec::new();
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
        let max_d = cfg
            .random_difficulty
            .iter()
            .copied()
            .chain([cfg.difficulty])
            .chain(cfg.load_levels.iter().filter_map(|l| l.difficulty))
            .max()
            .unwrap_or(cfg.difficulty);
        if max_d >= 9 {
            // ~20 millions de SHA-256 par seconde sur un PC à 8 cœurs.
            let secs = expected_hashes(max_d) / 20_000_000.0;
            let human = if secs < 3600.0 * 24.0 {
                format!("{:.0} minutes", secs / 60.0)
            } else if secs < 3600.0 * 24.0 * 365.0 {
                format!("{:.0} days", secs / 86400.0)
            } else {
                format!("{:.1e} years", secs / (86400.0 * 365.0))
            };
            let warn = format!(
                "warning: antibot {label}: difficulty {max_d} means ~{:.1e} hashes, about {human} for an 8-core PC — visitors will not get through",
                expected_hashes(max_d)
            );
            eprintln!("{warn}");
            tracing::warn!("{warn}");
        }
        summary.push(format!(
            "antibot {label}: {}difficulty {diffs}, {}, start {}–{}s{}{}{}, load levels [{}], pass {}s{}{}",
            match cfg.request {
                Some(r) => format!("active above {r} req / {}s (hold {}s), ", cfg.period, cfg.hold),
                None => "always active, ".to_string(),
            } + &cfg
                .lockdown
                .clone()
                .or_else(|| cfg.load_levels.iter().find_map(LoadLevel::lockdown_config))
                .map(|l| format!("lockdown above {} req / {}s, ", l.request, l.period))
                .unwrap_or_default(),
            algs.join("/"),
            cfg.min_start,
            cfg.max_start.max(cfg.min_start),
            if cfg.webgl { ", webgl" } else { "" },
            if cfg.reject_headless { ", no headless" } else { "" },
            if cfg.static_page.is_some() { ", custom page" } else { "" },
            cfg.load_levels
                .iter()
                .map(|l| format!(
                    "≥{}/{}s:{}{}",
                    l.request,
                    l.period,
                    l.difficulty.map(|d| format!(" d{d}")).unwrap_or_default(),
                    l.cookie_ttl.map(|t| format!(" pass {t}s")).unwrap_or_default()
                ))
                .collect::<Vec<_>>()
                .join(", "),
            cfg.cookie_ttl,
            cfg.detection_log.as_ref().map(|p| format!(", log {p}")).unwrap_or_default()
                + &if cfg.hostname_nofiltered.is_empty() {
                    String::new()
                } else {
                    format!(
                        ", hostnames never challenged: {}{}",
                        cfg.hostname_nofiltered.join(" "),
                        cfg.hostname_check_limit
                            .as_ref()
                            .map(|l| format!(" (check off above {} req / {}s)", l.request, l.period))
                            .unwrap_or_default()
                    )
                },
            cfg.ban
                .as_ref()
                .map(|b| format!(", ban after {} detections / {}s for {}s", b.after, b.period, b.duration))
                .unwrap_or_default()
        ));
        if let Some(path) = &cfg.detection_log {
            // Le dossier doit exister ; le fichier, lui, est créé au besoin.
            let dir = std::path::Path::new(path)
                .parent()
                .filter(|d| !d.as_os_str().is_empty());
            if let Some(d) = dir {
                if !d.is_dir() {
                    return Err(format!(
                        "{place}: the directory of `detection_log` {path} does not exist"
                    ));
                }
            }
        }
        let detector = Arc::new(Detector {
            label: label.clone(),
            log: cfg.detection_log.as_ref().map(|p| {
                Mutex::new(
                    writers
                        .entry(p.clone())
                        .or_insert_with(|| csv_writer(p.clone()))
                        .clone(),
                )
            }),
            ban: cfg.ban.clone(),
            offenders: dashmap::DashMap::new(),
            recent: dashmap::DashMap::new(),
        });
        detectors.push(detector.clone());
        let traffic = Arc::new(Traffic::new());
        let rule = Arc::new(Rule {
            cfg: cfg.clone(),
            exclude,
            nofiltered,
            traffic: traffic.clone(),
            page,
            active_until: std::sync::atomic::AtomicU64::new(0),
            detector,
            challenged: dashmap::DashMap::new(),
            hostname_off: std::sync::atomic::AtomicBool::new(false),
            software: cfg
                .gpu_check
                .clone()
                .map(|g| Arc::new(SoftwareGuard::new(g, &cfg.load_levels, traffic.clone()))),
            lockdown: cfg
                .lockdown
                .clone()
                .or_else(|| cfg.load_levels.iter().find_map(LoadLevel::lockdown_config))
                .map(|l| Arc::new(LockdownState::new(l))),
        });
        shared.insert(scope, rule.clone());
        by_route.push(Some(rule));
    }
    // Bannissements gardés d'un démarrage à l'autre (`ban.store`).
    let mut stores: Vec<String> = detectors
        .iter()
        .filter_map(|d| d.ban.as_ref().and_then(|b| b.store.clone()))
        .collect();
    stores.sort();
    stores.dedup();
    for path in &stores {
        let ds: Vec<Arc<Detector>> = detectors
            .iter()
            .filter(|d| d.ban.as_ref().and_then(|b| b.store.as_deref()) == Some(path.as_str()))
            .cloned()
            .collect();
        let (banned, counting) = load_store(path, &ds);
        summary.push(format!(
            "antibot ban store {path}: {banned} banned, {counting} being counted, restored"
        ));
    }
    if detectors
        .iter()
        .any(|d| d.ban.as_ref().is_some_and(|b| b.export.is_some()))
    {
        let _ = std::thread::Builder::new()
            .name("antibot-export".into())
            .spawn(|| {
                loop {
                    // Une IP bannie apparaît dans les 5 s ; un bannissement expiré
                    // ou levé en sort de même.
                    std::thread::sleep(Duration::from_secs(5));
                    write_exports();
                }
            });
    }
    if detectors.iter().any(|d| d.ban.is_some()) {
        let with_store = !stores.is_empty();
        let _ = std::thread::Builder::new()
            .name("antibot-purge".into())
            .spawn(move || {
                let mut tick = 0u64;
                loop {
                    std::thread::sleep(Duration::from_secs(30));
                    tick += 1;
                    if tick % 2 == 0 {
                        let sec = now_ms() / 1000;
                        for d in &detectors {
                            d.purge(sec);
                        }
                    }
                    if with_store {
                        save_all_stores();
                    }
                }
            });
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
#[cfg_attr(not(test), allow(dead_code))]
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
        "microsoft basic render",
        "warp",
    ]
    .iter()
    .any(|s| r.contains(s))
}

/// `émission.expiration.MAC` : l'heure d'émission permet de redéfier,
/// sous charge, les laissez-passer plus anciens que le palier le permet.
fn pass_cookie(key: &[u8; 32], issued: u64, expires: u64, ua: &str) -> String {
    format!(
        "{issued}.{expires}.{}",
        mac(key, &format!("pass|{issued}|{expires}|{ua}"))
    )
}

/// Heure d'émission du laissez-passer s'il est valide pour ce navigateur.
pub fn pass_issued(key: &[u8; 32], value: &str, ua: &str) -> Option<u64> {
    match pass_state(key, value, ua) {
        PassState::Valid(issued) => Some(issued),
        _ => None,
    }
}

/// État d'un cookie de laissez-passer présenté.
#[derive(Debug, PartialEq, Eq)]
pub enum PassState {
    /// Signature correcte et pas expiré : émis à cette date.
    Valid(u64),
    /// Signature correcte mais expiré : un visiteur dont le laissez-passer
    /// est simplement arrivé à échéance — pas une détection.
    Expired,
    /// Format inconnu (ancienne version de ProxyAuth, cookie tronqué) — pas
    /// une détection non plus.
    Malformed,
    /// Bien formé mais signature fausse : falsifié, ou copié d'un autre
    /// navigateur. Seul cas suspect.
    Forged,
}

pub fn pass_state(key: &[u8; 32], value: &str, ua: &str) -> PassState {
    let mut it = value.splitn(3, '.');
    let (Some(i), Some(e), Some(sig)) = (it.next(), it.next(), it.next()) else {
        return PassState::Malformed;
    };
    let (Ok(issued), Ok(expires)) = (i.parse::<u64>(), e.parse::<u64>()) else {
        return PassState::Malformed;
    };
    if sig.len() != 64 {
        return PassState::Malformed;
    }
    if !ct_eq(sig, &mac(key, &format!("pass|{issued}|{expires}|{ua}"))) {
        return PassState::Forged;
    }
    if expires > now_ms() / 1000 {
        PassState::Valid(issued)
    } else {
        PassState::Expired
    }
}

#[cfg(test)]
pub fn pass_is_valid(key: &[u8; 32], value: &str, ua: &str) -> bool {
    pass_issued(key, value, ua).is_some()
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
        // Tout le trafic du serveur, pour les paliers `scope: server`.
        server_traffic().record(now_ms() / 1000);
        let path = req.path().to_string();
        let host = request_host(req.request());
        if let Some(rest) = path.strip_prefix(GPU_PREFIX) {
            let ip = client_ip(req.request(), &self.state.config)
                .map(|i| i.to_string())
                .unwrap_or_default();
            let ua = user_agent(&req);
            let res = match rest.split_once('/') {
                Some((token, "start")) => match gpu_start(token, &ip, &ua) {
                    Some(json) => HttpResponse::Ok()
                        .insert_header((header::CONTENT_TYPE, "application/json"))
                        .insert_header((header::CACHE_CONTROL, "no-store"))
                        .body(json),
                    None => HttpResponse::NotFound().finish(),
                },
                Some((token, "done")) => match gpu_done(token, &ip, &ua, req.query_string()) {
                    Some(_) => HttpResponse::Ok()
                        .insert_header((header::CONTENT_TYPE, "application/json"))
                        .insert_header((header::CACHE_CONTROL, "no-store"))
                        .body(format!("{{\"extra\":{}}}", gpu_penalty(token))),
                    None => HttpResponse::NotFound().finish(),
                },
                _ => HttpResponse::NotFound().finish(),
            };
            return Box::pin(async move { Ok(req.into_response(res)) });
        }
        if let Some(token) = path
            .strip_prefix(JS_PREFIX)
            .and_then(|t| t.strip_suffix(".js"))
        {
            let ip = client_ip(req.request(), &self.state.config)
                .map(|i| i.to_string())
                .unwrap_or_default();
            let res = match serve_script(token, &ip, &user_agent(&req)) {
                Some(js) => HttpResponse::Ok()
                    .insert_header((
                        header::CONTENT_TYPE,
                        "application/javascript; charset=utf-8",
                    ))
                    .insert_header((header::CACHE_CONTROL, "no-store"))
                    .insert_header(("x-robots-tag", "noindex, nofollow"))
                    .body(js),
                None => HttpResponse::NotFound()
                    .insert_header((header::CACHE_CONTROL, "no-store"))
                    .finish(),
            };
            return Box::pin(async move { Ok(req.into_response(res)) });
        }
        if path == PASS_PATH {
            let res = verify_pass(reg, &req, &self.state, host.as_deref());
            return Box::pin(async move { Ok(req.into_response(res)) });
        }
        let Some(rule) = resolve(reg, &self.state.routes.routes, &path, host.as_deref()) else {
            return next.call(req);
        };
        // Le trafic du vhost, pour le seuil et `load_levels` : toutes les
        // requêtes comptent, défiées ou non — une attaque bloquée par le
        // défi maintient donc le seuil atteint.
        let sec = now_ms() / 1000;
        rule.traffic.record(sec);
        if path.starts_with("/.well-known/acme-challenge/") {
            return next.call(req);
        }
        let ip = client_ip(req.request(), &self.state.config);
        let ua = user_agent(&req);
        let host_s = host.clone().unwrap_or_default();
        let bypass = |why: &str| {
            if rule.cfg.log_bypass {
                rule.detector.bypass(sec, &host_s, ip, &ua, why, &path);
            }
        };
        if ip.is_some_and(|ip| rule.nofiltered.iter().any(|n| n.contains(&ip))) {
            bypass("address in ip_nofiltered");
            return next.call(req);
        }
        // Une adresse bannie est bloquée sur tout le vhost, que le défi
        // soit actif ou non.
        if let Some(until) = ip.and_then(|ip| rule.detector.banned_until(ip, sec)) {
            let lang = rule.cfg.language;
            return Box::pin(
                async move { Ok(req.into_response(banned_response(until - sec, lang))) },
            );
        }
        // Verrouillage : réévalué à chaque requête d'après le trafic compté ;
        // tant qu'il dure, l'anti-bot est actif quel que soit son seuil.
        let lockdown = rule.lockdown.as_ref().map(|l| {
            l.update(sec, &rule.traffic, rule.software.as_ref().map(|g| &g.seen));
            l
        });
        let locked = |r| lockdown.is_some_and(|l| l.refuses(sec, r));
        if !rule.active(sec) && !lockdown.is_some_and(|l| l.active(sec)) {
            bypass("below the activation threshold (request / period)");
            return next.call(req);
        }

        if path.starts_with("/.well-known/") || path == "/robots.txt" || path == "/favicon.ico" {
            return next.call(req);
        }
        if rule.exclude.iter().any(|re| re.is_match(&path)) {
            bypass("excluded path (exclude)");
            return next.call(req);
        }
        if rule.cfg.trust_authorization && req.headers().contains_key(header::AUTHORIZATION) {
            bypass("Authorization header (trust_authorization)");
            return next.call(req);
        }
        if !ua.contains("Mozilla") && locked(LockdownRule::NonBrowsers) {
            rule.detector.note(
                &host_s,
                ip,
                &ua,
                "non-browser client refused during lockdown",
                &path,
            );
            return Box::pin(async move {
                Ok(req.into_response(
                    HttpResponse::ServiceUnavailable()
                        .insert_header((header::RETRY_AFTER, "120"))
                        .insert_header((header::CACHE_CONTROL, "no-store"))
                        .insert_header(("x-antibot-reason", "lockdown"))
                        .finish(),
                ))
            });
        }
        if rule.cfg.only_browsers && !ua.contains("Mozilla") {
            bypass("User-Agent is not a browser (only_browsers)");
            return next.call(req);
        }
        // Laissez-passer valide, et pas plus ancien que ce que le palier de
        // charge actuel admet.
        if req
            .cookie(COOKIE)
            .and_then(|c| pass_issued(&reg.key, c.value(), &ua))
            .is_some_and(|issued| {
                sec.saturating_sub(issued) <= rule.pass_max_age(sec)
                    // Verrouillage : seuls les laissez-passer obtenus depuis.
                    && !(locked(LockdownRule::OldPasses)
                        && lockdown.is_some_and(|l| issued <= l.started.load(std::sync::atomic::Ordering::Relaxed)))
            })
        {
            return next.call(req);
        }
        // Robots identifiés par leur nom d'hôte (DNS inverse confirmé) :
        // résolution seulement maintenant, quand le client allait être
        // défié — jamais pour les requêtes qui passent déjà.
        // Coupée au-delà de `hostname_check_limit` : plus de DNS du tout.
        if !rule.cfg.hostname_nofiltered.is_empty()
            && rule.hostname_check_enabled(sec)
            && !locked(LockdownRule::Crawlers)
        {
            if let Some(addr) = ip {
                return Box::pin(async move {
                    let wait = Duration::from_secs_f64(rule.cfg.dns_timeout);
                    if let Some(name) =
                        hostname_allowed(addr, &rule.cfg.hostname_nofiltered, wait).await
                    {
                        if rule.cfg.log_bypass {
                            rule.detector.bypass(
                                sec,
                                &host_s,
                                ip,
                                &ua,
                                &format!("verified hostname {name}"),
                                &path,
                            );
                        }
                        tracing::debug!(client_ip = %addr, hostname = %name, "antibot: verified hostname, not challenged");
                        return next.call(req).await;
                    }
                    let res = challenge_or_refuse(reg, rule, sec, &host_s, ip, &ua, &path, &req);
                    Ok(req.into_response(res))
                });
            }
        }
        let res = challenge_or_refuse(reg, rule, sec, &host_s, ip, &ua, &path, &req);
        Box::pin(async move { Ok(req.into_response(res)) })
    }
}

/// Défi (GET/HEAD) ou refus (autres méthodes), avec les détections.
#[allow(clippy::too_many_arguments)]
fn challenge_or_refuse(
    reg: &'static Registry,
    rule: &'static Rule,
    sec: u64,
    host_s: &str,
    ip: Option<IpAddr>,
    ua: &str,
    path: &str,
    req: &ServiceRequest,
) -> HttpResponse {
    let method = req.method().clone();
    let h = |n: &str| {
        req.headers()
            .get(n)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
    };
    // Requête d'arrière-plan d'une page déjà ouverte (fetch, XHR, image…)
    // par un vrai navigateur : ses en-têtes `Sec-Fetch-*` le disent. Elle
    // reçoit un 403 sans page de défi — qu'en ferait un script ? — et
    // **sans détection** : c'est typiquement un onglet ouvert avant que le
    // laissez-passer n'expire (une page Forgejo qui interroge le serveur
    // toutes les dix secondes), pas un robot.
    let fetch_mode = h("sec-fetch-mode");
    let same_site = matches!(h("sec-fetch-site"), "same-origin" | "same-site");
    let background = !fetch_mode.is_empty() && fetch_mode != "navigate";
    let cookie = req.cookie(COOKIE);
    let state = cookie.as_ref().map(|c| pass_state(&reg.key, c.value(), ua));
    if state == Some(PassState::Forged) {
        // Journalisé, mais pas compté pour le bannissement : une mise à
        // jour du navigateur change son User-Agent et invalide ainsi un
        // laissez-passer authentique. Un faux cookie ne donne de toute façon
        // aucun accès.
        rule.detector.note(
            host_s,
            ip,
            ua,
            "pass cookie not valid for this browser (forged, or the browser was updated)",
            path,
        );
    }

    if background || (method != hyper::Method::GET && method != hyper::Method::HEAD) {
        // Une navigation non-GET (formulaire envoyé sans jamais être passé
        // par la vérification) reste une détection, sauf si elle vient
        // d'une page du site ouverte avant expiration du laissez-passer.
        let browser_background = background || same_site;
        if !browser_background {
            rule.detector.detect(
                sec,
                host_s,
                ip,
                ua,
                &format!("{method} request without a pass"),
                path,
            );
        }
        return HttpResponse::Forbidden()
            .insert_header((header::CONTENT_TYPE, "application/json"))
            .insert_header((header::CACHE_CONTROL, "no-store"))
            .body(r#"{"error":"antibot_challenge_required","message":"Reload the page to pass the browser check again."}"#);
    }

    // Navigation : la page de défi. Ne compte comme détection que le
    // navigateur qui la redemande après le délai de grâce sans l'avoir
    // résolue — pas un laissez-passer expiré, ni des onglets ouverts en
    // même temps.
    if state.is_none() && ip.is_some_and(|ip| rule.challenged_recently(ip, ua, sec)) {
        rule.detector.detect(
            sec,
            host_s,
            ip,
            ua,
            "challenge requested again without being solved",
            path,
        );
    }
    let ip_s = ip.map(|i| i.to_string()).unwrap_or_default();
    challenge_page(reg, rule, &ip_s, ua, req)
}

fn verify_pass(
    reg: &'static Registry,
    req: &ServiceRequest,
    state: &web::Data<AppState>,
    host: Option<&str>,
) -> HttpResponse {
    let ip_addr = client_ip(req.request(), &state.config);
    let ip = ip_addr.map(|i| i.to_string()).unwrap_or_default();
    let ua = user_agent(req);
    // La solution arrive chiffrée avec la clé de cette vérification ; une
    // fois déchiffrée, elle se lit comme une chaîne de requête.
    let decrypted = take_solution(req.query_string(), &ip, &ua);
    let q_owned = decrypted.clone().unwrap_or_default();
    let q = q_owned.as_str();
    let redirect = safe_redirect(&query_param(q, "redir").unwrap_or_default());
    // La règle du vhost, pour journaliser et bannir.
    let rule = resolve(reg, &state.routes.routes, &redirect, host)
        .or_else(|| resolve(reg, &state.routes.routes, "/", host));
    let sec = now_ms() / 1000;
    if let Some(until) = rule
        .zip(ip_addr)
        .and_then(|(r, ip)| r.detector.banned_until(ip, sec))
    {
        return banned_response(
            until - sec,
            rule.map(|r| r.cfg.language).unwrap_or_default(),
        );
    }

    // Résultat : (ttl, horodatage du défi, bits exigés).
    let outcome = (|| -> Result<(u64, u64, u32), &'static str> {
        decrypted.as_ref().map_err(|e| *e)?;
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
        if !(1..=MAX_DIFFICULTY).contains(&d)
            || ts > t + 60_000
            || t.saturating_sub(ts) > CHALLENGE_MAX_AGE_MS
        {
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
        // Difficulté de base (4 bits par cran), plus les bits du nombre de
        // workers annoncé. Annoncer moins de workers n'abaisse jamais sous
        // la base : un client qui ment ne gagne rien sur `difficulty`.
        let workers: u32 = query_param(q, "wk")
            .and_then(|v| v.parse().ok())
            .unwrap_or(1);
        let extra = if flags & FLAG_SCALE_WORKERS != 0 {
            worker_bits(workers)
        } else {
            0
        };
        // `on_software: harder` : bits fixés par le serveur à la fin de
        // l'épreuve GPU, jamais par le client.
        let penalty: u32 = query_param(q, "gpu_penalty_bits")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        if !meets_bits(&hash, 4 * u32::from(d) + extra + penalty) {
            return Err("proof of work not met");
        }
        // Mode décidé par le serveur à la fin de l'épreuve GPU (paliers
        // compris) ; un client qui a sauté l'épreuve reçoit celui du moment.
        let decision = query_param(q, "gpu_decision").and_then(|d| OnSoftware::parse(&d));
        let decision = decision.or_else(|| {
            rule.and_then(|r| r.software.as_ref())
                .map(|g| g.decision(now_ms() / 1000).0)
        });
        if decision == Some(OnSoftware::Refuse) && no_hardware_gpu(&effective_gpu_class(q)) {
            return Err("no hardware GPU (gpu_check)");
        }
        Ok((ttl, ts, 4 * u32::from(d) + extra + penalty))
    })();

    match outcome {
        Ok((ttl, ts, bits)) => {
            let issued = now_ms() / 1000;
            let expires = issued + ttl;
            let cookie = format!(
                "{COOKIE}={}; Path=/; Max-Age={ttl}; HttpOnly; SameSite=Lax{}",
                pass_cookie(&reg.key, issued, expires, &ua),
                if req.app_config().secure() {
                    "; Secure"
                } else {
                    ""
                }
            );
            let mut info = ClientInfo::from_query(q);
            // Un rendu logiciel annoncé par le navigateur lui-même (WebGL ou
            // WebGPU) n'est jamais un vrai GPU, quel que soit le temps.
            if matches!(info.gpu_check.as_str(), "hardware" | "slow")
                && (software_renderer(&info.renderer) || software_renderer(&info.gpu_adapter))
            {
                info.gpu_check = "software".into();
            }
            let server_ms = now_ms().saturating_sub(ts);
            info.bits = bits.to_string();
            info.server_ms = server_ms.to_string();
            tracing::info!(
                client_ip = %ip,
                difficulty = %info.difficulty,
                bits = bits,
                algorithm = %info.algorithm,
                workers = %info.workers,
                solve_ms = %info.solve_ms,
                server_ms = server_ms,
                gpu_check = %info.gpu_check,
                gpu_ms = %info.gpu_ms,
                "antibot: challenge solved in {} ms (browser) / {server_ms} ms (server), pass issued for {ttl}s",
                if info.solve_ms.is_empty() { "?" } else { info.solve_ms.as_str() }
            );
            if let Some(r) = rule {
                let detect = query_param(q, "gpu_decision").as_deref() == Some("detect");
                if r.cfg.gpu_check.is_some() && detect && no_hardware_gpu(&info.gpu_check) {
                    r.detector.detect(
                        sec,
                        host.unwrap_or(""),
                        ip_addr,
                        &ua,
                        &format!("no hardware GPU (gpu_check: {})", info.gpu_check),
                        &redirect,
                    );
                }
            }
            if let Some(r) = rule.filter(|r| r.cfg.log_passes) {
                r.detector
                    .passed(host.unwrap_or(""), &ip, &ua, &redirect, &info);
            }
            HttpResponse::Found()
                .insert_header((header::LOCATION, redirect))
                .insert_header((header::SET_COOKIE, cookie))
                .insert_header((header::CACHE_CONTROL, "no-store"))
                .finish()
        }
        Err(reason) => {
            tracing::warn!(client_ip = %ip, user_agent = %ua, reason = reason, "antibot: solution refused");
            if let Some(r) = rule {
                r.detector.detect_with(
                    sec,
                    host.unwrap_or(""),
                    ip_addr,
                    &ua,
                    reason,
                    &redirect,
                    &ClientInfo::from_query(q),
                );
            }
            let t = rule.map(|r| r.cfg.language).unwrap_or_default().texts();
            HttpResponse::Forbidden()
                .insert_header((header::CONTENT_TYPE, "text/html; charset=utf-8"))
                .insert_header((header::CACHE_CONTROL, "no-store"))
                .insert_header(("x-antibot-reason", reason))
                .body(format!(
                    "<!doctype html><html lang=\"{}\"><meta charset=utf-8><title>{}</title>\
                     <body style=\"font-family:system-ui;max-width:32rem;margin:4rem auto;padding:0 1rem\">\
                     <h1>{}</h1><p>{}</p><p><a href=\"{}\">{}</a></p>",
                    t.html_lang,
                    t.failed_title,
                    t.failed_title,
                    t.failed_body,
                    crate::network::proxy::html_escape(&redirect),
                    t.retry
                ))
        }
    }
}

/// Réponse à une adresse bannie.
fn banned_response(retry_after: u64, lang: Language) -> HttpResponse {
    let t = lang.texts();
    HttpResponse::Forbidden()
        .insert_header((header::CONTENT_TYPE, "text/html; charset=utf-8"))
        .insert_header((header::CACHE_CONTROL, "no-store"))
        .insert_header((header::RETRY_AFTER, retry_after.to_string()))
        .insert_header(("x-antibot-reason", "address banned"))
        .body(format!(
            "<!doctype html><html lang=\"{}\"><meta charset=utf-8><title>{}</title>\
             <body style=\"font-family:system-ui;max-width:32rem;margin:4rem auto;padding:0 1rem\">\
             <h1>{}</h1><p>{}</p>",
            t.html_lang, t.banned_title, t.banned_title, t.banned_body
        ))
}

fn challenge_page(
    reg: &'static Registry,
    rule: &Rule,
    ip: &str,
    ua: &str,
    req: &ServiceRequest,
) -> HttpResponse {
    let ts = now_ms();
    let t = rule.cfg.language.texts();
    let (d, alg, start_ms) = rule.draw(ts / 1000);
    let flags = rule.flags_at(ts / 1000);
    // Sous charge, un laissez-passer plus court (palier `cookie_time_challenge`).
    let ttl = rule.pass_max_age(ts / 1000);
    let challenge = challenge_for(&reg.key, ts, d, alg, ttl, start_ms, flags, ip, ua);
    let redir = match req.query_string() {
        "" => req.path().to_string(),
        q => format!("{}?{q}", req.path()),
    };
    let params = serde_json::json!({
        "challenge": challenge, "ts": ts, "d": d, "a": alg.name(), "algo": alg.webcrypto(),
        "single": alg.single_thread(), "cores": rule.client_cores(ts / 1000).divisor(), "scale": flags & FLAG_SCALE_WORKERS != 0, "ttl": ttl, "s": start_ms, "f": flags,
        "webgl": flags & FLAG_WEBGL != 0, "redir": redir, "pass": PASS_PATH,
        "gpu": rule.cfg.gpu_check.as_ref().map(|g| serde_json::json!({ "mode": g.mode.name(), "budget": (g.budget * 1000.0) as u64 })),
        "t": {
            "need_https": t.need_https, "need_webgl": t.need_webgl, "starting": t.starting,
            "running": t.running, "core": t.core, "cores": t.cores, "done": t.done,
            "worker_failed": t.worker_failed, "gpu": t.gpu,
        },
    });
    let params = params.to_string().replace("</", "<\\/");
    // Clé AES et script propres à cette page : le script est servi une
    // seule fois, à une URL que seule cette page connaît.
    let (token, _key) = register_pending_full(
        params,
        ip,
        ua,
        rule.cfg.key_ttl,
        rule.software.as_ref(),
        rule.lockdown.as_ref(),
    );
    let script = SCRIPT_HTML
        .replace("__PREPARING__", t.preparing)
        .replace("__NOSCRIPT__", t.noscript)
        .replace("__SRC__", &format!("{JS_PREFIX}{token}.js"));
    let body = rule
        .page
        .html()
        .replace("{{ script }}", &script)
        .replace("{{script}}", &script)
        .replace("{{ title }}", t.title)
        .replace("{{title}}", t.title)
        .replace("{{ description }}", t.description)
        .replace("{{description}}", t.description)
        .replace("{{ lang }}", t.html_lang)
        .replace("{{lang}}", t.html_lang);
    let mut res = HttpResponse::Ok()
        .insert_header((header::CONTENT_TYPE, "text/html; charset=utf-8"))
        .insert_header((header::CACHE_CONTROL, "no-store"))
        .insert_header(("x-robots-tag", "noindex, nofollow"))
        .body(body);
    res.headers_mut()
        .insert("x-proxyauth-antibot", HeaderValue::from_static("challenge"));
    res
}

/// Ce que `{{ script }}` insère : l'état, la barre de progression et le
/// script (WebGL, compte à rebours, calcul réparti sur les cœurs).
const SCRIPT_HTML: &str = r##"<div class="centered-div" id="pa-antibot">
  <p id="status">__PREPARING__</p>
  <div id="progress" style="display:block"><div class="bar-inner" id="pa-fill"></div></div>
  <p id="pa-stats" style="font:12px/1.4 monospace;opacity:.75;margin:0">&nbsp;</p>
  <noscript><p class="error-code">__NOSCRIPT__</p></noscript>
</div>
<script src="__SRC__"></script>"##;

/// Le script de la vérification, servi une seule fois à
/// `/.proxyauth/antibot/js/<jeton>.js` : version minifiée, sans aucun
/// commentaire, de `antibot_js/challenge.js` (`tools/minify-antibot-js.sh`
/// la régénère après une modification de la source).
const MAIN_JS: &str = include_str!("antibot_js/challenge.min.js");

/// La recherche de nonce, exécutée dans les Web Workers : version minifiée
/// de `antibot_js/worker.js`.
const WORKER_JS: &str = include_str!("antibot_js/worker.min.js");

/// Page par défaut, au style de ProxyAuth. `{{ title }}` et `{{ script }}`
/// sont remplacés à chaque envoi.
const DEFAULT_PAGE: &str = r##"<!DOCTYPE html>
<html lang="{{ lang }}">
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
      <p class="description">{{ description }}</p>
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
    fn difficulties_up_to_twenty() {
        let mut h = [0u8; 32];
        h[10] = 0x10;
        assert!(meets_difficulty(&h, 20), "80 bits of zeros");
        h[9] = 0x01;
        assert!(!meets_difficulty(&h, 20));
        // Byte 9 = 0x01: the 19th hex digit is still 0, the 20th is not.
        assert!(meets_difficulty(&h, 19));
        let c: AntiBotConfig = serde_yaml::from_str("{ difficulty: 20 }").unwrap();
        validate(&c, "t").unwrap();
        let c: AntiBotConfig = serde_yaml::from_str("{ difficulty: 21 }").unwrap();
        assert!(validate(&c, "t").is_err());
        assert_eq!(expected_hashes(6), 16_777_216.0);
    }

    #[test]
    fn difficulty_scales_with_workers() {
        assert_eq!(
            [1, 2, 3, 4, 8, 16, 64, 1000].map(worker_bits),
            [0, 1, 1, 2, 3, 4, 6, 8]
        );
        // Bits generalise hex digits: 4 bits per digit.
        let mut h = [0u8; 32];
        h[2] = 0x0f;
        assert!(meets_bits(&h, 20) && !meets_bits(&h, 21));
        assert_eq!(meets_bits(&h, 16), meets_difficulty(&h, 4));
        // A real solution at 4 hex digits + 3 bits (8 workers).
        let c = challenge_for(
            &KEY,
            1,
            2,
            Algorithm::Fast,
            60,
            0,
            FLAG_SCALE_WORKERS,
            "ip",
            "ua",
        );
        let bits = 4 * 2 + worker_bits(8);
        let n = (0u64..)
            .find(|n| meets_bits(&Algorithm::Fast.digest(format!("{c}{n}").as_bytes()), bits))
            .unwrap();
        assert!(
            meets_bits(&Algorithm::Fast.digest(format!("{c}{n}").as_bytes()), 4 * 2),
            "also meets the base"
        );
        let c: AntiBotConfig = serde_yaml::from_str("{}").unwrap();
        assert!(c.scale_with_workers, "on by default");
    }

    #[test]
    fn per_challenge_key_script_once_solution_once() {
        use base64::Engine;
        use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
        let (token, key) = register_pending("{\"a\":1}".into(), "203.0.113.9", "UA", 120);
        // The script: once, to the same client only.
        assert!(
            serve_script(&token, "198.51.100.1", "UA").is_none(),
            "another address"
        );
        let js = serve_script(&token, "203.0.113.9", "UA").expect("served");
        assert!(js.contains(&token) && js.contains("{\"a\":1}") && !js.contains("__KEY__"));
        assert!(
            serve_script(&token, "203.0.113.9", "UA").is_none(),
            "served only once"
        );
        // Seal like the browser does: AES-256-GCM, token as associated data.
        let seal = |key: &[u8; 32], text: &str| {
            let k = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key).unwrap());
            let iv = [7u8; 12];
            let mut buf = text.as_bytes().to_vec();
            k.seal_in_place_append_tag(
                Nonce::assume_unique_for_key(iv),
                Aad::from(token.as_bytes()),
                &mut buf,
            )
            .unwrap();
            let b = base64::engine::general_purpose::URL_SAFE_NO_PAD;
            (b.encode(iv), b.encode(buf))
        };
        let (iv, c) = seal(&key, r#"{"nonce":"42","redir":"/a b"}"#);
        let q = format!("t={token}&iv={iv}&c={c}");
        assert_eq!(
            take_solution(&q, "203.0.113.9", "UA").unwrap(),
            "nonce=42&redir=%2Fa%20b"
        );
        assert_eq!(
            take_solution(&q, "203.0.113.9", "UA").unwrap_err(),
            "unknown or already used challenge key",
            "single use"
        );
        // Wrong key, plaintext, script never loaded.
        let (token2, _) = register_pending("{}".into(), "ip", "UA", 120);
        serve_script(&token2, "ip", "UA").unwrap();
        let (iv, c) = seal(&[1; 32], "{}");
        assert_eq!(
            take_solution(&format!("t={token2}&iv={iv}&c={c}"), "ip", "UA").unwrap_err(),
            "solution could not be decrypted"
        );
        assert_eq!(
            take_solution("nonce=1&challenge=x", "ip", "UA").unwrap_err(),
            "unencrypted solution"
        );
        let (token3, _) = register_pending("{}".into(), "ip", "UA", 120);
        assert_eq!(
            take_solution(&format!("t={token3}&iv=x&c=y"), "ip", "UA").unwrap_err(),
            "challenge script was never loaded"
        );
    }

    #[test]
    fn hostname_check_turns_off_under_load() {
        let c: AntiBotConfig = serde_yaml::from_str(
            "{ hostname_nofiltered: [googlebot.com], hostname_check_limit: { request: 10, period: 5 } }",
        )
        .unwrap();
        validate(&c, "t").unwrap();
        let rule = Rule {
            cfg: c,
            exclude: vec![],
            nofiltered: vec![],
            traffic: Arc::new(Traffic::new()),
            page: Arc::new(Page::load(None).unwrap()),
            active_until: std::sync::atomic::AtomicU64::new(0),
            detector: Arc::new(Detector {
                label: String::new(),
                log: None,
                ban: None,
                offenders: dashmap::DashMap::new(),
                recent: dashmap::DashMap::new(),
            }),
            challenged: dashmap::DashMap::new(),
            hostname_off: std::sync::atomic::AtomicBool::new(false),
            software: None,
            lockdown: None,
        };
        assert!(rule.hostname_check_enabled(7000), "quiet: on");
        for _ in 0..10 {
            rule.traffic.record(7000);
        }
        assert!(
            !rule.hostname_check_enabled(7000),
            "10 requests in 5 s: off"
        );
        assert!(rule.hostname_check_enabled(7010), "traffic gone: on again");
        let alias: AntiBotConfig =
            serde_yaml::from_str("{ hostname_disable_above: { request: 5 } }").unwrap();
        assert_eq!(alias.hostname_check_limit.unwrap().period, 10);
        let bad: AntiBotConfig =
            serde_yaml::from_str("{ hostname_check_limit: { request: 0 } }").unwrap();
        assert!(validate(&bad, "t").is_err());
    }

    #[test]
    fn bans_survive_through_the_store() {
        let dir = std::env::temp_dir().join(format!("pa-banstore-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bans.json").display().to_string();
        let ban = BanConfig {
            after: 2,
            period: 60,
            duration: 600,
            store: Some(path.clone()),
            export: None,
        };
        let mk = |label: &str| {
            Arc::new(Detector {
                label: label.into(),
                log: None,
                ban: Some(ban.clone()),
                offenders: dashmap::DashMap::new(),
                recent: dashmap::DashMap::new(),
            })
        };
        let (a, b) = (mk("a.test"), mk("b.test"));
        let sec = now_ms() / 1000;
        let ip1: IpAddr = "203.0.113.9".parse().unwrap();
        let ip2: IpAddr = "198.51.100.7".parse().unwrap();
        a.detect(
            sec,
            "a",
            Some(ip1),
            "ua",
            "POST request without a pass",
            "/",
        );
        a.detect(
            sec,
            "a",
            Some(ip1),
            "ua",
            "POST request without a pass",
            "/",
        );
        b.detect(sec, "b", Some(ip2), "ua", "window of size zero", "/");
        assert_eq!(save_store(&path, &[a.clone(), b.clone()]).unwrap(), 2);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        // "Restart": fresh detectors, same file.
        let (a2, b2) = (mk("a.test"), mk("b.test"));
        assert_eq!(load_store(&path, &[a2.clone(), b2.clone()]), (1, 1));
        let left = a2
            .banned_until(ip1, sec)
            .expect("still banned after the restart");
        assert_eq!(left, a.banned_until(ip1, sec).unwrap(), "same end of ban");
        assert_eq!(
            a2.offenders.get(&ip1).unwrap().ban_reason,
            "POST request without a pass ×2"
        );
        // The counting goes on: one more detection on b bans ip2.
        b2.detect(sec, "b", Some(ip2), "ua", "window of size zero", "/");
        assert!(b2.banned_until(ip2, sec).is_some());
        // Unknown vhosts are skipped; a corrupt file is ignored.
        assert_eq!(load_store(&path, &[mk("other.test")]), (0, 0));
        std::fs::write(&path, b"garbage").unwrap();
        assert_eq!(load_store(&path, &[mk("a.test")]), (0, 0));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_wave_of_software_clients_escalates_then_calms_down() {
        let cfg: AntiBotConfig = serde_yaml::from_str(
            r#"{ gpu_check: { on_software: harder, software_extra: 2, software_hold: 30,
                 software_levels: [ { request: 10, period: 10, software_extra: 3 },
                                    { request: 20, period: 10, on_software: refuse } ] } }"#,
        )
        .unwrap();
        validate(&cfg, "t").unwrap();
        let guard = SoftwareGuard::new(cfg.gpu_check.unwrap(), &[], Arc::new(Traffic::new()));
        assert_eq!(guard.decision(5000), (OnSoftware::Harder, 2), "quiet");
        for _ in 0..10 {
            guard.record(5000);
        }
        assert_eq!(
            guard.decision(5000),
            (OnSoftware::Harder, 3),
            "10 in 10 s: heavier"
        );
        for _ in 0..10 {
            guard.record(5001);
        }
        assert_eq!(
            guard.decision(5001).0,
            OnSoftware::Refuse,
            "20 in 10 s: refuse"
        );
        // The wave stops: still refuse during software_hold, then back.
        assert_eq!(guard.decision(5020).0, OnSoftware::Refuse, "held");
        assert_eq!(
            guard.decision(5032),
            (OnSoftware::Harder, 2),
            "back to normal"
        );
        let bad: AntiBotConfig =
            serde_yaml::from_str("{ gpu_check: { software_levels: [ { request: 5 } ] } }").unwrap();
        assert!(validate(&bad, "t").is_err());
    }

    #[test]
    fn on_software_in_load_levels() {
        let c: AntiBotConfig = serde_yaml::from_str(
            r#"{ gpu_check: { on_software: harder, software_extra: 2, software_hold: 30 },
                 load_levels: [ { request: 10, period: 10, software_extra: 3 },
                                { request: 5, period: 10, count: software, on_software: refuse } ] }"#,
        )
        .unwrap();
        validate(&c, "t").unwrap();
        let requests = Arc::new(Traffic::new());
        let g = SoftwareGuard::new(
            c.gpu_check.clone().unwrap(),
            &c.load_levels,
            requests.clone(),
        );
        assert_eq!(g.decision(9000), (OnSoftware::Harder, 2), "quiet");
        for _ in 0..10 {
            requests.record(9000);
        }
        assert_eq!(
            g.decision(9000),
            (OnSoftware::Harder, 3),
            "10 requests in 10 s: heavier"
        );
        for _ in 0..5 {
            g.record(9001);
        }
        assert_eq!(
            g.decision(9001).0,
            OnSoftware::Refuse,
            "5 clients without a GPU: refuse"
        );
        let bad: AntiBotConfig =
            serde_yaml::from_str("{ load_levels: [ { request: 5, on_software: refuse } ] }")
                .unwrap();
        assert!(validate(&bad, "t").is_err(), "needs gpu_check");
    }

    #[test]
    fn lockdown_as_a_load_level() {
        let c: AntiBotConfig = serde_yaml::from_str(
            r#"{ load_levels: [ { request: 1000, period: 10, difficulty: 6 },
                                { request: 20000, period: 10, lockdown: true } ] }"#,
        )
        .unwrap();
        validate(&c, "t").unwrap();
        let l = c.load_levels[1].lockdown_config().unwrap();
        assert_eq!(
            (l.request, l.period, l.hold, l.refuse.len()),
            (20000, 10, 120, 7)
        );
        assert!(c.load_levels[0].lockdown_config().is_none());
        let c: AntiBotConfig = serde_yaml::from_str(
            "{ load_levels: [ { request: 500, scope: server, lockdown: { hold: 30s, refuse: [non_browsers, headless] } } ] }",
        )
        .unwrap();
        validate(&c, "t").unwrap();
        let l = c.load_levels[0].lockdown_config().unwrap();
        assert_eq!(
            (l.hold, l.scope, l.refuse.clone()),
            (
                30,
                LoadScope::Server,
                vec![LockdownRule::NonBrowsers, LockdownRule::Headless]
            )
        );
        for bad in [
            "{ load_levels: [ { request: 5, lockdown: true }, { request: 9, lockdown: true } ] }",
            "{ lockdown: { request: 5 }, load_levels: [ { request: 9, lockdown: true } ] }",
            "{ load_levels: [ { request: 5, lockdown: { refuse: [] } } ] }",
        ] {
            let c: AntiBotConfig = serde_yaml::from_str(bad).unwrap();
            assert!(validate(&c, "t").is_err(), "{bad}");
        }
    }

    #[test]
    fn lockdown_switches_everything_on() {
        let c: AntiBotConfig = serde_yaml::from_str(
            "{ webgl: false, reject_headless: false, lockdown: { request: 10, period: 10, hold: 30 } }",
        )
        .unwrap();
        validate(&c, "t").unwrap();
        assert_eq!(
            c.lockdown.as_ref().unwrap().refuse,
            all_lockdown_rules(),
            "everything by default"
        );
        let rule = Rule {
            lockdown: c.lockdown.clone().map(|l| Arc::new(LockdownState::new(l))),
            cfg: c,
            exclude: vec![],
            nofiltered: vec![],
            traffic: Arc::new(Traffic::new()),
            page: Arc::new(Page::load(None).unwrap()),
            active_until: std::sync::atomic::AtomicU64::new(0),
            detector: Arc::new(Detector {
                label: String::new(),
                log: None,
                ban: None,
                offenders: dashmap::DashMap::new(),
                recent: dashmap::DashMap::new(),
            }),
            challenged: dashmap::DashMap::new(),
            hostname_off: std::sync::atomic::AtomicBool::new(false),
            software: None,
        };
        let l = rule.lockdown.as_ref().unwrap();
        l.update(8000, &rule.traffic, None);
        assert!(!l.active(8000));
        assert_eq!(
            rule.flags_at(8000) & (FLAG_WEBGL | FLAG_REJECT_HEADLESS | FLAG_REJECT_SOFTWARE_GL),
            0,
            "relaxed config"
        );
        for _ in 0..10 {
            rule.traffic.record(8000);
        }
        l.update(8000, &rule.traffic, None);
        assert!(l.active(8000) && l.refuses(8000, LockdownRule::NonBrowsers));
        let f = rule.flags_at(8000);
        assert!(
            f & FLAG_WEBGL != 0
                && f & FLAG_REJECT_HEADLESS != 0
                && f & FLAG_REJECT_SOFTWARE_GL != 0,
            "all checks forced on"
        );
        l.update(8025, &rule.traffic, None);
        assert!(l.active(8025), "held");
        l.update(8031, &rule.traffic, None);
        assert!(!l.active(8031), "over");
        let only: AntiBotConfig =
            serde_yaml::from_str("{ lockdown: { request: 5, refuse: [non_browsers, crawlers] } }")
                .unwrap();
        assert_eq!(
            only.lockdown.unwrap().refuse,
            vec![LockdownRule::NonBrowsers, LockdownRule::Crawlers]
        );
        assert!(
            serde_yaml::from_str::<AntiBotConfig>(
                "{ lockdown: { request: 5, refuse: [everything] } }"
            )
            .is_err()
        );
    }

    #[test]
    fn export_lists_current_bans_in_blocklist_format() {
        let ban = BanConfig {
            after: 2,
            period: 60,
            duration: 600,
            store: None,
            export: None,
        };
        let d = Arc::new(Detector {
            label: "git.example.com".into(),
            log: None,
            ban: Some(ban),
            offenders: dashmap::DashMap::new(),
            recent: dashmap::DashMap::new(),
        });
        let sec = 1_800_000_000;
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        d.detect(sec, "h", Some(ip), "ua", "POST request without a pass", "/");
        d.detect(sec, "h", Some(ip), "ua", "POST request without a pass", "/");
        d.detect(
            sec,
            "h",
            Some("198.51.100.7".parse().unwrap()),
            "ua",
            "x",
            "/",
        );
        let text = export_text(&[d.clone()], sec + 1);
        assert!(text.contains("# 2027-01-15T08:00:00Z · git.example.com · POST request without a pass ×2\n203.0.113.9\n"), "{text}");
        assert!(
            !text.contains("198.51.100.7"),
            "counted but not banned: not listed"
        );
        // Every non-comment line parses as an IP, as ip_blocklists expects.
        for line in text
            .lines()
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
        {
            assert!(line.parse::<IpAddr>().is_ok(), "{line}");
        }
        // Once the ban has run out, the address leaves the file.
        assert!(!export_text(&[d], sec + 601).contains("203.0.113.9"));
    }

    #[test]
    fn dns_timeout_defaults_to_300ms() {
        let c: AntiBotConfig = serde_yaml::from_str("{}").unwrap();
        assert_eq!(c.dns_timeout, 0.3);
        let c: AntiBotConfig = serde_yaml::from_str("{ dns_timeout: 150ms }").unwrap();
        assert_eq!(c.dns_timeout, 0.15);
        let c: AntiBotConfig = serde_yaml::from_str("{ dns_timeout: 30 }").unwrap();
        assert!(validate(&c, "t").is_err());
    }

    #[test]
    fn gpu_hash_matches_the_shaders() {
        // Same values as the JavaScript / WGSL / GLSL version.
        assert_eq!(
            [
                (0, 0),
                (1, 2),
                (0xdeadbeef, 123456),
                (4294967295, 4294967295),
                (305419896, 99999999)
            ]
            .map(|(s, n)| gpu_hash(s, n)),
            [4135262099, 3724419150, 3846698384, 4135262099, 1118002738]
        );
        assert!(gpu_meets(0x0000_ffff, 16) && !gpu_meets(0x0001_0000, 16));
    }

    #[test]
    fn gpu_check_flow() {
        let g = Arc::new(SoftwareGuard::new(
            GpuCheck {
                mode: GpuMode::Auto,
                bits: 16,
                budget: 2.0,
                hardware_under: 2.0,
                on_software: OnSoftware::Allow,
                software_extra: 2,
                software_levels: vec![],
                software_hold: 60,
            },
            &[],
            Arc::new(Traffic::new()),
        ));
        let (token, _) = register_pending_with("{}".into(), "ip", "UA", 120, Some(&g));
        assert!(
            gpu_start(&token, "ip", "UA").is_none(),
            "script not loaded yet"
        );
        serve_script(&token, "ip", "UA").unwrap();
        let st: serde_json::Value =
            serde_json::from_str(&gpu_start(&token, "ip", "UA").unwrap()).unwrap();
        assert!(gpu_start(&token, "ip", "UA").is_none(), "started once");
        let seed = st["seed"].as_u64().unwrap() as u32;
        let n = (0u32..)
            .find(|n| gpu_meets(gpu_hash(seed, *n), 16))
            .unwrap();
        assert_eq!(
            gpu_done(&token, "ip", "UA", &format!("api=webgpu&n={n}")),
            Some("hardware")
        );
        assert!(
            gpu_done(&token, "ip", "UA", "api=x&n=1").is_none(),
            "one result only"
        );
        // A wrong nonce, a timeout, no GPU at all.
        let (t2, _) = register_pending_with("{}".into(), "ip", "UA", 120, Some(&g));
        serve_script(&t2, "ip", "UA").unwrap();
        let st: serde_json::Value =
            serde_json::from_str(&gpu_start(&t2, "ip", "UA").unwrap()).unwrap();
        let seed = st["seed"].as_u64().unwrap() as u32;
        let bad = (0u32..)
            .find(|n| !gpu_meets(gpu_hash(seed, *n), 16))
            .unwrap();
        assert_eq!(
            gpu_done(&t2, "ip", "UA", &format!("api=webgl2&n={bad}")),
            Some("invalid")
        );
        let (t3, _) = register_pending_with("{}".into(), "ip", "UA", 120, Some(&g));
        serve_script(&t3, "ip", "UA").unwrap();
        gpu_start(&t3, "ip", "UA").unwrap();
        assert_eq!(
            gpu_done(&t3, "ip", "UA", "api=webgl2&n=-1"),
            Some("timeout")
        );
        let (t4, _) = register_pending_with("{}".into(), "ip", "UA", 120, Some(&g));
        serve_script(&t4, "ip", "UA").unwrap();
        assert_eq!(gpu_done(&t4, "ip", "UA", "api=none"), Some("unavailable"));
        // on_software: harder → the server sets the extra bits when the GPU
        // test shows no real GPU, and tells the browser.
        let h = Arc::new(SoftwareGuard::new(
            GpuCheck {
                mode: GpuMode::Auto,
                bits: 16,
                budget: 2.0,
                hardware_under: 2.0,
                on_software: OnSoftware::Harder,
                software_extra: 3,
                software_levels: vec![],
                software_hold: 60,
            },
            &[],
            Arc::new(Traffic::new()),
        ));
        let (t5, _) = register_pending_with("{}".into(), "ip", "UA", 120, Some(&h));
        serve_script(&t5, "ip", "UA").unwrap();
        let st: serde_json::Value =
            serde_json::from_str(&gpu_start(&t5, "ip", "UA").unwrap()).unwrap();
        let seed = st["seed"].as_u64().unwrap() as u32;
        let n = (0u32..)
            .find(|n| gpu_meets(gpu_hash(seed, *n), 16))
            .unwrap();
        assert_eq!(
            gpu_done(
                &t5,
                "ip",
                "UA",
                &format!("api=webgl2&n={n}&r=Google%20SwiftShader")
            ),
            Some("software"),
            "fast, but announced software"
        );
        assert_eq!(gpu_penalty(&t5), 12, "3 steps = 12 bits");
        let (t6, _) = register_pending_with("{}".into(), "ip", "UA", 120, Some(&h));
        serve_script(&t6, "ip", "UA").unwrap();
        let st: serde_json::Value =
            serde_json::from_str(&gpu_start(&t6, "ip", "UA").unwrap()).unwrap();
        let seed = st["seed"].as_u64().unwrap() as u32;
        let n = (0u32..)
            .find(|n| gpu_meets(gpu_hash(seed, *n), 16))
            .unwrap();
        assert_eq!(
            gpu_done(
                &t6,
                "ip",
                "UA",
                &format!("api=webgpu&n={n}&ga=nvidia%2Fampere")
            ),
            Some("hardware")
        );
        assert_eq!(gpu_penalty(&t6), 0, "a real GPU pays nothing more");
        assert!(
            no_hardware_gpu("timeout")
                && no_hardware_gpu("unavailable")
                && !no_hardware_gpu("hardware")
        );
        let c: AntiBotConfig =
            serde_yaml::from_str("{ gpu_check: { on_software: refuse, software_extra: 9 } }")
                .unwrap();
        assert!(validate(&c, "t").is_err());
        let c: AntiBotConfig = serde_yaml::from_str("{ gpu_check: { bits: 40 } }").unwrap();
        assert!(validate(&c, "t").is_err());
    }

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
        let good = pass_cookie(&KEY, now_ms() / 1000, now_ms() / 1000 + 60, ua);
        assert!(pass_is_valid(&KEY, &good, ua));
        assert!(!pass_is_valid(&KEY, &good, "Mozilla/5.0 other"));
        assert!(!pass_is_valid(
            &KEY,
            &pass_cookie(&KEY, 1, now_ms() / 1000 - 1, ua),
            ua
        ));
        let sig = good.rsplit('.').next().unwrap();
        let issued = good.split('.').next().unwrap();
        assert!(
            !pass_is_valid(
                &KEY,
                &format!("{issued}.{}.{sig}", now_ms() / 1000 + 999_999),
                ua
            ),
            "forged expiry"
        );
        assert!(
            !pass_is_valid(
                &KEY,
                &format!("{}.{}.{sig}", now_ms() / 1000 + 10, now_ms() / 1000 + 60),
                ua
            ),
            "forged issue time"
        );
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
                 load_levels: [{ request: 10, period: 5, difficulty: "6", cookie_time_challenge: 10m }] }"#,
        )
        .unwrap();
        assert_eq!(c.random_difficulty, vec![3, 4]);
        assert_eq!(
            c.random_algorithm,
            vec![Algorithm::Slow, Algorithm::Fast, Algorithm::Sha512]
        );
        assert_eq!((c.min_start, c.max_start), (2.0, 5.0));
        let t: AntiBotConfig = serde_yaml::from_str("{ cookie_time_challenge: 12h }").unwrap();
        assert_eq!(
            t.cookie_ttl,
            12 * 3600,
            "cookie_time_challenge is the pass duration"
        );
        validate(&c, "t").unwrap();
        let rule = Rule {
            cfg: c,
            exclude: vec![],
            nofiltered: vec![],
            traffic: Arc::new(Traffic::new()),
            page: Arc::new(Page::load(None).unwrap()),
            active_until: std::sync::atomic::AtomicU64::new(0),
            detector: Arc::new(Detector {
                label: String::new(),
                log: None,
                ban: None,
                offenders: dashmap::DashMap::new(),
                recent: dashmap::DashMap::new(),
            }),
            challenged: dashmap::DashMap::new(),
            hostname_off: std::sync::atomic::AtomicBool::new(false),
            software: None,
            lockdown: None,
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
        assert_eq!(
            rule.pass_max_age(1000),
            7 * 24 * 3600,
            "quiet: the normal pass duration"
        );
        // Under load: 10 requests within 5 s raise the difficulty to 6 and
        // shorten passes to 10 minutes.
        for _ in 0..10 {
            rule.traffic.record(1000);
        }
        assert!((0..50).all(|_| rule.draw(1000).0 == 6));
        assert_eq!(rule.pass_max_age(1000), 600);
        // Ten seconds later the load has passed.
        assert!(rule.draw(1010).0 < 6);
        assert_eq!(rule.pass_max_age(1010), 7 * 24 * 3600);

        for bad in [
            "{ difficulty: 21 }",
            "{ random_difficulty: [0] }",
            "{ min_start: 5, max_start: 2 }",
            "{ min_start: 120 }",
            "{ load_levels: [{ request: 0, difficulty: 5 }] }",
            "{ load_levels: [{ request: 5, period: 120, difficulty: 5 }] }",
            "{ load_levels: [{ request: 5 }] }",
            "{ load_levels: [{ request: 5, cookie_time_challenge: 30 }] }",
        ] {
            let c: AntiBotConfig = serde_yaml::from_str(bad).unwrap();
            assert!(validate(&c, "t").is_err(), "{bad} must be refused");
        }
        assert!(serde_yaml::from_str::<AntiBotConfig>("{ algorithm: md5 }").is_err());
    }

    #[test]
    fn activation_threshold_and_hold() {
        let c: AntiBotConfig =
            serde_yaml::from_str("{ request: 20, period: 10, hold: 30s }").unwrap();
        validate(&c, "t").unwrap();
        let rule = Rule {
            cfg: c,
            exclude: vec![],
            nofiltered: vec![],
            traffic: Arc::new(Traffic::new()),
            page: Arc::new(Page::load(None).unwrap()),
            active_until: std::sync::atomic::AtomicU64::new(0),
            detector: Arc::new(Detector {
                label: String::new(),
                log: None,
                ban: None,
                offenders: dashmap::DashMap::new(),
                recent: dashmap::DashMap::new(),
            }),
            challenged: dashmap::DashMap::new(),
            hostname_off: std::sync::atomic::AtomicBool::new(false),
            software: None,
            lockdown: None,
        };
        // Quiet: 19 requests in 10 s — nobody is challenged.
        for i in 0..19 {
            rule.traffic.record(1000 + i % 10);
        }
        assert!(!rule.active(1009));
        // The 20th request reaches the threshold.
        rule.traffic.record(1009);
        assert!(rule.active(1009));
        // Traffic gone, but `hold` keeps it on for 30 s.
        assert!(rule.active(1030));
        assert!(rule.active(1038));
        assert!(!rule.active(1040));
        // Without `request`, always active.
        let always = Rule {
            cfg: serde_yaml::from_str("{}").unwrap(),
            ..rule
        };
        assert!(always.active(5000));
        for bad in [
            "{ request: 0 }",
            "{ request: 5, period: 0 }",
            "{ request: 5, period: 90 }",
        ] {
            let c: AntiBotConfig = serde_yaml::from_str(bad).unwrap();
            assert!(validate(&c, "t").is_err(), "{bad}");
        }
    }

    #[test]
    fn detections_are_logged_as_csv_and_lead_to_a_ban() {
        let dir = std::env::temp_dir().join(format!("pa-antibot-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("antibot.csv");
        let d = Detector {
            label: "bot.test".into(),
            log: Some(Mutex::new(csv_writer(log.display().to_string()))),
            ban: Some(BanConfig {
                after: 3,
                period: 60,
                duration: 600,
                store: None,
                export: None,
            }),
            offenders: dashmap::DashMap::new(),
            recent: dashmap::DashMap::new(),
        };
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        let other: IpAddr = "198.51.100.7".parse().unwrap();
        d.detect(
            1000,
            "bot.test",
            Some(ip),
            "Mozilla/5.0 \"evil\"\nInjected",
            "proof of work not met",
            "/x",
        );
        d.detect(
            1001,
            "bot.test",
            Some(ip),
            "ua",
            "window of size zero",
            "/x",
        );
        assert!(d.banned_until(ip, 1001).is_none(), "2 detections: not yet");
        d.detect(
            1002,
            "bot.test",
            Some(ip),
            "ua",
            "challenge requested again without being solved",
            "/x",
        );
        assert_eq!(
            d.banned_until(ip, 1002),
            Some(1602),
            "3rd detection: banned for 600 s"
        );
        assert!(d.banned_until(ip, 1602).is_none(), "ban over");
        assert!(
            d.banned_until(other, 1002).is_none(),
            "other addresses unaffected"
        );
        // Detections spread over more than `period` never add up to a ban.
        d.detect(1000, "h", Some(other), "ua", "r", "/");
        d.detect(1050, "h", Some(other), "ua", "r", "/");
        d.detect(1070, "h", Some(other), "ua", "r", "/");
        assert!(d.banned_until(other, 1070).is_none());
        d.purge(5000);
        assert!(d.offenders.is_empty(), "old entries purged");
        drop(d); // closes the writer, which flushes
        std::thread::sleep(Duration::from_millis(300));
        let csv = std::fs::read_to_string(&log).unwrap();
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines[0], CSV_HEADER.trim_end());
        assert!(lines[1].contains("\"203.0.113.9\""));
        assert!(
            lines[1].contains("\"Mozilla/5.0 \"\"evil\"\" Injected\""),
            "quotes doubled, newline removed: {}",
            lines[1]
        );
        assert!(lines[1].contains("\"proof of work not met\""));
        assert!(csv.contains("banned for 600s after 3 detections in 60s"));
        // The three identical detections of `other` (same reason, same path)
        // at 1000, 1050, 1070: the second is folded into the third.
        assert_eq!(
            lines.len(),
            1 + 3 + 1 + 2,
            "header, 3 detections, the ban, 2 lines for 3 identical others"
        );
        assert!(csv.contains("(+1 identical in the previous minute)"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn hostnames_are_verified_both_ways() {
        let domains = vec!["googlebot.com".to_string(), "*.search.msn.com".to_string()];
        assert!(hostname_matches(
            "crawl-66-249-66-1.googlebot.com",
            &domains
        ));
        assert!(hostname_matches("googlebot.com.", &domains));
        assert!(hostname_matches("msnbot-1.search.msn.com", &domains));
        assert!(
            !hostname_matches("evilgooglebot.com", &domains),
            "a suffix is not a subdomain"
        );
        assert!(!hostname_matches("googlebot.com.evil.net", &domains));

        let ip: IpAddr = "66.249.66.1".parse().unwrap();
        let real = |_: IpAddr| Some("crawl-66-249-66-1.googlebot.com".to_string());
        // Genuine crawler: the name resolves back to the address.
        assert!(verify_hostname(ip, &domains, real, |_| vec![ip]).is_some());
        // Forged PTR: the name does not point back to this address.
        let other: IpAddr = "203.0.113.9".parse().unwrap();
        assert!(verify_hostname(other, &domains, real, |_| vec![ip]).is_none());
        // No PTR, or a name outside the list.
        assert!(verify_hostname(ip, &domains, |_| None, |_| vec![ip]).is_none());
        assert!(
            verify_hostname(
                ip,
                &domains,
                |_| Some("host.example.net".into()),
                |_| vec![ip]
            )
            .is_none()
        );
        // The real resolver: loopback is `localhost`, which resolves back.
        let lo: IpAddr = "127.0.0.1".parse().unwrap();
        assert_eq!(
            verify_hostname(lo, &["localhost".to_string()], reverse_dns, forward_dns).as_deref(),
            Some("localhost")
        );
    }

    #[test]
    fn client_info_from_the_solution() {
        let q = "r=ANGLE%20(NVIDIA%20GeForce%20RTX%203060)&v=Google%20Inc.&gv=WebGL%201.0&w=1280&h=800&sw=1920&sh=1080\
                 &dpr=2&c=12&wd=0&l=fr-FR&p=Linux&tz=Europe%2FParis&d=4&a=fast&elapsed=1834";
        let i = ClientInfo::from_query(q);
        assert_eq!(i.gpu(), "hardware");
        assert_eq!(i.renderer, "ANGLE (NVIDIA GeForce RTX 3060)");
        assert_eq!(
            (i.viewport.as_str(), i.screen.as_str()),
            ("1280x800", "1920x1080")
        );
        assert_eq!(
            (i.cores.as_str(), i.webdriver.as_str(), i.timezone.as_str()),
            ("12", "no", "Europe/Paris")
        );
        let sw = ClientInfo::from_query("r=Google%20SwiftShader&w=800&h=600&wd=1");
        assert_eq!((sw.gpu(), sw.webdriver.as_str()), ("software", "yes"));
        assert_eq!(ClientInfo::from_query("w=800&h=600").gpu(), "none");
        assert_eq!(ClientInfo::default().gpu(), "");
        let long = format!("r={}", "A".repeat(5000));
        assert_eq!(
            ClientInfo::from_query(&long).renderer.len(),
            200,
            "client values are bounded"
        );
        // Same number of columns as the header.
        let d = Detector {
            label: String::new(),
            log: None,
            ban: None,
            offenders: dashmap::DashMap::new(),
            recent: dashmap::DashMap::new(),
        };
        let _ = &d;
        let row = csv_line(&[""; 29]);
        assert_eq!(
            row.matches("\",\"").count() + 1,
            CSV_HEADER.split(',').count()
        );
    }

    #[test]
    fn server_wide_load_levels() {
        let c: AntiBotConfig = serde_yaml::from_str(
            "{ difficulty: 3, cookie_ttl: 86400, load_levels: [{ request: 50, period: 5, scope: server, difficulty: 6, cookie_ttl: 600 }] }",
        )
        .unwrap();
        validate(&c, "t").unwrap();
        assert_eq!(c.load_levels[0].scope, LoadScope::Server);
        let rule = Rule {
            cfg: c,
            exclude: vec![],
            nofiltered: vec![],
            traffic: Arc::new(Traffic::new()),
            page: Arc::new(Page::load(None).unwrap()),
            active_until: std::sync::atomic::AtomicU64::new(0),
            detector: Arc::new(Detector {
                label: String::new(),
                log: None,
                ban: None,
                offenders: dashmap::DashMap::new(),
                recent: dashmap::DashMap::new(),
            }),
            challenged: dashmap::DashMap::new(),
            hostname_off: std::sync::atomic::AtomicBool::new(false),
            software: None,
            lockdown: None,
        };
        // This vhost is quiet; the server, through other vhosts, is not.
        let sec = 9_000_000;
        assert_eq!(rule.draw(sec).0, 3);
        for _ in 0..50 {
            server_traffic().record(sec);
        }
        assert_eq!(
            rule.draw(sec).0,
            6,
            "server-wide traffic raises the difficulty"
        );
        assert_eq!(rule.pass_max_age(sec), 600, "and shortens the pass");
        assert_eq!(rule.draw(sec + 10).0, 3, "once the server is quiet again");
        assert!(
            serde_yaml::from_str::<AntiBotConfig>(
                "{ load_levels: [{ request: 5, scope: planet, difficulty: 5 }] }"
            )
            .is_err()
        );
    }

    #[test]
    fn pass_states() {
        let ua = "Mozilla/5.0 test";
        let now = now_ms() / 1000;
        assert!(matches!(
            pass_state(&KEY, &pass_cookie(&KEY, now, now + 60, ua), ua),
            PassState::Valid(_)
        ));
        assert_eq!(
            pass_state(&KEY, &pass_cookie(&KEY, now - 100, now - 1, ua), ua),
            PassState::Expired,
            "expiry is normal"
        );
        assert_eq!(
            pass_state(&KEY, "1700000000.abcdef", ua),
            PassState::Malformed,
            "an older format is not a forgery"
        );
        assert_eq!(pass_state(&KEY, "garbage", ua), PassState::Malformed);
        let good = pass_cookie(&KEY, now, now + 60, ua);
        assert_eq!(
            pass_state(&KEY, &good, "Mozilla/5.0 other"),
            PassState::Forged,
            "copied to another browser"
        );
        assert_eq!(pass_state(&[9; 32], &good, ua), PassState::Forged);
    }

    #[test]
    fn re_challenge_needs_the_grace_period_and_is_per_browser() {
        let rule = Rule {
            cfg: serde_yaml::from_str("{ max_start: 5 }").unwrap(),
            exclude: vec![],
            nofiltered: vec![],
            traffic: Arc::new(Traffic::new()),
            page: Arc::new(Page::load(None).unwrap()),
            active_until: std::sync::atomic::AtomicU64::new(0),
            detector: Arc::new(Detector {
                label: String::new(),
                log: None,
                ban: None,
                offenders: dashmap::DashMap::new(),
                recent: dashmap::DashMap::new(),
            }),
            challenged: dashmap::DashMap::new(),
            hostname_off: std::sync::atomic::AtomicBool::new(false),
            software: None,
            lockdown: None,
        };
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        assert!(
            !rule.challenged_recently(ip, "Firefox", 1000),
            "first challenge"
        );
        assert!(
            !rule.challenged_recently(ip, "Firefox", 1001),
            "parallel tabs, same second"
        );
        assert!(
            !rule.challenged_recently(ip, "Firefox", 1030),
            "within the grace period (5 + 30 s)"
        );
        assert!(
            !rule.challenged_recently(ip, "Chrome", 1040),
            "someone else behind the same address"
        );
        assert!(
            rule.challenged_recently(ip, "Firefox", 1040),
            "asked again after the grace period without solving"
        );
        assert!(
            !rule.challenged_recently(ip, "Firefox", 1000 + 1800),
            "a new window after 30 min"
        );
    }

    #[test]
    fn pages_in_french_and_english() {
        let fr: AntiBotConfig = serde_yaml::from_str("{}").unwrap();
        assert_eq!(fr.language, Language::Fr, "French by default, as before");
        let en: AntiBotConfig = serde_yaml::from_str("{ language: en }").unwrap();
        assert_eq!(en.language, Language::En);
        assert_eq!(
            serde_yaml::from_str::<AntiBotConfig>("{ lang: english }")
                .unwrap()
                .language,
            Language::En
        );
        assert!(serde_yaml::from_str::<AntiBotConfig>("{ language: de }").is_err());
        for l in [Language::Fr, Language::En] {
            let t = l.texts();
            assert!(
                t.starting.contains("{s}")
                    && t.running.contains("{d}")
                    && t.running.contains("{cores}")
            );
        }
        assert_eq!(Language::En.texts().title, "Checking your browser");
        assert!(
            !MAIN_JS.contains("Vérification") && !MAIN_JS.contains("cœur"),
            "no French left in the script"
        );
        assert!(DEFAULT_PAGE.contains("{{ lang }}") && DEFAULT_PAGE.contains("{{ description }}"));
        assert!(
            WORKER_JS.contains("sha256Searcher") && WORKER_JS.contains("sha512Searcher"),
            "synchronous search embedded"
        );
        assert!(
            !WORKER_JS.contains("crypto.subtle.digest"),
            "no per-hash await"
        );
        assert!(
            SCRIPT_HTML.contains("__SRC__") && !SCRIPT_HTML.contains("__PARAMS__"),
            "the page only references the script"
        );
    }

    #[test]
    fn unban_lifts_the_ban_everywhere() {
        let d = Detector {
            label: "git.example.com".into(),
            log: None,
            ban: Some(BanConfig {
                after: 2,
                period: 60,
                duration: 600,
                store: None,
                export: None,
            }),
            offenders: dashmap::DashMap::new(),
            recent: dashmap::DashMap::new(),
        };
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        let sec = now_ms() / 1000;
        d.detect(sec, "h", Some(ip), "ua", "r1", "/");
        d.detect(sec, "h", Some(ip), "ua", "r2", "/");
        assert!(d.banned_until(ip, sec).is_some());
        // What `unban` does for each vhost's detector.
        let removed = d.offenders.remove(&ip).map(|(_, o)| o.banned_until > sec);
        assert_eq!(removed, Some(true));
        assert!(d.banned_until(ip, sec).is_none());
        // Detections forgotten too: one new one does not re-ban at once.
        d.detect(sec, "h", Some(ip), "ua", "r3", "/");
        assert!(d.banned_until(ip, sec).is_none());
    }

    #[test]
    fn authorization_is_not_trusted_by_default() {
        let c: AntiBotConfig = serde_yaml::from_str("{}").unwrap();
        assert!(!c.trust_authorization && !c.log_bypass);
        let c: AntiBotConfig =
            serde_yaml::from_str("{ trust_authorization: true, log_bypass: true }").unwrap();
        assert!(c.trust_authorization && c.log_bypass);
    }

    #[test]
    fn the_ban_keeps_its_reasons() {
        let d = Detector {
            label: "git.example.com".into(),
            log: None,
            ban: Some(BanConfig {
                after: 4,
                period: 60,
                duration: 600,
                store: None,
                export: None,
            }),
            offenders: dashmap::DashMap::new(),
            recent: dashmap::DashMap::new(),
        };
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        d.detect(
            1000,
            "h",
            Some(ip),
            "ua",
            "POST request without a pass",
            "/a",
        );
        d.detect(1001, "h", Some(ip), "ua", "window of size zero", "/b");
        d.detect(
            1002,
            "h",
            Some(ip),
            "ua",
            "POST request without a pass",
            "/c",
        );
        d.detect(
            1003,
            "h",
            Some(ip),
            "ua",
            "POST request without a pass",
            "/d",
        );
        let o = d.offenders.get(&ip).unwrap();
        assert!(o.banned_until > 1003);
        assert_eq!(
            o.ban_reason,
            "POST request without a pass ×3, window of size zero ×1"
        );
    }

    #[test]
    fn client_cores() {
        let c: AntiBotConfig = serde_yaml::from_str("{}").unwrap();
        assert_eq!(c.client_cores, CoreUsage::Full);
        assert_eq!(CoreUsage::Full.threads(8), 8);
        let half: AntiBotConfig = serde_yaml::from_str("{ client_cores: 2 }").unwrap();
        assert_eq!(half.client_cores, CoreUsage::Divide(2));
        assert_eq!(CoreUsage::Divide(2).threads(8), 3, "8 / 2 - 1");
        assert_eq!(CoreUsage::Divide(3).threads(8), 1, "8 / 3 - 1");
        assert_eq!(CoreUsage::Divide(3).threads(12), 3);
        assert_eq!(CoreUsage::Divide(2).threads(2), 1, "never below one core");
        assert_eq!(
            serde_yaml::from_str::<AntiBotConfig>("{ client_cores: \"3\" }")
                .unwrap()
                .client_cores,
            CoreUsage::Divide(3)
        );
        assert_eq!(
            serde_yaml::from_str::<AntiBotConfig>("{ client_cores: full }")
                .unwrap()
                .client_cores,
            CoreUsage::Full
        );
        assert!(serde_yaml::from_str::<AntiBotConfig>("{ client_cores: 1 }").is_err());
        assert!(serde_yaml::from_str::<AntiBotConfig>("{ client_cores: half }").is_err());

        // Per load level: quiet → `client_cores`, busy → the level's value.
        let c: AntiBotConfig = serde_yaml::from_str(
            "{ client_cores: 3, load_levels: [ { request: 10, period: 5, client_cores: 2 }, { request: 20, period: 5, client_cores: full } ] }",
        )
        .unwrap();
        validate(&c, "t").unwrap();
        let rule = Rule {
            cfg: c,
            exclude: vec![],
            nofiltered: vec![],
            traffic: Arc::new(Traffic::new()),
            page: Arc::new(Page::load(None).unwrap()),
            active_until: std::sync::atomic::AtomicU64::new(0),
            detector: Arc::new(Detector {
                label: String::new(),
                log: None,
                ban: None,
                offenders: dashmap::DashMap::new(),
                recent: dashmap::DashMap::new(),
            }),
            challenged: dashmap::DashMap::new(),
            hostname_off: std::sync::atomic::AtomicBool::new(false),
            software: None,
            lockdown: None,
        };
        assert_eq!(rule.client_cores(3000), CoreUsage::Divide(3));
        for _ in 0..10 {
            rule.traffic.record(3000);
        }
        assert_eq!(rule.client_cores(3000), CoreUsage::Divide(2));
        for _ in 0..10 {
            rule.traffic.record(3000);
        }
        assert_eq!(
            rule.client_cores(3000),
            CoreUsage::Full,
            "the last level reached wins"
        );
        let only: AntiBotConfig =
            serde_yaml::from_str("{ load_levels: [ { request: 5, client_cores: 2 } ] }").unwrap();
        validate(&only, "t").unwrap();
    }

    #[test]
    fn served_scripts_are_minified_and_in_sync() {
        for (name, js) in [("challenge", MAIN_JS), ("worker", WORKER_JS)] {
            assert!(!js.trim_end().contains('\n'), "{name}: one line");
            assert!(
                !js.contains("/*") && !js.contains("\n//") && !js.contains(" // "),
                "{name}: no comment"
            );
            let src_len = std::fs::read_to_string(format!(
                "{}/src/network/antibot_js/{name}.js",
                env!("CARGO_MANIFEST_DIR")
            ))
            .map(|s| s.len())
            .unwrap_or(usize::MAX);
            assert!(js.len() < src_len, "{name}: smaller than its source");
        }
        for p in ["__PARAMS__", "__KEY__", "__TOKEN__", "__WORKER__"] {
            assert!(MAIN_JS.contains(p), "placeholder {p} kept");
        }
    }

    #[test]
    fn default_page_has_the_tags() {
        assert!(DEFAULT_PAGE.contains("{{ script }}") && DEFAULT_PAGE.contains("{{ title }}"));
        assert!(MAIN_JS.contains("__PARAMS__") && MAIN_JS.contains("__KEY__"));
    }
}
