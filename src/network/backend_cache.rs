//! Cache des réponses du backend (`cache_backend`), par vhost ou par route.
//!
//! ```yaml
//! vhosts:
//!   - vhost: ["app.example.com"]
//!     cache_backend: true                # ou un bloc :
//!     # cache_backend:
//!     #   max_memory: "128MB"
//!     #   max_object_size: "2MB"
//!     #   default_ttl: 0
//!     routes:
//!       - prefix: "/"
//!         target: "http://127.0.0.1:3000"
//!       - prefix: "/api/live"
//!         target: "http://127.0.0.1:3000"
//!         cache_backend: false           # une route peut s'en retirer
//! ```
//!
//! ProxyAuth se comporte comme un cache partagé au sens de la RFC 9111 :
//! **c'est le backend qui décide**, par ses en-têtes.
//!
//! Une réponse est gardée seulement si :
//! * la requête est un `GET` (un `HEAD` est servi depuis l'entrée du
//!   `GET`), sans `Range`, sans `Cache-Control: no-store` ;
//! * le statut est cachable (200, 203, 204, 300, 301, 308, 404, 410) ;
//! * la réponse n'a ni `no-store`, ni `private`, ni `Set-Cookie`, ni
//!   `Vary: *` ;
//! * le backend donne une durée (`s-maxage`, `max-age`, `Expires`), ou
//!   `default_ttl` s'applique à une réponse sans aucun en-tête de cache,
//!   ou elle porte un validateur (`ETag`, `Last-Modified`) avec `no-cache` ;
//! * sa taille est ≤ `max_object_size` : annoncée (`Content-Length`), ou
//!   constatée en lisant une réponse envoyée en flux, qui passe sans être
//!   gardée dès qu'elle dépasse la limite.
//!
//! **Requêtes authentifiées** (`Authorization`, un cookie quelconque, ou
//! un utilisateur ProxyAuth transmis au backend dans `X-User`) : la
//! réponse peut être propre à la personne. Elle n'est stockée, et une
//! entrée ne leur est servie, que si le backend l'a explicitement déclarée
//! partageable (`Cache-Control: public` ou `s-maxage`). Un backend qui
//! ignore tout du cache ne peut donc pas provoquer de fuite entre
//! utilisateurs.
//!
//! Au service : `Vary` est respecté (une variante par valeur des en-têtes
//! nommés), une entrée périmée ou marquée `no-cache` est revalidée auprès
//! du backend (`If-None-Match` / `If-Modified-Since`, `304` → copie
//! servie), `Cache-Control: no-cache` côté client force une réponse
//! fraîche. `Age` et `X-Cache: HIT | MISS | REVALIDATED` sont ajoutés.
//! Une seule requête par ressource part vers le backend pendant un
//! rechargement ; les autres attendent son résultat.

use bytes::Bytes;
use dashmap::DashMap;
use http_body_util::{BodyExt, Full};
use hyper::header::{self, HeaderMap, HeaderName, HeaderValue};
use hyper::{Method, StatusCode};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant, SystemTime};

use crate::config::config::RouteRule;
use crate::config::internal_cache::ByteSize;

/// Réglages de `cache_backend`. `cache_backend: true` = valeurs par défaut.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct BackendCacheConfig {
    pub enabled: bool,
    /// Mémoire de ce cache (défaut 64 Mo).
    pub max_memory: Option<ByteSize>,
    /// Au-delà, une réponse n'est jamais gardée (défaut 1 Mo).
    pub max_object_size: Option<ByteSize>,
    /// Durée, en secondes, pour une réponse qui ne porte **aucun** en-tête
    /// de cache. `0` (défaut) : ne pas garder ces réponses.
    pub default_ttl: u64,
    /// Ajoute `X-Cache-Reason` aux réponses : pourquoi une réponse n'a pas
    /// été gardée (ou qu'elle vient de l'être). Pour la mise au point.
    pub debug: bool,
    /// Rempli par `expand_vhost_groups` quand la route hérite le bloc de
    /// son groupe : les routes du groupe partagent alors un seul cache.
    #[serde(skip)]
    pub inherited_from_group: Option<usize>,
}

impl Default for BackendCacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_memory: None,
            max_object_size: None,
            default_ttl: 0,
            debug: false,
            inherited_from_group: None,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BlockForm {
    #[serde(default = "yes")]
    enabled: bool,
    #[serde(default)]
    max_memory: Option<ByteSize>,
    #[serde(default)]
    max_object_size: Option<ByteSize>,
    #[serde(default)]
    default_ttl: u64,
    #[serde(default)]
    debug: bool,
}

fn yes() -> bool {
    true
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RawForm {
    Flag(bool),
    Block(BlockForm),
}

impl<'de> Deserialize<'de> for BackendCacheConfig {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(match RawForm::deserialize(d)? {
            RawForm::Flag(enabled) => Self {
                enabled,
                ..Self::default()
            },
            RawForm::Block(b) => Self {
                enabled: b.enabled,
                max_memory: b.max_memory,
                max_object_size: b.max_object_size,
                default_ttl: b.default_ttl,
                debug: b.debug,
                inherited_from_group: None,
            },
        })
    }
}

const DEFAULT_MAX_MEMORY: u64 = 64 * 1024 * 1024;
const DEFAULT_MAX_OBJECT: u64 = 1024 * 1024;
/// Une ressource dont la réponse n'est pas cachable est marquée « à ne pas
/// mettre en cache » ce temps-là : les requêtes suivantes vont directement
/// au backend, sans s'attendre les unes les autres.
const PASS_FOR: Duration = Duration::from_secs(10);
/// Entrée périmée mais revalidable (`ETag` / `Last-Modified`) : gardée ce
/// temps-là après sa fin de fraîcheur, pour une revalidation `304`.
const KEEP_STALE_FOR: Duration = Duration::from_secs(3600);
/// Variantes `Vary` gardées au plus par ressource.
const MAX_VARIANTS: usize = 8;

impl BackendCacheConfig {
    fn max_memory(&self) -> u64 {
        self.max_memory.map(|b| b.0).unwrap_or(DEFAULT_MAX_MEMORY)
    }
    fn max_object_size(&self) -> u64 {
        self.max_object_size
            .map(|b| b.0)
            .unwrap_or(DEFAULT_MAX_OBJECT)
    }
    pub fn describe(&self) -> String {
        format!(
            "max_memory {} MB, max_object_size {} KB, default_ttl {}s{}",
            self.max_memory() / (1024 * 1024),
            self.max_object_size() / 1024,
            self.default_ttl,
            if self.debug {
                ", debug (X-Cache-Reason)"
            } else {
                ""
            }
        )
    }
}

// ───────────────────────────────────────────── stored entries

struct Cached {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
    /// Pour `Age`.
    stored_at: Instant,
    /// Âge déjà annoncé par le backend (`Age`), en secondes.
    initial_age: u64,
    fresh_until: Instant,
    keep_until: Instant,
    /// `public` ou `s-maxage` : servable aux requêtes authentifiées.
    shared_explicit: bool,
    /// `no-cache` : revalider à chaque usage.
    always_revalidate: bool,
    /// Valeurs, dans la requête d'origine, des en-têtes nommés par `Vary`.
    vary: Vec<(HeaderName, Option<HeaderValue>)>,
}

impl Cached {
    fn weight(&self) -> u64 {
        let headers: usize = self
            .headers
            .iter()
            .map(|(k, v)| k.as_str().len() + v.len() + 32)
            .sum();
        self.body.len() as u64 + headers as u64 + 256
    }

    fn matches(&self, req: &HeaderMap) -> bool {
        self.vary
            .iter()
            .all(|(name, value)| req.get(name) == value.as_ref())
    }

    fn validators(&self) -> (Option<HeaderValue>, Option<HeaderValue>) {
        (
            self.headers.get(header::ETAG).cloned(),
            self.headers.get(header::LAST_MODIFIED).cloned(),
        )
    }
}

#[derive(Clone)]
enum Slot {
    Variants(Vec<Arc<Cached>>),
    Pass(Instant),
}

#[derive(Clone)]
struct SlotWeighter;

impl quick_cache::Weighter<[u8; 32], Slot> for SlotWeighter {
    fn weight(&self, _k: &[u8; 32], v: &Slot) -> u64 {
        match v {
            Slot::Variants(vs) => vs.iter().map(|c| c.weight()).sum::<u64>().max(1),
            Slot::Pass(_) => 64,
        }
    }
}

/// Un cache : un vhost (routes qui héritent du groupe) ou une route.
pub struct BackendCache {
    cfg: BackendCacheConfig,
    slots: quick_cache::sync::Cache<[u8; 32], Slot, SlotWeighter>,
    inflight: DashMap<[u8; 32], Arc<tokio::sync::Mutex<()>>>,
}

impl BackendCache {
    fn new(cfg: BackendCacheConfig) -> Self {
        let budget = cfg.max_memory().max(1024 * 1024);
        let estimated = (budget / (16 * 1024)).clamp(64, 1 << 20) as usize;
        Self {
            slots: quick_cache::sync::Cache::with_weighter(estimated, budget, SlotWeighter),
            inflight: DashMap::new(),
            cfg,
        }
    }
}

// ───────────────────────────────────────────── registry

struct Registry {
    by_scope: HashMap<String, Arc<BackendCache>>,
}

static REGISTRY: OnceLock<Registry> = OnceLock::new();

/// Portée du cache d'une route : son groupe `vhosts:` si elle en hérite le
/// bloc, sinon elle-même. Indépendant des index, donc stable à travers un
/// rechargement de routes.yml.
fn scope_of(rule: &RouteRule, cfg: &BackendCacheConfig) -> String {
    match cfg.inherited_from_group {
        Some(_) => format!("group:{}", rule.vhost.join(",")),
        None => format!(
            "route:{}|{}|{}",
            rule.vhost.join(","),
            rule.prefix,
            rule.regex.as_deref().unwrap_or("")
        ),
    }
}

/// Construit les caches au démarrage. Un `cache_backend` ajouté plus tard
/// par un rechargement de routes.yml prend effet au redémarrage suivant.
pub fn init_backend_caches(routes: &[RouteRule]) -> Vec<String> {
    let mut by_scope: HashMap<String, Arc<BackendCache>> = HashMap::new();
    let mut summary = Vec::new();
    for rule in routes {
        let Some(cfg) = rule.cache_backend.as_ref().filter(|c| c.enabled) else {
            continue;
        };
        let scope = scope_of(rule, cfg);
        by_scope.entry(scope.clone()).or_insert_with(|| {
            summary.push(format!("cache_backend {scope}: {}", cfg.describe()));
            Arc::new(BackendCache::new(cfg.clone()))
        });
    }
    let _ = REGISTRY.set(Registry { by_scope });
    summary
}

fn cache_for(rule: &RouteRule) -> Option<Arc<BackendCache>> {
    let cfg = rule.cache_backend.as_ref().filter(|c| c.enabled)?;
    REGISTRY.get()?.by_scope.get(&scope_of(rule, cfg)).cloned()
}

// ───────────────────────────────────────────── HTTP rules

#[derive(Default, Debug, PartialEq)]
struct Directives {
    no_store: bool,
    no_cache: bool,
    private: bool,
    public: bool,
    max_age: Option<u64>,
    s_maxage: Option<u64>,
    any: bool,
}

fn directives(headers: &HeaderMap) -> Directives {
    let mut d = Directives::default();
    for value in headers.get_all(header::CACHE_CONTROL) {
        let Ok(v) = value.to_str() else { continue };
        for part in v.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            d.any = true;
            let (name, arg) = match part.split_once('=') {
                Some((n, a)) => (
                    n.trim().to_ascii_lowercase(),
                    Some(a.trim().trim_matches('"')),
                ),
                None => (part.to_ascii_lowercase(), None),
            };
            match name.as_str() {
                "no-store" => d.no_store = true,
                // `no-cache="Set-Cookie"` et `private="..."` (forme avec
                // champs) : traités comme la forme simple, plus stricte.
                "no-cache" => d.no_cache = true,
                "private" => d.private = true,
                "public" => d.public = true,
                "max-age" => d.max_age = arg.and_then(|a| a.parse().ok()),
                "s-maxage" => d.s_maxage = arg.and_then(|a| a.parse().ok()),
                _ => {}
            }
        }
    }
    d
}

fn http_date(v: &HeaderValue) -> Option<SystemTime> {
    let s = v.to_str().ok()?;
    let dt = chrono::DateTime::parse_from_rfc2822(s.trim()).ok()?;
    let secs = u64::try_from(dt.timestamp()).ok()?;
    Some(SystemTime::UNIX_EPOCH + Duration::from_secs(secs))
}

/// Durée de fraîcheur annoncée par le backend, du point de vue d'un cache
/// partagé : `s-maxage`, puis `max-age`, puis `Expires` − `Date`.
fn freshness(headers: &HeaderMap, d: &Directives, default_ttl: u64) -> Option<Duration> {
    if let Some(s) = d.s_maxage.or(d.max_age) {
        return Some(Duration::from_secs(s));
    }
    if let Some(exp) = headers.get(header::EXPIRES) {
        // Une valeur invalide (`0`, `-1`) vaut « déjà expiré ».
        let Some(exp) = http_date(exp) else {
            return Some(Duration::ZERO);
        };
        let date = headers
            .get(header::DATE)
            .and_then(http_date)
            .unwrap_or_else(SystemTime::now);
        return Some(exp.duration_since(date).unwrap_or(Duration::ZERO));
    }
    if !d.any && default_ttl > 0 {
        return Some(Duration::from_secs(default_ttl));
    }
    None
}

const CACHEABLE_STATUS: &[u16] = &[200, 203, 204, 300, 301, 308, 404, 410];

/// La requête porte une identité : sa réponse peut être propre à quelqu'un.
fn is_authenticated(req: &HeaderMap) -> bool {
    req.contains_key(header::AUTHORIZATION)
        || req.contains_key(header::COOKIE)
        || req.contains_key("x-user")
}

fn base_key(method_get: bool, url: &str, req: &HeaderMap) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(if method_get { b"GET\n" } else { b"?\n" });
    h.update(url.as_bytes());
    h.update(b"\n");
    if let Some(host) = req.get(header::HOST) {
        h.update(host.as_bytes());
    }
    *h.finalize().as_bytes()
}

// ───────────────────────────────────────────── request flow

pub type ResponseBody = http_body_util::combinators::BoxBody<Bytes, hyper::Error>;

/// Résultat de [`begin`].
pub enum Step {
    /// Pas de cache pour cette requête : l'envoyer normalement.
    Off,
    /// Servie depuis le cache.
    Hit(hyper::Response<ResponseBody>),
    /// À envoyer au backend ; passer la réponse à [`Pending::finish`].
    Fetch(Pending),
}

pub struct Pending {
    cache: Arc<BackendCache>,
    key: [u8; 32],
    request_headers: HeaderMap,
    authenticated: bool,
    /// Entrée périmée en cours de revalidation.
    stale: Option<Arc<Cached>>,
    /// Verrou de chargement : une seule requête par ressource.
    _lock: Option<tokio::sync::OwnedMutexGuard<()>>,
    lock_key: Option<[u8; 32]>,
    /// Requête qui ne passe pas par le cache (méthode, `Range`…) : la
    /// réponse est seulement annotée en mode debug.
    bypass: Option<&'static str>,
    /// Le client a demandé une réponse fraîche (`no-cache`).
    forced: bool,
}

/// `X-Cache-Reason`, en mode debug.
fn annotate(headers: &mut HeaderMap, debug: bool, reason: &str) {
    if debug {
        if let Ok(v) = HeaderValue::from_str(reason) {
            headers.insert("x-cache-reason", v);
        }
    }
}

impl Drop for Pending {
    fn drop(&mut self) {
        if let Some(k) = self.lock_key.take() {
            // Retire le verrou s'il ne sert plus qu'à nous.
            self.cache
                .inflight
                .remove_if(&k, |_, m| Arc::strong_count(m) <= 2);
        }
    }
}

fn hit_response(c: &Cached, label: &'static str) -> hyper::Response<ResponseBody> {
    let mut b = hyper::Response::builder().status(c.status);
    if let Some(h) = b.headers_mut() {
        *h = c.headers.clone();
        let age = c.initial_age + c.stored_at.elapsed().as_secs();
        h.insert(header::AGE, HeaderValue::from(age));
        h.insert("x-cache", HeaderValue::from_static(label));
    }
    let body = Full::new(c.body.clone())
        .map_err(|e: std::convert::Infallible| match e {})
        .boxed();
    b.body(body).unwrap_or_else(|_| {
        hyper::Response::new(
            Full::new(Bytes::new())
                .map_err(|e: std::convert::Infallible| match e {})
                .boxed(),
        )
    })
}

fn find_variant(slot: &Slot, req: &HeaderMap, authenticated: bool) -> Option<Arc<Cached>> {
    match slot {
        Slot::Variants(vs) => vs
            .iter()
            .find(|c| c.matches(req) && (!authenticated || c.shared_explicit))
            .cloned(),
        Slot::Pass(_) => None,
    }
}

/// Avant d'envoyer `request` au backend. `url` est l'URL complète visée.
pub async fn begin(
    rule: &RouteRule,
    method: &Method,
    request: &HeaderMap,
    url: &str,
    lock_timeout: Duration,
) -> Step {
    let Some(cache) = cache_for(rule) else {
        return Step::Off;
    };
    // Requêtes qui ne passent pas par le cache. Sans debug, rien n'est
    // ajouté à leur réponse ; avec, elles disent pourquoi.
    let bypass = |reason: &'static str| {
        if cache.cfg.debug {
            Step::Fetch(Pending {
                cache: cache.clone(),
                key: [0; 32],
                request_headers: HeaderMap::new(),
                authenticated: false,
                stale: None,
                _lock: None,
                lock_key: None,
                bypass: Some(reason),
                forced: false,
            })
        } else {
            Step::Off
        }
    };
    if method != Method::GET && method != Method::HEAD {
        return bypass("method: only GET and HEAD are cached");
    }
    if request.contains_key(header::RANGE) {
        return bypass("request: Range");
    }
    let req_cc = directives(request);
    if req_cc.no_store {
        return bypass("request: Cache-Control no-store");
    }
    let force_fresh = req_cc.no_cache
        || req_cc.max_age == Some(0)
        || request
            .get(header::PRAGMA)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.to_ascii_lowercase().contains("no-cache"));
    let authenticated = is_authenticated(request);
    let key = base_key(true, url, request);
    let now = Instant::now();

    let mut pending = Pending {
        cache: cache.clone(),
        key,
        request_headers: request.clone(),
        authenticated,
        stale: None,
        _lock: None,
        lock_key: None,
        bypass: None,
        forced: force_fresh,
    };

    let lookup = |cache: &BackendCache| -> Result<Option<Arc<Cached>>, ()> {
        match cache.slots.get(&key) {
            Some(Slot::Pass(until)) if until > Instant::now() => Err(()),
            Some(slot) => Ok(find_variant(&slot, request, authenticated)),
            None => Ok(None),
        }
    };

    if !force_fresh {
        match lookup(&cache) {
            Err(()) => return Step::Fetch(pending),
            Ok(Some(c)) if c.fresh_until > now && !c.always_revalidate => {
                return Step::Hit(hit_response(&c, "HIT"));
            }
            Ok(Some(c)) if c.keep_until > now => {
                pending.stale = Some(c);
            }
            Ok(_) => {}
        }
    }

    // Une seule requête par ressource vers le backend.
    let lock = cache
        .inflight
        .entry(key)
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone();
    if let Ok(guard) = tokio::time::timeout(lock_timeout, lock.lock_owned()).await {
        pending._lock = Some(guard);
        pending.lock_key = Some(key);
        // Une autre requête vient peut-être de la charger.
        if !force_fresh {
            if let Ok(Some(c)) = lookup(&cache) {
                if c.fresh_until > Instant::now() && !c.always_revalidate {
                    return Step::Hit(hit_response(&c, "HIT"));
                }
            }
        }
    }
    Step::Fetch(pending)
}

impl Pending {
    /// En-têtes conditionnels à ajouter à la requête envoyée au backend
    /// quand une entrée périmée peut être revalidée.
    pub fn conditional_headers(&self) -> Vec<(HeaderName, HeaderValue)> {
        let Some(stale) = &self.stale else {
            return Vec::new();
        };
        let (etag, last_modified) = stale.validators();
        let mut out = Vec::new();
        if let Some(e) = etag {
            out.push((header::IF_NONE_MATCH, e));
        }
        if let Some(l) = last_modified {
            out.push((header::IF_MODIFIED_SINCE, l));
        }
        out
    }

    /// Après la réponse du backend : la garder si elle est cachable, ou
    /// servir la copie revalidée sur un `304`.
    pub async fn finish(
        self,
        resp: hyper::Response<ResponseBody>,
    ) -> hyper::Response<ResponseBody> {
        let cfg = &self.cache.cfg;

        if let Some(reason) = self.bypass {
            let (mut parts, body) = resp.into_parts();
            parts
                .headers
                .insert("x-cache", HeaderValue::from_static("MISS"));
            annotate(&mut parts.headers, cfg.debug, reason);
            return hyper::Response::from_parts(parts, body);
        }
        let passing = matches!(self.cache.slots.get(&self.key), Some(Slot::Pass(until)) if until > Instant::now());

        // Revalidation réussie.
        if resp.status() == StatusCode::NOT_MODIFIED {
            if let Some(stale) = &self.stale {
                let d = directives(resp.headers());
                let mut headers = stale.headers.clone();
                for name in [
                    header::CACHE_CONTROL,
                    header::EXPIRES,
                    header::DATE,
                    header::ETAG,
                ] {
                    if let Some(v) = resp.headers().get(&name) {
                        headers.insert(name, v.clone());
                    }
                }
                let fresh = freshness(&headers, &directives(&headers), cfg.default_ttl)
                    .unwrap_or(Duration::ZERO);
                let now = Instant::now();
                let refreshed = Arc::new(Cached {
                    status: stale.status,
                    headers,
                    body: stale.body.clone(),
                    stored_at: now,
                    initial_age: 0,
                    fresh_until: now + fresh,
                    keep_until: now + fresh + KEEP_STALE_FOR,
                    shared_explicit: stale.shared_explicit || d.public || d.s_maxage.is_some(),
                    always_revalidate: stale.always_revalidate || d.no_cache,
                    vary: stale.vary.clone(),
                });
                self.insert_variant(refreshed.clone());
                return hit_response(&refreshed, "REVALIDATED");
            }
        }

        let (mut parts, body) = resp.into_parts();
        let d = directives(&parts.headers);
        let vary_names: Option<Vec<HeaderName>> = {
            let mut names = Vec::new();
            let mut star = false;
            for v in parts.headers.get_all(header::VARY) {
                for n in v.to_str().unwrap_or("*").split(',') {
                    let n = n.trim();
                    if n == "*" {
                        star = true;
                    } else if let Ok(h) = HeaderName::try_from(n) {
                        names.push(h);
                    }
                }
            }
            (!star).then_some(names)
        };
        let length = parts
            .headers
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());
        let fresh = freshness(&parts.headers, &d, cfg.default_ttl);
        let has_validator = parts.headers.contains_key(header::ETAG)
            || parts.headers.contains_key(header::LAST_MODIFIED);
        let shared_explicit = d.public || d.s_maxage.is_some();

        // Première règle non remplie, ou `None` si la réponse peut être
        // gardée. Taille annoncée : bornée d'avance ; réponse en flux (sans
        // `Content-Length`) : lue jusqu'à `max_object_size`, plus bas.
        let refused: Option<String> = if !CACHEABLE_STATUS.contains(&parts.status.as_u16()) {
            Some(format!("status {} is not cacheable", parts.status.as_u16()))
        } else if d.no_store {
            Some("backend: Cache-Control no-store".into())
        } else if d.private {
            Some("backend: Cache-Control private".into())
        } else if parts.headers.contains_key(header::SET_COOKIE) {
            Some("backend: response sets a cookie (Set-Cookie)".into())
        } else if vary_names.is_none() {
            Some("backend: Vary *".into())
        } else if let Some(l) = length.filter(|&l| l > cfg.max_object_size()) {
            Some(format!(
                "too large: {l} bytes > max_object_size {}",
                cfg.max_object_size()
            ))
        } else if !(fresh.is_some_and(|f| !f.is_zero()) || (d.no_cache && has_validator)) {
            Some(if !d.any && !parts.headers.contains_key(header::EXPIRES) {
                "backend: no caching header (Cache-Control / Expires), default_ttl is 0".into()
            } else if d.no_cache {
                "backend: no-cache without ETag or Last-Modified to revalidate".into()
            } else {
                "backend: lifetime is 0 (max-age=0 or expired Expires)".into()
            })
        } else if self.authenticated && !shared_explicit {
            Some("request carries an identity (Authorization, Cookie or X-User) and backend did not mark the response public or s-maxage".into())
        } else {
            None
        };

        if let Some(reason) = refused {
            // Pas cachable : les requêtes suivantes pour cette ressource
            // vont directement au backend, sans s'attendre.
            if self.stale.is_none() && self.cache.slots.get(&self.key).is_none() {
                self.cache
                    .slots
                    .insert(self.key, Slot::Pass(Instant::now() + PASS_FOR));
            }
            parts
                .headers
                .insert("x-cache", HeaderValue::from_static("MISS"));
            let reason = if passing {
                format!(
                    "{reason} (resource marked uncacheable for {}s)",
                    PASS_FOR.as_secs()
                )
            } else {
                reason
            };
            annotate(&mut parts.headers, cfg.debug, &reason);
            return hyper::Response::from_parts(parts, body);
        }

        // On lit le corps pour le garder. Taille annoncée : déjà bornée.
        // Réponse en flux : lue trame par trame tant qu'elle reste sous
        // `max_object_size` ; au-delà, ce qui a été lu est renvoyé suivi du
        // reste du flux, sans rien garder.
        let max = cfg.max_object_size() as usize;
        let mut body = body;
        let mut buf = bytes::BytesMut::new();
        loop {
            match body.frame().await {
                None => break,
                Some(Ok(frame)) => {
                    let Ok(data) = frame.into_data() else {
                        continue; // trailers : ignorés, comme ailleurs
                    };
                    buf.extend_from_slice(&data);
                    if buf.len() > max {
                        self.cache
                            .slots
                            .insert(self.key, Slot::Pass(Instant::now() + PASS_FOR));
                        parts
                            .headers
                            .insert("x-cache", HeaderValue::from_static("MISS"));
                        annotate(
                            &mut parts.headers,
                            cfg.debug,
                            &format!(
                                "too large: chunked response over max_object_size {}",
                                cfg.max_object_size()
                            ),
                        );
                        let head = buf.freeze();
                        let rest = http_body_util::BodyStream::new(body);
                        let stream = futures_util::StreamExt::chain(
                            futures_util::stream::once(async move {
                                Ok::<_, hyper::Error>(hyper::body::Frame::data(head))
                            }),
                            rest,
                        );
                        return hyper::Response::from_parts(
                            parts,
                            BodyExt::boxed(http_body_util::StreamBody::new(stream)),
                        );
                    }
                }
                Some(Err(e)) => {
                    annotate(&mut parts.headers, cfg.debug, "backend body interrupted");
                    // Corps interrompu : rien n'est gardé ; le client reçoit
                    // ce qui était arrivé, puis l'erreur, comme sans cache.
                    let head = buf.freeze();
                    let stream = futures_util::StreamExt::chain(
                        futures_util::stream::once(async move {
                            Ok::<_, hyper::Error>(hyper::body::Frame::data(head))
                        }),
                        futures_util::stream::once(async move {
                            Err::<hyper::body::Frame<Bytes>, hyper::Error>(e)
                        }),
                    );
                    return hyper::Response::from_parts(
                        parts,
                        BodyExt::boxed(http_body_util::StreamBody::new(stream)),
                    );
                }
            }
        }
        let bytes = buf.freeze();
        // Le corps est maintenant entier : la copie gardée a une taille
        // fixe, l'encodage en flux de la réponse d'origine ne s'applique
        // plus.
        parts.headers.remove(header::TRANSFER_ENCODING);
        let now = Instant::now();
        let fresh = fresh.unwrap_or(Duration::ZERO);
        let initial_age = parts
            .headers
            .get(header::AGE)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let fresh = fresh.saturating_sub(Duration::from_secs(initial_age));
        let vary = vary_names
            .unwrap_or_default()
            .into_iter()
            .map(|n| {
                let v = self.request_headers.get(&n).cloned();
                (n, v)
            })
            .collect();
        let entry = Arc::new(Cached {
            status: parts.status,
            headers: parts.headers.clone(),
            body: bytes.clone(),
            stored_at: now,
            initial_age,
            fresh_until: now + fresh,
            keep_until: now
                + fresh
                + if has_validator {
                    KEEP_STALE_FOR
                } else {
                    Duration::ZERO
                },
            shared_explicit,
            always_revalidate: d.no_cache,
            vary,
        });
        self.insert_variant(entry);

        parts
            .headers
            .insert("x-cache", HeaderValue::from_static("MISS"));
        annotate(
            &mut parts.headers,
            cfg.debug,
            &format!(
                "stored for {}s{}",
                fresh.as_secs(),
                if self.forced {
                    " (client asked for a fresh response: no-cache)"
                } else {
                    ""
                }
            ),
        );
        let body = Full::new(bytes)
            .map_err(|e: std::convert::Infallible| match e {})
            .boxed();
        hyper::Response::from_parts(parts, body)
    }

    fn insert_variant(&self, entry: Arc<Cached>) {
        let mut variants = match self.cache.slots.get(&self.key) {
            Some(Slot::Variants(vs)) => vs,
            _ => Vec::new(),
        };
        let same_vary = |c: &Arc<Cached>| {
            c.vary.len() == entry.vary.len() && c.vary.iter().zip(&entry.vary).all(|(a, b)| a == b)
        };
        variants.retain(|c| !same_vary(c) && c.keep_until > Instant::now());
        variants.insert(0, entry);
        variants.truncate(MAX_VARIANTS);
        self.cache.slots.insert(self.key, Slot::Variants(variants));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut m = HeaderMap::new();
        for (k, v) in pairs {
            m.append(HeaderName::from_static(k), HeaderValue::from_static(v));
        }
        m
    }

    #[test]
    fn parses_true_false_and_block() {
        let t: BackendCacheConfig = serde_yaml::from_str("true").unwrap();
        assert!(t.enabled && t.default_ttl == 0);
        let f: BackendCacheConfig = serde_yaml::from_str("false").unwrap();
        assert!(!f.enabled);
        let b: BackendCacheConfig = serde_yaml::from_str(
            "{ max_memory: \"8MB\", max_object_size: \"256KB\", default_ttl: 30 }",
        )
        .unwrap();
        assert!(b.enabled);
        assert_eq!(b.max_memory(), 8 * 1024 * 1024);
        assert_eq!(b.max_object_size(), 256 * 1024);
        assert!(serde_yaml::from_str::<BackendCacheConfig>("{ max_mem: 1 }").is_err());
        assert!(!b.debug);
        let d: BackendCacheConfig = serde_yaml::from_str("{ debug: true }").unwrap();
        assert!(d.enabled && d.debug);
    }

    #[test]
    fn directives_and_freshness() {
        let d = directives(&h(&[("cache-control", "public, max-age=60, s-maxage=120")]));
        assert!(d.public && d.max_age == Some(60) && d.s_maxage == Some(120));
        // s-maxage wins for a shared cache.
        assert_eq!(
            freshness(&HeaderMap::new(), &d, 0),
            Some(Duration::from_secs(120))
        );
        // Expires relative to Date.
        let m = h(&[
            ("date", "Sun, 06 Nov 1994 08:49:37 GMT"),
            ("expires", "Sun, 06 Nov 1994 08:50:37 GMT"),
        ]);
        assert_eq!(
            freshness(&m, &directives(&m), 0),
            Some(Duration::from_secs(60))
        );
        // Invalid Expires: already expired.
        let m = h(&[("expires", "0")]);
        assert_eq!(freshness(&m, &directives(&m), 0), Some(Duration::ZERO));
        // Nothing at all: default_ttl only.
        assert_eq!(
            freshness(&HeaderMap::new(), &Directives::default(), 0),
            None
        );
        assert_eq!(
            freshness(&HeaderMap::new(), &Directives::default(), 30),
            Some(Duration::from_secs(30))
        );
        // default_ttl never overrides a backend that spoke (e.g. no-cache).
        let m = h(&[("cache-control", "no-cache")]);
        assert_eq!(freshness(&m, &directives(&m), 30), None);
    }

    #[test]
    fn authenticated_requests() {
        assert!(!is_authenticated(&h(&[("accept", "text/html")])));
        assert!(is_authenticated(&h(&[("authorization", "Bearer x")])));
        assert!(is_authenticated(&h(&[("cookie", "a=b")])));
        assert!(is_authenticated(&h(&[("x-user", "alice")])));
    }
}
