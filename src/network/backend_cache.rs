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
//!
//! # force_cache
//!
//! `force_cache: true` (avec `ttl`) : ProxyAuth garde les réponses
//! pendant `ttl` secondes **même si le backend l'interdit** (`no-store`,
//! `private`, `no-cache`, `max-age=0`, aucun en-tête). Restent exclus :
//! les statuts d'erreur, les réponses trop grosses, les méthodes autres
//! que `GET`/`HEAD`. Deux garde-fous :
//! * le client non plus n'a pas son mot à dire : `Cache-Control: no-cache`
//!   (rechargement du navigateur), `Pragma: no-cache` ou `no-store` côté
//!   requête n'empêchent pas de servir la copie ;
//! * une requête qui porte une identité reçoit **sa propre copie** (clé
//!   dérivée de `X-User`, sinon `Authorization`, sinon `Cookie`) : un
//!   utilisateur ne voit jamais la page d'un autre ;
//! * `Set-Cookie` n'est jamais gardé : il part avec la réponse qui l'a
//!   reçu, pas avec les copies.
//!
//! `identity_cookie: <nom>` : seul ce cookie identifie l'utilisateur (sa
//! session) ; les autres (`_csrf`, statistiques) ne créent plus une copie
//! par valeur, et une requête sans lui est anonyme. `shared: true` (avec
//! `force_cache`) : une seule copie pour tous, identité ignorée — pour un
//! contenu identique pour tout le monde.
//!
//! # type: ram | disk
//!
//! `ram` (défaut) : en mémoire, perdu au redémarrage. `disk` : LMDB sous
//! `/opt/proxyauth/db/backend_cache/<cache>/`, conservé au redémarrage ;
//! `max_size` (ou `max_memory`) en fixe la taille. Les dates étant
//! enregistrées en temps Unix, le TTL est respecté de la même façon dans
//! les deux cas.

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
    /// Où sont gardées les réponses : `ram` (défaut) ou `disk` (LMDB sous
    /// `/opt/proxyauth/db/backend_cache/`, conservé après un redémarrage).
    #[serde(rename = "type")]
    pub kind: StoreKind,
    /// Garder les réponses même si le backend l'interdit (`no-store`,
    /// `private`, pas d'en-tête…), pendant `ttl` secondes. Voir
    /// [`force_cache`](self#force_cache).
    pub force_cache: bool,
    /// Le cookie qui identifie un utilisateur (son cookie de session, par
    /// exemple `i_like_gitea`). Seul lui distingue les copies : les autres
    /// cookies (`_csrf`, statistiques…) sont ignorés, et une requête sans
    /// lui compte comme anonyme. Sans ce réglage, tout l'en-tête `Cookie`
    /// sert d'identité — et un cookie qui change à chaque page empêche
    /// toute réutilisation.
    pub identity_cookie: Option<String>,
    /// Avec `force_cache` : une seule copie pour **tous** les visiteurs,
    /// cookies et identité ignorés. Seulement pour un contenu identique
    /// pour tout le monde.
    pub shared: bool,
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
            kind: StoreKind::Ram,
            force_cache: false,
            identity_cookie: None,
            shared: false,
            inherited_from_group: None,
        }
    }
}

/// `type:` de `cache_backend`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum StoreKind {
    #[default]
    Ram,
    Disk,
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
    #[serde(default, alias = "ttl")]
    default_ttl: u64,
    #[serde(default)]
    debug: bool,
    #[serde(default, rename = "type")]
    kind: StoreKind,
    #[serde(default)]
    force_cache: bool,
    #[serde(default)]
    identity_cookie: Option<String>,
    #[serde(default)]
    shared: bool,
    /// Taille du cache ; synonyme de `max_memory` (plus parlant en
    /// `type: disk`).
    #[serde(default)]
    max_size: Option<ByteSize>,
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
                max_memory: b.max_memory.or(b.max_size),
                max_object_size: b.max_object_size,
                default_ttl: b.default_ttl,
                debug: b.debug,
                kind: b.kind,
                force_cache: b.force_cache,
                identity_cookie: b.identity_cookie,
                shared: b.shared,
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
            "type {}, size {} MB, max_object_size {} KB, ttl {}s{}{}",
            if self.kind == StoreKind::Disk {
                "disk (LMDB)"
            } else {
                "ram"
            },
            self.max_memory() / (1024 * 1024),
            self.max_object_size() / 1024,
            self.default_ttl,
            match (
                self.force_cache,
                self.shared,
                self.identity_cookie.as_deref()
            ) {
                (true, true, _) => ", force_cache shared by all visitors".to_string(),
                (true, false, Some(c)) => format!(", force_cache per user (cookie {c})"),
                (true, false, None) => ", force_cache (backend directives ignored)".to_string(),
                (false, _, Some(c)) => format!(", identity cookie {c}"),
                _ => String::new(),
            },
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
    slots: SlotStore,
    inflight: DashMap<[u8; 32], Arc<tokio::sync::Mutex<()>>>,
}

impl BackendCache {
    fn new(cfg: BackendCacheConfig, scope: &str) -> Result<Self, String> {
        let budget = cfg.max_memory().max(1024 * 1024);
        let estimated = (budget / (16 * 1024)).clamp(64, 1 << 20) as usize;
        let slots = match cfg.kind {
            StoreKind::Ram => SlotStore::Ram(quick_cache::sync::Cache::with_weighter(
                estimated,
                budget,
                SlotWeighter,
            )),
            StoreKind::Disk => SlotStore::Disk {
                db: Arc::new(DiskStore::open(scope, budget)?),
                passes: quick_cache::sync::Cache::new(4096),
            },
        };
        Ok(Self {
            slots,
            inflight: DashMap::new(),
            cfg,
        })
    }
}

/// Le stockage d'un cache. Le reste du module ne voit que `get` et
/// `insert` : la RAM et le disque se comportent pareil, TTL compris.
enum SlotStore {
    Ram(quick_cache::sync::Cache<[u8; 32], Slot, SlotWeighter>),
    /// Réponses dans LMDB ; les marques « à ne pas mettre en cache » (10 s)
    /// restent en mémoire, elles n'ont pas à survivre à un redémarrage.
    Disk {
        db: Arc<DiskStore>,
        passes: quick_cache::sync::Cache<[u8; 32], Instant>,
    },
}

impl SlotStore {
    fn get(&self, key: &[u8; 32]) -> Option<Slot> {
        match self {
            SlotStore::Ram(c) => c.get(key),
            SlotStore::Disk { db, passes } => {
                if let Some(until) = passes.get(key) {
                    if until > Instant::now() {
                        return Some(Slot::Pass(until));
                    }
                    passes.remove(key);
                }
                db.get(key).map(Slot::Variants)
            }
        }
    }

    fn insert(&self, key: [u8; 32], slot: Slot) {
        match self {
            SlotStore::Ram(c) => c.insert(key, slot),
            SlotStore::Disk { db, passes } => match slot {
                Slot::Pass(until) => passes.insert(key, until),
                Slot::Variants(vs) => {
                    passes.remove(&key);
                    db.put(&key, &vs);
                }
            },
        }
    }
}

// ───────────────────────────────────────────── disk (LMDB)

const DISK_ROOT: &str = "/opt/proxyauth/db/backend_cache";
const DISK_FORMAT: u8 = 1;

/// Réponses gardées sur disque, une base LMDB par cache. Les dates sont
/// enregistrées en temps Unix, pour rester valables après un redémarrage :
/// une entrée périmée n'est jamais servie, et une tâche de fond les
/// supprime chaque minute.
pub struct DiskStore {
    path: std::path::PathBuf,
    size: u64,
    /// Ouvert au premier usage, donc après l'abandon des privilèges root :
    /// les fichiers appartiennent à `run_user`, qui peut les écrire.
    opened: OnceLock<Option<(lmdb::Environment, lmdb::Database)>>,
}

impl DiskStore {
    fn open(scope: &str, size: u64) -> Result<Self, String> {
        let path =
            std::path::Path::new(DISK_ROOT).join(&blake3::hash(scope.as_bytes()).to_hex()[..16]);
        Ok(Self {
            path,
            size: size.max(16 * 1024 * 1024),
            opened: OnceLock::new(),
        })
    }

    fn handle(&self) -> Option<(&lmdb::Environment, lmdb::Database)> {
        self.opened
            .get_or_init(|| match self.open_now() {
                Ok(h) => Some(h),
                Err(e) => {
                    tracing::error!("cache_backend: {e} — this cache stays empty");
                    None
                }
            })
            .as_ref()
            .map(|(env, db)| (env, *db))
    }

    fn open_now(&self) -> Result<(lmdb::Environment, lmdb::Database), String> {
        std::fs::create_dir_all(&self.path)
            .map_err(|e| format!("cannot create {}: {e}", self.path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(DISK_ROOT, std::fs::Permissions::from_mode(0o700));
            let _ = std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o700));
        }
        let env = lmdb::Environment::new()
            .set_max_dbs(1)
            .set_map_size(self.size as usize)
            // Un cache se reconstruit : inutile de forcer chaque écriture
            // sur le disque, c'est ce qui coûterait le plus cher.
            .set_flags(lmdb::EnvironmentFlags::NO_SYNC | lmdb::EnvironmentFlags::NO_META_SYNC)
            .open(&self.path)
            .map_err(|e| format!("cannot open LMDB at {}: {e}", self.path.display()))?;
        let db = env
            .create_db(Some("responses"), lmdb::DatabaseFlags::empty())
            .map_err(|e| {
                format!(
                    "cannot create LMDB database at {}: {e}",
                    self.path.display()
                )
            })?;
        Ok((env, db))
    }

    fn get(&self, key: &[u8; 32]) -> Option<Vec<Arc<Cached>>> {
        use lmdb::Transaction;
        let (env, db) = self.handle()?;
        let txn = env.begin_ro_txn().ok()?;
        let bytes = txn.get(db, key).ok()?;
        let variants = decode_variants(bytes)?;
        let now = Instant::now();
        let live: Vec<Arc<Cached>> = variants
            .into_iter()
            .filter(|c| c.keep_until > now)
            .collect();
        (!live.is_empty()).then_some(live)
    }

    fn put(&self, key: &[u8; 32], variants: &[Arc<Cached>]) {
        use lmdb::{Transaction, WriteFlags};
        let Some((env, db)) = self.handle() else {
            return;
        };
        let bytes = encode_variants(variants);
        let write = |bytes: &[u8]| -> Result<(), lmdb::Error> {
            let mut txn = env.begin_rw_txn()?;
            txn.put(db, key, &bytes, WriteFlags::empty())?;
            txn.commit()
        };
        match write(&bytes) {
            Ok(()) => {}
            Err(lmdb::Error::MapFull) => {
                // Plein : on retire ce qui a expiré ; si cela ne suffit
                // pas, on repart d'un cache vide plutôt que de refuser
                // indéfiniment toute nouvelle entrée.
                if self.purge_expired() == 0 {
                    self.clear();
                }
                if let Err(e) = write(&bytes) {
                    tracing::warn!(
                        "cache_backend: disk cache at {} is full: {e}",
                        self.path.display()
                    );
                }
            }
            Err(e) => tracing::warn!(
                "cache_backend: disk write failed at {}: {e}",
                self.path.display()
            ),
        }
    }

    /// Supprime les entrées dont toutes les variantes ont expiré.
    fn purge_expired(&self) -> usize {
        use lmdb::{Cursor, Transaction};
        let Some((env, db)) = self.handle() else {
            return 0;
        };
        let expired: Vec<Vec<u8>> = {
            let Ok(txn) = env.begin_ro_txn() else {
                return 0;
            };
            let Ok(mut cursor) = txn.open_ro_cursor(db) else {
                return 0;
            };
            let now = unix_ms();
            cursor
                .iter()
                .filter_map(|item| item.ok())
                .filter(|(_, v)| keep_until_ms(v).is_none_or(|k| k <= now))
                .map(|(k, _)| k.to_vec())
                .collect()
        };
        if expired.is_empty() {
            return 0;
        }
        if let Ok(mut txn) = env.begin_rw_txn() {
            for k in &expired {
                let _ = txn.del(db, k, None);
            }
            let _ = txn.commit();
        }
        expired.len()
    }

    fn clear(&self) {
        use lmdb::Transaction;
        let Some((env, db)) = self.handle() else {
            return;
        };
        if let Ok(mut txn) = env.begin_rw_txn() {
            let _ = txn.clear_db(db);
            let _ = txn.commit();
        }
    }
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// `Instant` ↔ temps Unix (ms), par rapport à maintenant.
fn instant_to_ms(t: Instant) -> u64 {
    let now_i = Instant::now();
    let now_ms = unix_ms();
    if t >= now_i {
        now_ms + (t - now_i).as_millis() as u64
    } else {
        now_ms.saturating_sub((now_i - t).as_millis() as u64)
    }
}

fn ms_to_instant(ms: u64) -> Instant {
    let now_i = Instant::now();
    let now_ms = unix_ms();
    if ms >= now_ms {
        now_i + Duration::from_millis(ms - now_ms)
    } else {
        now_i
            .checked_sub(Duration::from_millis(now_ms - ms))
            .unwrap_or(now_i)
    }
}

struct Writer(Vec<u8>);
impl Writer {
    fn u8(&mut self, v: u8) {
        self.0.push(v);
    }
    fn u16(&mut self, v: u16) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }
    fn bytes(&mut self, b: &[u8]) {
        self.u32(b.len() as u32);
        self.0.extend_from_slice(b);
    }
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Some(a)
    }
    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_be_bytes(self.take(2)?.try_into().ok()?))
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes(self.take(4)?.try_into().ok()?))
    }
    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_be_bytes(self.take(8)?.try_into().ok()?))
    }
    fn bytes(&mut self) -> Option<&'a [u8]> {
        let n = self.u32()? as usize;
        self.take(n)
    }
}

/// Format : version, plus grande date de conservation (pour la purge sans
/// tout décoder), nombre de variantes, puis chaque variante.
fn encode_variants(variants: &[Arc<Cached>]) -> Vec<u8> {
    let mut w = Writer(Vec::new());
    w.u8(DISK_FORMAT);
    w.u64(
        variants
            .iter()
            .map(|c| instant_to_ms(c.keep_until))
            .max()
            .unwrap_or(0),
    );
    w.u16(variants.len() as u16);
    for c in variants {
        w.u16(c.status.as_u16());
        w.u8(u8::from(c.shared_explicit) | (u8::from(c.always_revalidate) << 1));
        w.u64(instant_to_ms(c.stored_at));
        w.u64(c.initial_age);
        w.u64(instant_to_ms(c.fresh_until));
        w.u64(instant_to_ms(c.keep_until));
        w.u32(c.headers.len() as u32);
        for (k, v) in &c.headers {
            w.bytes(k.as_str().as_bytes());
            w.bytes(v.as_bytes());
        }
        w.u16(c.vary.len() as u16);
        for (k, v) in &c.vary {
            w.bytes(k.as_str().as_bytes());
            match v {
                Some(v) => {
                    w.u8(1);
                    w.bytes(v.as_bytes());
                }
                None => w.u8(0),
            }
        }
        w.bytes(&c.body);
    }
    w.0
}

fn keep_until_ms(bytes: &[u8]) -> Option<u64> {
    let mut r = Reader(bytes);
    (r.u8()? == DISK_FORMAT).then_some(())?;
    r.u64()
}

fn decode_variants(bytes: &[u8]) -> Option<Vec<Arc<Cached>>> {
    let mut r = Reader(bytes);
    if r.u8()? != DISK_FORMAT {
        return None;
    }
    r.u64()?;
    let n = r.u16()?;
    let mut out = Vec::with_capacity(n as usize);
    for _ in 0..n {
        let status = StatusCode::from_u16(r.u16()?).ok()?;
        let flags = r.u8()?;
        let stored_at = ms_to_instant(r.u64()?);
        let initial_age = r.u64()?;
        let fresh_until = ms_to_instant(r.u64()?);
        let keep_until = ms_to_instant(r.u64()?);
        let mut headers = HeaderMap::new();
        for _ in 0..r.u32()? {
            let k = HeaderName::from_bytes(r.bytes()?).ok()?;
            let v = HeaderValue::from_bytes(r.bytes()?).ok()?;
            headers.append(k, v);
        }
        let mut vary = Vec::new();
        for _ in 0..r.u16()? {
            let k = HeaderName::from_bytes(r.bytes()?).ok()?;
            let v = match r.u8()? {
                1 => Some(HeaderValue::from_bytes(r.bytes()?).ok()?),
                _ => None,
            };
            vary.push((k, v));
        }
        let body = Bytes::copy_from_slice(r.bytes()?);
        out.push(Arc::new(Cached {
            status,
            headers,
            body,
            stored_at,
            initial_age,
            fresh_until,
            keep_until,
            shared_explicit: flags & 1 != 0,
            always_revalidate: flags & 2 != 0,
            vary,
        }));
    }
    Some(out)
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
pub fn init_backend_caches(routes: &[RouteRule]) -> Result<Vec<String>, String> {
    let mut by_scope: HashMap<String, Arc<BackendCache>> = HashMap::new();
    let mut summary = Vec::new();
    let mut disks = Vec::new();
    for rule in routes {
        let Some(cfg) = rule.cache_backend.as_ref().filter(|c| c.enabled) else {
            continue;
        };
        let place = format!(
            "routes.yml: route `{}` (vhost {:?}): cache_backend",
            rule.prefix, rule.vhost
        );
        if cfg.shared && !cfg.force_cache {
            return Err(format!(
                "{place}: `shared: true` only applies with `force_cache: true` — without it, the backend decides what is shared (Cache-Control: public)"
            ));
        }
        if cfg.shared && cfg.identity_cookie.is_some() {
            return Err(format!(
                "{place}: `shared` and `identity_cookie` contradict each other — one copy for everyone, or one per user"
            ));
        }
        if let Some(name) = cfg.identity_cookie.as_deref() {
            if name.is_empty()
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
            {
                return Err(format!(
                    "{place}: `identity_cookie` {name:?} is not a valid cookie name"
                ));
            }
        }
        if cfg.force_cache && cfg.default_ttl == 0 {
            return Err(format!(
                "routes.yml: route `{}` (vhost {:?}): cache_backend: `force_cache: true` needs a `ttl` (seconds) — ProxyAuth decides how long responses are kept",
                rule.prefix, rule.vhost
            ));
        }
        let scope = scope_of(rule, cfg);
        if by_scope.contains_key(&scope) {
            continue;
        }
        let cache = Arc::new(BackendCache::new(cfg.clone(), &scope)?);
        if let SlotStore::Disk { db, .. } = &cache.slots {
            summary.push(format!(
                "cache_backend {scope}: {} — {}",
                cfg.describe(),
                db.path.display()
            ));
            disks.push(db.clone());
        } else {
            summary.push(format!("cache_backend {scope}: {}", cfg.describe()));
        }
        by_scope.insert(scope, cache);
    }
    if !disks.is_empty() {
        // Les entrées expirées ne sont jamais servies ; cette tâche libère
        // leur place sur le disque.
        let _ = std::thread::Builder::new()
            .name("backend-cache-purge".into())
            .spawn(move || {
                loop {
                    std::thread::sleep(Duration::from_secs(60));
                    for d in &disks {
                        d.purge_expired();
                    }
                }
            });
    }
    let _ = REGISTRY.set(Registry { by_scope });
    Ok(summary)
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
#[cfg(test)]
fn is_authenticated(req: &HeaderMap) -> bool {
    is_authenticated_with(req, None)
}

/// La requête porte une identité. Avec `identity_cookie`, seul ce cookie
/// compte : une requête qui n'a que `_csrf` ou des cookies de statistiques
/// est anonyme.
fn is_authenticated_with(req: &HeaderMap, identity_cookie: Option<&str>) -> bool {
    req.contains_key(header::AUTHORIZATION)
        || req.contains_key("x-user")
        || match identity_cookie {
            Some(name) => cookie_value(req, name).is_some(),
            None => req.contains_key(header::COOKIE),
        }
}

/// Valeur d'un cookie de la requête (premier trouvé, tous en-têtes
/// `Cookie` confondus).
fn cookie_value<'a>(req: &'a HeaderMap, name: &str) -> Option<&'a str> {
    req.get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.trim())
        .filter(|v| !v.is_empty())
}

/// L'identité qui distingue les copies sous `force_cache`.
fn identity_of<'a>(req: &'a HeaderMap, identity_cookie: Option<&str>) -> &'a [u8] {
    if let Some(u) = req.get("x-user") {
        return u.as_bytes();
    }
    if let Some(v) = identity_cookie.and_then(|name| cookie_value(req, name)) {
        return v.as_bytes();
    }
    if let Some(a) = req.get(header::AUTHORIZATION) {
        return a.as_bytes();
    }
    if identity_cookie.is_none() {
        if let Some(c) = req.get(header::COOKIE) {
            return c.as_bytes();
        }
    }
    b""
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
    /// Sous `force_cache` : copie partagée ou propre à l'utilisateur (pour
    /// `X-Cache-Reason`).
    copy_scope: Option<&'static str>,
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
                copy_scope: None,
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
    // force_cache : c'est le proxy qui décide, ni le backend ni le client.
    // Un rechargement du navigateur (`Cache-Control: no-cache`, `Pragma`)
    // ou un `no-store` client ne font donc pas repartir la requête vers le
    // backend : la copie est servie tant que son `ttl` court.
    let forced = cache.cfg.force_cache;
    if req_cc.no_store && !forced {
        return bypass("request: Cache-Control no-store");
    }
    let force_fresh = !forced
        && (req_cc.no_cache
            || req_cc.max_age == Some(0)
            || request
                .get(header::PRAGMA)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.to_ascii_lowercase().contains("no-cache")));
    let identity_cookie = cache.cfg.identity_cookie.as_deref();
    let mut authenticated = is_authenticated_with(request, identity_cookie);
    let mut key = base_key(true, url, request);
    let mut copy_scope: Option<&'static str> = None;
    if cache.cfg.force_cache && cache.cfg.shared {
        // `shared` : une seule copie pour tout le monde, identité ignorée.
        authenticated = false;
        copy_scope = Some("shared by all visitors");
    } else if cache.cfg.force_cache && authenticated {
        // force_cache : le backend n'a plus son mot à dire sur le partage.
        // Une requête qui porte une identité reçoit donc sa propre copie —
        // clé dérivée de cette identité — et ne voit jamais celle d'un
        // autre. Avec `identity_cookie`, seul ce cookie la définit.
        let identity = identity_of(request, identity_cookie);
        copy_scope = Some("copy for this user");
        let mut h = blake3::Hasher::new();
        h.update(&key);
        h.update(b"\nidentity\n");
        h.update(identity);
        key = *h.finalize().as_bytes();
        authenticated = false;
    }
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
        copy_scope,
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
        let forced = cfg.force_cache;
        // force_cache : la durée est `ttl`, quoi que dise le backend, et
        // `Vary: *` est ignoré (les autres `Vary` restent respectés).
        let vary_names = if forced {
            vary_names.or_else(|| Some(Vec::new()))
        } else {
            vary_names
        };
        let fresh = if forced {
            Some(Duration::from_secs(cfg.default_ttl))
        } else {
            freshness(&parts.headers, &d, cfg.default_ttl)
        };
        let has_validator = parts.headers.contains_key(header::ETAG)
            || parts.headers.contains_key(header::LAST_MODIFIED);
        let shared_explicit = d.public || d.s_maxage.is_some();

        // Première règle non remplie, ou `None` si la réponse peut être
        // gardée. Taille annoncée : bornée d'avance ; réponse en flux (sans
        // `Content-Length`) : lue jusqu'à `max_object_size`, plus bas.
        let refused: Option<String> = if forced {
            // Seules restent les limites qui protègent ProxyAuth lui-même :
            // pas d'erreurs gardées, taille bornée.
            if !CACHEABLE_STATUS.contains(&parts.status.as_u16()) {
                Some(format!("status {} is not cacheable", parts.status.as_u16()))
            } else if let Some(l) = length.filter(|&l| l > cfg.max_object_size()) {
                Some(format!(
                    "too large: {l} bytes > max_object_size {}",
                    cfg.max_object_size()
                ))
            } else {
                None
            }
        } else if !CACHEABLE_STATUS.contains(&parts.status.as_u16()) {
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
        // Un cookie posé par le backend n'est destiné qu'à ce client-ci : il
        // part avec cette réponse, jamais avec la copie gardée.
        let mut stored_headers = parts.headers.clone();
        stored_headers.remove(header::SET_COOKIE);
        let entry = Arc::new(Cached {
            status: parts.status,
            headers: stored_headers,
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
            shared_explicit: shared_explicit || forced,
            always_revalidate: d.no_cache && !forced,
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
                "stored for {}s{}{}{}",
                fresh.as_secs(),
                if forced {
                    " (force_cache: backend directives ignored)"
                } else {
                    ""
                },
                self.copy_scope
                    .map(|c| format!(" ({c})"))
                    .unwrap_or_default(),
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
        let f: BackendCacheConfig = serde_yaml::from_str(
            "{ type: disk, force_cache: true, ttl: 120, max_size: \"256MB\" }",
        )
        .unwrap();
        assert_eq!(f.kind, StoreKind::Disk);
        assert!(f.force_cache);
        assert_eq!(f.default_ttl, 120);
        assert_eq!(f.max_memory(), 256 * 1024 * 1024);
        assert_eq!(BackendCacheConfig::default().kind, StoreKind::Ram);
        assert!(serde_yaml::from_str::<BackendCacheConfig>("{ type: tape }").is_err());
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
    fn disk_format_roundtrip_keeps_ttl() {
        let now = Instant::now();
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html"));
        headers.append("x-multi", HeaderValue::from_static("a"));
        headers.append("x-multi", HeaderValue::from_static("b"));
        let c = Arc::new(Cached {
            status: StatusCode::OK,
            headers,
            body: Bytes::from_static(b"hello"),
            stored_at: now,
            initial_age: 3,
            fresh_until: now + Duration::from_secs(60),
            keep_until: now + Duration::from_secs(60),
            shared_explicit: true,
            always_revalidate: false,
            vary: vec![
                (
                    header::ACCEPT_LANGUAGE,
                    Some(HeaderValue::from_static("fr")),
                ),
                (header::ACCEPT, None),
            ],
        });
        let bytes = encode_variants(&[c.clone()]);
        let back = decode_variants(&bytes).unwrap();
        assert_eq!(back.len(), 1);
        let b = &back[0];
        assert_eq!(b.status, StatusCode::OK);
        assert_eq!(b.body, c.body);
        assert_eq!(b.headers.get_all("x-multi").iter().count(), 2);
        assert_eq!(b.vary, c.vary);
        assert!(b.shared_explicit && !b.always_revalidate && b.initial_age == 3);
        // Lifetime survives the round trip (to the millisecond).
        let left = b
            .fresh_until
            .saturating_duration_since(Instant::now())
            .as_secs();
        assert!((58..=60).contains(&left), "{left}");
        assert!(keep_until_ms(&bytes).unwrap() > unix_ms());
        assert!(
            decode_variants(&bytes[..bytes.len() - 1]).is_none(),
            "truncated data is rejected"
        );
    }

    #[test]
    fn identity_cookie_ignores_other_cookies() {
        let with = |c: &'static str| h(&[("cookie", c)]);
        // Only the session cookie makes a request "signed in".
        assert!(!is_authenticated_with(
            &with("_csrf=abc; lang=fr"),
            Some("i_like_gitea")
        ));
        assert!(is_authenticated_with(
            &with("_csrf=abc; i_like_gitea=s1"),
            Some("i_like_gitea")
        ));
        assert!(
            is_authenticated_with(&with("_csrf=abc"), None),
            "without identity_cookie any cookie counts"
        );
        // A rotating _csrf does not change the identity.
        assert_eq!(
            identity_of(&with("_csrf=one; i_like_gitea=s1"), Some("i_like_gitea")),
            identity_of(&with("i_like_gitea=s1; _csrf=two"), Some("i_like_gitea"))
        );
        assert_ne!(
            identity_of(&with("i_like_gitea=s1"), Some("i_like_gitea")),
            identity_of(&with("i_like_gitea=s2"), Some("i_like_gitea"))
        );
        // X-User (set by ProxyAuth) wins over cookies.
        let mut m = with("i_like_gitea=s1");
        m.insert("x-user", HeaderValue::from_static("alice"));
        assert_eq!(identity_of(&m, Some("i_like_gitea")), b"alice");
        // Names must match exactly.
        assert_eq!(
            cookie_value(&with("i_like_gitea_x=1"), "i_like_gitea"),
            None
        );
        let s: BackendCacheConfig =
            serde_yaml::from_str("{ force_cache: true, ttl: 60, shared: true }").unwrap();
        assert!(s.shared && s.identity_cookie.is_none());
        let i: BackendCacheConfig =
            serde_yaml::from_str("{ force_cache: true, ttl: 60, identity_cookie: i_like_gitea }")
                .unwrap();
        assert_eq!(i.identity_cookie.as_deref(), Some("i_like_gitea"));
    }

    #[test]
    fn authenticated_requests() {
        assert!(!is_authenticated(&h(&[("accept", "text/html")])));
        assert!(is_authenticated(&h(&[("authorization", "Bearer x")])));
        assert!(is_authenticated(&h(&[("cookie", "a=b")])));
        assert!(is_authenticated(&h(&[("x-user", "alice")])));
    }
}
