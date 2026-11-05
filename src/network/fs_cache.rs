//! Cache mémoire des fichiers servis par les routes statiques et les
//! pages d'erreur.
//!
//! # Pourquoi
//!
//! Servir un fichier statique coûtait jusqu'à cinq opérations sur le
//! système de fichiers par requête (`canonicalize` ×2, `metadata` ×2,
//! `read`), chacune via `tokio::fs`, donc chacune avec un aller-retour
//! vers le pool de threads bloquants de tokio. Le contenu, lui, ne
//! change presque jamais.
//!
//! # Comment
//!
//! * **Rien n'est chargé au démarrage.** Un fichier n'entre en mémoire
//!   qu'à sa première demande, et seulement s'il passe les filtres de
//!   `internal_cache` (taille, extension, type MIME — voir
//!   `config::internal_cache`).
//! * **Chargé une seule fois** : si plusieurs requêtes demandent en même
//!   temps un fichier absent du cache, une seule le lit ; les autres
//!   attendent et reçoivent la même copie.
//! * **Les autres fichiers sont envoyés en flux depuis le disque**, par
//!   blocs de 64 Ko : un téléchargement de 2 Go coûte quelques dizaines
//!   de Ko de mémoire, pas 2 Go (c'était le cas avant : chaque requête
//!   lisait le fichier entier en mémoire).
//! * Résolutions de chemin, types (fichier / dossier) et contenus sont
//!   gardés en mémoire.
//! * Une entrée est **revalidée au plus une fois par
//!   [`REVALIDATE_EVERY`]** : pour un contenu, un seul `stat` compare la
//!   taille et la date de modification ; s'il a changé, il est relu. Une
//!   modification sur disque est donc visible en moins d'une seconde,
//!   sans redémarrage — pas d'invalidation manuelle à prévoir.
//! * Les échecs (fichier absent…) sont mémorisés aussi, une seconde :
//!   une rafale de requêtes vers des chemins inexistants ne se traduit
//!   pas en rafale d'appels système.
//! * Tout est borné : `internal_cache.max_file_size` par fichier,
//!   `internal_cache.max_memory` au total (éviction des moins utilisés),
//!   [`MAX_PATHS`] entrées de chemins. Les
//!   clés peuvent venir de requêtes arbitraires ; la mémoire, elle, ne
//!   peut pas grossir sans limite.
//! * Le contenu est un [`Bytes`] partagé : envoyer un fichier en cache ne
//!   le recopie pas.

use bytes::Bytes;
use once_cell::sync::Lazy;
use quick_cache::Weighter;
use quick_cache::sync::Cache;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

/// Délai maximal avant qu'une modification sur disque soit prise en compte.
pub const REVALIDATE_EVERY: Duration = Duration::from_secs(1);

/// Mémoire totale consacrée aux contenus, si `init` n'a pas été appelé.
pub const BYTES_BUDGET: u64 = crate::config::internal_cache::DEFAULT_MAX_MEMORY;

/// Entrées de résolution de chemin / type de fichier.
pub const MAX_PATHS: usize = 50_000;

/// Un fichier lu, avec de quoi détecter qu'il a changé.
#[derive(Debug)]
pub struct CachedFile {
    pub bytes: Bytes,
    pub len: u64,
    pub modified: Option<SystemTime>,
}

impl CachedFile {
    /// Validateur HTTP faible, dérivé de la taille et de la date de
    /// modification (même principe que nginx).
    pub fn etag(&self) -> String {
        let nanos = self
            .modified
            .and_then(|m| m.duration_since(SystemTime::UNIX_EPOCH).ok())
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        format!("W/\"{:x}-{:x}\"", self.len, nanos)
    }
}

#[derive(Clone)]
struct ContentEntry {
    file: Arc<CachedFile>,
    checked: Instant,
}

#[derive(Clone)]
struct ContentWeighter;

impl Weighter<PathBuf, ContentEntry> for ContentWeighter {
    fn weight(&self, key: &PathBuf, val: &ContentEntry) -> u64 {
        // Le chemin compte aussi : un très grand nombre de petits
        // fichiers ne doit pas contourner le budget.
        val.file.len + key.as_os_str().len() as u64 + 64
    }
}

/// Un cache de contenus de fichiers, avec son propre budget mémoire.
///
/// Il y en a un global (`internal_cache.max_memory` de config.json) et,
/// pour chaque vhost qui fixe son propre `max_memory` dans routes.yml,
/// un cache à lui (partagé par les routes du vhost).
pub struct FileCache {
    contents: Cache<PathBuf, ContentEntry, ContentWeighter>,
}

impl FileCache {
    pub fn with_budget(budget: u64) -> Self {
        // Estimation du nombre d'entrées pour dimensionner les tables : on
        // suppose des fichiers de ~16 Ko en moyenne, borné.
        let estimated = (budget / (16 * 1024)).clamp(64, 65_536) as usize;
        FileCache {
            contents: Cache::with_weighter(estimated, budget.max(1), ContentWeighter),
        }
    }
}

/// Tous les caches de fichiers, résolus au démarrage.
struct FilePools {
    global: Option<Arc<FileCache>>,
    /// vhost → (budget, cache). Une route qui fixe un `max_memory`
    /// différent de son groupe a son propre cache.
    by_vhost: std::collections::HashMap<Vec<String>, Vec<(u64, Arc<FileCache>)>>,
}

static POOLS: std::sync::OnceLock<FilePools> = std::sync::OnceLock::new();

/// Sans `init` (tests) : un cache global au budget par défaut.
static DEFAULT_POOL: Lazy<Arc<FileCache>> =
    Lazy::new(|| Arc::new(FileCache::with_budget(BYTES_BUDGET)));

/// Crée les caches de fichiers. À appeler une fois au démarrage, après
/// le chargement des routes.
///
/// Le cache global n'existe que si `internal_cache.enabled` vaut `true`
/// dans config.json ; un vhost qui active le cache sans fixer son propre
/// `max_memory` utilise ce budget global (le cache est alors créé pour
/// lui). Chaque `max_memory` de vhost s'ajoute au budget global.
pub fn init(
    global: &crate::config::internal_cache::InternalCacheConfig,
    routes: &[crate::config::config::RouteRule],
) {
    let _ = POOLS.set(FilePools::build(global, routes));
}

impl FilePools {
    fn build(
        global: &crate::config::internal_cache::InternalCacheConfig,
        routes: &[crate::config::config::RouteRule],
    ) -> Self {
        let global_enabled = global.enabled.unwrap_or(false);
        let mut needs_global = global_enabled;
        let mut by_vhost: std::collections::HashMap<Vec<String>, Vec<(u64, Arc<FileCache>)>> =
            std::collections::HashMap::new();
        for r in routes {
            let rc = r.internal_cache.as_ref();
            if !rc.and_then(|c| c.enabled).unwrap_or(global_enabled) {
                continue;
            }
            match rc.and_then(|c| c.max_memory).map(|b| b.0) {
                None => needs_global = true,
                Some(budget) => {
                    let entry = by_vhost.entry(r.vhost.clone()).or_default();
                    if !entry.iter().any(|(b, _)| *b == budget) {
                        entry.push((budget, Arc::new(FileCache::with_budget(budget))));
                    }
                }
            }
        }
        FilePools {
            global: needs_global.then(|| Arc::new(FileCache::with_budget(global.max_memory()))),
            by_vhost,
        }
    }

    fn pick(&self, rule: Option<&crate::config::config::RouteRule>) -> Option<Arc<FileCache>> {
        let own = rule.and_then(|r| {
            let budget = r.internal_cache.as_ref()?.max_memory?.0;
            self.by_vhost
                .get(&r.vhost)?
                .iter()
                .find(|(b, _)| *b == budget)
                .map(|(_, c)| c.clone())
        });
        own.or_else(|| self.global.clone())
    }
}

/// Le cache de fichiers d'une route : le sien (`max_memory` de son
/// vhost), sinon le global. `None` s'il n'y en a aucun.
pub fn pool_for(rule: Option<&crate::config::config::RouteRule>) -> Option<Arc<FileCache>> {
    match POOLS.get() {
        Some(p) => p.pick(rule),
        None => Some(DEFAULT_POOL.clone()),
    }
}

/// Résultat mémorisé d'un `canonicalize` ou d'un `metadata`.
#[derive(Clone)]
enum PathInfo {
    Resolved(PathBuf),
    Kind { is_file: bool, is_dir: bool },
    Failed(io::ErrorKind, String),
}

#[derive(Clone)]
struct PathEntry {
    info: PathInfo,
    checked: Instant,
}

#[derive(Clone, PartialEq, Eq, Hash)]
enum PathKey {
    Canonical(PathBuf),
    Kind(PathBuf),
}

static PATHS: Lazy<Cache<PathKey, PathEntry>> = Lazy::new(|| Cache::new(MAX_PATHS));

fn fresh(checked: Instant) -> bool {
    checked.elapsed() < REVALIDATE_EVERY
}

fn to_error(kind: io::ErrorKind, msg: &str) -> io::Error {
    io::Error::new(kind, msg.to_string())
}

/// `tokio::fs::canonicalize`, mémorisé.
pub async fn canonicalize(path: &Path) -> io::Result<PathBuf> {
    let key = PathKey::Canonical(path.to_path_buf());
    if let Some(e) = PATHS.get(&key) {
        if fresh(e.checked) {
            return match e.info {
                PathInfo::Resolved(p) => Ok(p),
                PathInfo::Failed(k, m) => Err(to_error(k, &m)),
                PathInfo::Kind { .. } => unreachable!("canonical key holds a path"),
            };
        }
    }
    let res = tokio::fs::canonicalize(path).await;
    let info = match &res {
        Ok(p) => PathInfo::Resolved(p.clone()),
        Err(e) => PathInfo::Failed(e.kind(), e.to_string()),
    };
    PATHS.insert(
        key,
        PathEntry {
            info,
            checked: Instant::now(),
        },
    );
    res
}

/// `(is_file, is_dir)` d'un chemin, mémorisé.
pub async fn kind(path: &Path) -> io::Result<(bool, bool)> {
    let key = PathKey::Kind(path.to_path_buf());
    if let Some(e) = PATHS.get(&key) {
        if fresh(e.checked) {
            return match e.info {
                PathInfo::Kind { is_file, is_dir } => Ok((is_file, is_dir)),
                PathInfo::Failed(k, m) => Err(to_error(k, &m)),
                PathInfo::Resolved(_) => unreachable!("kind key holds a kind"),
            };
        }
    }
    let res = tokio::fs::metadata(path).await;
    let (info, out) = match res {
        Ok(m) => (
            PathInfo::Kind {
                is_file: m.is_file(),
                is_dir: m.is_dir(),
            },
            Ok((m.is_file(), m.is_dir())),
        ),
        Err(e) => (PathInfo::Failed(e.kind(), e.to_string()), Err(e)),
    };
    PATHS.insert(
        key,
        PathEntry {
            info,
            checked: Instant::now(),
        },
    );
    out
}

/// Un fichier prêt à être envoyé : en mémoire, ou à lire en flux.
#[derive(Debug, Clone)]
pub enum FileHandle {
    Memory(Arc<CachedFile>),
    Disk {
        path: PathBuf,
        len: u64,
        modified: Option<SystemTime>,
    },
}

impl FileHandle {
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> u64 {
        match self {
            FileHandle::Memory(f) => f.len,
            FileHandle::Disk { len, .. } => *len,
        }
    }

    /// Validateur HTTP faible (taille + date de modification).
    pub fn etag(&self) -> String {
        match self {
            FileHandle::Memory(f) => f.etag(),
            FileHandle::Disk { len, modified, .. } => CachedFile {
                bytes: Bytes::new(),
                len: *len,
                modified: *modified,
            }
            .etag(),
        }
    }

    /// Corps HTTP : copie partagée de la mémoire, ou flux par blocs.
    pub async fn into_body(self) -> io::Result<crate::hyper_web::body::Body> {
        match self {
            FileHandle::Memory(f) => Ok(f.bytes.clone().into()),
            FileHandle::Disk { path, .. } => {
                let file = tokio::fs::File::open(&path).await?;
                let stream = tokio_util::io::ReaderStream::with_capacity(file, 64 * 1024);
                Ok(crate::hyper_web::body::Body::from_stream(stream))
            }
        }
    }

    /// Contenu complet en mémoire (modèles HTML à réécrire). Refusé
    /// au-delà de `limit` pour ne jamais charger un très gros fichier.
    pub async fn into_bytes(self, limit: u64) -> io::Result<Bytes> {
        match self {
            FileHandle::Memory(f) => Ok(f.bytes.clone()),
            FileHandle::Disk { path, len, .. } => {
                if len > limit {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("{} is too large to be rendered in memory", path.display()),
                    ));
                }
                Ok(Bytes::from(tokio::fs::read(&path).await?))
            }
        }
    }
}

/// Un fichier : depuis la mémoire s'il y est et n'a pas changé ; mis en
/// mémoire s'il passe les filtres de `policy` ; sinon à lire en flux.
///
/// `mime` est le type MIME que la réponse annoncera (filtre
/// `mime_types`).
pub async fn read(
    path: &Path,
    mime: &str,
    policy: &crate::config::internal_cache::CachePolicy<'_>,
    pool: Option<&FileCache>,
) -> io::Result<FileHandle> {
    let revalidate = policy.revalidate();
    // Pas de cache pour cette route : flux depuis le disque.
    let pool = if policy.enabled() { pool } else { None };
    let Some(pool) = pool else {
        let meta = tokio::fs::metadata(path).await?;
        if !meta.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not a regular file",
            ));
        }
        return Ok(FileHandle::Disk {
            path: path.to_path_buf(),
            len: meta.len(),
            modified: meta.modified().ok(),
        });
    };
    let contents = &pool.contents;

    let cached = contents.get(path);
    if let Some(e) = &cached {
        if e.checked.elapsed() < revalidate {
            return Ok(FileHandle::Memory(e.file.clone()));
        }
    }

    let meta = tokio::fs::metadata(path).await?;
    if !meta.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    let (len, modified) = (meta.len(), meta.modified().ok());

    if !policy.accepts(path, len, mime) {
        // Plus éligible (fichier grossi, filtre changé…) : libérer la place.
        if cached.is_some() {
            contents.remove(path);
        }
        return Ok(FileHandle::Disk {
            path: path.to_path_buf(),
            len,
            modified,
        });
    }

    // Revalidation : inchangé → on repart pour un tour sans relire.
    if let Some(e) = cached {
        if e.file.len == len && e.file.modified == modified {
            contents.insert(
                path.to_path_buf(),
                ContentEntry {
                    file: e.file.clone(),
                    checked: Instant::now(),
                },
            );
            return Ok(FileHandle::Memory(e.file));
        }
        // Modifié : on retire l'ancienne version et on relit ci-dessous.
        contents.remove(path);
    }

    // Chargement unique : la première requête lit, les suivantes
    // attendent son résultat au lieu de relire le même fichier.
    match contents.get_value_or_guard_async(path).await {
        Ok(e) => Ok(FileHandle::Memory(e.file)),
        Err(guard) => {
            let bytes = Bytes::from(tokio::fs::read(path).await?);
            let file = Arc::new(CachedFile {
                len: bytes.len() as u64,
                bytes,
                modified,
            });
            let _ = guard.insert(ContentEntry {
                file: file.clone(),
                checked: Instant::now(),
            });
            Ok(FileHandle::Memory(file))
        }
    }
}

/// Contenu texte d'un fichier (pages d'erreur), via le cache.
pub async fn read_to_string(
    path: &Path,
    policy: &crate::config::internal_cache::CachePolicy<'_>,
    pool: Option<&FileCache>,
) -> io::Result<String> {
    let mime = crate::network::proxy::content_type_for(path);
    let bytes = read(path, mime, policy, pool)
        .await?
        .into_bytes(16 * 1024 * 1024)
        .await?;
    String::from_utf8(bytes.to_vec()).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("proxyauth-fscache-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    use crate::config::internal_cache::{CachePolicy, InternalCacheConfig};

    /// Cache activé (il est désactivé par défaut).
    fn defaults() -> InternalCacheConfig {
        serde_json::from_str(r#"{"enabled": true}"#).unwrap()
    }

    fn pool() -> Arc<FileCache> {
        Arc::new(FileCache::with_budget(BYTES_BUDGET))
    }

    static TEST_POOL: Lazy<Arc<FileCache>> = Lazy::new(pool);

    async fn content(f: &Path, cfg: &InternalCacheConfig) -> (bool, Vec<u8>) {
        let h = read(
            f,
            "text/plain",
            &CachePolicy::new(cfg, None),
            Some(&TEST_POOL),
        )
        .await
        .unwrap();
        let in_memory = matches!(h, FileHandle::Memory(_));
        let body = h.into_bytes(u64::MAX).await.unwrap().to_vec();
        (in_memory, body)
    }

    #[tokio::test]
    async fn serves_from_memory_then_sees_changes_within_a_second() {
        let d = tmp("change");
        let f = d.join("page.html");
        std::fs::write(&f, "v1").unwrap();
        let cfg = defaults();

        assert_eq!(content(&f, &cfg).await, (true, b"v1".to_vec()));

        // Modifié sur disque : tant que l'entrée est fraîche, la mémoire
        // répond (pas d'appel système)…
        std::fs::write(&f, "version-2").unwrap();
        assert_eq!(content(&f, &cfg).await.1, b"v1");

        // … et après le délai de revalidation, le nouveau contenu.
        tokio::time::sleep(REVALIDATE_EVERY + Duration::from_millis(50)).await;
        assert_eq!(content(&f, &cfg).await.1, b"version-2");
    }

    #[tokio::test]
    async fn deleted_file_is_noticed_and_failures_are_remembered() {
        let d = tmp("delete");
        let f = d.join("gone.txt");
        std::fs::write(&f, "x").unwrap();
        let cfg = defaults();
        let p = CachePolicy::new(&cfg, None);
        assert!(read(&f, "text/plain", &p, Some(&TEST_POOL)).await.is_ok());
        std::fs::remove_file(&f).unwrap();
        tokio::time::sleep(REVALIDATE_EVERY + Duration::from_millis(50)).await;
        assert!(read(&f, "text/plain", &p, Some(&TEST_POOL)).await.is_err());

        let missing = d.join("never.txt");
        assert!(canonicalize(&missing).await.is_err());
        std::fs::write(&missing, "now").unwrap();
        // Échec mémorisé une seconde…
        assert!(canonicalize(&missing).await.is_err());
        tokio::time::sleep(REVALIDATE_EVERY + Duration::from_millis(50)).await;
        // … puis revérifié.
        assert!(canonicalize(&missing).await.is_ok());
    }

    #[tokio::test]
    async fn large_files_are_streamed_not_kept_in_memory() {
        let d = tmp("large");
        let f = d.join("big.bin");
        let size = (crate::config::internal_cache::DEFAULT_MAX_FILE_SIZE + 1) as usize;
        std::fs::write(&f, vec![7u8; size]).unwrap();
        let cfg = defaults();
        let h = read(
            &f,
            "application/octet-stream",
            &CachePolicy::new(&cfg, None),
            Some(&TEST_POOL),
        )
        .await
        .unwrap();
        assert!(matches!(h, FileHandle::Disk { .. }), "streamed from disk");
        assert!(
            TEST_POOL.contents.get(f.as_path()).is_none(),
            "never kept in memory"
        );
        let body = crate::hyper_web::body::to_bytes(h.into_body().await.unwrap())
            .await
            .unwrap();
        assert_eq!(body.len(), size);
    }

    #[tokio::test]
    async fn filters_and_disabled_cache_stream_instead() {
        let d = tmp("filters");
        let css = d.join("a.css");
        let png = d.join("b.png");
        std::fs::write(&css, "body{}").unwrap();
        std::fs::write(&png, "png").unwrap();
        let only_css: InternalCacheConfig =
            serde_json::from_str(r#"{"enabled": true, "extensions": ["css"]}"#).unwrap();
        let p = CachePolicy::new(&only_css, None);
        assert!(matches!(
            read(&css, "text/css", &p, Some(&TEST_POOL)).await.unwrap(),
            FileHandle::Memory(_)
        ));
        assert!(matches!(
            read(&png, "image/png", &p, Some(&TEST_POOL)).await.unwrap(),
            FileHandle::Disk { .. }
        ));

        // Désactivé par défaut : rien en mémoire.
        let default = InternalCacheConfig::default();
        let other = d.join("c.css");
        std::fs::write(&other, "x").unwrap();
        assert!(matches!(
            read(
                &other,
                "text/css",
                &CachePolicy::new(&default, None),
                Some(&TEST_POOL)
            )
            .await
            .unwrap(),
            FileHandle::Disk { .. }
        ));
        assert!(TEST_POOL.contents.get(other.as_path()).is_none());
    }

    #[tokio::test]
    async fn concurrent_misses_load_the_file_once() {
        let d = tmp("once");
        let f = d.join("shared.js");
        std::fs::write(&f, vec![b'x'; 200_000]).unwrap();
        let cfg = defaults();
        let p = CachePolicy::new(&cfg, None);
        let handles = futures_util::future::join_all(
            (0..20).map(|_| read(&f, "text/javascript", &p, Some(&TEST_POOL))),
        )
        .await;
        let ptrs: std::collections::HashSet<usize> = handles
            .into_iter()
            .map(|h| match h.unwrap() {
                FileHandle::Memory(a) => Arc::as_ptr(&a) as usize,
                FileHandle::Disk { .. } => panic!("should be cached"),
            })
            .collect();
        assert_eq!(
            ptrs.len(),
            1,
            "one copy in memory for all concurrent readers"
        );
    }

    #[tokio::test]
    async fn kind_reports_files_and_directories() {
        let d = tmp("kind");
        std::fs::write(d.join("a"), "1").unwrap();
        assert_eq!(kind(&d).await.unwrap(), (false, true));
        assert_eq!(kind(&d.join("a")).await.unwrap(), (true, false));
        assert!(kind(&d.join("nope")).await.is_err());
    }

    #[test]
    fn pools_per_vhost() {
        use crate::config::config::RouteConfig;
        let routes: RouteConfig = serde_yaml::from_str(
            r#"
vhosts:
  - vhost: ["cdn.example.com"]
    internal_cache: { enabled: true, max_memory: "8MB" }
    routes:
      - { prefix: "/a", static: "/tmp" }
      - { prefix: "/b", static: "/tmp" }
  - vhost: ["on.example.com"]
    internal_cache: { enabled: true }
    routes:
      - { prefix: "/", static: "/tmp" }
  - vhost: ["plain.example.com"]
    routes:
      - { prefix: "/", static: "/tmp" }
"#,
        )
        .unwrap();
        let routes = routes.expand_vhost_groups().routes;
        // Global désactivé (défaut) : seuls les vhosts qui l'activent ont un cache.
        let p = FilePools::build(&InternalCacheConfig::default(), &routes);
        let ptr = |i: usize| p.pick(Some(&routes[i])).map(|c| Arc::as_ptr(&c));
        assert!(
            ptr(0).is_some() && ptr(0) == ptr(1),
            "one cache for the vhost's routes"
        );
        assert!(
            ptr(2).is_some() && ptr(2) != ptr(0),
            "enabled without max_memory: global budget"
        );
        assert!(
            p.global.is_some(),
            "global cache created for the vhost that needs it"
        );
        let none = FilePools::build(&InternalCacheConfig::default(), &routes[3..]);
        assert!(none.global.is_none(), "nothing enabled: no cache at all");
    }

    #[test]
    fn etag_changes_with_content() {
        let a = CachedFile {
            bytes: Bytes::from_static(b"a"),
            len: 1,
            modified: Some(SystemTime::UNIX_EPOCH),
        };
        let b = CachedFile {
            bytes: Bytes::from_static(b"ab"),
            len: 2,
            modified: Some(SystemTime::UNIX_EPOCH),
        };
        assert_ne!(a.etag(), b.etag());
    }
}
