//! `internal_cache` : cache mémoire des fichiers statiques et des pages
//! d'erreur, et des réponses compressées.
//!
//! ```json
//! "internal_cache": {
//!   "enabled": true,
//!   "max_memory": "64MB",
//!   "min_file_size": 0,
//!   "max_file_size": "1MB",
//!   "extensions": ["html", "css", "js", "svg", "woff2"],
//!   "mime_types": ["text/*", "application/javascript", "image/*"],
//!   "revalidate_ms": 1000,
//!   "compressed_max_memory": "32MB"
//! }
//! ```
//!
//! Le même bloc peut être posé sur un groupe `vhosts:` ou une route de
//! `routes.yml` ; chaque champ absent y est hérité de `config.json`.
//!
//! * **Désactivé par défaut.** `enabled: true` dans config.json l'active
//!   pour tout le monde ; `enabled` sur un vhost l'active ou le coupe
//!   pour ce vhost seulement, quel que soit le réglage global.
//! * `max_memory` (fichiers) et `compressed_max_memory` (réponses
//!   compressées) posés sur un vhost lui donnent **ses propres** caches,
//!   avec ces budgets, en plus des caches globaux ; `0` coupe le cache
//!   compressé du vhost. Absents, le vhost utilise les caches globaux.
//! * Les filtres (`min_file_size`, `max_file_size`, `extensions`,
//!   `mime_types`) et `revalidate_ms` se règlent aussi par vhost.
//!
//! Les tailles s'écrivent en octets (`1048576`) ou avec une unité :
//! `"512KB"`, `"64MB"`, `"1GB"` (puissances de 1024 ; `KiB`/`MiB`/`GiB`
//! acceptés aussi).

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Une taille en octets, lisible depuis un nombre ou une chaîne (`"64MB"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ByteSize(pub u64);

impl ByteSize {
    pub fn parse(s: &str) -> Result<Self, String> {
        let t = s.trim();
        let split = t
            .find(|c: char| !(c.is_ascii_digit() || c == '.'))
            .unwrap_or(t.len());
        let (num, unit) = t.split_at(split);
        let n: f64 = num
            .trim()
            .parse()
            .map_err(|_| format!("invalid size `{s}`"))?;
        let mult: u64 = match unit.trim().to_ascii_lowercase().as_str() {
            "" | "b" => 1,
            "k" | "kb" | "kib" => 1024,
            "m" | "mb" | "mib" => 1024 * 1024,
            "g" | "gb" | "gib" => 1024 * 1024 * 1024,
            other => return Err(format!("invalid size unit `{other}` in `{s}`")),
        };
        if n < 0.0 {
            return Err(format!("negative size `{s}`"));
        }
        Ok(ByteSize((n * mult as f64) as u64))
    }
}

impl<'de> Deserialize<'de> for ByteSize {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Num(u64),
            Str(String),
        }
        match Raw::deserialize(d)? {
            Raw::Num(n) => Ok(ByteSize(n)),
            Raw::Str(s) => ByteSize::parse(&s).map_err(serde::de::Error::custom),
        }
    }
}

impl Serialize for ByteSize {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u64(self.0)
    }
}

pub const DEFAULT_MAX_MEMORY: u64 = 64 * 1024 * 1024;
pub const DEFAULT_MAX_FILE_SIZE: u64 = 1024 * 1024;
pub const DEFAULT_COMPRESSED_MAX_MEMORY: u64 = 32 * 1024 * 1024;
pub const DEFAULT_REVALIDATE_MS: u64 = 1000;

/// Bloc `internal_cache` (config.json, groupe `vhosts:` ou route).
/// Tous les champs sont optionnels : absents, ils sont hérités (route →
/// config.json → défaut).
#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InternalCacheConfig {
    /// Défaut : `false` (cache désactivé). Un vhost peut l'activer ou le
    /// désactiver indépendamment de config.json.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,

    /// Mémoire des fichiers en cache. Dans config.json : le cache global.
    /// Sur un vhost : un cache propre au vhost, avec ce budget (partagé
    /// par ses routes), en plus du global. Défaut : 64 Mo.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_memory: Option<ByteSize>,

    /// Fichiers plus petits : jamais mis en cache. Défaut : 0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_file_size: Option<ByteSize>,

    /// Fichiers plus grands : jamais mis en cache, envoyés en flux
    /// depuis le disque (quelques dizaines de Ko de mémoire par
    /// téléchargement, quelle que soit leur taille). Défaut : 1 Mo.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_file_size: Option<ByteSize>,

    /// Extensions à mettre en cache (`"css"`, `".js"`…). Absent ou vide :
    /// toutes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Vec<String>>,

    /// Types MIME à mettre en cache (`"text/*"`, `"image/png"`…), tels
    /// qu'envoyés dans `Content-Type`. Absent ou vide : tous.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime_types: Option<Vec<String>>,

    /// Délai maximal avant qu'une modification sur disque soit vue.
    /// Défaut : 1000 ms.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revalidate_ms: Option<u64>,

    /// Mémoire des réponses compressées gardées. Dans config.json : le
    /// cache global. Sur un vhost : un cache propre à ce vhost (partagé
    /// par ses routes). `0` désactive. Défaut : 32 Mo (global).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compressed_max_memory: Option<ByteSize>,
}

impl InternalCacheConfig {
    pub fn max_memory(&self) -> u64 {
        self.max_memory.map(|b| b.0).unwrap_or(DEFAULT_MAX_MEMORY)
    }

    pub fn compressed_max_memory(&self) -> u64 {
        self.compressed_max_memory
            .map(|b| b.0)
            .unwrap_or(DEFAULT_COMPRESSED_MAX_MEMORY)
    }

}

/// Réglages effectifs pour une route : la route d'abord, puis
/// config.json, puis les défauts. Rien n'est copié.
#[derive(Debug, Clone, Copy)]
pub struct CachePolicy<'a> {
    global: &'a InternalCacheConfig,
    route: Option<&'a InternalCacheConfig>,
}

impl<'a> CachePolicy<'a> {
    pub fn new(global: &'a InternalCacheConfig, route: Option<&'a InternalCacheConfig>) -> Self {
        CachePolicy { global, route }
    }

    fn pick<T: Copy>(&self, f: impl Fn(&InternalCacheConfig) -> Option<T>) -> Option<T> {
        self.route.and_then(&f).or_else(|| f(self.global))
    }

    fn pick_list(&self, f: impl Fn(&InternalCacheConfig) -> Option<&Vec<String>>) -> Option<&'a [String]> {
        let from = |c: &'a InternalCacheConfig| f(c).map(|v| v.as_slice());
        self.route.and_then(from).or_else(|| from(self.global))
    }

    /// Désactivé par défaut : il faut `enabled: true` dans config.json
    /// ou sur le vhost.
    pub fn enabled(&self) -> bool {
        self.pick(|c| c.enabled).unwrap_or(false)
    }

    pub fn min_file_size(&self) -> u64 {
        self.pick(|c| c.min_file_size).map(|b| b.0).unwrap_or(0)
    }

    pub fn max_file_size(&self) -> u64 {
        self.pick(|c| c.max_file_size)
            .map(|b| b.0)
            .unwrap_or(DEFAULT_MAX_FILE_SIZE)
    }

    pub fn revalidate(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.pick(|c| c.revalidate_ms).unwrap_or(DEFAULT_REVALIDATE_MS))
    }

    /// Ce fichier (taille, extension, type MIME) doit-il être gardé en
    /// mémoire ?
    pub fn accepts(&self, path: &std::path::Path, len: u64, mime: &str) -> bool {
        if !self.enabled() || len < self.min_file_size() || len > self.max_file_size() {
            return false;
        }
        if let Some(exts) = self.pick_list(|c| c.extensions.as_ref()) {
            if !exts.is_empty() {
                let ext = path
                    .extension()
                    .and_then(|e| e.to_str())
                    .unwrap_or("")
                    .to_ascii_lowercase();
                if !exts
                    .iter()
                    .any(|e| e.trim_start_matches('.').eq_ignore_ascii_case(&ext))
                {
                    return false;
                }
            }
        }
        if let Some(types) = self.pick_list(|c| c.mime_types.as_ref()) {
            if !types.is_empty() && !types.iter().any(|p| mime_matches(p, mime)) {
                return false;
            }
        }
        true
    }
}

/// `"text/*"`, `"image/png"`, `"*/*"` contre un `Content-Type`
/// (paramètres comme `; charset=utf-8` ignorés).
pub fn mime_matches(pattern: &str, content_type: &str) -> bool {
    let ct = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let p = pattern.trim().to_ascii_lowercase();
    if p == "*" || p == "*/*" {
        return true;
    }
    match p.strip_suffix("/*") {
        Some(major) => ct.split('/').next() == Some(major),
        None => ct == p,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn sizes_parse_with_and_without_units() {
        assert_eq!(ByteSize::parse("1048576").unwrap().0, 1_048_576);
        assert_eq!(ByteSize::parse("512KB").unwrap().0, 512 * 1024);
        assert_eq!(ByteSize::parse("64 MiB").unwrap().0, 64 * 1024 * 1024);
        assert_eq!(ByteSize::parse("1.5GB").unwrap().0, 1_610_612_736);
        assert!(ByteSize::parse("10 parsecs").is_err());
        let c: InternalCacheConfig =
            serde_json::from_str(r#"{"max_memory": "8MB", "max_file_size": 4096}"#).unwrap();
        assert_eq!(c.max_memory(), 8 * 1024 * 1024);
        assert_eq!(c.max_file_size, Some(ByteSize(4096)));
        assert!(serde_json::from_str::<InternalCacheConfig>(r#"{"max_memroy": 1}"#).is_err());
    }

    #[test]
    fn route_overrides_global_field_by_field() {
        let global: InternalCacheConfig = serde_json::from_str(
            r#"{"max_file_size": "1MB", "extensions": ["css", "js"]}"#,
        )
        .unwrap();
        let route: InternalCacheConfig =
            serde_json::from_str(r#"{"max_file_size": "10MB"}"#).unwrap();
        let p = CachePolicy::new(&global, Some(&route));
        assert_eq!(p.max_file_size(), 10 * 1024 * 1024, "route wins");
        assert_eq!(p.revalidate(), std::time::Duration::from_millis(1000));
        assert!(!p.enabled(), "disabled by default");
        let on: InternalCacheConfig =
            serde_json::from_str(r#"{"enabled": true, "max_file_size": "10MB"}"#).unwrap();
        let p = CachePolicy::new(&global, Some(&on));
        assert!(p.accepts(Path::new("/a/app.js"), 5 * 1024 * 1024, "text/javascript"));
        assert!(!p.accepts(Path::new("/a/photo.png"), 10, "image/png"), "extension inherited from global");
        // Global activé, vhost désactivé : le vhost gagne.
        let global_on: InternalCacheConfig =
            serde_json::from_str(r#"{"enabled": true, "extensions": ["css"]}"#).unwrap();
        assert!(CachePolicy::new(&global_on, None).accepts(Path::new("/a.css"), 10, "text/css"));
        let off: InternalCacheConfig = serde_json::from_str(r#"{"enabled": false}"#).unwrap();
        assert!(!CachePolicy::new(&global_on, Some(&off)).accepts(Path::new("/a.css"), 10, "text/css"));
    }

    #[test]
    fn size_and_mime_filters() {
        let c: InternalCacheConfig = serde_json::from_str(
            r#"{"enabled": true, "min_file_size": 100, "max_file_size": 1000, "mime_types": ["text/*", "image/svg+xml"]}"#,
        )
        .unwrap();
        let p = CachePolicy::new(&c, None);
        assert!(p.accepts(Path::new("x.css"), 500, "text/css; charset=utf-8"));
        assert!(p.accepts(Path::new("x.svg"), 500, "image/svg+xml"));
        assert!(!p.accepts(Path::new("x.png"), 500, "image/png"));
        assert!(!p.accepts(Path::new("x.css"), 50, "text/css"), "too small");
        assert!(!p.accepts(Path::new("x.css"), 5000, "text/css"), "too large");
    }

    #[test]
    fn mime_patterns() {
        assert!(mime_matches("text/*", "text/html; charset=utf-8"));
        assert!(mime_matches("*/*", "application/octet-stream"));
        assert!(!mime_matches("text/*", "application/json"));
        assert!(mime_matches("application/json", "Application/JSON"));
    }
}
