// Copyright 2025 Vladimir Souchet
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! `compression` configuration — global (`config.json`) and per-route
//! or per-vhost-group (`routes.yml`).
//!
//! Every field is optional so a route can override exactly one thing
//! (typically `enabled: false`, or a different `algorithm`) and inherit
//! the rest from the global block — the same partial-override shape
//! `need_csrf` already uses, rather than forcing an operator to restate
//! the whole block per route.

use serde::{Deserialize, Serialize};

fn default_level() -> u32 {
    5
}

fn default_min_size() -> usize {
    1024
}

/// Bodies at or above this size are compressed on the blocking pool
/// instead of inline. 256 KiB is well past the point where the
/// compression itself dominates the cost of moving the work to another
/// thread, and well below the point where holding a tokio worker would
/// start hurting other connections.
fn default_spawn_blocking_threshold() -> usize {
    262_144
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CompressionConfig {
    /// `None` at route level means "inherit"; at global level it means
    /// "off" (see `is_enabled`) — compression is opt-in, so an existing
    /// `config.json` with no `compression` block behaves exactly as
    /// before.
    #[serde(default)]
    pub enabled: Option<bool>,

    /// Preference order, most-preferred first. Accepts a single value
    /// (`"br"`) or a comma-separated list (`"br, gzip, deflate"`).
    /// Filtered against the client's `Accept-Encoding` at request time;
    /// the client's own q-values win over this order when it expresses
    /// a preference. `None` means the built-in order in `algorithms`.
    #[serde(default)]
    pub algorithm: Option<String>,

    /// Compression level for *dynamic* content (responses generated on
    /// the fly by backends, auth handlers, error pages, etc.).
    /// Clamped per algorithm at use (gzip/deflate 0–9, brotli 0–11).
    #[serde(default = "default_level")]
    pub level: u32,

    /// Compression level for *static* files (served via the `static`
    /// route directive).  Static content can tolerate a slower,
    /// higher-ratio compress since the result is often cached.
    /// `None` means "use `level`" (no differentiation).
    #[serde(default)]
    pub level_static: Option<u32>,

    /// Responses smaller than this are sent uncompressed: below roughly
    /// a kilobyte the encoding overhead and the extra CPU outweigh
    /// anything saved on the wire, and for a single-MTU response they
    /// save no round trip at all.
    #[serde(default = "default_min_size")]
    pub min_size: usize,

    /// Responses larger than this are sent uncompressed too — the
    /// opposite end of `min_size`. Unlike `min_size`, this has no
    /// built-in default (`None` — no ceiling) since there's no
    /// universally "too big" size; `spawn_blocking_threshold` already
    /// keeps a large compression from stalling a tokio worker, this is
    /// specifically for operators who'd rather skip the CPU cost
    /// entirely past some size than pay it off the hot path — e.g. a
    /// route that occasionally proxies a very large JSON export where
    /// the network savings no longer justify the CPU time.
    #[serde(default)]
    pub max_size: Option<usize>,

    /// Overrides the built-in compressible-media-type allow-list.
    /// Entries are matched as prefixes against the response's
    /// `Content-Type` (`"text/"` covers every text subtype). The
    /// always-excluded set (images, video, audio, woff/zip/gzip) still
    /// applies on top of this.
    #[serde(default)]
    pub types: Option<Vec<String>>,

    /// Rewrites the request's `Accept-Encoding` to `identity` on the
    /// way to the backend, so ProxyAuth receives a plain body and
    /// applies the algorithm/level configured here instead of passing
    /// the backend's own compressed body straight through — nginx's
    /// `proxy_set_header Accept-Encoding ""`.
    ///
    /// Defaults to `true` when compression is enabled: without it, a
    /// backend that compresses on its own leaves this whole block with
    /// no observable effect on proxied routes (the middleware correctly
    /// refuses to double-compress), which is a confusing thing to
    /// debug. Set it to `false` to leave the backend in charge — worth
    /// doing if the backend caches its compressed output, since this
    /// otherwise moves that CPU cost onto ProxyAuth on every request.
    #[serde(default)]
    pub upstream_identity: Option<bool>,

    /// File extensions treated as "static content" for compression
    /// purposes.  When a response's URL ends with one of these
    /// extensions, `level_static` (if set) is used instead of `level`.
    /// The comparison is case-insensitive and the leading `.` is
    /// optional — both `".js"` and `"js"` work.  Empty list means
    /// "no static/dynamic differentiation; always use `level`".
    ///
    /// Example: `[".js", ".css", ".svg", ".html", ".png"]`
    #[serde(default)]
    pub file_static: Vec<String>,

    #[serde(default = "default_spawn_blocking_threshold")]
    pub spawn_blocking_threshold: usize,
}

impl Default for CompressionConfig {
    fn default() -> Self {
        Self {
            enabled: None,
            algorithm: None,
            level: default_level(),
            level_static: None,
            min_size: default_min_size(),
            max_size: None,
            types: None,
            upstream_identity: None,
            file_static: Vec::new(),
            spawn_blocking_threshold: default_spawn_blocking_threshold(),
        }
    }
}

impl CompressionConfig {
    pub fn is_enabled(&self) -> bool {
        self.enabled.unwrap_or(false)
    }

    /// Preference order, defaulting to brotli → gzip → deflate: brotli
    /// gives the best ratio on text and is supported by every current
    /// browser, gzip is the universal fallback, and deflate is last
    /// because its ambiguous raw-vs-zlib framing is mishandled by some
    /// older clients.
    pub fn algorithms(&self) -> Vec<String> {
        match self.algorithm.as_deref() {
            Some(s) if !s.trim().is_empty() => s
                .split(',')
                .map(|p| p.trim().to_string())
                .filter(|p| !p.is_empty())
                .collect(),
            _ => vec!["br".into(), "gzip".into(), "deflate".into()],
        }
    }

    pub fn strips_upstream_accept_encoding(&self) -> bool {
        self.upstream_identity.unwrap_or(true)
    }

    /// Returns the compression level appropriate for the content type.
    /// When `is_static` is `true` and `level_static` is set, the
    /// static level is returned; otherwise the regular `level`.
    pub fn effective_level(&self, is_static: bool) -> u32 {
        if is_static {
            self.level_static.unwrap_or(self.level)
        } else {
            self.level
        }
    }

    /// Checks whether `size` exceeds `max_size` (never true when
    /// `max_size` is unset — "no ceiling" is the default).
    pub fn exceeds_max_size(&self, size: usize) -> bool {
        self.max_size.is_some_and(|max| size > max)
    }

    /// Checks whether `url`'s extension is in the `file_static` list.
    /// The match is case-insensitive; the leading `.` is optional.
    pub fn is_static_file(&self, url: &str) -> bool {
        if self.file_static.is_empty() {
            return false;
        }
        let ext = url.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
        if ext.is_empty() {
            return false;
        }
        self.file_static.iter().any(|e| {
            let e = e.trim_start_matches('.').to_ascii_lowercase();
            e == ext
        })
    }

    /// Layers this (route-level) config over the global one: every
    /// field left unset here falls back to `base`.
    ///
    /// `level`/`min_size`/`spawn_blocking_threshold` have non-`Option`
    /// defaults, so "unset" is indistinguishable from "set to the
    /// default value" for them — a route explicitly setting
    /// `level: 5` while the global block says `level: 9` therefore
    /// inherits `9`. That's the deliberate trade for keeping the config
    /// shape simple; a route that needs a level different from the
    /// global one should pick a value that isn't the default, or the
    /// global one should be left at its default.
    pub fn merged_over(&self, base: &CompressionConfig) -> CompressionConfig {
        CompressionConfig {
            enabled: self.enabled.or(base.enabled),
            algorithm: self.algorithm.clone().or_else(|| base.algorithm.clone()),
            level: if self.level == default_level() {
                base.level
            } else {
                self.level
            },
            level_static: self.level_static.or(base.level_static),
            min_size: if self.min_size == default_min_size() {
                base.min_size
            } else {
                self.min_size
            },
            max_size: self.max_size.or(base.max_size),
            types: self.types.clone().or_else(|| base.types.clone()),
            upstream_identity: self.upstream_identity.or(base.upstream_identity),
            file_static: if self.file_static.is_empty() {
                base.file_static.clone()
            } else {
                self.file_static.clone()
            },
            spawn_blocking_threshold: if self.spawn_blocking_threshold
                == default_spawn_blocking_threshold()
            {
                base.spawn_blocking_threshold
            } else {
                self.spawn_blocking_threshold
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_by_default() {
        assert!(!CompressionConfig::default().is_enabled());
    }

    #[test]
    fn default_algorithm_order() {
        assert_eq!(
            CompressionConfig::default().algorithms(),
            vec!["br", "gzip", "deflate"]
        );
    }

    #[test]
    fn parses_comma_separated_algorithms() {
        let c = CompressionConfig {
            algorithm: Some("gzip, br".into()),
            ..Default::default()
        };
        assert_eq!(c.algorithms(), vec!["gzip", "br"]);
    }

    #[test]
    fn route_inherits_unset_fields() {
        let global = CompressionConfig {
            enabled: Some(true),
            algorithm: Some("br".into()),
            level: 9,
            min_size: 2048,
            ..Default::default()
        };
        // Route only turns it off; everything else comes from global.
        let route = CompressionConfig {
            enabled: Some(false),
            ..Default::default()
        };
        let merged = route.merged_over(&global);
        assert!(!merged.is_enabled());
        assert_eq!(merged.level, 9);
        assert_eq!(merged.min_size, 2048);
        assert_eq!(merged.algorithms(), vec!["br"]);
    }

    #[test]
    fn route_can_override_algorithm_only() {
        let global = CompressionConfig {
            enabled: Some(true),
            algorithm: Some("br".into()),
            ..Default::default()
        };
        let route = CompressionConfig {
            algorithm: Some("gzip".into()),
            ..Default::default()
        };
        let merged = route.merged_over(&global);
        assert!(merged.is_enabled());
        assert_eq!(merged.algorithms(), vec!["gzip"]);
    }

    #[test]
    fn upstream_identity_defaults_on() {
        assert!(CompressionConfig::default().strips_upstream_accept_encoding());
    }

    #[test]
    fn effective_level_static_falls_back() {
        let cfg = CompressionConfig {
            level: 5,
            level_static: None,
            ..Default::default()
        };
        assert_eq!(cfg.effective_level(true), 5);
        assert_eq!(cfg.effective_level(false), 5);
    }

    #[test]
    fn effective_level_static_override() {
        let cfg = CompressionConfig {
            level: 3,
            level_static: Some(9),
            ..Default::default()
        };
        assert_eq!(cfg.effective_level(true), 9);
        assert_eq!(cfg.effective_level(false), 3);
    }

    #[test]
    fn is_static_file_matches() {
        let cfg = CompressionConfig {
            file_static: vec![".js".into(), "css".into(), ".svg".into()],
            ..Default::default()
        };
        assert!(cfg.is_static_file("/assets/app.js"));
        assert!(cfg.is_static_file("/style.CSS"));
        assert!(cfg.is_static_file("/img/icon.svg"));
        assert!(!cfg.is_static_file("/api/data.json"));
        assert!(!cfg.is_static_file("/noext"));
    }

    #[test]
    fn exceeds_max_size_unset_never_triggers() {
        let cfg = CompressionConfig::default();
        assert!(!cfg.exceeds_max_size(usize::MAX));
    }

    #[test]
    fn exceeds_max_size_respects_the_ceiling() {
        let cfg = CompressionConfig {
            max_size: Some(1_000_000),
            ..Default::default()
        };
        assert!(!cfg.exceeds_max_size(999_999));
        assert!(!cfg.exceeds_max_size(1_000_000));
        assert!(cfg.exceeds_max_size(1_000_001));
    }

    #[test]
    fn merged_over_inherits_max_size() {
        let global = CompressionConfig {
            max_size: Some(5_000_000),
            ..Default::default()
        };
        let route = CompressionConfig::default();
        let merged = route.merged_over(&global);
        assert_eq!(merged.max_size, Some(5_000_000));
    }

    #[test]
    fn is_static_file_empty_list() {
        let cfg = CompressionConfig::default();
        assert!(!cfg.is_static_file("/anything.js"));
    }

    #[test]
    fn merged_over_inherits_level_static() {
        let global = CompressionConfig {
            level: 5,
            level_static: Some(9),
            ..Default::default()
        };
        let route = CompressionConfig::default();
        let merged = route.merged_over(&global);
        assert_eq!(merged.level_static, Some(9));
    }

    #[test]
    fn merged_over_inherits_file_static() {
        let global = CompressionConfig {
            file_static: vec![".js".into(), ".css".into()],
            ..Default::default()
        };
        let route = CompressionConfig::default();
        let merged = route.merged_over(&global);
        assert_eq!(merged.file_static, vec![".js", ".css"]);
    }
}
