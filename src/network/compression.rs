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

//! Response compression (gzip / brotli / deflate).
//!
//! Sits as a middleware **inside** the access logger and **outside**
//! every handler, so it covers proxied routes, `static` routes,
//! `/auth`, `/adm/*` and error responses uniformly — the same reason
//! `accesslog` is a middleware rather than a call at the end of each
//! handler.
//!
//! # Interaction with upstream compression
//!
//! `proxy_without_proxy`/`proxy_with_proxy` forward the client's
//! `Accept-Encoding` header to the backend verbatim, and copy the
//! backend's response headers (including `Content-Encoding`) back to
//! the client. So for a proxied route the backend usually compresses
//! first and this middleware must **not** touch the result — double
//! compression would produce a body no client can read. That's the
//! `Content-Encoding` check in `should_compress`.
//!
//! Which leaves a choice for proxied routes: let the backend keep
//! doing it, or take it over here. `upstream_identity` (default
//! `true` when compression is enabled) rewrites the request's
//! `Accept-Encoding` to `identity` on the way *to* the backend, so
//! ProxyAuth receives a plain body and applies the algorithm and level
//! configured here — nginx's `proxy_set_header Accept-Encoding ""`.
//! Set it to `false` to leave the backend in charge and have this
//! middleware only cover what ProxyAuth generates itself (static
//! files, auth responses, error pages).
//!
//! # Cost on the hot path
//!
//! With compression disabled the middleware is a boolean load and a
//! pass-through. When enabled it still returns early — before touching
//! the body at all — for a response that is already encoded, too
//! small, not a compressible media type, or whose client didn't offer
//! a supported encoding.
//!
//! # Compressed-output cache
//!
//! Compressing is by far the most expensive thing done to a response
//! (several milliseconds for a 100 KB page at brotli 5, against tens of
//! microseconds to hash it). The result is therefore kept, keyed by the
//! BLAKE3 hash of the *uncompressed* body plus the algorithm and level:
//! the same bytes always compress to the same bytes, so a hit can never
//! serve stale or someone else's content — the key *is* the content. No
//! TTL, no invalidation. See [`CompressedCache`].
//!
//! Compressing is synchronous CPU work. Small bodies are compressed
//! inline (cheaper than the cost of moving work to another thread);
//! anything above `spawn_blocking_threshold` goes to
//! `tokio::task::spawn_blocking` so a large body can't stall a tokio
//! worker and starve every other connection on it.

use crate::AppState;
use crate::config::config::CompressionConfig;
use crate::hyper_web::body::{BodySize, to_bytes};
use crate::hyper_web::dev::{Middleware, Next, ServiceFuture, ServiceRequest, ServiceResponse};
use crate::hyper_web::http::header;
use crate::hyper_web::web;
use brotli::CompressorWriter;
use bytes::Bytes;
use flate2::Compression as FlateLevel;
use flate2::write::{DeflateEncoder, GzEncoder};
use std::io::Write;

use crate::network::accesslog::LogContext;

// ─────────────────────────────────────────────────────────────────────
// Algorithm selection
// ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Algorithm {
    Gzip,
    Brotli,
    Deflate,
}

impl Algorithm {
    pub fn from_name(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "gzip" => Some(Algorithm::Gzip),
            "br" | "brotli" => Some(Algorithm::Brotli),
            "deflate" => Some(Algorithm::Deflate),
            _ => None,
        }
    }

    fn header_value(self) -> &'static str {
        match self {
            Algorithm::Gzip => "gzip",
            Algorithm::Brotli => "br",
            Algorithm::Deflate => "deflate",
        }
    }

    fn token(self) -> &'static str {
        self.header_value()
    }
}

/// Parses `Accept-Encoding` and returns the client's acceptance weight
/// for `algo`, honouring q-values and the `*` wildcard.
///
/// `None` means the client did not offer this encoding (or explicitly
/// refused it with `q=0`) — an encoding a client refused must never be
/// sent, so this is a hard gate rather than a preference.
fn client_weight(accept_encoding: &str, algo: Algorithm) -> Option<f32> {
    let mut wildcard: Option<f32> = None;

    for part in accept_encoding.split(',') {
        let mut bits = part.split(';');
        let Some(token) = bits.next().map(|t| t.trim().to_ascii_lowercase()) else {
            continue;
        };

        let q = bits
            .find_map(|p| {
                let p = p.trim();
                p.strip_prefix("q=").or_else(|| p.strip_prefix("Q="))
            })
            .and_then(|v| v.trim().parse::<f32>().ok())
            .unwrap_or(1.0);

        if token == algo.token() {
            return if q > 0.0 { Some(q) } else { None };
        }
        if token == "*" {
            wildcard = Some(q);
        }
    }

    wildcard.filter(|q| *q > 0.0)
}

/// Picks the encoding to use: the configured preference order,
/// filtered to what the client will actually accept, then ordered by
/// the client's own q-value so an explicit `br;q=1.0, gzip;q=0.5` is
/// respected.
fn negotiate(accept_encoding: &str, cfg: &CompressionConfig) -> Option<Algorithm> {
    let mut best: Option<(Algorithm, f32, usize)> = None;

    for (rank, name) in cfg.algorithms().iter().enumerate() {
        let Some(algo) = Algorithm::from_name(name) else {
            continue;
        };
        let Some(q) = client_weight(accept_encoding, algo) else {
            continue;
        };
        let better = match best {
            // Higher client q wins; ties broken by the order the
            // operator listed the algorithms in.
            Some((_, bq, brank)) => q > bq || (q == bq && rank < brank),
            None => true,
        };
        if better {
            best = Some((algo, q, rank));
        }
    }

    best.map(|(a, _, _)| a)
}

// ─────────────────────────────────────────────────────────────────────
// Compressibility
// ─────────────────────────────────────────────────────────────────────

/// Media types worth compressing. An allow-list rather than a
/// deny-list: an unrecognized type is left alone, so a new binary
/// format never gets pointlessly re-compressed just because nobody
/// remembered to add it to a deny-list. Overridable per config via
/// `types`.
const DEFAULT_COMPRESSIBLE: &[&str] = &[
    "text/",
    "application/json",
    "application/javascript",
    "application/x-javascript",
    "application/xml",
    "application/xhtml+xml",
    "application/rss+xml",
    "application/atom+xml",
    "application/ld+json",
    "application/manifest+json",
    "application/wasm",
    "application/graphql",
    "application/x-ndjson",
    "image/svg+xml",
    "font/ttf",
    "font/otf",
    "application/vnd.ms-fontobject",
];

fn is_compressible(content_type: &str, cfg: &CompressionConfig) -> bool {
    let ct = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if ct.is_empty() {
        return false;
    }

    // Already-compressed containers, regardless of the allow-list —
    // `font/woff2` is deflate inside, `image/png` is already zlib.
    const NEVER: &[&str] = &[
        "font/woff",
        "font/woff2",
        "application/font-woff",
        "application/zip",
        "application/gzip",
        "application/x-gzip",
        "application/x-brotli",
        "application/zstd",
        "application/x-7z-compressed",
        "application/x-rar-compressed",
    ];
    if NEVER.iter().any(|p| ct == *p) {
        return false;
    }
    if ct.starts_with("image/") && ct != "image/svg+xml" {
        return false;
    }
    if ct.starts_with("video/") || ct.starts_with("audio/") {
        return false;
    }

    match cfg.types.as_ref() {
        Some(list) => list
            .iter()
            .any(|p| ct.starts_with(&p.trim().to_ascii_lowercase())),
        None => DEFAULT_COMPRESSIBLE.iter().any(|p| ct.starts_with(p)),
    }
}

// ─────────────────────────────────────────────────────────────────────
// Compression
// ─────────────────────────────────────────────────────────────────────

fn compress_sync(data: &[u8], algo: Algorithm, level: u32) -> Option<Vec<u8>> {
    match algo {
        Algorithm::Gzip => {
            let mut e = GzEncoder::new(Vec::with_capacity(data.len() / 3), FlateLevel::new(level));
            e.write_all(data).ok()?;
            e.finish().ok()
        }
        Algorithm::Deflate => {
            let mut e =
                DeflateEncoder::new(Vec::with_capacity(data.len() / 3), FlateLevel::new(level));
            e.write_all(data).ok()?;
            e.finish().ok()
        }
        Algorithm::Brotli => {
            // 4096 buffer / lgwin 22, matching the existing brotli use
            // in `network::error`.
            let mut out = Vec::with_capacity(data.len() / 3);
            {
                let mut e = CompressorWriter::new(&mut out, 4096, level, 22);
                e.write_all(data).ok()?;
                e.flush().ok()?;
            }
            Some(out)
        }
    }
}

/// Clamps the configured level into the range the chosen algorithm
/// actually accepts — flate2 panics above 9, and brotli's quality is
/// 0..=11. A shared `level: 5` in config.json therefore means
/// something sensible for all three rather than being a foot-gun.
fn clamp_level(algo: Algorithm, level: u32) -> u32 {
    match algo {
        Algorithm::Gzip | Algorithm::Deflate => level.min(9),
        Algorithm::Brotli => level.min(11),
    }
}

// ─────────────────────────────────────────────────────────────────────
// Middleware
// ─────────────────────────────────────────────────────────────────────

pub struct Compress {
    pub state: web::Data<AppState>,
}

impl Middleware for Compress {
    fn call(&self, req: ServiceRequest, next: Next) -> ServiceFuture {
        let state = self.state.clone();

        // Global off switch: one boolean, then straight through. No
        // header lookup, no body buffering, no body type change beyond
        // the (free) boxing every actix response ends up doing anyway.
        if !state.config.compression.is_enabled() {
            let fut = next.call(req);
            return fut;
        }

        let accept_encoding = req
            .headers()
            .get(header::ACCEPT_ENCODING)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        // A HEAD response has no body to compress, and rewriting its
        // Content-Length would misreport the size of the GET the client
        // is probing for.
        let is_head = req.method() == crate::hyper_web::http::Method::HEAD;

        let fut = next.call(req);

        Box::pin(async move {
            let res = fut.await?;

            // Route-level override, resolved from the same
            // `LogContext` the access logger uses — set by
            // `global_proxy` once the route is matched.
            let route_idx = res
                .request()
                .extensions()
                .get::<LogContext>()
                .and_then(|c| c.route_idx);

            let cfg: CompressionConfig = match route_idx
                .and_then(|i| state.routes.routes.get(i))
                .and_then(|r| r.compression.as_ref())
            {
                Some(route_cfg) => route_cfg.merged_over(&state.config.compression),
                None => state.config.compression.clone(),
            };

            if !cfg.is_enabled() || is_head || accept_encoding.is_empty() {
                return Ok(res.map_into_boxed_body());
            }

            let status = res.status();
            // 204/304 have no body; 1xx are not final responses.
            if status.as_u16() < 200 || status == 204 || status == 304 {
                return Ok(res.map_into_boxed_body());
            }

            // Already encoded — by the backend, or by `network::error`'s
            // error page, which re-compresses with whatever encoding the
            // upstream used. Compressing again would break the client.
            if res.headers().contains_key(header::CONTENT_ENCODING) {
                return Ok(res.map_into_boxed_body());
            }

            // RFC 9111: an intermediary must not alter the payload
            // encoding when the response says `no-transform`.
            if res
                .headers()
                .get(header::CACHE_CONTROL)
                .and_then(|v| v.to_str().ok())
                .map(|v| v.to_ascii_lowercase().contains("no-transform"))
                .unwrap_or(false)
            {
                return Ok(res.map_into_boxed_body());
            }

            let content_type = res
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();

            if !is_compressible(&content_type, &cfg) {
                return Ok(res.map_into_boxed_body());
            }

            let Some(algo) = negotiate(&accept_encoding, &cfg) else {
                // Nothing the client accepts. Still advertise that the
                // representation varies, so a shared cache doesn't hand
                // this identity copy to a client that *would* have got
                // a compressed one.
                let mut res = res.map_into_boxed_body();
                append_vary(&mut res);
                return Ok(res);
            };

            // Cheap pre-check before buffering: if the handler already
            // knows the length and it's outside the [min_size,
            // max_size] window, skip without consuming the body at
            // all — this matters more for max_size than min_size,
            // since the whole point of a ceiling is usually to avoid
            // ever buffering a very large body just to decide not to
            // compress it.
            if let BodySize::Sized(n) = res.response().body().size() {
                if n < cfg.min_size as u64 || cfg.exceeds_max_size(n as usize) {
                    let mut res = res.map_into_boxed_body();
                    append_vary(&mut res);
                    return Ok(res);
                }
            }

            let (http_req, mut head) = res.into_parts();
            let body = head.take_body();

            // Determine if this is a static-file response *before*
            // decomposing the response, since we need the request URI.
            let is_static = cfg.is_static_file(http_req.uri().path());

            let original: Bytes = match to_bytes(body).await {
                Ok(b) => b,
                // The body failed mid-read; there's nothing left to
                // send either way. Surface it as a 500 rather than a
                // silently truncated 200.
                Err(_) => {
                    return Err(crate::hyper_web::error::ErrorInternalServerError(
                        "500 Internal Server Error",
                    ));
                }
            };

            if original.len() < cfg.min_size || cfg.exceeds_max_size(original.len()) {
                let mut res = ServiceResponse::new(http_req, head.set_body(original));
                append_vary(&mut res);
                return Ok(res);
            }

            let level = clamp_level(algo, cfg.effective_level(is_static));

            // Cache de ce vhost (ou le cache global), s'il y en a un.
            let cache = compressed_cache_for(route_idx);
            let cache_key = (cache.is_some() && original.len() <= CompressedCache::MAX_INPUT)
                .then(|| CompressedCache::key(&original, algo, level));
            let cached = match (cache, cache_key.as_ref()) {
                (Some(c), Some(k)) => c.get(k),
                _ => None,
            };

            let compressed: Option<Bytes> = if let Some(hit) = cached {
                hit
            } else if original.len() >= cfg.spawn_blocking_threshold {
                // Big body: hand the CPU work to the blocking pool so a
                // slow compression can't hold a tokio worker (and every
                // other connection scheduled on it) hostage.
                let data = original.clone();
                let out = match tokio::task::spawn_blocking(move || compress_sync(&data, algo, level)).await {
                    Ok(v) => v,
                    Err(_) => None,
                };
                CompressedCache::store_in(cache, cache_key, &original, out)
            } else {
                let out = compress_sync(&original, algo, level);
                CompressedCache::store_in(cache, cache_key, &original, out)
            };

            // If compression failed, or didn't actually shrink anything
            // (already-entropic payload that slipped past the media-type
            // check), send the original — a larger "compressed" body
            // would be strictly worse for the client.
            let Some(compressed) = compressed.filter(|c| c.len() < original.len()) else {
                let mut res = ServiceResponse::new(http_req, head.set_body(original));
                append_vary(&mut res);
                return Ok(res);
            };

            head.headers_mut().insert(
                header::CONTENT_ENCODING,
                header::HeaderValue::from_static(algo.header_value()),
            );
            // The upstream Content-Length now describes the wrong body.
            // Replace rather than remove: leaving a stale value would
            // truncate the response.
            head.headers_mut().remove(header::CONTENT_LENGTH);
            if let Ok(v) = header::HeaderValue::from_str(&compressed.len().to_string()) {
                head.headers_mut().insert(header::CONTENT_LENGTH, v);
            }

            let mut res = ServiceResponse::new(http_req, head.set_body(compressed));
            append_vary(&mut res);
            Ok(res)
        })
    }
}

/// Cache of compressed bodies, keyed by content.
///
/// * Key: BLAKE3 of the uncompressed body, algorithm, level. Identical
///   input → identical output, so entries never go stale and cannot mix
///   up two different responses.
/// * Value: the compressed body, or `None` when compression did not make
///   it smaller (remembered too, so the attempt is not repeated).
/// * Bounded: [`Self::BUDGET`] bytes in total, bodies above
///   [`Self::MAX_INPUT`] are not cached (still compressed, just not
///   kept). Least-recently-used entries are evicted first.
pub struct CompressedCache {
    inner: quick_cache::sync::Cache<CompressedKey, Option<Bytes>, CompressedWeighter>,
}

type CompressedKey = ([u8; 32], Algorithm, u32);

#[derive(Clone)]
pub struct CompressedWeighter;

impl quick_cache::Weighter<CompressedKey, Option<Bytes>> for CompressedWeighter {
    fn weight(&self, _k: &CompressedKey, v: &Option<Bytes>) -> u64 {
        v.as_ref().map(|b| b.len() as u64).unwrap_or(0) + 64
    }
}

impl CompressedCache {
    /// Memory for compressed bodies when `init` was not called.
    pub const BUDGET: u64 = crate::config::internal_cache::DEFAULT_COMPRESSED_MAX_MEMORY;
    /// Largest uncompressed body worth keeping.
    pub const MAX_INPUT: usize = 4 * 1024 * 1024;

    #[cfg(test)]
    fn new() -> Self {
        Self::with_budget(Self::BUDGET)
    }

    fn with_budget(budget: u64) -> Self {
        CompressedCache {
            inner: quick_cache::sync::Cache::with_weighter(4_096, budget.max(1), CompressedWeighter),
        }
    }

    fn key(body: &[u8], algo: Algorithm, level: u32) -> CompressedKey {
        (*blake3::hash(body).as_bytes(), algo, level)
    }

    fn get(&self, key: &CompressedKey) -> Option<Option<Bytes>> {
        self.inner.get(key)
    }

    /// [`Self::store`] on `cache` when there is one.
    fn store_in(
        cache: Option<&CompressedCache>,
        key: Option<CompressedKey>,
        original: &Bytes,
        out: Option<Vec<u8>>,
    ) -> Option<Bytes> {
        match cache {
            Some(c) => c.store(key, original, out),
            None => out.filter(|c| c.len() < original.len()).map(Bytes::from),
        }
    }

    /// Remembers `out` under `key` (when there is one) and returns it
    /// as the body to send.
    fn store(&self, key: Option<CompressedKey>, original: &Bytes, out: Option<Vec<u8>>) -> Option<Bytes> {
        // Only a result that actually shrinks the body is worth sending;
        // anything else is remembered as "send the original".
        let out = out.filter(|c| c.len() < original.len()).map(Bytes::from);
        if let Some(k) = key {
            self.inner.insert(k, out.clone());
        }
        out
    }
}

/// Which compressed cache a route uses.
enum Pool {
    /// The process-wide cache (`config.json`).
    Global,
    /// The vhost's own cache (`internal_cache.compressed_max_memory` in
    /// routes.yml). Routes of the same `vhosts:` group share it.
    Own(std::sync::Arc<CompressedCache>),
    /// No compressed cache (budget `0`, or `internal_cache.enabled:
    /// false` on the route).
    Off,
}

/// Every compressed cache, resolved once at startup.
struct CompressedCaches {
    global: Option<CompressedCache>,
    by_route: Vec<Pool>,
}

static CACHES: std::sync::OnceLock<CompressedCaches> = std::sync::OnceLock::new();

/// Builds the compressed caches: the global one from
/// `config.json` (`internal_cache.compressed_max_memory`, `0` = none) and
/// one per vhost that sets its own `compressed_max_memory` in
/// routes.yml. Call once at startup, after loading the routes.
///
/// Memory: each vhost cache has its own budget, on top of the global
/// one.
pub fn init_compressed_caches(
    global: &crate::config::internal_cache::InternalCacheConfig,
    routes: &[crate::config::config::RouteRule],
) {
    let _ = CACHES.set(CompressedCaches::build(global, routes));
}

impl CompressedCaches {
    fn build(
        global: &crate::config::internal_cache::InternalCacheConfig,
        routes: &[crate::config::config::RouteRule],
    ) -> Self {
    use std::collections::HashMap;
    let global_budget = global.compressed_max_memory();
    // internal_cache est désactivé par défaut : il faut `enabled: true`
    // dans config.json, ou sur le vhost.
    let global_enabled = global.enabled.unwrap_or(false);
    let mut needs_global = global_enabled;
    let mut shared: HashMap<(Vec<String>, u64), std::sync::Arc<CompressedCache>> = HashMap::new();
    let by_route = routes
        .iter()
        .map(|r| {
            let rc = r.internal_cache.as_ref();
            if !rc.and_then(|c| c.enabled).unwrap_or(global_enabled) {
                return Pool::Off;
            }
            match rc.and_then(|c| c.compressed_max_memory).map(|b| b.0) {
                None => {
                    needs_global = true;
                    Pool::Global
                }
                Some(0) => Pool::Off,
                Some(budget) => Pool::Own(
                    shared
                        .entry((r.vhost.clone(), budget))
                        .or_insert_with(|| std::sync::Arc::new(CompressedCache::with_budget(budget)))
                        .clone(),
                ),
            }
        })
        .collect();
    CompressedCaches {
        global: (needs_global && global_budget > 0).then(|| CompressedCache::with_budget(global_budget)),
        by_route,
    }
    }

    fn pick(&self, route_idx: Option<usize>) -> Option<&CompressedCache> {
        match route_idx.and_then(|i| self.by_route.get(i)) {
            Some(Pool::Own(c)) => Some(c.as_ref()),
            Some(Pool::Off) => None,
            Some(Pool::Global) | None => self.global.as_ref(),
        }
    }
}

/// Fallback when `init_compressed_caches` was never called (tests,
/// embedding): one global cache with the default budget.
static DEFAULT_CACHE: once_cell::sync::Lazy<CompressedCache> =
    once_cell::sync::Lazy::new(|| CompressedCache::with_budget(CompressedCache::BUDGET));

/// The compressed cache for the route that produced a response
/// (`route_idx` from `LogContext`); the global one when there is no
/// route (responses ProxyAuth builds itself) or the route has no cache
/// of its own.
fn compressed_cache_for(route_idx: Option<usize>) -> Option<&'static CompressedCache> {
    match CACHES.get() {
        Some(caches) => caches.pick(route_idx),
        None => Some(&DEFAULT_CACHE),
    }
}

/// Adds `Accept-Encoding` to `Vary` without clobbering a `Vary` the
/// backend already set (e.g. `Vary: Origin` from a CORS-aware upstream).
fn append_vary(res: &mut ServiceResponse) {
    let headers = res.headers_mut();
    let existing = headers
        .get(header::VARY)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let new_value = match existing {
        Some(v) if v.to_ascii_lowercase().contains("accept-encoding") => return,
        Some(v) if v.trim() == "*" => return,
        Some(v) => format!("{}, Accept-Encoding", v.trim_end_matches(',').trim()),
        None => "Accept-Encoding".to_string(),
    };

    if let Ok(hv) = header::HeaderValue::from_str(&new_value) {
        headers.insert(header::VARY, hv);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_with(algorithms: &[&str]) -> CompressionConfig {
        CompressionConfig {
            enabled: Some(true),
            algorithm: Some(
                algorithms
                    .iter()
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
                    .join(","),
            ),
            level: 5,
            level_static: None,
            min_size: 1024,
            max_size: None,
            types: None,
            upstream_identity: Some(true),
            file_static: Vec::new(),
            spawn_blocking_threshold: 262_144,
        }
    }

    #[test]
    fn negotiates_configured_preference() {
        let cfg = cfg_with(&["br", "gzip"]);
        assert_eq!(negotiate("gzip, br", &cfg), Some(Algorithm::Brotli));
    }

    #[test]
    fn respects_client_q_values() {
        let cfg = cfg_with(&["br", "gzip"]);
        // Client prefers gzip explicitly, even though br is listed first.
        assert_eq!(
            negotiate("br;q=0.1, gzip;q=0.9", &cfg),
            Some(Algorithm::Gzip)
        );
    }

    #[test]
    fn never_sends_a_refused_encoding() {
        let cfg = cfg_with(&["br"]);
        assert_eq!(negotiate("br;q=0, gzip", &cfg), None);
    }

    #[test]
    fn honours_wildcard() {
        let cfg = cfg_with(&["gzip"]);
        assert_eq!(negotiate("*", &cfg), Some(Algorithm::Gzip));
    }

    #[test]
    fn no_accept_encoding_means_no_compression() {
        let cfg = cfg_with(&["gzip", "br", "deflate"]);
        assert_eq!(negotiate("", &cfg), None);
    }

    #[test]
    fn media_type_gate() {
        let cfg = cfg_with(&["gzip"]);
        assert!(is_compressible("text/html; charset=utf-8", &cfg));
        assert!(is_compressible("application/json", &cfg));
        assert!(is_compressible("image/svg+xml", &cfg));
        assert!(!is_compressible("image/png", &cfg));
        assert!(!is_compressible("font/woff2", &cfg));
        assert!(!is_compressible("video/mp4", &cfg));
        assert!(!is_compressible("", &cfg));
    }

    #[test]
    fn levels_are_clamped_per_algorithm() {
        assert_eq!(clamp_level(Algorithm::Gzip, 11), 9);
        assert_eq!(clamp_level(Algorithm::Brotli, 11), 11);
        assert_eq!(clamp_level(Algorithm::Deflate, 20), 9);
    }

    #[test]
    fn compressed_cache_per_vhost() {
        use crate::config::config::RouteConfig;
        use crate::config::internal_cache::InternalCacheConfig;
        let routes: RouteConfig = serde_yaml::from_str(
            r#"
vhosts:
  - vhost: ["big.example.com"]
    internal_cache: { compressed_max_memory: "8MB" }
    routes:
      - { prefix: "/a", target: "http://127.0.0.1:1" }
      - { prefix: "/b", target: "http://127.0.0.1:1" }
  - vhost: ["off.example.com"]
    internal_cache: { compressed_max_memory: 0 }
    routes:
      - { prefix: "/", target: "http://127.0.0.1:1" }
  - vhost: ["plain.example.com"]
    routes:
      - { prefix: "/", target: "http://127.0.0.1:1" }
"#,
        )
        .unwrap();
        let routes = routes.expand_vhost_groups().routes;
        // Désactivé par défaut : aucun cache.
        let c = CompressedCaches::build(&InternalCacheConfig::default(), &routes);
        assert!(c.pick(None).is_none() && c.pick(Some(0)).is_none());

        let global: InternalCacheConfig = serde_json::from_str(r#"{"enabled": true}"#).unwrap();
        let c = CompressedCaches::build(&global, &routes);
        let ptr = |i| c.pick(Some(i)).map(|x| x as *const CompressedCache);

        assert!(ptr(0).is_some() && ptr(0) == ptr(1), "one cache shared by the vhost's routes");
        assert_ne!(ptr(0), c.global.as_ref().map(|x| x as *const _), "distinct from the global cache");
        assert!(ptr(2).is_none(), "0 disables the cache for that vhost");
        assert_eq!(ptr(3), c.global.as_ref().map(|x| x as *const _), "no setting: global cache");
        assert_eq!(c.pick(None).map(|x| x as *const _), c.global.as_ref().map(|x| x as *const _));

        let none: InternalCacheConfig =
            serde_json::from_str(r#"{"enabled": true, "compressed_max_memory": 0}"#).unwrap();
        let c = CompressedCaches::build(&none, &routes);
        assert!(c.pick(Some(3)).is_none(), "global 0: no global cache");
        assert!(c.pick(Some(0)).is_some(), "vhost budget still applies");
    }

    #[test]
    fn compressed_cache_is_keyed_by_content() {
        let cache = CompressedCache::new();
        let a = Bytes::from(vec![b'a'; 10_000]);
        let b = Bytes::from(vec![b'b'; 10_000]);
        let ka = CompressedCache::key(&a, Algorithm::Gzip, 5);
        let kb = CompressedCache::key(&b, Algorithm::Gzip, 5);
        assert_ne!(ka, kb, "different content, different key");
        assert_ne!(ka, CompressedCache::key(&a, Algorithm::Brotli, 5), "algorithm is part of the key");
        assert_ne!(ka, CompressedCache::key(&a, Algorithm::Gzip, 6), "level is part of the key");

        assert!(cache.get(&ka).is_none());
        let out = cache.store(Some(ka), &a, compress_sync(&a, Algorithm::Gzip, 5));
        let hit = cache.get(&ka).expect("cached");
        assert_eq!(hit, out);
        let mut dec = Vec::new();
        std::io::Read::read_to_end(&mut flate2::read::GzDecoder::new(&hit.unwrap()[..]), &mut dec).unwrap();
        assert_eq!(dec, a.to_vec(), "the cached body decompresses to the original");
    }

    #[test]
    fn compressed_cache_remembers_incompressible_bodies() {
        let cache = CompressedCache::new();
        let mut noise = vec![0u8; 4096];
        getrandom::fill(&mut noise).unwrap();
        let noise = Bytes::from(noise);
        let k = CompressedCache::key(&noise, Algorithm::Gzip, 5);
        assert!(cache.store(Some(k), &noise, compress_sync(&noise, Algorithm::Gzip, 5)).is_none());
        assert_eq!(cache.get(&k), Some(None), "\"send the original\" is cached too");
    }

    #[test]
    fn round_trips_every_algorithm() {
        use flate2::read::{DeflateDecoder, GzDecoder};
        use std::io::Read;

        let data = "hello ".repeat(500).into_bytes();

        let gz = compress_sync(&data, Algorithm::Gzip, 5).unwrap();
        let mut out = Vec::new();
        GzDecoder::new(&gz[..]).read_to_end(&mut out).unwrap();
        assert_eq!(out, data);

        let df = compress_sync(&data, Algorithm::Deflate, 5).unwrap();
        let mut out = Vec::new();
        DeflateDecoder::new(&df[..]).read_to_end(&mut out).unwrap();
        assert_eq!(out, data);

        let br = compress_sync(&data, Algorithm::Brotli, 5).unwrap();
        let mut out = Vec::new();
        brotli::Decompressor::new(&br[..], 4096)
            .read_to_end(&mut out)
            .unwrap();
        assert_eq!(out, data);
    }
}
