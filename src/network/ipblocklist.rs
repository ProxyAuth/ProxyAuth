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

//! Loads external IP/CIDR abuse-blocklists (Spamhaus DROP, FireHOL,
//! AbuseIPDB exports, ...) — see `AppConfig.ip_blocklists`. A source is
//! either a local file or an `http(s)://` URL, plain text or CSV,
//! optionally gzip-compressed (detected from the gzip magic bytes, not
//! the file extension, so it works regardless of naming). Fetching and
//! parsing never panics: a broken/unreachable source is logged and
//! skipped, since these are third-party feeds outside the admin's
//! control — one bad feed should degrade, never take the server down
//! or block startup.
//!
//! Every fetch is cached to `/etc/proxyauth/abuse/<name>.txt` (one
//! normalized entry per line): each refresh overwrites its own file,
//! and a fetch that fails (network down, source moved, ...) falls back
//! to whatever was cached from the last successful fetch instead of
//! going empty — so a transient outage never blanks out the
//! blocklist, and `cat`-ing that directory is enough to see exactly
//! what each source currently contributes.

use crate::config::config::{AppConfig, IpBlocklistSource};
use flate2::read::GzDecoder;
use ipnet::IpNet;
use std::io::Read;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use tracing::warn;

/// Where cached copies of every source are kept. Fixed, like
/// ProxyAuth's other well-known `/etc/proxyauth/...` paths (certs,
/// config) — not meant to be relocated per install.
const ABUSE_CACHE_DIR: &str = "/etc/proxyauth/abuse";

/// Local cache file for `source` — `name` if the admin set one
/// (friendlier to browse), otherwise derived from `source` itself with
/// anything that isn't filesystem-safe swapped for `_`.
fn cache_path(source: &IpBlocklistSource) -> PathBuf {
    let base = source.name.as_deref().unwrap_or(&source.source);
    let mut slug: String = base
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    slug = slug.trim_matches('_').to_string();
    if slug.is_empty() {
        slug = "source".to_string();
    }
    // Keep filenames reasonable even for a very long URL.
    slug.truncate(120);
    Path::new(ABUSE_CACHE_DIR).join(format!("{slug}.txt"))
}

/// Overwrites `path` with one normalized entry per line — written to a
/// temp file and renamed into place, so a concurrent reader (e.g. an
/// admin `cat`-ing the file mid-write) never sees a half-written list.
async fn write_cache(path: &Path, entries: &[IpNet]) {
    if let Err(e) = tokio::fs::create_dir_all(ABUSE_CACHE_DIR).await {
        warn!("ip_blocklist: failed to create {ABUSE_CACHE_DIR}: {e}");
        return;
    }

    let mut content = String::with_capacity(entries.len() * 18);
    for net in entries {
        content.push_str(&net.to_string());
        content.push('\n');
    }

    let tmp_path = path.with_extension("txt.tmp");
    if let Err(e) = tokio::fs::write(&tmp_path, &content).await {
        warn!(
            "ip_blocklist: failed to write cache {}: {e}",
            tmp_path.display()
        );
        return;
    }
    if let Err(e) = tokio::fs::rename(&tmp_path, path).await {
        warn!(
            "ip_blocklist: failed to finalize cache {}: {e}",
            path.display()
        );
    }
}

/// Reads back a previously cached file. Missing/unreadable/empty just
/// yields an empty list — this is a best-effort fallback, never a hard
/// dependency.
async fn read_cache(path: &Path) -> Vec<IpNet> {
    match tokio::fs::read_to_string(path).await {
        Ok(text) => text
            .lines()
            .filter_map(|line| {
                let line = line.trim();
                if line.is_empty() {
                    return None;
                }
                line.parse::<IpNet>()
                    .or_else(|_| line.parse::<IpAddr>().map(IpNet::from))
                    .ok()
            })
            .collect(),
        Err(_) => Vec::new(),
    }
}

async fn fetch_bytes(source: &str) -> Result<Vec<u8>, String> {
    if source.starts_with("http://") || source.starts_with("https://") {
        let resp = reqwest::get(source)
            .await
            .map_err(|e| format!("request failed: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("HTTP {}", resp.status()));
        }
        resp.bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| format!("failed reading response body: {e}"))
    } else {
        tokio::fs::read(source)
            .await
            .map_err(|e| format!("failed reading file: {e}"))
    }
}

/// Gzip magic bytes are `1f 8b` — checked directly rather than trusting
/// a `.gz` extension, so a URL/path without one still decompresses.
fn maybe_gunzip(bytes: Vec<u8>) -> Vec<u8> {
    if bytes.len() >= 2 && bytes[0] == 0x1f && bytes[1] == 0x8b {
        let mut out = Vec::new();
        match GzDecoder::new(&bytes[..]).read_to_end(&mut out) {
            Ok(_) => out,
            Err(e) => {
                warn!("ip_blocklist: gzip payload failed to decompress: {e}");
                Vec::new()
            }
        }
    } else {
        bytes
    }
}

fn parse_entries(text: &str, source: &IpBlocklistSource) -> Vec<IpNet> {
    let mut out = Vec::new();
    let mut skipped: usize = 0;

    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }

        let candidate = if source.csv {
            match line.split(',').nth(source.csv_column) {
                Some(field) => field.trim().trim_matches('"'),
                None => {
                    skipped += 1;
                    continue;
                }
            }
        } else {
            // Strip a trailing "# comment" some plain-text feeds add
            // after the address, then take the first token — handles
            // "1.2.3.4 # some ISP" and "1.2.3.4 some-hostname" alike.
            let before_comment = line.split('#').next().unwrap_or(line);
            match before_comment.split_whitespace().next() {
                Some(tok) => tok,
                None => {
                    skipped += 1;
                    continue;
                }
            }
        };

        match candidate
            .parse::<IpNet>()
            .or_else(|_| candidate.parse::<IpAddr>().map(IpNet::from))
        {
            Ok(net) => out.push(net),
            Err(_) => skipped += 1,
        }
    }

    if skipped > 0 {
        warn!(
            "ip_blocklist: skipped {skipped} unparseable line(s) from \"{}\"",
            source.source
        );
    }
    out
}

/// Fetches and parses a single source, then persists it to its cache
/// file for next time. Never fails outward — an unreachable URL, a
/// 404, a garbled payload all just log a warning and fall back to
/// whatever's in the local cache (last successful fetch), so one
/// broken feed never blanks itself out or blocks the others.
pub async fn fetch_source(source: &IpBlocklistSource) -> Vec<IpNet> {
    let path = cache_path(source);

    match fetch_bytes(&source.source).await {
        Ok(bytes) => {
            let bytes = maybe_gunzip(bytes);
            let text = String::from_utf8_lossy(&bytes);
            let entries = parse_entries(&text, source);
            if entries.is_empty() {
                warn!(
                    "ip_blocklist: \"{}\" parsed to 0 entries — keeping the last cached copy, if any",
                    source.source
                );
                return read_cache(&path).await;
            }
            write_cache(&path, &entries).await;
            entries
        }
        Err(e) => {
            warn!(
                "ip_blocklist: failed to load \"{}\": {e} — falling back to cached copy at {}",
                source.source,
                path.display()
            );
            read_cache(&path).await
        }
    }
}

/// Fetches every configured source and merges them into one
/// deduplicated list, ready to hot-swap into `AppState.ip_blocklist`.
/// Sources are fetched sequentially (these feeds can be large; this
/// runs on its own background task on a fixed interval, not on the
/// request path, so there's no latency pressure to parallelize it).
pub async fn refresh_all(config: &AppConfig) -> Vec<IpNet> {
    let mut merged = Vec::new();
    for src in &config.ip_blocklists {
        merged.extend(fetch_source(src).await);
    }
    merged.sort_by_key(|n| n.to_string());
    merged.dedup();
    merged
}
