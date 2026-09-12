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

//! `logging` configuration — the access log's on/off switches and line
//! format.
//!
//! Distinct from the pre-existing `log` map in `config.json`, which
//! configures the *transport* (`local` / `loki` / `http` / `disabled`)
//! for `tracing` as a whole. That map is untouched: this block decides
//! **what** an access-log line contains and **which requests** get one;
//! `log` still decides where every line — access or diagnostic — is
//! written. Turning `logging.enabled` off silences access lines while
//! leaving warnings and errors intact, which is usually what "disable
//! logs on this noisy endpoint" actually means.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

pub const DEFAULT_FORMAT: &str =
    "[time] [[vhost]] [[ip]] - [method] [protocol] [status] [length] [path] [tid:[token-id]] '[user-agent]' '[referer]' [request-time-ns]";

fn default_true() -> bool {
    true
}

fn default_format() -> String {
    DEFAULT_FORMAT.to_string()
}

fn default_resource_sample_interval() -> u64 {
    1
}

fn default_global_log_file() -> String {
    "access.log".to_string()
}

fn default_flush_interval_ms() -> u64 {
    500
}

/// Per-vhost override. Its own struct rather than a bare `bool` so
/// per-vhost `format` (and anything added later) doesn't need a
/// breaking config change.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct VhostLogging {
    #[serde(default)]
    pub enabled: Option<bool>,

    /// Per-vhost log file.  Written into `/var/log/proxyauth/`
    /// automatically — only the filename (or a relative path under that
    /// directory) should be provided.  Path-traversal (`../`) and
    /// absolute paths are rejected at startup.  When unset the vhost
    /// falls back to the global access log (tracing).
    #[serde(default)]
    pub log_file: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LoggingConfig {
    /// Proxy-wide switch. `true` by default so upgrading to a build
    /// with this block starts producing access logs rather than
    /// silently producing none.
    #[serde(default = "default_true", alias = "log")]
    pub enabled: bool,

    /// Line format, as `[placeholder]` tokens mixed with literal text.
    /// Parsed once at startup (`network::accesslog::compile_format`);
    /// an unknown placeholder is left in the output verbatim so a typo
    /// is visible instead of silently dropping a column.
    ///
    /// Available: `[vhost] [ip] [path] [method] [status] [length]`
    /// `[user-agent] [x-forwarded-for] [host] [protocol] [query]`
    /// `[referer] [request-time] [cpu-usage] [memory-usage]`
    /// `[username] [token-id] [route] [time] [error_detail]`
    #[serde(
        default = "default_format",
        alias = "format-log",
        alias = "format_log"
    )]
    pub format: String,

    /// Per-vhost overrides, keyed by hostname (port stripped, compared
    /// lowercase). Applies to every request arriving on that `Host`,
    /// including ones that match no route at all — which is the point:
    /// a 404 flood against one domain can be silenced without touching
    /// the others.
    #[serde(default)]
    pub vhosts: HashMap<String, VhostLogging>,

    /// Per-route overrides keyed by the route's `prefix`, as an
    /// alternative to setting `log:` on the route in `routes.yml` —
    /// useful for keeping every logging decision in one file. The
    /// route's own `log:` wins when both are set.
    #[serde(default)]
    pub routes: HashMap<String, bool>,

    /// How often `[cpu-usage]`/`[memory-usage]` are re-sampled from
    /// `/proc/self`, in seconds. Only relevant when the format uses one
    /// of those two placeholders (no sampler is started otherwise).
    /// Sampling rather than reading per request keeps a syscall and a
    /// file parse off the critical path, at the cost of the value being
    /// up to this many seconds stale.
    #[serde(default = "default_resource_sample_interval")]
    pub resource_sample_interval_secs: u64,

    /// Global access log file, written into `/var/log/proxyauth/`.
    /// Defaults to `access.log`.  Requests whose vhost has its own
    /// `log_file` go to that file instead; only requests without a
    /// per-vhost override land here.
    #[serde(default = "default_global_log_file")]
    pub log_file: String,

    /// How often (in milliseconds) buffered log writers — both the
    /// per-vhost/route access-log files and the global `proxyauth.log`
    /// — are flushed to disk. Lines sit in an in-memory buffer between
    /// flushes rather than costing a syscall each (see
    /// `network::accesslog::VhostLogWriter`), so this is the real
    /// trade-off knob: lower means log lines become visible on disk
    /// sooner (useful while actively tailing a file during debugging),
    /// higher means fewer flush syscalls under heavy request volume.
    /// Defaults to 500ms — noticeably fast without turning every
    /// request into its own disk write. A value below ~50ms starts
    /// approaching per-line flushing and mostly defeats the point of
    /// buffering at all.
    #[serde(default = "default_flush_interval_ms")]
    pub flush_interval_ms: u64,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            format: default_format(),
            vhosts: HashMap::new(),
            routes: HashMap::new(),
            resource_sample_interval_secs: default_resource_sample_interval(),
            log_file: default_global_log_file(),
            flush_interval_ms: default_flush_interval_ms(),
        }
    }
}

/// Base directory for all proxyauth log files.
pub const LOG_DIR: &str = "/var/log/proxyauth";

impl LoggingConfig {
    /// Per-vhost switch. Unlisted vhosts inherit the global setting,
    /// so the map only ever needs the exceptions.
    pub fn vhost_enabled(&self, vhost: &str) -> bool {
        if self.vhosts.is_empty() {
            return true;
        }
        self.vhosts
            .get(vhost)
            .and_then(|v| v.enabled)
            .unwrap_or(true)
    }

    /// Per-route switch from *this* block (`logging.routes`), keyed by
    /// prefix. The route's own `log:` field in `routes.yml` is checked
    /// separately and takes precedence.
    pub fn route_enabled(&self, prefix: &str) -> Option<bool> {
        self.routes.get(prefix).copied()
    }

    /// Validates that every `log_file` (global + per-vhost) is a
    /// simple filename with no path traversal or absolute-path tricks.
    /// Called once at startup; returns `Err(message)` on the first
    /// invalid entry.
    pub fn validate_log_paths(&self) -> Result<(), String> {
        validate_log_filename(&self.log_file, "logging.log_file")?;
        for (vhost, entry) in &self.vhosts {
            if let Some(f) = &entry.log_file {
                validate_log_filename(
                    f,
                    &format!("logging.vhosts.{}.log_file", vhost),
                )?;
            }
        }
        Ok(())
    }
}

fn validate_log_filename(name: &str, ctx: &str) -> Result<(), String> {
    if name.is_empty() {
        return Ok(());
    }
    let p = Path::new(name);
    if p.is_absolute() {
        return Err(format!(
            "{ctx}: log_file must be a relative filename, not an absolute path (got \"{name}\")"
        ));
    }
    if name.contains("..") {
        return Err(format!(
            "{ctx}: log_file must not contain path traversal (got \"{name}\")"
        ));
    }
    if p.components().count() > 1 {
        return Err(format!(
            "{ctx}: log_file must be a single filename, not a path (got \"{name}\")"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enabled_by_default() {
        assert!(LoggingConfig::default().enabled);
    }

    #[test]
    fn unlisted_vhosts_inherit_global() {
        let mut cfg = LoggingConfig::default();
        cfg.vhosts.insert(
            "quiet.example.com".into(),
            VhostLogging {
                enabled: Some(false),
                ..Default::default()
            },
        );
        assert!(!cfg.vhost_enabled("quiet.example.com"));
        assert!(cfg.vhost_enabled("other.example.com"));
    }

    #[test]
    fn empty_vhost_map_is_a_fast_path() {
        assert!(LoggingConfig::default().vhost_enabled("anything"));
    }

    #[test]
    fn accepts_format_log_alias() {
        let json = r#"{"log": false, "format-log": "[ip] [status]"}"#;
        let cfg: LoggingConfig = serde_json::from_str(json).unwrap();
        assert!(!cfg.enabled);
        assert_eq!(cfg.format, "[ip] [status]");
    }

    #[test]
    fn missing_block_uses_defaults() {
        let cfg: LoggingConfig = serde_json::from_str("{}").unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.format, DEFAULT_FORMAT);
    }
}
