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

pub const DEFAULT_FORMAT: &str =
    "[vhost] [ip] [method] [path] [status] [length] [user-agent] [x-forwarded-for]";

fn default_true() -> bool {
    true
}

fn default_format() -> String {
    DEFAULT_FORMAT.to_string()
}

fn default_resource_sample_interval() -> u64 {
    1
}

/// Per-vhost override. Its own struct rather than a bare `bool` so
/// per-vhost `format` (and anything added later) doesn't need a
/// breaking config change.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct VhostLogging {
    #[serde(default)]
    pub enabled: Option<bool>,
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
    /// `[username] [token-id] [route] [time]`
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
    /// of them (no sampler is started otherwise). Sampling rather than
    /// reading per request keeps a syscall and a file parse off the
    /// critical path, at the cost of the value being up to this many
    /// seconds stale.
    #[serde(default = "default_resource_sample_interval")]
    pub resource_sample_interval_secs: u64,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            format: default_format(),
            vhosts: HashMap::new(),
            routes: HashMap::new(),
            resource_sample_interval_secs: default_resource_sample_interval(),
        }
    }
}

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
