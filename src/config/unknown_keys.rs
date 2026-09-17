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

//! Unknown keys in `config.json` and `routes.yml`.
//!
//! Deserialization ignores keys it does not know, which is what keeps an
//! older config loading on a newer binary — and also what turns a typo
//! (`refresh_token`, `session_cookie_ttl`) into a setting that silently
//! does nothing. These checks find such keys and name the closest real
//! one, without refusing to start.

use crate::config::config::{AppConfig, RouteRule};
use std::collections::BTreeSet;

/// One key that nothing reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownKey {
    /// Where it was found, e.g. `config.json` or
    /// `routes.yml › vhosts[0] (blog.example.com) › routes[2]`.
    pub location: String,
    pub key: String,
    pub suggestion: Option<String>,
}

impl std::fmt::Display for UnknownKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}: unknown key `{}` is ignored",
            self.location, self.key
        )?;
        if let Some(s) = &self.suggestion {
            write!(f, " — did you mean `{s}`?")?;
        }
        Ok(())
    }
}

/// Keys `config.json` accepts: everything `AppConfig` writes back, plus
/// accepted aliases.
fn app_config_keys(config: &AppConfig) -> BTreeSet<String> {
    let mut keys: BTreeSet<String> = match serde_json::to_value(config) {
        Ok(serde_json::Value::Object(map)) => map.keys().cloned().collect(),
        _ => BTreeSet::new(),
    };
    keys.insert("acme".into());
    keys
}

/// Keys a route or a `vhosts:` group accepts.
fn route_keys() -> BTreeSet<String> {
    let sample: RouteRule =
        serde_json::from_str(r#"{"prefix": "/"}"#).expect("a bare route always parses");
    let mut keys: BTreeSet<String> = match serde_json::to_value(&sample) {
        Ok(serde_json::Value::Object(map)) => map.keys().cloned().collect(),
        _ => BTreeSet::new(),
    };
    // `static_path` is read as `static`; aliases are accepted too.
    for extra in [
        "static",
        "csrf_token",
        "session_cookie_age",
        "login_page_url",
        "certbot_rew",
        "routes",
    ] {
        keys.insert(extra.to_string());
    }
    keys.remove("static_path");
    keys
}

/// Unknown top-level keys of `config.json`.
pub fn check_app_config(raw: &serde_json::Value, config: &AppConfig) -> Vec<UnknownKey> {
    let Some(object) = raw.as_object() else {
        return Vec::new();
    };
    let known = app_config_keys(config);
    object
        .keys()
        .filter(|k| !known.contains(k.as_str()))
        .map(|k| UnknownKey {
            location: "config.json".into(),
            key: k.clone(),
            suggestion: suggest(k, &known),
        })
        .collect()
}

/// Unknown keys of `routes.yml`: top level, `vhosts:` groups and routes.
pub fn check_routes(raw_yaml: &str) -> Vec<UnknownKey> {
    let Ok(doc) = serde_yaml::from_str::<serde_yaml::Value>(raw_yaml) else {
        return Vec::new();
    };
    let Some(top) = doc.as_mapping() else {
        return Vec::new();
    };

    let known_route = route_keys();
    let known_top: BTreeSet<String> = ["routes", "vhosts"].iter().map(|s| s.to_string()).collect();
    let mut found = Vec::new();

    check_mapping(top, "routes.yml", &known_top, &mut found);

    if let Some(routes) = top.get("routes").and_then(|v| v.as_sequence()) {
        for (i, route) in routes.iter().enumerate() {
            if let Some(map) = route.as_mapping() {
                let at = format!("routes.yml › routes[{i}]{}", route_label(map));
                check_mapping(map, &at, &known_route, &mut found);
            }
        }
    }

    if let Some(groups) = top.get("vhosts").and_then(|v| v.as_sequence()) {
        for (g, group) in groups.iter().enumerate() {
            let Some(group_map) = group.as_mapping() else {
                continue;
            };
            let group_at = format!("routes.yml › vhosts[{g}]{}", vhost_label(group_map));
            check_mapping(group_map, &group_at, &known_route, &mut found);

            if let Some(routes) = group_map.get("routes").and_then(|v| v.as_sequence()) {
                for (i, route) in routes.iter().enumerate() {
                    if let Some(map) = route.as_mapping() {
                        let at = format!("{group_at} › routes[{i}]{}", route_label(map));
                        check_mapping(map, &at, &known_route, &mut found);
                    }
                }
            }
        }
    }

    found
}

fn check_mapping(
    map: &serde_yaml::Mapping,
    location: &str,
    known: &BTreeSet<String>,
    found: &mut Vec<UnknownKey>,
) {
    for key in map.keys().filter_map(|k| k.as_str()) {
        if !known.contains(key) {
            found.push(UnknownKey {
                location: location.to_string(),
                key: key.to_string(),
                suggestion: suggest(key, known),
            });
        }
    }
}

fn route_label(map: &serde_yaml::Mapping) -> String {
    map.get("prefix")
        .and_then(|v| v.as_str())
        .map(|p| format!(" ({p})"))
        .unwrap_or_default()
}

fn vhost_label(map: &serde_yaml::Mapping) -> String {
    match map.get("vhost") {
        Some(serde_yaml::Value::Sequence(seq)) => seq
            .first()
            .and_then(|v| v.as_str())
            .map(|v| format!(" ({v})"))
            .unwrap_or_default(),
        Some(serde_yaml::Value::String(s)) => format!(" ({s})"),
        _ => String::new(),
    }
}

/// The known key most likely meant: a close spelling first, otherwise
/// the one sharing the most meaningful words (`refresh_token` →
/// `session_refresh_interval_secs`).
pub fn suggest(key: &str, known: &BTreeSet<String>) -> Option<String> {
    let lower = key.to_ascii_lowercase();

    if let Some(hint) = intent_hint(&lower).filter(|h| known.contains(*h)) {
        return Some(hint.to_string());
    }

    let close = known
        .iter()
        .map(|k| (levenshtein(&lower, k), k))
        .min_by_key(|(d, _)| *d)
        .filter(|(d, k)| *d <= (k.len().max(lower.len()) / 4).max(2))
        .map(|(_, k)| k.clone());
    if close.is_some() {
        return close;
    }

    let words: BTreeSet<&str> = lower
        .split(['_', '-', '.'])
        .filter(|w| w.len() >= 4)
        .collect();
    if words.is_empty() {
        return None;
    }

    known
        .iter()
        .map(|k| {
            let shared = k.split('_').filter(|w| words.contains(w)).count();
            (shared, std::cmp::Reverse(k.len()), k)
        })
        .filter(|(shared, _, _)| *shared > 0)
        .max()
        .map(|(_, _, k)| k.clone())
}

/// Names people reach for, mapped to the setting they are looking for.
/// Checked before spelling, because the words that matter here
/// (`refresh`, `renew`) are not the ones spelling distance favours.
fn intent_hint(key: &str) -> Option<&'static str> {
    let has = |w: &str| key.contains(w);
    if (has("refresh") || has("renew") || has("rotat") || has("sliding"))
        && !has("blocklist")
        && !has("protect")
        && !has("grace")
    {
        return Some("session_refresh_interval_secs");
    }
    if has("grace") {
        return Some("session_refresh_grace_secs");
    }
    if (has("session") || has("login")) && (has("max") || has("absolute")) && has("life") {
        return Some("session_max_lifetime_secs");
    }
    if has("cookie") && (has("age") || has("ttl") || has("expir") || has("lifetime")) {
        return Some("max_age_session_cookie");
    }
    if (has("token") || has("session")) && (has("ttl") || has("expir") || has("lifetime")) {
        return Some("token_expiry_seconds");
    }
    if has("login") && (has("page") || has("url")) && !has("redirect") {
        return Some("redirect_login_url");
    }
    None
}

fn levenshtein(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut cur = vec![i + 1; b.len() + 1];
        for (j, cb) in b.iter().enumerate() {
            let cost = usize::from(ca != *cb);
            cur[j + 1] = (prev[j] + cost).min(prev[j + 1] + 1).min(cur[j] + 1);
        }
        prev = cur;
    }
    prev[b.len()]
}
