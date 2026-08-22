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

//! `proxyauth routes-audit` / `proxyauth check-access` / `proxyauth
//! check-routes` — CLI tooling to answer "which routes are secured by
//! what, can this specific account reach them, and who exactly can
//! reach each route right now" without needing to poke the running
//! server with real requests. All three read `routes.yml`/`config.json`
//! directly and call `AppConfig::route_access_decision` — the exact
//! same function `network::proxy`'s live access check calls — so none
//! of them can silently disagree with what's actually enforced.
//!
//! No color-library dependency: a handful of raw ANSI escape codes,
//! disabled automatically when stdout isn't a terminal (piped to a
//! file, `| cat`, etc.) or `NO_COLOR` is set, per
//! <https://no-color.org/>.

use crate::config::config::{AppConfig, RouteAccessDecision, RouteConfig, RouteRule};
use std::io::IsTerminal;

struct Palette {
    bold: &'static str,
    dim: &'static str,
    reset: &'static str,
    green: &'static str,
    red: &'static str,
    yellow: &'static str,
    cyan: &'static str,
}

const COLOR: Palette = Palette {
    bold: "\x1b[1m",
    dim: "\x1b[2m",
    reset: "\x1b[0m",
    green: "\x1b[32m",
    red: "\x1b[31m",
    yellow: "\x1b[33m",
    cyan: "\x1b[36m",
};

const PLAIN: Palette = Palette {
    bold: "",
    dim: "",
    reset: "",
    green: "",
    red: "",
    yellow: "",
    cyan: "",
};

fn palette() -> &'static Palette {
    let no_color = std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty());
    if no_color || !std::io::stdout().is_terminal() {
        &PLAIN
    } else {
        &COLOR
    }
}

/// Reads `routes.yml` directly (same path and parsing `main.rs` uses
/// for the running server) — this tool doesn't need the server itself
/// running, just the same two config files it would start from.
pub fn load_routes_for_cli() -> Result<RouteConfig, String> {
    let routes_str = std::fs::read_to_string("/etc/proxyauth/config/routes.yml")
        .map_err(|e| format!("Failed to read routes.yml: {e}"))?;
    crate::config::config::check_deprecated_secure_key(&routes_str)?;
    serde_yaml::from_str(&routes_str).map_err(|e| format!("Failed to parse routes.yml: {e}"))
}

fn describe_restrictions(rule: &RouteRule) -> String {
    let mut parts = Vec::new();
    if !rule.username.is_empty() {
        parts.push(format!("username [{}]", rule.username.join(", ")));
    }
    if !rule.groups.is_empty() {
        parts.push(format!("groups [{}]", rule.groups.join(", ")));
    }
    if !rule.roles.is_empty() {
        parts.push(format!("roles [{}]", rule.roles.join(", ")));
    }
    if parts.is_empty() {
        "none".to_string()
    } else {
        parts.join(" · ")
    }
}

/// `proxyauth routes-audit` — one route at a time, what secures it.
pub fn print_routes_audit(config: &AppConfig, routes: &RouteConfig) {
    let p = palette();

    println!("{}{}Route security audit{}", p.bold, p.cyan, p.reset);
    println!();

    let mut public_count = 0usize;
    let mut open_count = 0usize;
    let mut restricted_count = 0usize;

    for rule in &routes.routes {
        println!(
            "{}{}{}{} {}->{} {}",
            p.bold, p.cyan, rule.prefix, p.reset, p.dim, p.reset, rule.target
        );

        if !rule.required_login {
            println!(
                "  required_login : {}no{}",
                p.yellow, p.reset
            );
            println!(
                "  {}{}⚠ PUBLIC{} — no authentication required at all",
                p.bold, p.red, p.reset
            );
            public_count += 1;
            println!();
            continue;
        }

        println!("  required_login : {}yes{}", p.green, p.reset);

        let no_restriction =
            rule.username.is_empty() && rule.groups.is_empty() && rule.roles.is_empty();

        if no_restriction {
            println!(
                "  {}{}⚠ OPEN{} — no username/groups/roles configured: any authenticated account can reach this route",
                p.bold, p.yellow, p.reset
            );
            open_count += 1;
        } else {
            println!("  secured by     : {}", describe_restrictions(rule));
            restricted_count += 1;
        }

        println!();
    }

    let total = routes.routes.len();
    println!(
        "{}{} route(s) checked{} — {}{} public{}, {}{} open-to-any-authenticated-account{}, {}{} restricted{}",
        p.bold, total, p.reset,
        p.red, public_count, p.reset,
        p.yellow, open_count, p.reset,
        p.green, restricted_count, p.reset,
    );

    // Silences an unused-import warning if `config` ever stops being
    // needed here directly — kept in the signature for symmetry with
    // `print_check_access` and because a future revision of this audit
    // (e.g. resolving *which* accounts belong to each listed group)
    // will need it.
    let _ = config;
}

/// `proxyauth check-access --username <name>` — one account, every
/// route, allowed or not and why.
pub fn print_check_access(config: &AppConfig, routes: &RouteConfig, username: &str) {
    let p = palette();

    println!(
        "{}{}Access check for '{}'{}",
        p.bold, p.cyan, username, p.reset
    );
    println!();

    let name_width = routes
        .routes
        .iter()
        .map(|r| r.prefix.len())
        .max()
        .unwrap_or(0);

    let mut allowed_count = 0usize;
    let mut denied_count = 0usize;

    for rule in &routes.routes {
        if !rule.required_login {
            println!(
                "{}✓{} {:<width$}  {}allowed{} — public route, no authentication required",
                p.green, p.reset, rule.prefix, p.dim, p.reset, width = name_width
            );
            allowed_count += 1;
            continue;
        }

        let decision = config.route_access_decision(rule, username);

        match decision {
            RouteAccessDecision::AllowedByUsername => {
                println!(
                    "{}✓{} {:<width$}  {}allowed{} — username explicitly listed",
                    p.green, p.reset, rule.prefix, p.dim, p.reset, width = name_width
                );
                allowed_count += 1;
            }
            RouteAccessDecision::AllowedByGroup(g) => {
                println!(
                    "{}✓{} {:<width$}  {}allowed{} — member of group '{}'",
                    p.green, p.reset, rule.prefix, p.dim, p.reset, g, width = name_width
                );
                allowed_count += 1;
            }
            RouteAccessDecision::AllowedByRole(r) => {
                println!(
                    "{}✓{} {:<width$}  {}allowed{} — has role '{}'",
                    p.green, p.reset, rule.prefix, p.dim, p.reset, r, width = name_width
                );
                allowed_count += 1;
            }
            RouteAccessDecision::AllowedNoRestrictionConfigured => {
                println!(
                    "{}✓{} {:<width$}  {}allowed{} — no restriction configured on this route",
                    p.green, p.reset, rule.prefix, p.dim, p.reset, width = name_width
                );
                allowed_count += 1;
            }
            RouteAccessDecision::Denied => {
                println!(
                    "{}✗{} {:<width$}  {}denied{}  — requires {}",
                    p.red, p.reset, rule.prefix, p.red, p.reset,
                    describe_restrictions(rule),
                    width = name_width
                );
                denied_count += 1;
            }
        }
    }

    println!();
    println!(
        "{}{} route(s) checked{} — {} can access {}{}{}, denied on {}{}{}",
        p.bold, routes.routes.len(), p.reset,
        username,
        p.green, allowed_count, p.reset,
        p.red, denied_count, p.reset,
    );
}

/// `proxyauth check-routes` — the combined, "everything at once" view:
/// for every route, resolves the abstract username/groups/roles rule
/// down to the concrete list of accounts that currently match it (each
/// tagged with *why* — listed by name, via a group, via a role), by
/// checking every known account (`AppConfig::combined_users` — file
/// and database accounts both) against `route_access_decision`. Also
/// flags any route where that resolved list comes up empty — secured
/// by something, but no current account actually satisfies it, so
/// nobody at all can get in right now (almost always a typo in a
/// group/role name, or an account that was renamed/removed after the
/// route was written).
pub fn print_check_routes(config: &AppConfig, routes: &RouteConfig) {
    let p = palette();
    let users = config.combined_users();

    println!(
        "{}{}Global route / access overview{}",
        p.bold, p.cyan, p.reset
    );
    println!(
        "{}{} route(s) · {} known account(s){}",
        p.dim,
        routes.routes.len(),
        users.len(),
        p.reset
    );
    println!();

    let mut unreachable_routes = Vec::new();

    for rule in &routes.routes {
        println!(
            "{}{}{}{} {}->{} {}",
            p.bold, p.cyan, rule.prefix, p.reset, p.dim, p.reset, rule.target
        );

        if !rule.required_login {
            println!("  required_login : {}no{}", p.yellow, p.reset);
            println!(
                "  {}{}⚠ PUBLIC{} — no authentication required at all",
                p.bold, p.red, p.reset
            );
            println!();
            continue;
        }

        println!("  required_login : {}yes{}", p.green, p.reset);

        let no_restriction =
            rule.username.is_empty() && rule.groups.is_empty() && rule.roles.is_empty();

        let mut reachable: Vec<(String, String)> = Vec::new(); // (username, reason)
        for user in &users {
            let reason = match config.route_access_decision(rule, &user.username) {
                RouteAccessDecision::AllowedByUsername => Some("listed".to_string()),
                RouteAccessDecision::AllowedByGroup(g) => Some(format!("group '{g}'")),
                RouteAccessDecision::AllowedByRole(r) => Some(format!("role '{r}'")),
                RouteAccessDecision::AllowedNoRestrictionConfigured => Some("open route".to_string()),
                RouteAccessDecision::Denied => None,
            };
            if let Some(reason) = reason {
                reachable.push((user.username.clone(), reason));
            }
        }
        reachable.sort_by(|a, b| a.0.cmp(&b.0));

        if no_restriction {
            println!(
                "  {}{}⚠ OPEN{} — no restriction configured: all {} known account(s) can reach this route",
                p.bold, p.yellow, p.reset, reachable.len()
            );
        } else if reachable.is_empty() {
            println!(
                "  {}{}⚠ UNREACHABLE{} — secured by {}, but no current account matches: nobody can get in right now",
                p.bold, p.red, p.reset, describe_restrictions(rule)
            );
            unreachable_routes.push(rule.prefix.clone());
        } else {
            println!("  secured by     : {}", describe_restrictions(rule));
            let list = reachable
                .iter()
                .map(|(u, why)| format!("{u} ({why})"))
                .collect::<Vec<_>>()
                .join(", ");
            println!("  reachable by ({}) : {}", reachable.len(), list);
        }

        println!();
    }

    if !unreachable_routes.is_empty() {
        println!(
            "{}{}⚠ {} route(s) nobody can currently reach:{} {}",
            p.bold,
            p.red,
            unreachable_routes.len(),
            p.reset,
            unreachable_routes.join(", ")
        );
        println!(
            "  {}(secured by a group/role/username that no current account actually matches — check for a typo){}",
            p.dim, p.reset
        );
    }
}
