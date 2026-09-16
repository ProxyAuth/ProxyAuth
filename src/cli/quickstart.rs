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

//! Guided setup for the three things people configure most often:
//! a vhost and its routes, an account, and who may log in on a vhost.
//!
//! Three principles the whole module is built around:
//!
//! 1. **Nothing is written before it has been shown.** Every command
//!    ends its questions by printing the exact block it would add and
//!    asking for a yes. Answering no leaves both files byte-for-byte
//!    unchanged.
//!
//! 2. **The generated block is printed again afterwards**, with its
//!    file path, so the next one can be written by hand — this is a
//!    shortcut for learning the configuration format, not a layer that
//!    hides it.
//!
//! 3. **`routes.yml` is edited as text, not re-serialized.**
//!    `RouteConfig` only derives `Deserialize` (several of its fields
//!    are compiled artifacts — `Regex`, `IpNet`, `CompiledAllow` — that
//!    have no textual form), so a parse/serialize round-trip is not
//!    even possible; and if it were, it would drop every comment in the
//!    file. Insertion is therefore textual, and the result is re-parsed
//!    with the real deserializer before it is committed — a block that
//!    would not load is rolled back rather than left on disk.

use crate::config::config::{AppConfig, RouteConfig};
use std::collections::BTreeSet;
use std::io::{self, IsTerminal, Write};

pub const CONFIG_PATH: &str = "/etc/proxyauth/config/config.json";
pub const ROUTES_PATH: &str = "/etc/proxyauth/config/routes.yml";

// ───────────────────────────── presentation ─────────────────────────────

struct Palette {
    bold: &'static str,
    dim: &'static str,
    reset: &'static str,
    green: &'static str,
    yellow: &'static str,
    cyan: &'static str,
}

const COLOR: Palette = Palette {
    bold: "\x1b[1m",
    dim: "\x1b[2m",
    reset: "\x1b[0m",
    green: "\x1b[32m",
    yellow: "\x1b[33m",
    cyan: "\x1b[36m",
};

const PLAIN: Palette = Palette {
    bold: "",
    dim: "",
    reset: "",
    green: "",
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

fn title(text: &str) {
    let c = palette();
    println!("\n{}{}{}", c.bold, text, c.reset);
    println!("{}{}{}", c.dim, "─".repeat(text.chars().count()), c.reset);
}

fn step(current: usize, total: usize, text: &str) {
    let c = palette();
    println!(
        "\n{}[{current}/{total}]{} {}{}{}",
        c.cyan, c.reset, c.bold, text, c.reset
    );
}

fn note(text: &str) {
    let c = palette();
    println!("{}      {}{}", c.dim, text, c.reset);
}

fn warn(text: &str) {
    let c = palette();
    println!("{}  !   {}{}", c.yellow, text, c.reset);
}

fn ok(text: &str) {
    let c = palette();
    println!("{}  ✓   {}{}", c.green, text, c.reset);
}

/// Prints a block of configuration the way it will appear in the file,
/// indented and labelled. Used both for the preview (before the
/// confirmation) and for the recap (after the write).
fn show_block(label: &str, body: &str) {
    let c = palette();
    println!("\n{}{}{}", c.dim, label, c.reset);
    for line in body.lines() {
        println!("  {}{}{}", c.cyan, line, c.reset);
    }
}

// ─────────────────────────────── questions ──────────────────────────────

fn read_line() -> Result<String, String> {
    io::stdout()
    .flush()
    .map_err(|e| format!("Failed to flush stdout: {e}"))?;
    let mut buf = String::new();
    io::stdin()
    .read_line(&mut buf)
    .map_err(|e| format!("Failed to read from stdin: {e}"))?;
    Ok(buf.trim().to_string())
}

/// A question with a default — pressing Enter accepts what is shown in
/// brackets. Every question in this module has one wherever a sensible
/// default exists, so a whole run can be completed on Enter alone.
fn ask(label: &str, default: &str) -> Result<String, String> {
    let c = palette();
    if default.is_empty() {
        print!("      {label}: ");
    } else {
        print!("      {label} {}[{default}]{}: ", c.dim, c.reset);
    }
    let answer = read_line()?;
    Ok(if answer.is_empty() {
        default.to_string()
    } else {
        answer
    })
}

/// Same, but refuses an empty answer instead of accepting one.
fn ask_required(label: &str) -> Result<String, String> {
    loop {
        print!("      {label}: ");
        let answer = read_line()?;
        if !answer.is_empty() {
            return Ok(answer);
        }
        warn("This one is required.");
    }
}

fn ask_bool(label: &str, default: bool) -> Result<bool, String> {
    let hint = if default { "Y/n" } else { "y/N" };
    loop {
        let c = palette();
        print!("      {label} {}[{hint}]{}: ", c.dim, c.reset);
        let answer = read_line()?.to_lowercase();
        match answer.as_str() {
            "" => return Ok(default),
            "y" | "yes" | "o" | "oui" => return Ok(true),
            "n" | "no" | "non" => return Ok(false),
            _ => warn("Answer y or n."),
        }
    }
}

/// A numbered menu. Returns the index of the chosen entry.
fn ask_choice(label: &str, options: &[(&str, &str)]) -> Result<usize, String> {
    let c = palette();
    println!("      {label}");
    for (i, (name, help)) in options.iter().enumerate() {
        println!(
            "        {}{}{}) {name} {}— {help}{}",
            c.bold,
            i + 1,
            c.reset,
            c.dim,
            c.reset
        );
    }
    loop {
        print!("      choice {}[1]{}: ", c.dim, c.reset);
        let answer = read_line()?;
        if answer.is_empty() {
            return Ok(0);
        }
        match answer.parse::<usize>() {
            Ok(n) if n >= 1 && n <= options.len() => return Ok(n - 1),
            _ => warn(&format!("Enter a number between 1 and {}.", options.len())),
        }
    }
}

/// A comma-separated list. Empty answer means an empty list, which is
/// meaningful on its own for several of these fields.
fn ask_list(label: &str, default: &str) -> Result<Vec<String>, String> {
    let raw = ask(&format!("{label} (comma separated)"), default)?;
    Ok(raw
    .split(',')
    .map(|s| s.trim().to_string())
    .filter(|s| !s.is_empty())
    .collect())
}

fn confirm_write(paths: &[&str]) -> Result<bool, String> {
    println!();
    for p in paths {
        note(&format!("target file: {p}"));
    }
    ask_bool("Write this?", false)
}

// ──────────────────────────── YAML rendering ────────────────────────────

/// Renders a list the way it is written inline in YAML — `["a", "b"]`.
/// Flow style rather than block style on purpose: what this module
/// generates stays compact and visually distinct from whatever the
/// operator wrote by hand around it.
fn yaml_list(items: &[String]) -> String {
    let quoted: Vec<String> = items.iter().map(|s| format!("{:?}", s)).collect();
    format!("[{}]", quoted.join(", "))
}

fn yaml_str(value: &str) -> String {
    format!("{:?}", value)
}

// ───────────────────────────── file handling ────────────────────────────

fn timestamp() -> String {
    chrono::Local::now().format("%Y%m%d-%H%M%S").to_string()
}

/// Copies a file next to itself before it is modified. Every write in
/// this module goes through here first, so a bad run is always one `mv`
/// away from being undone.
fn backup(path: &str) -> Result<String, String> {
    let dest = format!("{path}.bak-{}", timestamp());
    std::fs::copy(path, &dest).map_err(|e| format!("Failed to back up {path}: {e}"))?;
    Ok(dest)
}

fn read_file(path: &str) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("Failed to read {path}: {e}"))
}

/// Writes `contents` to `path` only if it still parses as a valid
/// `routes.yml`. A generated block that would stop the server from
/// starting is rejected here, with the file left untouched, rather than
/// discovered on the next restart.
fn write_routes_checked(path: &str, contents: &str) -> Result<String, String> {
    crate::config::config::check_deprecated_secure_key(contents)?;
    serde_yaml::from_str::<RouteConfig>(contents)
    .map_err(|e| format!("The generated routes.yml does not parse ({e}) — nothing written."))?;

    let backup_path = backup(path)?;
    std::fs::write(path, contents).map_err(|e| format!("Failed to write {path}: {e}"))?;
    Ok(backup_path)
}

// ─────────────────────── routes.yml textual surgery ─────────────────────

/// Where the top-level `vhosts:` block ends — the index of the first
/// line after it that starts a new top-level key.
///
/// Comments and blank lines belong to whatever follows them, not to the
/// block being closed, so the scan walks back over a trailing run of
/// them: a comment written to introduce the *next* section must not end
/// up stranded above the item this inserts.
fn end_of_vhosts_block(lines: &[&str]) -> Option<usize> {
    let start = lines
    .iter()
    .position(|l| l.trim_start() == "vhosts:" && !l.starts_with([' ', '\t']))?;

    let mut end = lines.len();
    for (i, line) in lines.iter().enumerate().skip(start + 1) {
        let is_top_level = !line.is_empty()
        && !line.starts_with([' ', '\t'])
        && !line.trim_start().starts_with('#');
        if is_top_level {
            end = i;
            break;
        }
    }

    while end > start + 1 {
        let prev = lines[end - 1].trim();
        if prev.is_empty() || prev.starts_with('#') {
            end -= 1;
        } else {
            break;
        }
    }

    Some(end)
}

/// Renders one `vhosts:` entry exactly as it will appear in the file —
/// bullet on the first line, two more spaces on the rest.
///
/// Deliberately the single source of truth for that layout: the preview
/// shown before the confirmation is produced by this same function, so
/// what is displayed cannot drift from what is written.
fn render_group_item(item: &str) -> String {
    let mut out = String::new();
    for (i, line) in item.lines().enumerate() {
        if i == 0 {
            out.push_str(&format!("  - {line}\n"));
        } else if line.trim().is_empty() {
            out.push('\n');
        } else {
            out.push_str(&format!("    {line}\n"));
        }
    }
    out
}

/// Adds one `vhosts:` entry to the file, creating the `vhosts:` key if
/// the file does not have one yet. `item` is the entry *without* its
/// leading `- `, indented from column zero.
fn append_vhost_group(original: &str, item: &str) -> String {
    let body = render_group_item(item);
    let lines: Vec<&str> = original.lines().collect();

    match end_of_vhosts_block(&lines) {
        Some(end) => {
            let mut out = String::new();
            for line in &lines[..end] {
                out.push_str(line);
                out.push('\n');
            }
            out.push('\n');
            out.push_str(&body);
            for line in &lines[end..] {
                out.push_str(line);
                out.push('\n');
            }
            out
        }
        None => {
            let mut out = original.to_string();
            if !out.ends_with('\n') {
                out.push('\n');
            }
            out.push_str("\nvhosts:\n");
            out.push_str(&body);
            out
        }
    }
}

/// Locates one `vhosts:` entry by a hostname it declares.
///
/// Returns `(first_line, end_line, key_indent)`: the `- vhost: …` line,
/// the line after the last one belonging to the entry, and the column
/// its own keys sit at.
fn find_vhost_group(lines: &[&str], host: &str) -> Option<(usize, usize, usize)> {
    let start = lines
    .iter()
    .position(|l| l.trim_start() == "vhosts:" && !l.starts_with([' ', '\t']))?;
    let block_end = end_of_vhosts_block(lines)?;

    let mut items: Vec<usize> = Vec::new();
    let mut item_indent = None;
    for (i, line) in lines.iter().enumerate().take(block_end).skip(start + 1) {
        let trimmed = line.trim_start();
        if !trimmed.starts_with("- ") {
            continue;
        }
        let indent = line.len() - trimmed.len();
        match item_indent {
            None => {
                item_indent = Some(indent);
                items.push(i);
            }
            // A nested `- ` (a route, a backend) is deeper than the
            // entry's own bullet and must not be mistaken for one.
            Some(expected) if indent == expected => items.push(i),
            _ => {}
        }
    }

    let item_indent = item_indent?;
    let key_indent = item_indent + 2;

    for (n, &first) in items.iter().enumerate() {
        let end = items.get(n + 1).copied().unwrap_or(block_end);
        let body = lines[first..end].join("\n");
        if declares_host(&body, host) {
            return Some((first, end, key_indent));
        }
    }

    None
}

/// Whether a raw entry body lists `host` in its `vhost:` field. Parses
/// just that fragment rather than pattern-matching the text, so both
/// flow (`["a", "b"]`) and block (`- a`) styles are handled by the YAML
/// parser instead of by a regex that would have to guess.
fn declares_host(body: &str, host: &str) -> bool {
    let dedented = {
        let indent = body
        .lines()
        .next()
        .map(|l| l.len() - l.trim_start().len())
        .unwrap_or(0);
        body.lines()
        .map(|l| if l.len() > indent { &l[indent..] } else { l.trim_start() })
        .collect::<Vec<_>>()
        .join("\n")
    };

    let Ok(value) = serde_yaml::from_str::<serde_yaml::Value>(&dedented) else {
        return false;
    };
    let item = match &value {
        serde_yaml::Value::Sequence(seq) => seq.first(),
        other => Some(other),
    };
    let Some(vhosts) = item.and_then(|i| i.get("vhost")) else {
        return false;
    };
    match vhosts {
        serde_yaml::Value::Sequence(seq) => seq
        .iter()
        .filter_map(|v| v.as_str())
        .any(|v| v.eq_ignore_ascii_case(host)),
        serde_yaml::Value::String(s) => s.eq_ignore_ascii_case(host),
        _ => false,
    }
}

/// Replaces the four login-authorization keys of one `vhosts:` entry.
///
/// Existing occurrences are removed first — including their
/// continuation lines, so a block-style list does not leave orphaned
/// `- value` rows behind — and the new keys are inserted just above
/// `routes:` when the entry has one, keeping vhost-level settings
/// together and above the route list rather than trailing after it.
fn set_access_keys(original: &str, host: &str, keys: &[(String, String)]) -> Result<String, String> {
    let lines: Vec<&str> = original.lines().collect();
    let (first, end, key_indent) = find_vhost_group(&lines, host).ok_or_else(|| {
        format!(
            "No `vhosts:` entry in routes.yml declares '{host}'. \
Login authorization is a vhost-level setting, so the host has to be \
declared in a `vhosts:` group — `proxyauth quickstart vhost` creates one."
        )
    })?;

    const MANAGED: [&str; 4] = ["allow_users", "allow_groups", "allow_roles", "exclude_users"];

    let mut kept: Vec<String> = Vec::new();
    let mut routes_at: Option<usize> = None;
    let mut skipping = false;

    for line in &lines[first..end] {
        let trimmed = line.trim_start();
        let indent = line.len() - trimmed.len();

        if skipping {
            // Continuation lines of a removed key are deeper than it.
            if indent > key_indent && !trimmed.is_empty() {
                continue;
            }
            skipping = false;
        }

        let is_managed_key = indent == key_indent
        && MANAGED
        .iter()
        .any(|k| trimmed.starts_with(&format!("{k}:")));
        if is_managed_key {
            skipping = true;
            continue;
        }

        if indent == key_indent && trimmed.starts_with("routes:") && routes_at.is_none() {
            routes_at = Some(kept.len());
        }
        kept.push((*line).to_string());
    }

    let pad = " ".repeat(key_indent);
    let rendered: Vec<String> = keys
    .iter()
    .map(|(k, v)| format!("{pad}{k}: {v}"))
    .collect();

    let at = routes_at.unwrap_or(kept.len());
    let mut rebuilt = kept[..at].to_vec();
    rebuilt.extend(rendered);
    rebuilt.extend_from_slice(&kept[at..]);

    let mut out = String::new();
    for line in &lines[..first] {
        out.push_str(line);
        out.push('\n');
    }
    for line in &rebuilt {
        out.push_str(line);
        out.push('\n');
    }
    for line in &lines[end..] {
        out.push_str(line);
        out.push('\n');
    }
    Ok(out)
}

// ───────────────────────────── quickstart vhost ─────────────────────────

pub fn run_vhost() -> Result<(), String> {
    title("Quickstart — a vhost and its routes");
    note("Every question has a default. Press Enter to accept it.");
    note("Nothing is written until you confirm at the end.");

    let total = 6;

    step(1, total, "Which hostname does this vhost answer to?");
    note("Several are fine — they share one certificate and one policy.");
    let hosts = {
        let raw = ask_list("hostname(s)", "")?;
        if raw.is_empty() {
            vec![ask_required("hostname")?]
        } else {
            raw
        }
    };
    let primary = hosts[0].clone();

    step(2, total, "TLS");
    let tls_choice = ask_choice(
        "How is this vhost's certificate handled?",
        &[
            (
                "Let's Encrypt",
             "ProxyAuth issues and renews it, nothing else to install",
            ),
            ("Own certificate", "you provide the cert and key paths"),
                                ("None", "plain HTTP — local development only"),
        ],
    )?;
    let (cert_paths, certbot) = match tls_choice {
        0 => (
            Some((
                format!("/etc/proxyauth/cert/{primary}/fullchain.pem"),
                    format!("/etc/proxyauth/cert/{primary}/privkey.pem"),
            )),
            true,
        ),
        1 => {
            let cert = ask(
                "certificate path",
                &format!("/etc/proxyauth/cert/{primary}/fullchain.pem"),
            )?;
            let key = ask(
                "private key path",
                &format!("/etc/proxyauth/cert/{primary}/privkey.pem"),
            )?;
            (Some((cert, key)), false)
        }
        _ => (None, false),
    };

    step(3, total, "Who talks to this vhost?");
    let audience = ask_choice(
        "Pick the one that fits — it decides cookies and CSRF.",
        &[
            (
                "Browsers",
             "session cookie + CSRF, the answer for a dashboard or a site",
            ),
            (
                "Scripts and APIs",
             "bearer token, no cookie, no CSRF",
            ),
        ],
    )?;
    let browser = audience == 0;

    step(4, total, "Who may sign in here?");
    note("A vhost that names nobody accepts no login at all — that is the");
    note("default, and it is deliberate. You can set this later with");
    note("`proxyauth quickstart vhost-access`.");
    let allow_groups = ask_list("groups allowed to log in", "")?;
    let allow_users = if allow_groups.is_empty() {
        ask_list("usernames allowed to log in", "")?
    } else {
        Vec::new()
    };
    if allow_groups.is_empty() && allow_users.is_empty() {
        warn("No login rule set — nobody will be able to sign in on this vhost yet.");
    }

    step(5, total, "The application behind it");
    let backend = ask("backend URL", "http://127.0.0.1:8000")?;
    let app_prefix = ask("path it is served at", if browser { "/app" } else { "/" })?;
    let required_login = ask_bool("Require a session to reach it?", true)?;
    let forward = ask_bool(
        "Send the visitor's real IP and Host to the backend?",
        true,
    )?;

    step(6, total, "The login page");
    let login_page = if browser {
        let serve = ask_bool("Serve a login page from disk on /?", true)?;
        if serve {
            let dir = ask("directory", "/var/www/login/")?;
            let index = ask("index file", "login.html")?;
            Some((dir, index))
        } else {
            None
        }
    } else {
        note("Skipped — an API client posts straight to /auth.");
        None
    };

    // ---- build the block -------------------------------------------
    let mut item = String::new();
    item.push_str(&format!("vhost: {}\n", yaml_list(&hosts)));

    if let Some((cert, key)) = &cert_paths {
        item.push_str("vhost_cert:\n");
        item.push_str(&format!("  cert: {}\n", yaml_str(cert)));
        item.push_str(&format!("  key: {}\n", yaml_str(key)));
        if certbot {
            item.push_str("certbot_renew: true\n");
        }
    }

    if !allow_groups.is_empty() {
        item.push_str(&format!("allow_groups: {}\n", yaml_list(&allow_groups)));
    }
    if !allow_users.is_empty() {
        item.push_str(&format!("allow_users: {}\n", yaml_list(&allow_users)));
    }

    if browser {
        item.push_str("session_cookie: true\n");
        item.push_str("tag_csrf_token: true\n");
        item.push_str(&format!("login_redirect_url: {}\n", yaml_str(&app_prefix)));
        item.push_str("logout_redirect_url: \"/\"\n");
    } else {
        item.push_str("session_cookie: false\n");
        item.push_str("tag_csrf_token: false\n");
    }

    item.push_str("\nroutes:\n");
    if let Some((dir, index)) = &login_page {
        item.push_str("  # The login page is public by definition — nobody can sign in\n");
        item.push_str("  # through a page that already requires being signed in.\n");
        item.push_str("  - prefix: \"/\"\n");
        item.push_str(&format!("    static: {}\n", yaml_str(dir)));
        item.push_str(&format!("    static_index: {}\n", yaml_str(index)));
        item.push_str("    tag_proxyauth: true\n");
        item.push_str("    cache: false\n\n");
    }
    item.push_str(&format!("  - prefix: {}\n", yaml_str(&app_prefix)));
    item.push_str(&format!("    target: {}\n", yaml_str(&backend)));
    item.push_str(&format!("    required_login: {required_login}\n"));
    if forward {
        item.push_str("    forward_proxy_headers: true\n");
    }

    let item = item.trim_end().to_string();
    let preview = render_group_item(&item).trim_end().to_string();

    title("What this adds to routes.yml");
    show_block("vhosts:", &preview);

    if !confirm_write(&[ROUTES_PATH])? {
        println!("\nNothing written.");
        return Ok(());
    }

    let original = read_file(ROUTES_PATH)?;
    let updated = append_vhost_group(&original, &item);
    let backup_path = write_routes_checked(ROUTES_PATH, &updated)?;

    title("Done");
    ok(&format!("{ROUTES_PATH} updated"));
    note(&format!("previous version kept at {backup_path}"));

    title("What was added, so you can write the next one yourself");
    show_block(&format!("{ROUTES_PATH}  ·  under vhosts:"), &preview);

    title("Next");
    println!("      routes.yml is reloaded live — no restart needed for this change.");
    if certbot {
        println!("      Issue the certificate:  proxyauth certbot new {primary}");
        println!("      Then restart once, so the new vhost's certificate gets watched.");
    }
    if allow_groups.is_empty() && allow_users.is_empty() {
        println!("      Open it to someone:     proxyauth quickstart vhost-access");
    }
    println!("      Check what it secures:  proxyauth routes-audit");
    Ok(())
}

// ───────────────────────────── quickstart users ─────────────────────────

pub fn run_users(config: &AppConfig) -> Result<(), String> {
    title("Quickstart — an account");
    note("Nothing is written until you confirm at the end.");

    let has_db = config.databases.is_some();
    let total = if has_db { 6 } else { 5 };

    step(1, total, "Where should this account live?");
    let to_db = if has_db {
        ask_choice(
            "Both work, and a login is checked against both.",
            &[
                (
                    "Database",
                 "shared by every instance, the right answer past a handful of accounts",
                ),
                ("config.json", "local to this instance, fine to start with"),
            ],
        )? == 0
    } else {
        note("No `databases` block in config.json — writing to the file.");
        false
    };

    step(2, total, "Identity");
    let username = ask_required("username")?;

    step(3, total, "Password");
    let temporary = ask_bool(
        "Is this a temporary password you are handing over?",
        true,
    )?;
    if temporary {
        note("The account will be marked must_change_password: the next login");
        note("lands on the reset page instead of issuing a session.");
    }
    let password = loop {
        let first = rpassword::prompt_password("      password: ")
        .map_err(|e| format!("Failed to read the password: {e}"))?;
        if first.is_empty() {
            warn("Empty password — try again.");
            continue;
        }
        let second = rpassword::prompt_password("      repeat: ")
        .map_err(|e| format!("Failed to read the password: {e}"))?;
        if first == second {
            break first;
        }
        warn("The two do not match — try again.");
    };

    step(4, total, "Access");
    note("Groups gate routes. Roles do that too and are also forwarded");
    note("to the backend as X-User-Roles.");
    let groups = ask_list("groups", "")?;
    let roles = ask_list("roles", "")?;

    step(5, total, "Email");
    note("Needed for `proxyauth reset-password` to have somewhere to write.");
    let emails = ask_list("address(es)", "")?;
    let primary_email = if emails.len() > 1 {
        ask("which one is primary", &emails[0])?
    } else {
        emails.first().cloned().unwrap_or_default()
    };
    if emails.len() > 1 && !emails.contains(&primary_email) {
        return Err(format!(
            "'{primary_email}' is not one of the addresses given."
        ));
    }

    if has_db {
        step(6, total, "Confirmation");
    }

    // ---- hash once, used by either destination ---------------------
    use argon2::password_hash::{SaltString, rand_core::OsRng};
    use argon2::{Argon2, PasswordHasher};
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
    .hash_password(password.as_bytes(), &salt)
    .map_err(|e| format!("Failed to hash the password: {e}"))?
    .to_string();

    let email_entries: Vec<crate::config::config::EmailEntry> = emails
    .iter()
    .map(|addr| crate::config::config::EmailEntry {
        address: addr.clone(),
         primary: *addr == primary_email,
    })
    .collect();

    let user = crate::config::config::User {
        username: username.clone(),
        password: hash.clone(),
        otpkey: None,
        allow: None,
        roles: if roles.is_empty() {
            None
        } else {
            Some(roles.clone())
        },
        groups: if groups.is_empty() {
            None
        } else {
            Some(groups.clone())
        },
        email: if email_entries.is_empty() {
            None
        } else {
            Some(email_entries.clone())
        },
        must_change_password: temporary,
    };

    // The preview shows the real hash truncated: it is what goes in the
    // file, but printing 100 characters of Argon2 output in the middle
    // of a confirmation prompt buries everything else.
    let short_hash = format!("{}…", &hash[..hash.len().min(24)]);
    let mut preview = String::new();
    preview.push_str("{\n");
    preview.push_str(&format!("  \"username\": {},\n", yaml_str(&username)));
    preview.push_str(&format!("  \"password\": \"{short_hash}\",\n"));
    if !groups.is_empty() {
        preview.push_str(&format!("  \"groups\": {},\n", yaml_list(&groups)));
    }
    if !roles.is_empty() {
        preview.push_str(&format!("  \"roles\": {},\n", yaml_list(&roles)));
    }
    if !email_entries.is_empty() {
        preview.push_str("  \"email\": [\n");
        for e in &email_entries {
            preview.push_str(&format!(
                "    {{ \"address\": {}, \"primary\": {} }},\n",
                yaml_str(&e.address),
                                      e.primary
            ));
        }
        preview.push_str("  ],\n");
    }
    preview.push_str(&format!("  \"must_change_password\": {temporary}\n"));
    preview.push('}');

    let destination = if to_db { "the database" } else { CONFIG_PATH };
    title(&format!("What this writes to {destination}"));
    show_block(
        if to_db {
            "one row in users, plus its groups/roles/email rows"
        } else {
            "one entry appended to \"users\""
        },
        &preview,
    );
    note("The password is stored as an Argon2id hash, never in clear.");

    if !confirm_write(&[if to_db { "the database" } else { CONFIG_PATH }])? {
        println!("\nNothing written.");
        return Ok(());
    }

    if to_db {
        let db_cfg = config
        .databases
        .as_ref()
        .ok_or("No `databases` block in config.json.")?;

        // A live connection, never the LMDB fallback cache: that cache
        // exists for reads during an outage, and a write landing there
        // would vanish on the next successful sync while looking like
        // it had succeeded.
        crate::databases::db::with_connection(db_cfg, |conn| {
            crate::databases::db::ensure_schema(conn)?;
            crate::databases::db::upsert_user(conn, &user)
        })
        .map_err(|e| format!("Database is not reachable — nothing written: {e}"))?;

        title("Done");
        ok(&format!(
            "'{username}' written to the database (revived if it had been soft-deleted)"
        ));
        note("Every instance picks it up on its next incremental scan — seconds, not a restart.");

        title("The same thing without the wizard");
        let mut cmd = format!("proxyauth db-add-user --username {username}");
        for g in &groups {
            cmd.push_str(&format!(" --groups {g}"));
        }
        for r in &roles {
            cmd.push_str(&format!(" --roles {r}"));
        }
        for e in &emails {
            cmd.push_str(&format!(" --email {e}"));
        }
        if emails.len() > 1 {
            cmd.push_str(&format!(" --primary-email {primary_email}"));
        }
        if temporary {
            cmd.push_str(" --must-change-password");
        }
        show_block("shell", &cmd);
    } else {
        let original = read_file(CONFIG_PATH)?;
        let mut json: serde_json::Value = serde_json::from_str(&original)
        .map_err(|e| format!("Failed to parse {CONFIG_PATH}: {e}"))?;

        let users = json
        .as_object_mut()
        .ok_or("config.json is not a JSON object.")?
        .entry("users")
        .or_insert_with(|| serde_json::Value::Array(Vec::new()))
        .as_array_mut()
        .ok_or("`users` in config.json is not an array.")?;

        if users
            .iter()
            .any(|u| u.get("username").and_then(|v| v.as_str()) == Some(username.as_str()))
            {
                return Err(format!(
                    "'{username}' already exists in {CONFIG_PATH} — edit it there, or pick another name."
                ));
            }

            // Built by hand rather than serialized from `User`: that struct
            // only derives `Deserialize`, and deriving `Serialize` on it
            // would emit `"otpkey": null, "allow": null, …` for every field
            // left unset — noise in a file people read and edit.
            let mut entry = serde_json::Map::new();
            entry.insert("username".into(), username.clone().into());
            entry.insert("password".into(), hash.clone().into());
            if !groups.is_empty() {
                entry.insert("groups".into(), groups.clone().into());
            }
            if !roles.is_empty() {
                entry.insert("roles".into(), roles.clone().into());
            }
            if !email_entries.is_empty() {
                let addresses: Vec<serde_json::Value> = email_entries
                .iter()
                .map(|e| {
                    serde_json::json!({ "address": e.address, "primary": e.primary })
                })
                .collect();
                entry.insert("email".into(), addresses.into());
            }
            if temporary {
                entry.insert("must_change_password".into(), true.into());
            }
            users.push(serde_json::Value::Object(entry));

            let rendered = serde_json::to_string_pretty(&json)
            .map_err(|e| format!("Failed to serialize {CONFIG_PATH}: {e}"))?;
            let backup_path = backup(CONFIG_PATH)?;
            std::fs::write(CONFIG_PATH, rendered)
            .map_err(|e| format!("Failed to write {CONFIG_PATH}: {e}"))?;

            title("Done");
            ok(&format!("'{username}' appended to {CONFIG_PATH}"));
            note(&format!("previous version kept at {backup_path}"));
            warn("config.json is read once at startup — restart to pick this up.");

            title("What was added, so you can write the next one yourself");
            show_block(&format!("{CONFIG_PATH}  ·  inside \"users\""), &preview);
            note("The hash above is shortened for display; the file holds it in full.");
    }

    Ok(())
}

// ─────────────────────── quickstart vhost-access ────────────────────────

pub fn run_vhost_access() -> Result<(), String> {
    title("Quickstart — who may sign in on a vhost");
    note("This is the gate at login, not what a route lets someone reach");
    note("afterwards. The two are separate on purpose.");

    let original = read_file(ROUTES_PATH)?;
    let parsed: RouteConfig = serde_yaml::from_str(&original)
    .map_err(|e| format!("Failed to parse {ROUTES_PATH}: {e}"))?;

    // Only hosts declared in a `vhosts:` group can be edited here: these
    // keys are vhost-level, and a flat route carries no group to put
    // them on.
    let mut hosts: BTreeSet<String> = BTreeSet::new();
    for group in &parsed.vhosts {
        for h in &group.vhost {
            hosts.insert(h.clone());
        }
    }

    if hosts.is_empty() {
        return Err(format!(
            "No `vhosts:` group found in {ROUTES_PATH}. \
Run `proxyauth quickstart vhost` to create one first."
        ));
    }

    let host_list: Vec<String> = hosts.into_iter().collect();
    let total = 3;

    step(1, total, "Which vhost?");
    let options: Vec<(&str, &str)> = host_list
    .iter()
    .map(|h| (h.as_str(), "declared in routes.yml"))
    .collect();
    let chosen = ask_choice("Pick one.", &options)?;
    let host = host_list[chosen].clone();

    // Show what is in force right now, resolved the same way the server
    // resolves it, so the run starts from fact rather than from memory.
    let expanded = parsed.expand_vhost_groups();
    let current = expanded
    .routes
    .iter()
    .find(|r| r.vhost.iter().any(|v| v.eq_ignore_ascii_case(&host)));

    if let Some(rule) = current {
        title(&format!("Currently on {host}"));
        let describe = |label: &str, values: &[String]| {
            if values.is_empty() {
                note(&format!("{label}: —"));
            } else {
                note(&format!("{label}: {}", values.join(", ")));
            }
        };
        describe("allow_users ", &rule.allow_users);
        describe("allow_groups", &rule.allow_groups);
        describe("allow_roles ", &rule.allow_roles);
        describe("exclude_users", &rule.exclude_users);
        if rule.allow_users.is_empty()
            && rule.allow_groups.is_empty()
            && rule.allow_roles.is_empty()
            {
                warn("Nothing is allowed, so no login succeeds on this vhost today.");
            }
    }

    step(2, total, "Who gets in?");
    note("These three combine as an OR — being in any one of them is enough.");
    let allow_groups = ask_list("groups", "")?;
    let allow_roles = ask_list("roles", "")?;
    let allow_users = ask_list("usernames", "")?;

    if allow_groups.is_empty() && allow_roles.is_empty() && allow_users.is_empty() {
        warn("All three empty — this closes the vhost to every login.");
        if !ask_bool("Is that what you want?", false)? {
            println!("\nNothing written.");
            return Ok(());
        }
    }

    step(3, total, "Any exception?");
    note("exclude_users beats every rule above, even a direct username match.");
    let exclude_users = ask_list("usernames denied", "")?;

    let mut keys: Vec<(String, String)> = Vec::new();
    if !allow_users.is_empty() {
        keys.push(("allow_users".into(), yaml_list(&allow_users)));
    }
    if !allow_groups.is_empty() {
        keys.push(("allow_groups".into(), yaml_list(&allow_groups)));
    }
    if !allow_roles.is_empty() {
        keys.push(("allow_roles".into(), yaml_list(&allow_roles)));
    }
    if !exclude_users.is_empty() {
        keys.push(("exclude_users".into(), yaml_list(&exclude_users)));
    }

    let preview = if keys.is_empty() {
        "# every allow_*/exclude_users key removed from this vhost".to_string()
    } else {
        keys.iter()
        .map(|(k, v)| format!("{k}: {v}"))
        .collect::<Vec<_>>()
        .join("\n")
    };

    title(&format!("What this sets on {host}"));
    show_block("in its vhosts: entry", &preview);
    note("Any allow_*/exclude_users already on that entry is replaced, not merged.");

    if !confirm_write(&[ROUTES_PATH])? {
        println!("\nNothing written.");
        return Ok(());
    }

    let updated = set_access_keys(&original, &host, &keys)?;
    let backup_path = write_routes_checked(ROUTES_PATH, &updated)?;

    title("Done");
    ok(&format!("{ROUTES_PATH} updated for {host}"));
    note(&format!("previous version kept at {backup_path}"));
    note("routes.yml is reloaded live — this is already in force.");

    title("What was set, so you can write the next one yourself");
    show_block(&format!("{ROUTES_PATH}  ·  on the {host} entry"), &preview);

    title("Next");
    println!("      Check the result:  proxyauth routes-audit");
    if let Some(name) = allow_users.first() {
        println!("      Check one account: proxyauth check-access --username {name}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn appends_to_an_existing_vhosts_block() {
        let original = "vhosts:\n  - vhost: [\"a.example.com\"]\n    routes:\n      - prefix: \"/\"\n        target: \"http://127.0.0.1:1\"\n";
        let out = append_vhost_group(original, "vhost: [\"b.example.com\"]\nroutes:\n  - prefix: \"/\"\n    target: \"http://127.0.0.1:2\"");
        assert_eq!(out.matches("- vhost:").count(), 2);
        let parsed: RouteConfig = serde_yaml::from_str(&out).expect("must still parse");
        assert_eq!(parsed.vhosts.len(), 2);
    }

    #[test]
    fn creates_the_vhosts_key_when_missing() {
        let original = "routes:\n  - prefix: \"/\"\n    target: \"http://127.0.0.1:1\"\n";
        let out = append_vhost_group(original, "vhost: [\"b.example.com\"]\nroutes:\n  - prefix: \"/\"\n    target: \"http://127.0.0.1:2\"");
        let parsed: RouteConfig = serde_yaml::from_str(&out).expect("must still parse");
        assert_eq!(parsed.routes.len(), 1);
        assert_eq!(parsed.vhosts.len(), 1);
    }

    #[test]
    fn keeps_comments_around_the_insertion() {
        let original = "# top comment\nvhosts:\n  - vhost: [\"a.example.com\"]\n    routes:\n      - prefix: \"/\"\n        target: \"http://127.0.0.1:1\"\n\n# a note about what follows\nroutes:\n  - prefix: \"/legacy\"\n    target: \"http://127.0.0.1:9\"\n";
        let out = append_vhost_group(original, "vhost: [\"b.example.com\"]\nroutes:\n  - prefix: \"/\"\n    target: \"http://127.0.0.1:2\"");
        assert!(out.contains("# top comment"));
        assert!(out.contains("# a note about what follows"));
        // The trailing comment still introduces `routes:`, not the new item.
        let comment = out.find("# a note about what follows").unwrap();
        let legacy = out.find("routes:\n  - prefix: \"/legacy\"").unwrap();
        let inserted = out.find("b.example.com").unwrap();
        assert!(inserted < comment && comment < legacy);
        serde_yaml::from_str::<RouteConfig>(&out).expect("must still parse");
    }

    #[test]
    fn replaces_access_keys_in_place() {
        let original = "vhosts:\n  - vhost: [\"a.example.com\"]\n    allow_groups:\n      - old\n      - stale\n    session_cookie: true\n    routes:\n      - prefix: \"/\"\n        target: \"http://127.0.0.1:1\"\n";
        let out = set_access_keys(
            original,
            "a.example.com",
            &[("allow_groups".into(), "[\"staff\"]".into())],
        )
        .expect("the host is declared");
        assert!(!out.contains("stale"), "continuation lines must go too");
        assert!(out.contains("allow_groups: [\"staff\"]"));
        assert!(out.contains("session_cookie: true"), "other keys untouched");
        let parsed: RouteConfig = serde_yaml::from_str(&out).expect("must still parse");
        assert_eq!(parsed.vhosts[0].allow_groups, vec!["staff".to_string()]);
    }

    #[test]
    fn access_keys_land_above_routes() {
        let original = "vhosts:\n  - vhost: [\"a.example.com\"]\n    routes:\n      - prefix: \"/\"\n        target: \"http://127.0.0.1:1\"\n";
        let out = set_access_keys(
            original,
            "a.example.com",
            &[("allow_users".into(), "[\"alice\"]".into())],
        )
        .unwrap();
        assert!(out.find("allow_users").unwrap() < out.find("routes:").unwrap());
        serde_yaml::from_str::<RouteConfig>(&out).expect("must still parse");
    }

    #[test]
    fn refuses_a_host_that_is_not_in_a_group() {
        let original = "vhosts:\n  - vhost: [\"a.example.com\"]\n    routes:\n      - prefix: \"/\"\n        target: \"http://127.0.0.1:1\"\n";
        assert!(set_access_keys(original, "other.example.com", &[]).is_err());
    }

    #[test]
    fn nested_bullets_are_not_mistaken_for_entries() {
        let original = "vhosts:\n  - vhost: [\"a.example.com\"]\n    routes:\n      - prefix: \"/\"\n        backends:\n          - url: \"http://127.0.0.1:1\"\n            weight: 1\n  - vhost: [\"b.example.com\"]\n    routes:\n      - prefix: \"/\"\n        target: \"http://127.0.0.1:2\"\n";
        let out = set_access_keys(
            original,
            "b.example.com",
            &[("allow_users".into(), "[\"bob\"]".into())],
        )
        .unwrap();
        let parsed: RouteConfig = serde_yaml::from_str(&out).expect("must still parse");
        assert!(parsed.vhosts[0].allow_users.is_empty());
        assert_eq!(parsed.vhosts[1].allow_users, vec!["bob".to_string()]);
    }
}
