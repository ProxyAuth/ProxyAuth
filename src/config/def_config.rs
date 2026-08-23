use nix::unistd::Group;
use nix::unistd::{Gid, Uid, User, setgid, setuid};
use std::fs;
use std::io;
use std::io::Write;
use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::Duration;

/// Exits unless the effective user matches `expected_username` exactly
/// — the safety check run right after dropping privileges (or
/// confirming the process was already started as the right user), so
/// a misconfigured `run_user`/failed `setuid` never silently falls
/// through to running as whoever actually launched the process.
pub fn ensure_running_as(expected_username: &str) {
    let uid = Uid::effective();

    if let Some(user) = User::from_uid(uid).expect("Failed to get current user") {
        if user.name != expected_username {
            eprintln!(
                "This program must be run as '{expected_username}'. Current user is '{}'",
                user.name
            );
            std::process::exit(1);
        }
    } else {
        eprintln!("Unable to find current user info.");
        std::process::exit(1);
    }
}

/// Called once, at the very start of `main()`, before any privileged
/// setup (creating `config.json`/`routes.yml`, binding sockets,
/// reading TLS certs) — fails fast with a clear, actionable message
/// instead of letting the real cause surface later as a confusing
/// "Permission denied" wherever the first privileged operation
/// happens to run (which is exactly what a raw `fs::create_dir_all`/
/// `File::create` panic looks like: same OS error a config.json typo
/// would produce, with none of the context).
///
/// Passes if either: this process is root (so it can do the
/// privileged bind/cert-read phase, then drop to `expected_username`
/// on its own later), or it's *already* running as `expected_username`
/// directly (skipping the internal drop entirely — a valid deployment
/// too, as long as whatever set it up made sure sockets/certs are
/// already reachable without root). Anything else — some other
/// non-root user — can do neither, so it's refused immediately rather
/// than left to fail unpredictably on whatever runs first.
pub fn ensure_can_become(expected_username: &str) {
    if Uid::effective().is_root() {
        return;
    }

    let current = User::from_uid(Uid::effective())
        .ok()
        .flatten()
        .map(|u| u.name)
        .unwrap_or_else(|| "?".to_string());

    if current != expected_username {
        eprintln!(
            "ProxyAuth must be started as root — it needs root briefly at startup to bind \
             listening sockets and read TLS certificate files, then drops to '{expected_username}' \
             on its own before handling any request (see AppConfig.run_user). It can also be \
             started already running as '{expected_username}' directly, skipping that internal \
             drop. Currently running as '{current}', which is neither — refusing to start now \
             instead of failing later on the first operation that happens to need root."
        );
        std::process::exit(1);
    }
}

/// Lightweight peek at `run_user`/`run_group` in `config.json`, safe
/// to call before the file necessarily even exists (a missing file, or
/// missing/empty fields, all just resolve to the defaults —
/// `"proxyauth"`/no explicit group). Deliberately NOT the full
/// `load_config`: that seeds role indexes, may write the file back for
/// a fresh `token_admin`, etc. — side effects this early "just tell me
/// who we're supposed to run as" peek must not trigger. Shared by
/// `main.rs`'s early `ensure_can_become` check and `prepare`, so both
/// resolve `run_user`/`run_group` with exactly the same rules.
pub fn peek_run_user_group() -> (String, Option<String>) {
    let default = ("proxyauth".to_string(), None);
    let Ok(content) = fs::read_to_string("/etc/proxyauth/config/config.json") else {
        return default;
    };
    let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) else {
        return default;
    };
    // An explicit "" (present but empty) is treated the same as the
    // field being absent — same reasoning as
    // `AppConfig::effective_run_user`/`effective_run_group`.
    let run_user = json
        .get("run_user")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("proxyauth")
        .to_string();
    let run_group = json
        .get("run_group")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    (run_user, run_group)
}

/// Back-compat wrapper for the default user — every existing call site
/// (`prompt.rs`'s `stats` subcommand, tests, ...) keeps working
/// unchanged. `main.rs`'s own startup uses `ensure_running_as` with
/// `AppConfig.run_user` instead, since that's configurable.
pub fn ensure_running_as_proxyauth() {
    ensure_running_as("proxyauth");
}

pub fn ensure_running_as_root() {
    let uid = Uid::effective();

    if let Some(user) = User::from_uid(uid).expect("Failed to get current user") {
        if user.name == "root" {
        } else {
            eprintln!(
                "This program must be run as 'root'. Current user is '{}'",
                user.name
            );
            std::process::exit(1);
        }
    } else {
        eprintln!("Unable to find current user info.");
        std::process::exit(1);
    }
}

fn is_alpine() -> bool {
    if let Ok(content) = fs::read_to_string("/etc/os-release") {
        content.to_lowercase().contains("alpine")
    } else {
        false
    }
}

/// Creates the `proxyauth` system user/group if missing — the default
/// bootstrap target. For a custom `run_user` (e.g. `www-data`, which
/// belongs to some *other* package and shouldn't be created/owned by
/// ProxyAuth's setup), use `ensure_run_user_exists` instead, which only
/// verifies rather than creates.
pub fn ensure_user_proxyauth_exists() -> io::Result<()> {
    let alpine = is_alpine();

    println!(
        "Detected OS: {}",
        if alpine { "Alpine" } else { "Debian/Ubuntu" }
    );

    if Group::from_name("proxyauth")?.is_none() {
        println!("Group 'proxyauth' not found. Creating group...");

        let group_cmd = if alpine { "addgroup" } else { "groupadd" };

        let status_group = Command::new(group_cmd).arg("proxyauth").status()?;

        if !status_group.success() {
            eprintln!("Failed to create group 'proxyauth'.");
            std::process::exit(1);
        }
        println!("Group 'proxyauth' created.");
    } else {
        println!("Group 'proxyauth' already exists.");
    }

    if User::from_name("proxyauth")?.is_none() {
        println!("User 'proxyauth' not found. Creating user...");

        let status_user = if alpine {
            Command::new("adduser")
                .args(["-S", "-G", "proxyauth", "proxyauth"])
                .status()?
        } else {
            Command::new("useradd")
                .args([
                    "--system",
                    "--no-create-home",
                    "--shell",
                    "/usr/sbin/nologin",
                    "--gid",
                    "proxyauth",
                    "proxyauth",
                ])
                .status()?
        };

        if !status_user.success() {
            eprintln!("Failed to create user 'proxyauth'.");
            std::process::exit(1);
        }

        println!("User 'proxyauth' created.");
        println!("Waiting for system to register new user...");
        thread::sleep(Duration::from_millis(500));
    } else {
        println!("User 'proxyauth' already exists.");
    }

    Ok(())
}

/// Verifies a *custom* `run_user` (and, if given, `run_group`) already
/// exists on the system — used by `prepare` instead of
/// `ensure_user_proxyauth_exists` whenever `config.json` sets `run_user`
/// to something other than `"proxyauth"`. Deliberately does NOT create
/// the account: a value like `www-data`/`nginx` is expected to already
/// exist, installed and owned by that other package — ProxyAuth
/// creating or modifying it would be surprising and out of scope.
pub fn ensure_run_user_exists(username: &str, groupname: Option<&str>) -> io::Result<()> {
    if User::from_name(username)?.is_none() {
        eprintln!(
            "run_user is set to '{username}' but no such system user exists. \
             Create it first (it's expected to belong to whatever else already \
             owns the files you want ProxyAuth to read, e.g. a web server package) \
             — ProxyAuth won't create a non-default run_user automatically."
        );
        std::process::exit(1);
    }
    if let Some(group) = groupname {
        if Group::from_name(group)?.is_none() {
            eprintln!("run_group is set to '{group}' but no such system group exists.");
            std::process::exit(1);
        }
    }
    println!("run_user '{username}' verified.");
    Ok(())
}

pub fn setup_proxyauth_directory() -> io::Result<()> {
    setup_proxyauth_directory_for("proxyauth", "proxyauth")
}

/// Same as `setup_proxyauth_directory`, but for an arbitrary
/// `user:group` — used by `prepare` when `config.json` sets a custom
/// `run_user`/`run_group`, so `/etc/proxyauth` (config, routes, certs,
/// ...) ends up owned by whoever the server will actually run as,
/// instead of always `proxyauth:proxyauth`.
pub fn setup_proxyauth_directory_for(user: &str, group: &str) -> io::Result<()> {
    let path = Path::new("/etc/proxyauth");

    if !path.exists() {
        println!("Creating /etc/proxyauth directory...");
        fs::create_dir_all(path)?;
    } else {
        println!("Directory /etc/proxyauth already exists.");
    }

    let owner_spec = format!("{user}:{group}");
    let status_chown = Command::new("chown")
        .args(["-R", &owner_spec, "/etc/proxyauth"])
        .status()?;

    if !status_chown.success() {
        eprintln!("Failed to change owner of /etc/proxyauth.");
        std::process::exit(1);
    }

    let status_chmod = Command::new("chmod")
        .args(["750", "/etc/proxyauth"])
        .status()?;

    if !status_chmod.success() {
        eprintln!("Failed to set permissions on /etc/proxyauth.");
        std::process::exit(1);
    }

    println!("Directory /etc/proxyauth is ready and secured for '{owner_spec}'.");
    Ok(())
}

pub fn setup_proxyauth_db_directory(insecure: bool) -> io::Result<()> {
    let path = Path::new("/opt/proxyauth/db");

    if !path.exists() {
        println!("Creating /opt/proxyauth/db directory...");
        fs::create_dir_all(path)?;
    } else {
        println!("Directory /opt/proxyauth/db already exists.");
    }

    let status_chown = Command::new("chown")
        .args(["-R", "proxyauth:proxyauth", "/opt/proxyauth"])
        .status()?;

    if !status_chown.success() {
        eprintln!("Failed to change owner of /opt/proxyauth.");
        std::process::exit(1);
    }

    let chmod_mode = if insecure { "777" } else { "700" };

    let status_chmod = Command::new("chmod")
        .args([chmod_mode, "/opt/proxyauth"])
        .status()?;

    if !status_chmod.success() {
        eprintln!("Failed to set permissions on /opt/proxyauth.");
        std::process::exit(1);
    }

    if insecure {
        println!("WARN ! Directory /opt/proxyauth/db is set to insecure mode.");
    } else {
        println!("Directory /opt/proxyauth/db is secured.");
    }

    Ok(())
}

pub fn switch_to_user(username: &str) -> Result<(), Box<dyn std::error::Error>> {
    switch_to_user_and_group(username, None)
}

/// Like `switch_to_user`, but also sets the group — either an
/// explicit `groupname`, or the target user's own primary group when
/// `None`. **Order matters**: group must be set *before* dropping the
/// user ID, since once the effective UID is no longer root the process
/// typically no longer has `CAP_SETGID` to change it — dropping UID
/// first and GID second is a classic way to end up silently still
/// running with root's original group.
pub fn switch_to_user_and_group(
    username: &str,
    groupname: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let user = User::from_name(username)?.ok_or("User not found")?;

    let gid: Gid = match groupname {
        Some(g) => Group::from_name(g)?.ok_or("Group not found")?.gid,
        None => user.gid,
    };

    setgid(gid)?;
    setuid(user.uid)?;
    Ok(())
}

/// Best-effort re-assertion of `/etc/proxyauth` ownership, meant to be
/// called every single startup — right before dropping from root to
/// the configured `run_user`/`run_group` — not just once during
/// `proxyauth prepare` like `setup_proxyauth_directory` above. Covers
/// the case where `config.json`/`routes.yml` (or a TLS cert) got
/// created for the first time *during this run's brief root phase*
/// (bind + cert load): without this, a freshly-created file would stay
/// root-owned forever, and the server — already unprivileged by the
/// time it needs to write back to it (e.g. regenerating `token_admin`,
/// persisting an OTP reset) — would silently lose write access to it.
///
/// Deliberately non-fatal (unlike `setup_proxyauth_directory`, which
/// `exit(1)`s on failure): this runs unconditionally on every normal
/// server startup, not just an explicit one-time admin action, so a
/// transient failure here must never take the whole server down. A
/// failure is logged and startup continues — whatever ownership
/// already existed from a prior `proxyauth prepare` run is very likely
/// still correct anyway.
pub fn reassert_proxyauth_ownership() {
    reassert_ownership("proxyauth", None);
}

/// Same as `reassert_proxyauth_ownership`, generalized to whatever
/// `run_user`/`run_group` `config.json` configures.
pub fn reassert_ownership(user: &str, group: Option<&str>) {
    if !Uid::effective().is_root() {
        // We were never root this run (e.g. already started as the
        // target user at the service-manager level) — nothing to fix
        // up, and we couldn't chown as a non-root user anyway.
        return;
    }

    let owner_spec = format!("{user}:{}", group.unwrap_or(user));
    match Command::new("chown")
        .args(["-R", &owner_spec, "/etc/proxyauth"])
        .status()
    {
        Ok(status) if status.success() => {}
        Ok(status) => {
            eprintln!(
                "Warning: chown -R {owner_spec} /etc/proxyauth exited with {status}; continuing anyway"
            );
        }
        Err(e) => {
            eprintln!("Warning: failed to run chown on /etc/proxyauth: {e}; continuing anyway");
        }
    }
}

pub async fn create_config(url: &str, path: &str) -> Result<(), Box<dyn std::error::Error>> {
    if Path::new(path).exists() {
        return Ok(());
    }

    println!("Config file {} not found. Downloading from {}", path, url);

    let response = reqwest::get(url).await?;
    if !response.status().is_success() {
        return Err(format!("Failed to download config: HTTP {}", response.status()).into());
    }

    let content = response.bytes().await?;

    if let Some(parent) = Path::new(path).parent() {
        if !parent.exists() {
            fs::create_dir_all(parent)?;
        }
    }

    let mut file = fs::File::create(path)?;
    file.write_all(&content)?;

    println!("Config downloaded and saved to {}", path);

    Ok(())
}

/// Default `routes.yml` written on first run when the file is missing.
/// Built line by line with explicit "\n" so the exact bytes written to
/// disk are fully controlled (no ambiguity from how a multi-line raw
/// string literal is stored/edited).
pub const DEFAULT_ROUTES_YML: &str = concat!(
    "routes:\n",
    "  - prefix: \"/login\"\n",
    "    target: \"http://127.0.0.1:8000/login\"\n",
    "    required_login: false\n",
    "  - prefix: \"/private\"\n",
    "    target: \"http://127.0.0.1:8000/myapp/\"\n",
    "    required_login: true\n",
    "    username: [\"admin\"]\n",
    "  # vhost is optional. Leave it out (as above) and the route\n",
    "  # matches any Host header, same as before this field existed.\n",
    "  # List one or more hostnames to scope a route to specific\n",
    "  # frontend domain(s) — several routes can reuse the same\n",
    "  # prefix as long as their vhost lists don't overlap.\n",
    "  # - prefix: \"/private\"\n",
    "  #   vhost: [\"app.example.com\"]\n",
    "  #   target: \"http://127.0.0.1:8001/myapp/\"\n",
    "  #   required_login: true\n",
    "  #   username: [\"admin\"]\n",
    "  #   # Optional: serve a dedicated certificate for this vhost\n",
    "  #   # (SNI). Omit it and this vhost falls back to the server's\n",
    "  #   # global TLS certificate.\n",
    "  #   vhost_cert:\n",
    "  #     cert: \"/etc/proxyauth/certs/app.example.com/cert.pem\"\n",
    "  #     key: \"/etc/proxyauth/certs/app.example.com/key.pem\"\n",
    "  # allow_ips/deny_ips are optional too. Left out, a route has no IP\n",
    "  # restriction, same as before these fields existed. deny_ips wins\n",
    "  # over allow_ips (checked first).\n",
    "  # allow_ips: [\"192.168.1.0/24\", \"10.0.0.5\"]\n",
    "  # deny_ips: [\"192.168.1.66\"]\n",
    "  # A route can also serve file(s) straight from disk instead of\n",
    "  # proxying — set `static` (target is then ignored/optional). It can\n",
    "  # point at a directory (served with static_index, default\n",
    "  # \"index.html\", for directory-shaped requests) or at a single file\n",
    "  # (always served as-is, e.g. a fixed /robots.txt). Only GET/HEAD.\n",
    "  # - prefix: \"/docs\"\n",
    "  #   static: \"/var/www/docs\"\n",
    "  # - prefix: \"/robots.txt\"\n",
    "  #   static: \"/var/www/robots.txt\"\n",
    "  # Regex routes are matched by pattern instead of prefix (tried\n",
    "  # before every plain-prefix route), like nginx's \"location ~\".\n",
    "  # Named captures can rewrite the target/static path via {name}.\n",
    "  # - prefix: \"/config-version\"          # label only, not matched\n",
    "  #   regex: '^/config/(?<major>\\d+)\\.(?<minor>\\d+)\\.(?<patch>\\d+)(?:-[^/]+)?/(?<file>.+)$'\n",
    "  #   static: \"/var/www/docs/config\"\n",
    "  #   static_rewrite: \"{major}.{minor}.x/{file}\"\n",
    "  # need_csrf (per route, default true — only matters when both\n",
    "  # session_cookie and csrf_token are also true) can also be set once\n",
    "  # on a \"vhosts:\" group instead of on every route in it; an explicit\n",
    "  # need_csrf on a route always wins over its group's.\n",
    "  # vhosts:\n",
    "  #   - vhost: [\"api.example.com\"]\n",
    "  #     need_csrf: false   # e.g. a pure API/webhook domain, no cookies\n",
    "  #     routes:\n",
    "  #       - prefix: \"/\"\n",
    "  #         target: \"http://127.0.0.1:9000\"\n",
);

/// Default `config.json` written on first run when the file is missing.
/// Same approach: explicit "\n"-joined lines, no raw string block.
pub const DEFAULT_CONFIG_JSON: &str = concat!(
    "{\n",
    "  \"token_expiry_seconds\": 432000,\n",
    "  \"secret\": \"supersecretvalue\",\n",
    "  \"host\": \"0.0.0.0\",\n",
    "  \"port\": 8080,\n",
    "  \"worker\": 8,\n",
    "  \"log\": {\"type\": \"disabled\"},\n",
    "  \"stats\": false,\n",
    "  \"max_idle_per_host\": 500,\n",
    "  \"ratelimit_auth\": {\n",
    "    \"burst\": 100,\n",
    "    \"block_delay\": 5000,\n",
    "    \"requests_per_second\": 5\n",
    "  },\n",
    "  \"ratelimit_proxy\": {\n",
    "    \"block_delay\": 5000,\n",
    "    \"requests_per_second\": 5,\n",
    "    \"burst\": 10\n",
    "  },\n",
    "  \"users\": [\n",
    "    {\n",
    "      \"username\": \"admin\",\n",
    "      \"password\": \"$argon2id$v=19$m=19456,t=2,p=1$aZVPx4hZQllgOdwX8i/PYg$Fyw3kArZTM/EKSWEmltNjV5UqW8fJLaFxt9vi95TcWY\"\n",
    "    },\n",
    "    {\n",
    "      \"username\": \"alice\",\n",
    "      \"password\": \"$argon2id$v=19$m=19456,t=2,p=1$r73ntuqsRREIylIXQZo+Tw$Vo75eHcuhtCKmycN9aO049HwXU/iW5jHNkCrOSL56zQ\"\n",
    "    }\n",
    "  ]\n",
    "}\n",
);

/// Writes `content` to `path` only if the file does not already exist.
/// Used to seed default config files (`config.json`, `routes.yml`) on first
/// run, without ever overwriting a config the user has customized.
pub fn create_default_file(path: &str, content: &str) -> io::Result<()> {
    if Path::new(path).exists() {
        return Ok(());
    }

    println!("Config file {} not found. Creating default file...", path);

    if let Some(parent) = Path::new(path).parent() {
        if !parent.exists() {
            fs::create_dir_all(parent)?;
        }
    }

    let mut file = fs::File::create(path)?;
    file.write_all(content.as_bytes())?;

    println!("Default config written to {}", path);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::create_config;
    use std::{fs, net::SocketAddr, path::PathBuf};
    use tokio::task::JoinHandle;

    use actix_web::{App, HttpResponse, HttpServer, web};

    // --- Helpers -------------------------------------------------------------

    async fn start_test_server(status: u16, body: &'static [u8]) -> (SocketAddr, JoinHandle<()>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.set_nonblocking(true).unwrap();
        let local_addr = listener.local_addr().unwrap();

        let handle = tokio::spawn(async move {
            HttpServer::new(move || {
                App::new().default_service(web::to(move || async move {
                    HttpResponse::build(actix_web::http::StatusCode::from_u16(status).unwrap())
                        .body(body)
                }))
            })
            .listen(listener)
            .unwrap()
            .run()
            .await
            .unwrap();
        });

        // Laisser le serveur démarrer
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        (local_addr, handle)
    }

    fn tmp_path(name: &str) -> PathBuf {
        let suffix = format!(
            "{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        std::env::temp_dir().join(format!("proxyauth_test_{}_{}", name, suffix))
    }

    // --- Tests ---------------------------------------------------------------

    #[tokio::test(flavor = "current_thread")]
    async fn create_config_downloads_when_missing() {
        let expected = b"CONFIG_CONTENT";
        let (addr, _h) = start_test_server(200, expected).await;
        let url = format!("http://{}/config.json", addr);

        let path = tmp_path("dl_ok").join("cfg/config.json");
        let _ = fs::remove_file(&path);

        create_config(&url, path.to_str().unwrap())
            .await
            .expect("download OK");

        let got = fs::read(&path).expect("file exists");
        assert_eq!(got, expected);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn create_config_is_noop_when_file_exists() {
        let server_body = b"SHOULD_NOT_OVERWRITE";
        let (addr, _h) = start_test_server(200, server_body).await;
        let url = format!("http://{}/conf.json", addr);

        let path = tmp_path("noop").join("already/exists/config.json");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let original = b"LOCAL_PRESENT";
        fs::write(&path, original).unwrap();

        create_config(&url, path.to_str().unwrap())
            .await
            .expect("noop OK");

        let got = fs::read(&path).unwrap();
        assert_eq!(&got, original, "existing file must not be overwritten");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn create_config_returns_error_on_non_200() {
        let (addr, _h) = start_test_server(404, b"nope").await;
        let url = format!("http://{}/missing.json", addr);

        let path = tmp_path("err").join("cfg/config.json");
        let _ = fs::remove_file(&path);

        let err = create_config(&url, path.to_str().unwrap()).await.err();
        assert!(err.is_some(), "non-200 must yield an error");
    }
}
