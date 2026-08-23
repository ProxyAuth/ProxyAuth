use nix::unistd::Group;
use nix::unistd::{Uid, User, setuid};
use std::fs;
use std::io;
use std::io::Write;
use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::Duration;

pub fn ensure_running_as_proxyauth() {
    let uid = Uid::effective();

    if let Some(user) = User::from_uid(uid).expect("Failed to get current user") {
        if user.name == "proxyauth" {
        } else {
            eprintln!(
                "This program must be run as 'proxyauth'. Current user is '{}'",
                user.name
            );
            std::process::exit(1);
        }
    } else {
        eprintln!("Unable to find current user info.");
        std::process::exit(1);
    }
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

pub fn setup_proxyauth_directory() -> io::Result<()> {
    let path = Path::new("/etc/proxyauth");

    if !path.exists() {
        println!("Creating /etc/proxyauth directory...");
        fs::create_dir_all(path)?;
    } else {
        println!("Directory /etc/proxyauth already exists.");
    }

    let status_chown = Command::new("chown")
        .args(["-R", "proxyauth:proxyauth", "/etc/proxyauth"])
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

    println!("Directory /etc/proxyauth is ready and secured.");
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
    let user = User::from_name(username)?.ok_or("User not found")?;
    setuid(user.uid)?;
    Ok(())
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
