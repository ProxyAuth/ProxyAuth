//! End-to-end checks of the login redirect, through `global_proxy`.
//!
//! The `topics.proxyauth.app` vhost below is the real production layout:
//! a public site on `/`, a public login page on `/login`, and an admin
//! area on `/admin` behind `required_login`. Requests go through the
//! whole request path — routing, session check, proxying to a real
//! local backend — with real session tokens.

#[cfg(test)]
mod tests {
    use actix_web::body::MessageBody;
    use actix_web::dev::{Service, ServiceResponse};
    use actix_web::http::{StatusCode, header};
    use actix_web::test::{self, TestRequest};
    use actix_web::{App, web};
    use proxyauth::config::config::{AppConfig, AppState, RouteConfig, load_config};
    use proxyauth::network::proxy::global_proxy;
    use proxyauth::network::stats::RequestStats;
    use proxyauth::stats::tokencount::CounterToken;
    use proxyauth::token::security::issue_token;
    use std::io::{BufRead, BufReader, Write};
    use std::net::{SocketAddr, TcpListener};
    use std::path::PathBuf;
    use std::sync::{Arc, OnceLock};

    const SITE: &str = "topics.proxyauth.app";
    const RESTRICTED: &str = "restricted.example.com";
    const LEGACY: &str = "legacy.example.com";

    const ADMIN: usize = 0;
    const BOB: usize = 1;

    // ── shared fixtures ──────────────────────────────────────

    /// A tiny HTTP backend: answers every request with
    /// `backend:<path>`, so a test can tell the request was proxied.
    fn backend() -> SocketAddr {
        static ADDR: OnceLock<SocketAddr> = OnceLock::new();
        *ADDR.get_or_init(|| {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind test backend");
            let addr = listener.local_addr().unwrap();
            std::thread::spawn(move || {
                for stream in listener.incoming().flatten() {
                    std::thread::spawn(move || {
                        let mut reader = BufReader::new(stream);
                        let mut request_line = String::new();
                        if reader.read_line(&mut request_line).is_err() {
                            return;
                        }
                        let path = request_line
                            .split_whitespace()
                            .nth(1)
                            .unwrap_or("?")
                            .to_string();
                        let mut line = String::new();
                        while reader.read_line(&mut line).is_ok() {
                            if line == "\r\n" || line.is_empty() {
                                break;
                            }
                            line.clear();
                        }
                        let body = format!("backend:{path}");
                        let mut stream = reader.into_inner();
                        let _ = write!(
                            stream,
                            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                    });
                }
            });
            addr
        })
    }

    fn static_dir() -> PathBuf {
        static DIR: OnceLock<PathBuf> = OnceLock::new();
        DIR.get_or_init(|| {
            let dir = std::env::temp_dir().join(format!("proxyauth-login-e2e-{}", std::process::id()));
            std::fs::create_dir_all(dir.join("topics")).unwrap();
            std::fs::write(
                dir.join("topics/login.html"),
                r#"<form method="POST" action="/auth"><input name="csrf_token" value="{{ csrf_token }}"></form>"#,
            )
            .unwrap();
            std::fs::write(dir.join("sitemap.xml"), "<urlset/>").unwrap();
            std::fs::write(dir.join("robots.txt"), "User-agent: *").unwrap();
            dir
        })
        .clone()
    }

    /// Loaded through `load_config`, the same function the server uses
    /// at startup, so group membership is indexed exactly as in
    /// production.
    fn config() -> Arc<AppConfig> {
        static CONFIG: OnceLock<Arc<AppConfig>> = OnceLock::new();
        CONFIG
            .get_or_init(|| {
                let path = static_dir().join("config.json");
                let json = serde_json::json!({
                    "token_expiry_seconds": 3600,
                    "secret": "e2e-login-redirect-secret-e2e-login-redirect-secret-0123456789",
                    "users": [
                        { "username": "admin", "password": "unused", "groups": ["ops"] },
                        { "username": "bob", "password": "unused", "groups": ["guests"] }
                    ],
                    "log": { "type": "disabled" },
                    "smtp": null,
                    "session_cookie": true,
                    "csrf_token": true
                });
                std::fs::write(&path, serde_json::to_string_pretty(&json).unwrap()).unwrap();
                let config = load_config(path.to_str().unwrap());
                assert_eq!(config.users[ADMIN].username, "admin");
                assert_eq!(config.users[BOB].username, "bob");
                proxyauth::token::vault::init(&config).expect("initialise the token vault");
                config
            })
            .clone()
    }

    /// The production vhost, unchanged apart from the backend address
    /// and the static paths, plus two small vhosts for the cases it
    /// does not cover.
    fn routes() -> RouteConfig {
        let backend = format!("http://{}", backend());
        let dir = static_dir();
        let dir = dir.display();
        let yaml = format!(
            r#"
vhosts:
  - vhost: ["{SITE}"]
    log_file: "topics.proxyauth.app.access.log"
    certbot_renew: true
    tag_proxyauth: false
    forward_proxy_headers: true
    login_redirect_url: "/admin"
    login_via_otp: false
    logout_redirect_url: "/login"
    max_age_session_cookie: 3600
    allow_users: ["admin"]
    routes:
      - prefix: "/"
        target: "{backend}"
        cache: false
        tag_proxyauth: false
        csrf_token: false
        required_login: false
      - prefix: "/sitemap.xml"
        static: "{dir}/sitemap.xml"
      - prefix: "/robots.txt"
        static: "{dir}/robots.txt"
      - prefix: "/admin"
        target: "{backend}"
        preserve_prefix: true
        required_login: true
        cache: false
      - prefix: "/login"
        static: "{dir}/topics/"
        static_index: "login.html"
        tag_proxyauth: true
        csrf_token: true
        cache: false

  - vhost: ["{RESTRICTED}"]
    redirect_login_url: "/sign-in"
    allow_users: ["admin", "bob"]
    routes:
      - prefix: "/ops"
        target: "{backend}"
        preserve_prefix: true
        required_login: true
        groups: ["ops"]
      - prefix: "/docs"
        static: "{dir}/topics/"
        static_index: "login.html"
        required_login: true

  - vhost: ["{LEGACY}"]
    login_redirect_url: "/app"
    allow_users: ["admin"]
    routes:
      - prefix: "/"
        static: "{dir}/topics/"
        static_index: "login.html"
      - prefix: "/app"
        target: "{backend}"
        preserve_prefix: true
        required_login: true
"#
        );
        serde_yaml::from_str::<RouteConfig>(&yaml)
            .expect("routes.yml fixture must parse")
            .expand_vhost_groups()
    }

    fn state() -> AppState {
        AppState {
            config: config(),
            routes: Arc::new(routes()),
            counter: Arc::new(CounterToken::new()),
            revoked_tokens: Arc::new(dashmap::DashMap::new()),
            stats: RequestStats::new(),
            ip_blocklist: Arc::new(arc_swap::ArcSwap::from_pointee(Vec::new())),
            redirect_protect_url_ips: Arc::new(dashmap::DashMap::new()),
            otp_overrides: Arc::new(dashmap::DashMap::new()),
            password_overrides: Arc::new(dashmap::DashMap::new()),
            must_change_overrides: Arc::new(dashmap::DashMap::new()),
        }
    }

    fn session(user_index: usize, username: &str, token_id: &str) -> String {
        config();
        let expires = (chrono::Utc::now().timestamp() + 600).to_string();
        issue_token(username, user_index, &expires, token_id).expect("issue a session token")
    }

    fn admin_session() -> String {
        session(ADMIN, "admin", "e2e-admin")
    }

    /// A browser opening `path` on `host`, over HTTPS terminated by a
    /// trusted local proxy — the setup under which ProxyAuth accepts the
    /// `Secure` session cookie.
    fn open(host: &str, path: &str) -> TestRequest {
        TestRequest::get()
            .uri(path)
            .peer_addr("127.0.0.1:45000".parse().unwrap())
            .insert_header((header::HOST, host))
            .insert_header(("x-forwarded-proto", "https"))
            .insert_header(("sec-fetch-mode", "navigate"))
            .insert_header((header::ACCEPT, "text/html,application/xhtml+xml,*/*;q=0.8"))
    }

    fn with_cookie(req: TestRequest, token: &str) -> TestRequest {
        req.insert_header((header::COOKIE, format!("session_token={token}")))
    }

    async fn call(
        state: AppState,
        req: TestRequest,
    ) -> ServiceResponse<impl MessageBody> {
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(state))
                .default_service(web::to(global_proxy)),
        )
        .await;
        app.call(req.to_request()).await.expect("service call")
    }

    async fn send(req: TestRequest) -> (StatusCode, Option<String>, Option<String>, String) {
        let resp = call(state(), req).await;
        let status = resp.status();
        let header_value = |name| {
            resp.headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        };
        let location = header_value(header::LOCATION);
        let cookie = header_value(header::SET_COOKIE);
        let body = test::read_body(resp).await;
        (status, location, cookie, String::from_utf8_lossy(&body).into_owned())
    }

    fn assert_cleared(cookie: Option<String>) {
        let cookie = cookie.expect("the stale session cookie must be cleared");
        assert!(cookie.starts_with("session_token=;") && cookie.contains("Max-Age=0"), "{cookie}");
    }

    // ── not signed in ────────────────────────────────────────

    #[actix_web::test]
    async fn anonymous_visitor_reads_the_public_site() {
        let (status, location, _, body) = send(open(SITE, "/")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(location, None);
        assert_eq!(body, "backend:/");

        let (status, _, _, body) = send(open(SITE, "/blog/some-article")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "backend:/blog/some-article");

        let (status, _, _, body) = send(open(SITE, "/sitemap.xml")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "<urlset/>");
    }

    #[actix_web::test]
    async fn anonymous_visitor_is_sent_from_admin_to_the_login_page() {
        for path in ["/admin", "/admin/", "/admin/stats?days=30"] {
            let (status, location, cookie, _) = send(open(SITE, path)).await;
            assert_eq!(status, StatusCode::FOUND, "{path}");
            assert_eq!(location.as_deref(), Some("/login"), "{path}");
            assert_eq!(cookie, None, "{path}: nothing to clear without a cookie");
        }
    }

    #[actix_web::test]
    async fn the_login_page_itself_is_public() {
        let (status, location, _, body) = send(open(SITE, "/login")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(location, None);
        assert!(body.contains("action=\"/auth\""));
        assert!(!body.contains("{{ csrf_token }}"), "tag_proxyauth must fill the CSRF token");
    }

    #[actix_web::test]
    async fn api_calls_and_writes_keep_their_401() {
        let json = TestRequest::get()
            .uri("/admin/api/stats")
            .peer_addr("127.0.0.1:45000".parse().unwrap())
            .insert_header((header::HOST, SITE))
            .insert_header((header::ACCEPT, "application/json"));
        let (status, location, _, _) = send(json).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(location, None);

        let post = TestRequest::post()
            .uri("/admin")
            .peer_addr("127.0.0.1:45000".parse().unwrap())
            .insert_header((header::HOST, SITE))
            .insert_header((header::ACCEPT, "text/html"));
        let (status, _, _, _) = send(post).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        let bearer = open(SITE, "/admin").insert_header((header::AUTHORIZATION, "Bearer nope"));
        let (status, _, _, _) = send(bearer).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[actix_web::test]
    async fn a_route_level_redirect_login_url_is_used() {
        let (status, location, _, _) = send(open(RESTRICTED, "/ops")).await;
        assert_eq!(status, StatusCode::FOUND);
        assert_eq!(location.as_deref(), Some("/sign-in"));
    }

    #[actix_web::test]
    async fn protected_static_routes_redirect_too() {
        let (status, location, _, _) = send(open(RESTRICTED, "/docs")).await;
        assert_eq!(status, StatusCode::FOUND);
        assert_eq!(location.as_deref(), Some("/sign-in"));
    }

    // ── invalid session ──────────────────────────────────────

    #[actix_web::test]
    async fn an_invalid_cookie_on_admin_goes_to_the_login_page_and_is_cleared() {
        let (status, location, cookie, _) =
            send(with_cookie(open(SITE, "/admin"), "not-a-real-token")).await;
        assert_eq!(status, StatusCode::FOUND);
        assert_eq!(location.as_deref(), Some("/login"));
        assert_cleared(cookie);
    }

    #[actix_web::test]
    async fn a_revoked_session_on_admin_goes_to_the_login_page() {
        let token = session(ADMIN, "admin", "e2e-revoked");
        let state = state();
        state.revoked_tokens.insert("e2e-revoked".to_string(), 0);

        let resp = call(state, with_cookie(open(SITE, "/admin"), &token)).await;
        assert_eq!(resp.status(), StatusCode::FOUND);
        assert_eq!(resp.headers().get(header::LOCATION).unwrap(), "/login");
    }

    #[actix_web::test]
    async fn an_invalid_cookie_does_not_block_the_public_site() {
        let (status, location, _, body) =
            send(with_cookie(open(SITE, "/"), "not-a-real-token")).await;
        assert_eq!(status, StatusCode::OK, "the public home page must still load");
        assert_eq!(location, None);
        assert_eq!(body, "backend:/");
    }

    // ── signed in ────────────────────────────────────────────

    #[actix_web::test]
    async fn signed_in_visitor_can_browse_the_public_site() {
        let token = admin_session();
        for (path, expected) in [
            ("/", "backend:/"),
            ("/blog/some-article", "backend:/blog/some-article"),
            ("/sitemap.xml", "<urlset/>"),
            ("/robots.txt", "User-agent: *"),
        ] {
            let (status, location, _, body) = send(with_cookie(open(SITE, path), &token)).await;
            assert_eq!(status, StatusCode::OK, "{path} must be served, not redirected");
            assert_eq!(location, None, "{path}");
            assert_eq!(body, expected, "{path}");
        }
    }

    #[actix_web::test]
    async fn signed_in_visitor_reaches_admin() {
        let token = admin_session();
        let (status, location, cookie, body) =
            send(with_cookie(open(SITE, "/admin/stats"), &token)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(location, None);
        assert_eq!(cookie, None, "a valid session is never cleared");
        assert_eq!(body, "backend:/admin/stats");
    }

    #[actix_web::test]
    async fn signed_in_visitor_on_the_login_page_goes_to_login_redirect_url() {
        let token = admin_session();
        let (status, location, _, _) = send(with_cookie(open(SITE, "/login"), &token)).await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        assert_eq!(location.as_deref(), Some("/admin"));
    }

    #[actix_web::test]
    async fn signed_in_visitor_without_the_right_group_gets_a_403() {
        let token = session(BOB, "bob", "e2e-bob");
        let (status, location, cookie, _) =
            send(with_cookie(open(RESTRICTED, "/ops"), &token)).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(location, None, "signing in again would not help, so no redirect");
        assert_eq!(cookie, None, "the session stays valid for other routes");

        let token = admin_session();
        let (status, _, _, body) = send(with_cookie(open(RESTRICTED, "/ops"), &token)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "backend:/ops");
    }

    // ── historical layout: login form on "/" ─────────────────

    #[actix_web::test]
    async fn legacy_layout_still_forwards_signed_in_visitors_from_the_root() {
        let token = admin_session();
        let (status, location, _, _) = send(with_cookie(open(LEGACY, "/"), &token)).await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        assert_eq!(location.as_deref(), Some("/app"));

        let (status, _, _, body) = send(open(LEGACY, "/")).await;
        assert_eq!(status, StatusCode::OK, "anonymous visitors get the login form");
        assert!(body.contains("action=\"/auth\""));
    }

    #[actix_web::test]
    async fn legacy_layout_without_a_login_page_keeps_the_401() {
        let (status, location, _, _) = send(open(LEGACY, "/app")).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "no login page configured: the historical 401 is kept");
        assert_eq!(location, None);
    }
}
