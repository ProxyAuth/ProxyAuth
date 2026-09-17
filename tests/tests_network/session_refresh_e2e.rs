//! Session renewal through `global_proxy`, with real tokens and a real
//! backend: a stale session gets a new cookie without signing in again,
//! the replaced token keeps working for the grace period and is refused
//! afterwards.

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
    use proxyauth::revoke::load::{pack_rotation, rotated_key};
    use proxyauth::stats::tokencount::CounterToken;
    use proxyauth::token::security::{TokenData, issue_session_token, now_secs};
    use std::io::{BufRead, BufReader, Write};
    use std::net::{SocketAddr, TcpListener};
    use std::sync::{Arc, OnceLock};

    const SITE: &str = "refresh.example.com";
    const NO_REFRESH: &str = "norefresh.example.com";
    const SHORT: &str = "short.example.com";

    const INTERVAL: u64 = 900;
    const GRACE: u64 = 30;
    const LIFETIME: u64 = 3600;

    fn backend() -> SocketAddr {
        static ADDR: OnceLock<SocketAddr> = OnceLock::new();
        *ADDR.get_or_init(|| {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind test backend");
            let addr = listener.local_addr().unwrap();
            std::thread::spawn(move || {
                for stream in listener.incoming().flatten() {
                    std::thread::spawn(move || {
                        let mut reader = BufReader::new(stream);
                        let mut first = String::new();
                        if reader.read_line(&mut first).is_err() {
                            return;
                        }
                        let path = first.split_whitespace().nth(1).unwrap_or("?").to_string();
                        let mut line = String::new();
                        while reader.read_line(&mut line).is_ok() {
                            if line == "\r\n" || line.is_empty() {
                                break;
                            }
                            line.clear();
                        }
                        let body = format!("backend:{path}");
                        // Pages under /cached are what a CDN would keep.
                        let cache = if path.starts_with("/cached") {
                            "Cache-Control: public, max-age=3600\r\nExpires: Thu, 01 Jan 2099 00:00:00 GMT\r\n"
                        } else {
                            ""
                        };
                        let mut stream = reader.into_inner();
                        let _ = write!(
                            stream,
                            "HTTP/1.1 200 OK\r\n{cache}Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                    });
                }
            });
            addr
        })
    }

    fn config() -> Arc<AppConfig> {
        static CONFIG: OnceLock<Arc<AppConfig>> = OnceLock::new();
        CONFIG
            .get_or_init(|| {
                let dir = std::env::temp_dir()
                    .join(format!("proxyauth-refresh-e2e-{}", std::process::id()));
                std::fs::create_dir_all(&dir).unwrap();
                let path = dir.join("config.json");
                let json = serde_json::json!({
                    "token_expiry_seconds": LIFETIME,
                    "secret": "session-refresh-e2e-secret-session-refresh-e2e-secret-0123",
                    "users": [ { "username": "admin", "password": "unused" } ],
                    "log": { "type": "disabled" },
                    "smtp": null,
                    "session_cookie": true,
                    "max_age_session_cookie": 1800,
                    "session_refresh_interval_secs": INTERVAL,
                    "session_refresh_grace_secs": GRACE,
                    "timezone": "UTC"
                });
                std::fs::write(&path, serde_json::to_string_pretty(&json).unwrap()).unwrap();
                let config = load_config(path.to_str().unwrap());
                proxyauth::token::vault::init(&config).expect("token vault");
                config
            })
            .clone()
    }

    fn static_dir() -> std::path::PathBuf {
        static DIR: OnceLock<std::path::PathBuf> = OnceLock::new();
        DIR.get_or_init(|| {
            let dir = std::env::temp_dir()
                .join(format!("proxyauth-refresh-e2e-www-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("index.html"), "public static page").unwrap();
            dir
        })
        .clone()
    }

    fn routes() -> RouteConfig {
        let backend = format!("http://{}", backend());
        let www = static_dir();
        let www = www.display();
        let yaml = format!(
            r#"
vhosts:
  - vhost: ["{SITE}"]
    logout_redirect_url: "/login"
    allow_users: ["admin"]
    routes:
      - prefix: "/"
        target: "{backend}"
      - prefix: "/docs"
        static: "{www}/"
      - prefix: "/admin"
        target: "{backend}"
        preserve_prefix: true
        required_login: true

  - vhost: ["{NO_REFRESH}"]
    logout_redirect_url: "/login"
    session_refresh_interval_secs: 0
    allow_users: ["admin"]
    routes:
      - prefix: "/"
        target: "{backend}"
      - prefix: "/admin"
        target: "{backend}"
        preserve_prefix: true
        required_login: true

  - vhost: ["{SHORT}"]
    logout_redirect_url: "/login"
    session_max_lifetime_secs: 7200
    allow_users: ["admin"]
    routes:
      - prefix: "/"
        target: "{backend}"
      - prefix: "/admin"
        target: "{backend}"
        preserve_prefix: true
        required_login: true
"#
        );
        serde_yaml::from_str::<RouteConfig>(&yaml)
            .expect("routes fixture")
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

    /// A session token issued `age` seconds ago, in a session that began
    /// `session_age` seconds ago.
    fn token(id: &str, age: u64, session_age: u64) -> String {
        config();
        let now = now_secs();
        let issued_at = now - age;
        issue_session_token(
            "admin",
            issued_at + LIFETIME,
            id,
            &TokenData {
                index_user: 0,
                issued_at,
                session_started_at: now - session_age,
            },
        )
        .expect("issue token")
    }

    fn open(host: &str, path: &str, cookie: &str) -> TestRequest {
        TestRequest::get()
            .uri(path)
            .peer_addr("127.0.0.1:45001".parse().unwrap())
            .insert_header((header::HOST, host))
            .insert_header(("x-forwarded-proto", "https"))
            .insert_header(("sec-fetch-mode", "navigate"))
            .insert_header((header::ACCEPT, "text/html"))
            .insert_header((header::COOKIE, format!("session_token={cookie}")))
    }

    async fn call(state: &AppState, req: TestRequest) -> ServiceResponse<impl MessageBody> {
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(state.clone()))
                .default_service(web::to(global_proxy)),
        )
        .await;
        app.call(req.to_request()).await.expect("service call")
    }

    struct Outcome {
        status: StatusCode,
        location: Option<String>,
        new_token: Option<String>,
        cookie: Option<String>,
        cleared: bool,
        body: String,
    }

    async fn send(state: &AppState, req: TestRequest) -> Outcome {
        let resp = call(state, req).await;
        let status = resp.status();
        let location = resp
            .headers()
            .get(header::LOCATION)
            .map(|v| v.to_str().unwrap().to_string());
        let cookie = resp
            .headers()
            .get_all(header::SET_COOKIE)
            .map(|v| v.to_str().unwrap().to_string())
            .find(|c| c.starts_with("session_token=") && !c.starts_with("session_token=;"));
        let cleared = resp
            .headers()
            .get_all(header::SET_COOKIE)
            .filter_map(|v| v.to_str().ok())
            .any(|c| c.starts_with("session_token=;") && c.contains("Max-Age=0"));
        let new_token = cookie.as_ref().map(|c| {
            c.trim_start_matches("session_token=")
                .split(';')
                .next()
                .unwrap()
                .to_string()
        });
        let body = String::from_utf8_lossy(&test::read_body(resp).await).into_owned();
        Outcome {
            status,
            location,
            new_token,
            cookie,
            cleared,
            body,
        }
    }

    // ── no renewal ───────────────────────────────────────────

    #[actix_web::test]
    async fn a_recent_session_is_served_without_a_new_cookie() {
        let state = state();
        let out = send(&state, open(SITE, "/admin", &token("fresh", 60, 60))).await;
        assert_eq!(out.status, StatusCode::OK);
        assert_eq!(out.body, "backend:/admin");
        assert_eq!(out.cookie, None);
        assert!(state.revoked_tokens.is_empty());
    }

    // ── caching ──────────────────────────────────────────────

    async fn cache_headers(state: &AppState, req: TestRequest) -> (Option<String>, Option<String>, bool) {
        let resp = call(state, req).await;
        let get = |name| {
            resp.headers()
                .get(name)
                .map(|v: &header::HeaderValue| v.to_str().unwrap().to_string())
        };
        let has_session_cookie = resp
            .headers()
            .get_all(header::SET_COOKIE)
            .any(|v| v.to_str().unwrap().starts_with("session_token="));
        (get(header::CACHE_CONTROL), get(header::EXPIRES), has_session_cookie)
    }

    #[actix_web::test]
    async fn a_response_carrying_a_new_session_is_never_cached() {
        let state = state();
        let (cache, expires, renewed) =
            cache_headers(&state, open(SITE, "/cached/page", &token("cached-renew", 1200, 1200))).await;
        assert!(renewed);
        let cache = cache.expect("cache-control set");
        assert!(cache.contains("no-store") && cache.contains("private"), "{cache}");
        assert!(!cache.contains("public"), "the backend's public caching is overridden: {cache}");
        assert_eq!(expires, None);
    }

    #[actix_web::test]
    async fn a_response_clearing_the_session_is_never_cached() {
        let state = state();
        let (cache, _, cleared) = cache_headers(&state, open(SITE, "/cached/page", "garbage")).await;
        assert!(cleared);
        assert!(cache.unwrap().contains("no-store"));
    }

    #[actix_web::test]
    async fn caching_is_untouched_when_no_session_cookie_is_sent_back() {
        let state = state();
        let anonymous = TestRequest::get()
            .uri("/cached/page")
            .peer_addr("127.0.0.1:45001".parse().unwrap())
            .insert_header((header::HOST, SITE))
            .insert_header(("x-forwarded-proto", "https"));
        let (cache, expires, cookie) = cache_headers(&state, anonymous).await;
        assert!(!cookie);
        // The route's own caching policy applies, as before.
        let cache = cache.expect("cache-control");
        assert!(cache.starts_with("public"), "{cache}");
        let _ = expires;

        let (cache, _, cookie) =
            cache_headers(&state, open(SITE, "/cached/page", &token("cached-fresh", 30, 30))).await;
        assert!(!cookie, "recent session: nothing sent back");
        assert!(cache.unwrap().starts_with("public"));
    }

    // ── public pages ─────────────────────────────────────────

    #[actix_web::test]
    async fn a_public_page_renews_a_stale_session() {
        let state = state();
        let out = send(&state, open(SITE, "/blog/article", &token("public", 1200, 1200))).await;
        assert_eq!(out.status, StatusCode::OK);
        assert_eq!(out.body, "backend:/blog/article");
        let new_token = out.new_token.expect("renewed on a public page too");

        let session = proxyauth::token::vault::vault().verify(&new_token).unwrap();
        assert_ne!(session.id(), "public");
        assert!(state.revoked_tokens.contains_key(&rotated_key("public")));

        // The renewed session opens the protected area right away.
        let admin = send(&state, open(SITE, "/admin", &new_token)).await;
        assert_eq!(admin.status, StatusCode::OK);
        assert_eq!(admin.cookie, None);
    }

    #[actix_web::test]
    async fn a_public_static_page_renews_too() {
        let state = state();
        let out = send(&state, open(SITE, "/docs/", &token("public-static", 1200, 1200))).await;
        assert_eq!(out.status, StatusCode::OK);
        assert_eq!(out.body, "public static page");
        assert!(out.new_token.is_some());
    }

    #[actix_web::test]
    async fn a_public_page_keeps_a_recent_session_as_is() {
        let state = state();
        let out = send(&state, open(SITE, "/", &token("public-fresh", 30, 30))).await;
        assert_eq!(out.status, StatusCode::OK);
        assert_eq!(out.cookie, None);
        assert!(!out.cleared);
        assert!(state.revoked_tokens.is_empty());
    }

    #[actix_web::test]
    async fn a_public_page_without_a_cookie_is_untouched() {
        let state = state();
        let req = TestRequest::get()
            .uri("/")
            .peer_addr("127.0.0.1:45001".parse().unwrap())
            .insert_header((header::HOST, SITE))
            .insert_header(("x-forwarded-proto", "https"));
        let resp = call(&state, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().get(header::SET_COOKIE).is_none());
    }

    #[actix_web::test]
    async fn a_public_page_clears_an_invalid_cookie_but_is_still_served() {
        let state = state();
        let out = send(&state, open(SITE, "/blog", "not-a-real-token")).await;
        assert_eq!(out.status, StatusCode::OK);
        assert_eq!(out.body, "backend:/blog");
        assert!(out.cleared, "the stale cookie is dropped");
        assert_eq!(out.new_token, None);
    }

    #[actix_web::test]
    async fn a_public_page_clears_a_token_past_its_grace_period() {
        let state = state();
        let old = token("public-after-grace", 1200, 1200);
        let now = now_secs();
        state.revoked_tokens.insert(
            rotated_key("public-after-grace"),
            pack_rotation(now - 1, now + 3600),
        );
        let out = send(&state, open(SITE, "/", &old)).await;
        assert_eq!(out.status, StatusCode::OK);
        assert!(out.cleared);
        assert_eq!(out.new_token, None);
    }

    #[actix_web::test]
    async fn a_public_page_shares_the_renewal_during_the_grace_period() {
        let state = state();
        let old = token("public-grace", 1200, 1200);
        let first = send(&state, open(SITE, "/a", &old)).await;
        let second = send(&state, open(SITE, "/b.css", &old)).await;
        assert_eq!(second.status, StatusCode::OK);
        assert!(first.new_token.is_some(), "the page renews the session");
        assert_eq!(first.new_token, second.new_token, "one renewal for a page and its assets");
    }

    #[actix_web::test]
    async fn a_public_page_clears_a_session_past_its_max_lifetime() {
        let state = state();
        let out = send(&state, open(SHORT, "/", &token("public-too-old", 100, 7300))).await;
        assert_eq!(out.status, StatusCode::OK);
        assert!(out.cleared);
    }

    #[actix_web::test]
    async fn a_public_page_does_nothing_when_renewal_is_off() {
        let state = state();
        let out = send(&state, open(NO_REFRESH, "/", &token("public-off", 1200, 1200))).await;
        assert_eq!(out.status, StatusCode::OK);
        assert_eq!(out.cookie, None);
        assert!(!out.cleared);
    }

    #[actix_web::test]
    async fn a_public_page_ignores_the_cookie_on_an_insecure_connection() {
        let state = state();
        let req = TestRequest::get()
            .uri("/")
            .insert_header((header::HOST, SITE))
            .insert_header((header::COOKIE, format!("session_token={}", token("public-http", 1200, 1200))));
        let resp = call(&state, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().get(header::SET_COOKIE).is_none());
    }

    #[actix_web::test]
    async fn a_public_page_does_not_renew_bearer_clients() {
        let state = state();
        let t = token("public-bearer", 1200, 1200);
        let req = open(SITE, "/", &t).insert_header((header::AUTHORIZATION, format!("Bearer {t}")));
        let out = send(&state, req).await;
        assert_eq!(out.status, StatusCode::OK);
        assert_eq!(out.cookie, None);
        assert!(!out.cleared);
    }

    #[actix_web::test]
    async fn renewal_can_be_disabled_per_vhost() {
        let state = state();
        let out = send(&state, open(NO_REFRESH, "/admin", &token("vhost-off", 1200, 1200))).await;
        assert_eq!(out.status, StatusCode::OK);
        assert_eq!(out.cookie, None);
    }

    #[actix_web::test]
    async fn bearer_clients_are_not_renewed() {
        let state = state();
        let bearer = token("bearer", 1200, 1200);
        let req = TestRequest::get()
            .uri("/admin")
            .peer_addr("127.0.0.1:45001".parse().unwrap())
            .insert_header((header::HOST, SITE))
            .insert_header((header::AUTHORIZATION, format!("Bearer {bearer}")));
        let out = send(&state, req).await;
        assert_eq!(out.status, StatusCode::OK);
        assert_eq!(out.cookie, None);
        assert!(state.revoked_tokens.is_empty());
    }

    // ── renewal ──────────────────────────────────────────────

    #[actix_web::test]
    async fn a_stale_session_gets_a_new_cookie_and_stays_signed_in() {
        let state = state();
        let out = send(&state, open(SITE, "/admin/page", &token("stale", 1000, 1000))).await;

        assert_eq!(out.status, StatusCode::OK, "no sign-in asked");
        assert_eq!(out.body, "backend:/admin/page");

        let cookie = out.cookie.expect("a renewed session cookie");
        for attr in ["HttpOnly", "Secure", "SameSite=Strict", "Path=/", "Max-Age=1800"] {
            assert!(cookie.contains(attr), "{attr} missing in {cookie}");
        }

        let new_token = out.new_token.unwrap();
        let next = send(&state, open(SITE, "/admin/next", &new_token)).await;
        assert_eq!(next.status, StatusCode::OK, "the new token works");
        assert_eq!(next.cookie, None, "and is not renewed again right away");
    }

    #[actix_web::test]
    async fn the_new_token_keeps_the_original_login_time() {
        let state = state();
        let out = send(&state, open(SITE, "/admin", &token("keeps-login", 1000, 5000))).await;
        let new_token = out.new_token.expect("renewed");

        let session = proxyauth::token::vault::vault().verify(&new_token).unwrap();
        let data = TokenData::parse(session.data()).unwrap();
        let now = now_secs();
        assert!(now - data.issued_at < 5, "issued just now");
        assert!((4995..=5005).contains(&(now - data.session_started_at)), "login time kept");
        assert!(session.expires_at() >= now + LIFETIME - 5, "full lifetime");
        assert_ne!(session.id(), "keeps-login", "new token id");
    }

    #[actix_web::test]
    async fn the_old_token_works_during_the_grace_period() {
        let state = state();
        let old = token("grace", 1000, 1000);

        let first = send(&state, open(SITE, "/admin", &old)).await;
        let renewed = first.new_token.expect("renewed");

        let entry = *state
            .revoked_tokens
            .get(&rotated_key("grace"))
            .expect("delayed revocation recorded");
        let (refuse_from, _) = proxyauth::revoke::load::unpack_rotation(entry);
        let now = now_secs();
        assert!((now + GRACE - 2..=now + GRACE).contains(&refuse_from));

        // Another tab still sends the old cookie.
        let again = send(&state, open(SITE, "/admin", &old)).await;
        assert_eq!(again.status, StatusCode::OK);
        assert_eq!(
            again.new_token.as_deref(),
            Some(renewed.as_str()),
            "concurrent requests share one renewal"
        );
    }

    #[actix_web::test]
    async fn the_old_token_is_refused_after_the_grace_period() {
        let state = state();
        let old = token("expired-grace", 1000, 1000);
        let now = now_secs();
        state.revoked_tokens.insert(
            rotated_key("expired-grace"),
            pack_rotation(now - 1, now + 3600),
        );

        let out = send(&state, open(SITE, "/admin", &old)).await;
        assert_eq!(out.status, StatusCode::FOUND);
        assert_eq!(out.location.as_deref(), Some("/login"));
        assert_eq!(out.new_token, None);
    }

    #[actix_web::test]
    async fn a_session_past_its_max_lifetime_must_sign_in_again() {
        let state = state();
        let out = send(&state, open(SHORT, "/admin", &token("too-old", 1000, 7300))).await;
        assert_eq!(out.status, StatusCode::FOUND);
        assert_eq!(out.location.as_deref(), Some("/login"));
        assert_eq!(out.new_token, None);
    }

    #[actix_web::test]
    async fn renewal_stops_extending_near_the_max_lifetime() {
        let state = state();
        // Started 4200s ago with a 7200s limit: the session ends in 50
        // minutes, so the renewed token must end with it, not in an hour.
        let out = send(&state, open(SHORT, "/admin", &token("capped", 1000, 4200))).await;
        let new_token = out.new_token.expect("renewed");
        let session = proxyauth::token::vault::vault().verify(&new_token).unwrap();
        let data = TokenData::parse(session.data()).unwrap();
        assert_eq!(session.expires_at(), data.session_started_at + 7200);
        assert!(session.expires_at() < now_secs() + LIFETIME);
    }

    #[actix_web::test]
    async fn no_renewal_when_it_could_not_extend_the_session() {
        let state = state();
        // Started 5000s ago with a 7200s limit: the session ends before
        // the current token does, so there is nothing to renew.
        let out = send(&state, open(SHORT, "/admin", &token("at-limit", 1000, 5000))).await;
        assert_eq!(out.status, StatusCode::OK);
        assert_eq!(out.new_token, None);
    }

    #[actix_web::test]
    async fn legacy_tokens_are_renewed_into_the_new_format() {
        config();
        let now = now_secs();
        let legacy = proxyauth::token::security::issue_token(
            "admin",
            0,
            &(now + LIFETIME - 1000).to_string(),
            "legacy",
        )
        .unwrap();
        // issue_token now writes the new format; rebuild a genuinely old
        // one with only the index in its data field.
        let legacy_old_format = proxyauth::token::vault::vault()
            .token("admin")
            .expires_at(now + LIFETIME - 1000)
            .id("legacy-old")
            .data("0")
            .issue()
            .unwrap();
        assert_ne!(legacy, legacy_old_format);

        let state = state();
        let out = send(&state, open(SITE, "/admin", &legacy_old_format)).await;
        assert_eq!(out.status, StatusCode::OK);
        let renewed = out.new_token.expect("an old-format token past the interval is renewed");
        let session = proxyauth::token::vault::vault().verify(&renewed).unwrap();
        assert!(TokenData::parse(session.data()).unwrap().issued_at > 0);
    }
}
