//! Signing in with a token or cookie lifetime under 60 seconds.
//!
//! `/auth` used to compute the cookie lifetime with `.clamp(60, max)`,
//! which panics when `max < 60`: every login failed with such a
//! configuration.

#[cfg(test)]
mod tests {
    use actix_web::dev::Service;
    use actix_web::http::header;
    use actix_web::test::{self, TestRequest};
    use actix_web::{App, web};
    use proxyauth::config::config::{AppState, RouteConfig, load_config};
    use proxyauth::network::stats::RequestStats;
    use proxyauth::stats::tokencount::CounterToken;
    use std::sync::Arc;

    async fn login_cookie(token_expiry: u64, cookie_max_age: u64) -> (u16, Option<String>) {
        let dir = std::env::temp_dir().join(format!(
            "proxyauth-short-login-{}-{token_expiry}-{cookie_max_age}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.json");
        let json = serde_json::json!({
            "token_expiry_seconds": token_expiry,
            "max_age_session_cookie": cookie_max_age,
            "secret": "short-login-secret-short-login-secret-short-login-0123",
            "users": [ { "username": "alice", "password": "wonderland" } ],
            "log": { "type": "disabled" },
            "smtp": null,
            "session_cookie": true,
            "csrf_token": false,
            "timezone": "UTC"
        });
        std::fs::write(&path, serde_json::to_string_pretty(&json).unwrap()).unwrap();
        let config = load_config(path.to_str().unwrap());
        proxyauth::token::vault::init(&config).unwrap();

        let routes: RouteConfig = serde_yaml::from_str::<RouteConfig>(
            r#"
vhosts:
  - vhost: ["short.example.com"]
    allow_users: ["alice"]
    routes:
      - prefix: "/app"
        target: "http://127.0.0.1:1"
        required_login: true
"#,
        )
        .unwrap()
        .expand_vhost_groups();

        let state = AppState {
            config,
            routes: Arc::new(routes),
            counter: Arc::new(CounterToken::new()),
            revoked_tokens: Arc::new(dashmap::DashMap::new()),
            stats: RequestStats::new(),
            ip_blocklist: Arc::new(arc_swap::ArcSwap::from_pointee(Vec::new())),
            redirect_protect_url_ips: Arc::new(dashmap::DashMap::new()),
            otp_overrides: Arc::new(dashmap::DashMap::new()),
            password_overrides: Arc::new(dashmap::DashMap::new()),
            must_change_overrides: Arc::new(dashmap::DashMap::new()),
        };

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(state))
                .route("/auth", web::post().to(proxyauth::auth)),
        )
        .await;

        let req = TestRequest::post()
            .uri("/auth")
            .peer_addr("127.0.0.1:45003".parse().unwrap())
            .insert_header((header::HOST, "short.example.com"))
            .insert_header(("x-forwarded-proto", "https"))
            .set_form([("username", "alice"), ("password", "wonderland")])
            .to_request();
        let resp = app.call(req).await.expect("login must not fail");
        let cookie = resp
            .headers()
            .get_all(header::SET_COOKIE)
            .filter_map(|v| v.to_str().ok())
            .find(|c| c.starts_with("session_token=") && !c.starts_with("session_token=;"))
            .map(str::to_string);
        (resp.status().as_u16(), cookie)
    }

    fn max_age(cookie: &str) -> i64 {
        cookie
            .split(';')
            .find_map(|part| part.trim().strip_prefix("Max-Age="))
            .and_then(|v| v.parse().ok())
            .or_else(|| {
                // `Expires=` form: accept it, the lifetime is checked by
                // the absence of a panic above.
                cookie.contains("Expires=").then_some(0)
            })
            .expect("the cookie carries a lifetime")
    }

    #[actix_web::test]
    async fn a_token_shorter_than_a_minute_still_signs_in() {
        let (status, cookie) = login_cookie(30, 3600).await;
        assert!(status < 500, "login failed with {status}");
        let cookie = cookie.expect("a session cookie");
        assert!(max_age(&cookie) <= 30, "never outlives the token: {cookie}");
    }

    #[actix_web::test]
    async fn a_cookie_shorter_than_a_minute_still_signs_in() {
        let (status, cookie) = login_cookie(3600, 20).await;
        assert!(status < 500, "login failed with {status}");
        assert!(max_age(&cookie.expect("a session cookie")) <= 20);
    }

    #[actix_web::test]
    async fn usual_lifetimes_are_unchanged() {
        let (status, cookie) = login_cookie(3600, 1800).await;
        assert!(status < 500);
        let age = max_age(&cookie.expect("a session cookie"));
        assert!(age <= 1800);
    }
}
