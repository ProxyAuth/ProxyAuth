//! `POST /adm/revoke`, end to end: the token is refused immediately,
//! whatever `exp` says, and the record outlives every live token.

#[cfg(test)]
mod tests {
    use actix_web::dev::Service;
    use actix_web::http::{StatusCode, header};
    use actix_web::test::{self, TestRequest};
    use actix_web::{App, web};
    use proxyauth::adm::revoke::revoke_route;
    use proxyauth::config::config::{AppConfig, AppState, RouteConfig, load_config};
    use proxyauth::network::proxy::global_proxy;
    use proxyauth::network::stats::RequestStats;
    use proxyauth::stats::tokencount::CounterToken;
    use proxyauth::token::security::{TokenData, issue_session_token, now_secs};
    use std::path::PathBuf;
    use std::sync::{Arc, OnceLock};

    const HOST: &str = "revoke.example.com";
    const LIFETIME: u64 = 3600;

    fn dir() -> PathBuf {
        static DIR: OnceLock<PathBuf> = OnceLock::new();
        DIR.get_or_init(|| {
            let dir = std::env::temp_dir().join(format!("proxyauth-revoke-e2e-{}", std::process::id()));
            std::fs::create_dir_all(dir.join("www")).unwrap();
            std::fs::write(dir.join("www/index.html"), "private page").unwrap();
            dir
        })
        .clone()
    }

    fn config() -> Arc<AppConfig> {
        static CONFIG: OnceLock<Arc<AppConfig>> = OnceLock::new();
        CONFIG
            .get_or_init(|| {
                let path = dir().join("config.json");
                let json = serde_json::json!({
                    "token_expiry_seconds": LIFETIME,
                    "secret": "revoke-route-e2e-secret-revoke-route-e2e-secret-0123456789",
                    "token_admin": "admin-token-for-tests",
                    "users": [ { "username": "admin", "password": "unused" } ],
                    "log": { "type": "disabled" },
                    "smtp": null,
                    "session_cookie": true,
                    "timezone": "UTC"
                });
                std::fs::write(&path, serde_json::to_string_pretty(&json).unwrap()).unwrap();
                let config = load_config(path.to_str().unwrap());
                proxyauth::token::vault::init(&config).expect("token vault");
                config
            })
            .clone()
    }

    /// Revocations are persisted to LMDB; open a throwaway one, once per
    /// test binary, the way `main.rs` does at startup.
    async fn ensure_lmdb() {
        static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
        let _guard = LOCK.lock().await;
        if proxyauth::revoke::db::LMDB_ENV.get().is_some() {
            return;
        }
        let path = dir().join("lmdb");
        std::fs::create_dir_all(&path).unwrap();
        // SAFETY: set before any thread reads it, under the lock above.
        unsafe {
            std::env::set_var("LMDB_PATH", &path);
        }
        proxyauth::revoke::db::start_revoked_token_ttl(
            Arc::new(dashmap::DashMap::new()),
            std::time::Duration::from_secs(3600),
            None,
        )
        .await;
    }

    fn state() -> AppState {
        let www = dir().join("www");
        let yaml = format!(
            r#"
vhosts:
  - vhost: ["{HOST}"]
    logout_redirect_url: "/login"
    allow_users: ["admin"]
    routes:
      - prefix: "/private"
        static: "{}/"
        required_login: true
"#,
            www.display()
        );
        let routes: RouteConfig = serde_yaml::from_str::<RouteConfig>(&yaml)
            .unwrap()
            .expand_vhost_groups();
        AppState {
            config: config(),
            routes: Arc::new(routes),
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

    fn token(id: &str) -> (String, u64) {
        config();
        let now = now_secs();
        let expires_at = now + LIFETIME;
        let token = issue_session_token(
            "admin",
            expires_at,
            id,
            &TokenData {
                index_user: 0,
                issued_at: now,
                session_started_at: now,
                previous_token_id: None,
                ..TokenData::default()
            },
        )
        .unwrap();
        (token, expires_at)
    }

    async fn status(state: &AppState, req: TestRequest) -> (StatusCode, String) {
        ensure_lmdb().await;
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(state.clone()))
                .route("/adm/revoke", web::post().to(revoke_route))
                .default_service(web::to(global_proxy)),
        )
        .await;
        let resp = app.call(req.to_request()).await.expect("call");
        let status = resp.status();
        let body = String::from_utf8_lossy(&test::read_body(resp).await).into_owned();
        (status, body)
    }

    fn open_private(token: &str) -> TestRequest {
        TestRequest::get()
            .uri("/private/")
            .peer_addr("127.0.0.1:45002".parse().unwrap())
            .insert_header((header::HOST, HOST))
            .insert_header(("x-forwarded-proto", "https"))
            .insert_header((header::ACCEPT, "text/html"))
            .insert_header((header::COOKIE, format!("session_token={token}")))
    }

    fn revoke(body: serde_json::Value) -> TestRequest {
        TestRequest::post()
            .uri("/adm/revoke")
            .insert_header(("X-Auth-Token", "admin-token-for-tests"))
            .set_json(body)
    }

    async fn assert_refused(state: &AppState, token: &str) {
        let (code, _) = status(state, open_private(token)).await;
        assert_eq!(code, StatusCode::FOUND, "a revoked session is sent to the login page");
    }

    #[actix_web::test]
    async fn the_session_works_before_revocation() {
        let state = state();
        let (token, _) = token("before");
        let (code, body) = status(&state, open_private(&token)).await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(body, "private page");
    }

    #[actix_web::test]
    async fn revoking_without_exp_lasts_as_long_as_the_token_could() {
        let state = state();
        let (token, expires_at) = token("no-exp");
        let before = now_secs();
        let (code, body) = status(&state, revoke(serde_json::json!({ "token_id": "no-exp" }))).await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(body, "Token revoked with expiration.");
        assert_refused(&state, &token).await;

        let kept_until = *state.revoked_tokens.get("no-exp").unwrap();
        assert!(kept_until >= expires_at, "outlives the token");
        assert!(kept_until <= now_secs() + LIFETIME && kept_until >= before + LIFETIME);
    }

    #[actix_web::test]
    async fn exp_zero_no_longer_means_forever() {
        let state = state();
        let (token, _) = token("zero");
        let before = now_secs();
        let (code, body) = status(
            &state,
            revoke(serde_json::json!({ "token_id": "zero", "exp": 0 })),
        )
        .await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(body, "Token revoked with expiration.");
        assert_refused(&state, &token).await;
        let kept_until = *state.revoked_tokens.get("zero").unwrap();
        assert!(kept_until >= before + LIFETIME && kept_until <= now_secs() + LIFETIME);
    }

    #[actix_web::test]
    async fn a_far_exp_does_not_keep_the_record_longer_than_needed() {
        let state = state();
        let before = now_secs();
        let _ = status(
            &state,
            revoke(serde_json::json!({ "token_id": "far", "exp": before + 10 * 365 * 86400 })),
        )
        .await;
        let kept_until = *state.revoked_tokens.get("far").unwrap();
        assert!(kept_until <= now_secs() + LIFETIME, "kept only while a token could live");
    }

    #[actix_web::test]
    async fn the_record_notes_when_the_revocation_was_made() {
        let state = state();
        let before = now_secs();
        let _ = status(&state, revoke(serde_json::json!({ "token_id": "dated" }))).await;
        let record = proxyauth::revoke::db::lmdb_get_record("dated").expect("written to LMDB");
        assert!(record.revoked_at >= before && record.revoked_at <= now_secs());
        assert_eq!(record.value, *state.revoked_tokens.get("dated").unwrap());
    }

    #[actix_web::test]
    async fn logout_also_ends_the_token_a_renewal_replaced() {
        let state = state();
        ensure_lmdb().await;
        config();
        let now = now_secs();
        let prev = "70c0000000000000000000000000000000000000000000000000000000000001";
        // The replaced token is still inside a long grace period.
        state.revoked_tokens.insert(
            proxyauth::revoke::load::rotated_key(prev),
            proxyauth::revoke::load::pack_rotation(now + 600, now + LIFETIME),
        );
        let successor = issue_session_token(
            "admin",
            now + LIFETIME,
            "70c0000000000000000000000000000000000000000000000000000000000002",
            &TokenData {
                index_user: 0,
                issued_at: now,
                session_started_at: now - 60,
                previous_token_id: Some(prev.to_string()),
                ..TokenData::default()
            },
        )
        .unwrap();

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(state.clone()))
                .route("/logout", web::get().to(proxyauth::token::logout::logout_dispatch)),
        )
        .await;
        let req = TestRequest::get()
            .uri("/logout")
            .peer_addr("127.0.0.1:45002".parse().unwrap())
            .insert_header((header::HOST, HOST))
            .insert_header(("x-forwarded-proto", "https"))
            .insert_header((header::COOKIE, format!("session_token={successor}")))
            .to_request();
        let _ = app.call(req).await.expect("logout");

        let (refuse, purge) = proxyauth::revoke::load::unpack_rotation(
            *state
                .revoked_tokens
                .get(&proxyauth::revoke::load::rotated_key(prev))
                .unwrap(),
        );
        assert!(refuse <= now_secs(), "refused from the logout on");
        assert_eq!(purge, now + LIFETIME);
    }

    #[actix_web::test]
    async fn logout_revokes_until_the_token_would_have_expired() {
        let state = state();
        let (token, expires_at) = token("logout");
        ensure_lmdb().await;
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(state.clone()))
                .route("/logout", web::get().to(proxyauth::token::logout::logout_dispatch))
                .default_service(web::to(global_proxy)),
        )
        .await;
        let req = TestRequest::get()
            .uri("/logout")
            .peer_addr("127.0.0.1:45002".parse().unwrap())
            .insert_header((header::HOST, HOST))
            .insert_header(("x-forwarded-proto", "https"))
            .insert_header((header::COOKIE, format!("session_token={token}")))
            .to_request();
        let resp = app.call(req).await.expect("logout");
        assert!(resp.status().is_redirection() || resp.status().is_success());

        assert_eq!(
            *state.revoked_tokens.get("logout").expect("revoked on logout"),
            expires_at,
            "kept exactly until the token's own expiry, not forever"
        );
        assert_refused(&state, &token).await;
    }

    #[actix_web::test]
    async fn revoking_with_the_token_expiry_is_immediate() {
        // The case that used to do nothing at all.
        let state = state();
        let (token, expires_at) = token("with-exp");
        let (code, body) = status(
            &state,
            revoke(serde_json::json!({ "token_id": "with-exp", "exp": expires_at })),
        )
        .await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(body, "Token revoked with expiration.");
        assert_refused(&state, &token).await;
        assert!(*state.revoked_tokens.get("with-exp").unwrap() >= expires_at);
    }

    #[actix_web::test]
    async fn a_past_exp_still_revokes_and_keeps_the_record_long_enough() {
        let state = state();
        let (token, expires_at) = token("past-exp");
        let (code, _) = status(
            &state,
            revoke(serde_json::json!({ "token_id": "past-exp", "exp": 1 })),
        )
        .await;
        assert_eq!(code, StatusCode::OK);
        assert_refused(&state, &token).await;

        let kept_until = *state.revoked_tokens.get("past-exp").unwrap();
        assert!(
            kept_until >= expires_at,
            "the record ({kept_until}) must outlive the token ({expires_at}), or the purge would revive it"
        );
    }

    #[actix_web::test]
    async fn other_tokens_are_unaffected() {
        let state = state();
        let (other, _) = token("untouched");
        let _ = status(&state, revoke(serde_json::json!({ "token_id": "someone-else" }))).await;
        let (code, _) = status(&state, open_private(&other)).await;
        assert_eq!(code, StatusCode::OK);
    }

    #[actix_web::test]
    async fn the_admin_token_is_required() {
        let state = state();
        let req = TestRequest::post()
            .uri("/adm/revoke")
            .set_json(serde_json::json!({ "token_id": "x" }));
        let (code, _) = status(&state, req).await;
        assert_eq!(code, StatusCode::UNAUTHORIZED);

        let wrong = TestRequest::post()
            .uri("/adm/revoke")
            .insert_header(("X-Auth-Token", "wrong"))
            .set_json(serde_json::json!({ "token_id": "x" }));
        let (code, _) = status(&state, wrong).await;
        assert_eq!(code, StatusCode::UNAUTHORIZED);
        assert!(state.revoked_tokens.is_empty());
    }

    #[actix_web::test]
    async fn internal_or_empty_ids_are_refused() {
        let state = state();
        for id in ["", "   ", "rotated:abc"] {
            let (code, _) = status(&state, revoke(serde_json::json!({ "token_id": id }))).await;
            assert_eq!(code, StatusCode::BAD_REQUEST, "{id:?}");
        }
        assert!(state.revoked_tokens.is_empty());
    }
}
