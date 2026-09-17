//! API sessions with refresh tokens, end to end: `POST /auth`,
//! `POST /refresh_token`, and a protected route checked with the tokens
//! they return.

#[cfg(test)]
mod tests {
    use actix_web::dev::Service;
    use actix_web::http::{StatusCode, header};
    use actix_web::test::{self, TestRequest};
    use actix_web::{App, web};
    use proxyauth::config::config::{AppConfig, AppState, RouteConfig, load_config};
    use proxyauth::network::proxy::global_proxy;
    use proxyauth::network::stats::RequestStats;
    use proxyauth::stats::tokencount::CounterToken;
    use proxyauth::token::auth::auth_dispatch;
    use proxyauth::token::refresh_token::refresh_token_dispatch;
    use proxyauth::token::security::{TokenData, TokenKind, issue_session_token, now_secs};
    use proxyauth::token::vault::vault;
    use std::path::PathBuf;
    use std::sync::{Arc, OnceLock};

    const API: &str = "api.example.com";
    const NO_REFRESH: &str = "norefresh.example.com";
    const CAPPED: &str = "capped.example.com";
    const COOKIES: &str = "cookies.example.com";
    const ACCESS_LIFETIME: u64 = 600;
    const REFRESH_LIFETIME: u64 = 86400;

    fn dir() -> PathBuf {
        static DIR: OnceLock<PathBuf> = OnceLock::new();
        DIR.get_or_init(|| {
            let dir = std::env::temp_dir()
                .join(format!("proxyauth-refresh-token-e2e-{}", std::process::id()));
            std::fs::create_dir_all(dir.join("www")).unwrap();
            std::fs::write(dir.join("www/index.html"), "private data").unwrap();
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
                    "token_expiry_seconds": ACCESS_LIFETIME,
                    "refresh_token_expiry_seconds": REFRESH_LIFETIME,
                    "secret": "refresh-token-e2e-secret-refresh-token-e2e-secret-0123456",
                    "users": [
                        { "username": "alice", "password": "wonderland" },
                        { "username": "bob", "password": "builder" }
                    ],
                    "log": { "type": "disabled" },
                    "smtp": null,
                    "session_cookie": false,
                    "csrf_token": false,
                    "timezone": "UTC"
                });
                std::fs::write(&path, serde_json::to_string_pretty(&json).unwrap()).unwrap();
                let config = load_config(path.to_str().unwrap());
                proxyauth::token::vault::init(&config).expect("token vault");
                config
            })
            .clone()
    }

    fn routes(api_users: &str) -> RouteConfig {
        let www = dir().join("www");
        let www = www.display();
        let yaml = format!(
            r#"
vhosts:
  - vhost: ["{API}"]
    allow_users: [{api_users}]
    routes:
      - prefix: "/data"
        static: "{www}/"
        required_login: true

  - vhost: ["{NO_REFRESH}"]
    refresh_token_expiry_seconds: 0
    allow_users: ["alice"]
    routes:
      - prefix: "/data"
        static: "{www}/"
        required_login: true

  - vhost: ["{COOKIES}"]
    session_cookie: true
    allow_users: ["alice"]
    routes:
      - prefix: "/data"
        static: "{www}/"
        required_login: true

  - vhost: ["{CAPPED}"]
    session_max_lifetime_secs: 7200
    allow_users: ["alice"]
    routes:
      - prefix: "/data"
        static: "{www}/"
        required_login: true
"#
        );
        serde_yaml::from_str::<RouteConfig>(&yaml).unwrap().expand_vhost_groups()
    }

    fn state_with(api_users: &str, revoked: proxyauth::revoke::db::RevokedTokenMap) -> AppState {
        AppState {
            config: config(),
            routes: Arc::new(routes(api_users)),
            counter: Arc::new(CounterToken::new()),
            revoked_tokens: revoked,
            stats: RequestStats::new(),
            ip_blocklist: Arc::new(arc_swap::ArcSwap::from_pointee(Vec::new())),
            redirect_protect_url_ips: Arc::new(dashmap::DashMap::new()),
            otp_overrides: Arc::new(dashmap::DashMap::new()),
            password_overrides: Arc::new(dashmap::DashMap::new()),
            must_change_overrides: Arc::new(dashmap::DashMap::new()),
        }
    }

    fn state() -> AppState {
        state_with(r#""alice""#, Arc::new(dashmap::DashMap::new()))
    }

    struct Reply {
        status: StatusCode,
        cache_control: Option<String>,
        json: serde_json::Value,
        body: String,
    }

    async fn call(state: &AppState, req: TestRequest) -> Reply {
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(state.clone()))
                .route("/auth", web::post().to(auth_dispatch))
                .route("/refresh_token", web::post().to(refresh_token_dispatch))
                .default_service(web::to(global_proxy)),
        )
        .await;
        let resp = app.call(req.to_request()).await.expect("service call");
        let status = resp.status();
        let cache_control = resp
            .headers()
            .get(header::CACHE_CONTROL)
            .map(|v| v.to_str().unwrap().to_string());
        let body = String::from_utf8_lossy(&test::read_body(resp).await).into_owned();
        let json = serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
        Reply { status, cache_control, json, body }
    }

    fn base(host: &str, req: TestRequest) -> TestRequest {
        req.peer_addr("127.0.0.1:45010".parse().unwrap())
            .insert_header((header::HOST, host))
            .insert_header(("x-forwarded-proto", "https"))
    }

    async fn login(state: &AppState, host: &str, user: &str, password: &str) -> Reply {
        call(
            state,
            base(host, TestRequest::post().uri("/auth"))
                .set_form([("username", user), ("password", password)]),
        )
        .await
    }

    async fn refresh(state: &AppState, host: &str, refresh_token: &str) -> Reply {
        call(
            state,
            base(host, TestRequest::post().uri("/refresh_token"))
                .set_json(serde_json::json!({ "refresh_token": refresh_token })),
        )
        .await
    }

    async fn api_call(state: &AppState, host: &str, token: &str) -> StatusCode {
        call(
            state,
            base(host, TestRequest::get().uri("/data/"))
                .insert_header((header::AUTHORIZATION, format!("Bearer {token}")))
                .insert_header((header::ACCEPT, "application/json")),
        )
        .await
        .status
    }

    fn token_of(reply: &Reply, field: &str) -> String {
        reply.json[field]
            .as_str()
            .unwrap_or_else(|| panic!("no {field} in {}", reply.body))
            .to_string()
    }

    fn inspect(token: &str) -> (String, TokenData, u64) {
        let session = vault().verify(token).expect("a valid token");
        (
            session.id().to_string(),
            TokenData::parse(session.data()).unwrap(),
            session.expires_at(),
        )
    }

    // ── login ────────────────────────────────────────────────

    #[actix_web::test]
    async fn login_returns_two_tokens_with_one_token_id() {
        let state = state();
        let reply = login(&state, API, "alice", "wonderland").await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
        assert_eq!(reply.cache_control.as_deref(), Some("no-store"));
        for field in ["token", "expires_at", "refresh_token", "refresh_token_expires_at"] {
            assert!(reply.json.get(field).is_some(), "{field} missing: {}", reply.body);
        }

        let access = token_of(&reply, "token");
        let refresh_tok = token_of(&reply, "refresh_token");
        assert_ne!(access, refresh_tok, "two different tokens");

        let (access_id, access_data, access_exp) = inspect(&access);
        let (refresh_id, refresh_data, refresh_exp) = inspect(&refresh_tok);
        assert_eq!(access_id, refresh_id, "one token id for the session");
        assert_eq!(access_data.kind, TokenKind::Access);
        assert_eq!(refresh_data.kind, TokenKind::Refresh);
        let now = now_secs();
        assert!((now + ACCESS_LIFETIME - 5..=now + ACCESS_LIFETIME + 1).contains(&access_exp));
        assert!((now + REFRESH_LIFETIME - 5..=now + REFRESH_LIFETIME + 1).contains(&refresh_exp));
    }

    #[actix_web::test]
    async fn no_refresh_token_when_the_vhost_disables_it() {
        let state = state();
        let reply = login(&state, NO_REFRESH, "alice", "wonderland").await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
        assert!(reply.json.get("token").is_some());
        assert!(reply.json.get("refresh_token").is_none(), "{}", reply.body);
        assert!(reply.json.get("refresh_token_expires_at").is_none());

        let refused = refresh(&state, NO_REFRESH, "anything").await;
        assert_eq!(refused.status, StatusCode::BAD_REQUEST);
        assert_eq!(refused.json["error"], "unsupported_grant_type");
    }

    #[actix_web::test]
    async fn a_cookie_vhost_has_no_refresh_tokens() {
        let state = state();
        let refused = refresh(&state, COOKIES, "anything").await;
        assert_eq!(refused.status, StatusCode::BAD_REQUEST);
        assert_eq!(refused.json["error"], "unsupported_grant_type");
    }

    // ── what each token is good for ──────────────────────────

    #[actix_web::test]
    async fn each_token_only_works_where_it_belongs() {
        let state = state();
        let reply = login(&state, API, "alice", "wonderland").await;
        let access = token_of(&reply, "token");
        let refresh_tok = token_of(&reply, "refresh_token");

        assert_eq!(api_call(&state, API, &access).await, StatusCode::OK);
        assert_eq!(
            api_call(&state, API, &refresh_tok).await,
            StatusCode::UNAUTHORIZED,
            "a refresh token is not an access token"
        );

        let wrong = refresh(&state, API, &access).await;
        assert_eq!(wrong.status, StatusCode::UNAUTHORIZED, "an access token cannot refresh");
        assert_eq!(wrong.json["error"], "invalid_grant");
    }

    // ── refreshing ───────────────────────────────────────────

    #[actix_web::test]
    async fn a_refresh_returns_a_new_pair_on_the_same_token_id() {
        let state = state();
        let first = login(&state, API, "alice", "wonderland").await;
        let old_access = token_of(&first, "token");
        let old_refresh = token_of(&first, "refresh_token");
        let (session_id, first_data, _) = inspect(&old_access);

        let second = refresh(&state, API, &old_refresh).await;
        assert_eq!(second.status, StatusCode::OK, "{}", second.body);
        assert_eq!(second.cache_control.as_deref(), Some("no-store"));
        let new_access = token_of(&second, "token");
        let new_refresh = token_of(&second, "refresh_token");
        assert_ne!(new_access, old_access);
        assert_ne!(new_refresh, old_refresh);

        let (access_id, access_data, _) = inspect(&new_access);
        let (refresh_id, refresh_data, _) = inspect(&new_refresh);
        assert_eq!(access_id, session_id, "same token id after a refresh");
        assert_eq!(refresh_id, session_id);
        assert_eq!(access_data.generation, 1);
        assert_eq!(refresh_data.generation, 1);
        assert_eq!(access_data.session_started_at, first_data.session_started_at, "login time kept");

        assert_eq!(api_call(&state, API, &new_access).await, StatusCode::OK);
        assert_eq!(
            api_call(&state, API, &old_access).await,
            StatusCode::UNAUTHORIZED,
            "the previous access token is superseded"
        );

        // And again.
        let third = refresh(&state, API, &new_refresh).await;
        assert_eq!(third.status, StatusCode::OK, "{}", third.body);
        let (_, third_data, _) = inspect(&token_of(&third, "token"));
        assert_eq!(third_data.generation, 2);
        assert_eq!(api_call(&state, API, &new_access).await, StatusCode::UNAUTHORIZED);
        assert_eq!(api_call(&state, API, &token_of(&third, "token")).await, StatusCode::OK);
    }

    #[actix_web::test]
    async fn reusing_a_refresh_token_revokes_the_whole_session() {
        let state = state();
        let first = login(&state, API, "alice", "wonderland").await;
        let old_refresh = token_of(&first, "refresh_token");
        let (session_id, _, _) = inspect(&old_refresh);

        let second = refresh(&state, API, &old_refresh).await;
        let new_access = token_of(&second, "token");
        let new_refresh = token_of(&second, "refresh_token");

        // Someone replays the refresh token that was already exchanged.
        let replay = refresh(&state, API, &old_refresh).await;
        assert_eq!(replay.status, StatusCode::UNAUTHORIZED);
        assert_eq!(replay.json["error"], "invalid_grant");
        assert!(state.revoked_tokens.contains_key(&session_id), "the session id is revoked");

        // Both parties are out.
        assert_eq!(api_call(&state, API, &new_access).await, StatusCode::UNAUTHORIZED);
        assert_eq!(refresh(&state, API, &new_refresh).await.status, StatusCode::UNAUTHORIZED);
    }

    #[actix_web::test]
    async fn revoking_the_token_id_ends_both_tokens() {
        let state = state();
        let reply = login(&state, API, "alice", "wonderland").await;
        let access = token_of(&reply, "token");
        let refresh_tok = token_of(&reply, "refresh_token");
        let (session_id, _, _) = inspect(&access);

        // What /adm/revoke does; no storage backend in this test, so the
        // in-memory write is what counts.
        let _ = proxyauth::revoke::load::revoke_token(
            &session_id,
            Some(now_secs() + REFRESH_LIFETIME),
            &state.revoked_tokens,
        )
        .await;

        assert_eq!(api_call(&state, API, &access).await, StatusCode::UNAUTHORIZED);
        assert_eq!(refresh(&state, API, &refresh_tok).await.status, StatusCode::UNAUTHORIZED);
    }

    // ── refusals ─────────────────────────────────────────────

    #[actix_web::test]
    async fn malformed_requests_are_refused() {
        let state = state();

        let empty = call(
            &state,
            base(API, TestRequest::post().uri("/refresh_token"))
                .set_json(serde_json::json!({})),
        )
        .await;
        assert_eq!(empty.status, StatusCode::BAD_REQUEST);
        assert_eq!(empty.json["error"], "invalid_request");

        let plain = call(
            &state,
            base(API, TestRequest::post().uri("/refresh_token"))
                .insert_header((header::CONTENT_TYPE, "text/plain"))
                .set_payload("refresh_token=abc"),
        )
        .await;
        assert_eq!(plain.status, StatusCode::BAD_REQUEST);

        let garbage = refresh(&state, API, "not-a-token").await;
        assert_eq!(garbage.status, StatusCode::UNAUTHORIZED);
    }

    #[actix_web::test]
    async fn a_form_body_is_accepted() {
        let state = state();
        let reply = login(&state, API, "alice", "wonderland").await;
        let refresh_tok = token_of(&reply, "refresh_token");
        let form = call(
            &state,
            base(API, TestRequest::post().uri("/refresh_token"))
                .set_form([("refresh_token", refresh_tok.as_str())]),
        )
        .await;
        assert_eq!(form.status, StatusCode::OK, "{}", form.body);
    }

    #[actix_web::test]
    async fn an_account_no_longer_allowed_cannot_refresh() {
        let revoked = Arc::new(dashmap::DashMap::new());
        let before = state_with(r#""alice""#, revoked.clone());
        let reply = login(&before, API, "alice", "wonderland").await;
        let refresh_tok = token_of(&reply, "refresh_token");

        // routes.yml now names someone else on this vhost.
        let after = state_with(r#""bob""#, revoked);
        let refused = refresh(&after, API, &refresh_tok).await;
        assert_eq!(refused.status, StatusCode::FORBIDDEN);
        assert_eq!(refused.json["error"], "access_denied");
    }

    #[actix_web::test]
    async fn a_refresh_token_longer_than_configured_is_refused() {
        let state = state();
        config();
        let now = now_secs();
        let too_long = issue_session_token(
            "alice",
            now + REFRESH_LIFETIME * 10,
            "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f01",
            &TokenData {
                index_user: 0,
                issued_at: now,
                session_started_at: now,
                kind: TokenKind::Refresh,
                ..TokenData::default()
            },
        )
        .unwrap();
        assert_eq!(refresh(&state, API, &too_long).await.status, StatusCode::UNAUTHORIZED);
    }

    #[actix_web::test]
    async fn an_expired_refresh_token_is_refused() {
        let state = state();
        config();
        let now = now_secs();
        let short = issue_session_token(
            "alice",
            now + 1,
            "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f02",
            &TokenData {
                index_user: 0,
                issued_at: now,
                session_started_at: now,
                kind: TokenKind::Refresh,
                ..TokenData::default()
            },
        )
        .unwrap();
        actix_web::rt::time::sleep(std::time::Duration::from_millis(2100)).await;
        assert_eq!(refresh(&state, API, &short).await.status, StatusCode::UNAUTHORIZED);
    }

    // ── session lifetime cap ─────────────────────────────────

    fn capped_refresh_token(id: &str, session_age: u64) -> String {
        config();
        let now = now_secs();
        issue_session_token(
            "alice",
            now + 3600,
            id,
            &TokenData {
                index_user: 0,
                issued_at: now - 60,
                session_started_at: now - session_age,
                kind: TokenKind::Refresh,
                ..TokenData::default()
            },
        )
        .unwrap()
    }

    #[actix_web::test]
    async fn a_refreshed_pair_never_outlives_the_session() {
        let state = state();
        let token = capped_refresh_token(
            "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f03",
            7000,
        );
        let reply = refresh(&state, CAPPED, &token).await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
        let (_, data, access_exp) = inspect(&token_of(&reply, "token"));
        let (_, _, refresh_exp) = inspect(&token_of(&reply, "refresh_token"));
        let session_end = data.session_started_at + 7200;
        assert_eq!(access_exp, session_end, "capped: 200 s left, not {ACCESS_LIFETIME}");
        assert_eq!(refresh_exp, session_end);
    }

    #[actix_web::test]
    async fn a_session_past_its_lifetime_cannot_refresh() {
        let state = state();
        let token = capped_refresh_token(
            "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f04",
            7300,
        );
        let reply = refresh(&state, CAPPED, &token).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        assert_eq!(reply.json["error"], "invalid_grant");
    }

    // ── cookie sessions are unchanged ────────────────────────

    #[actix_web::test]
    async fn access_tokens_without_refresh_keep_working() {
        let state = state();
        let reply = login(&state, NO_REFRESH, "alice", "wonderland").await;
        assert_eq!(api_call(&state, NO_REFRESH, &token_of(&reply, "token")).await, StatusCode::OK);
    }
}
