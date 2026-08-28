use actix_web::FromRequest;
use actix_web::Responder;
use actix_web::cookie::Cookie;
use actix_web::http::StatusCode;
use proxyauth::AppState;
use proxyauth::CounterToken;
use proxyauth::config::config::AuthRequest;
use proxyauth::network::stats::{RequestStats, spawn_stats_ticker};
use proxyauth::token::crypto::calcul_cipher;
use proxyauth::token::crypto::derive_key_from_secret;
use proxyauth::token::crypto::encrypt;
use proxyauth::token::security::generate_token;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;
use totp_rs::Algorithm;
use totp_rs::TOTP;

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::body::to_bytes as actix_to_bytes;
    use actix_web::{http::header, test};
    use dashmap::DashMap;
    use proxyauth::config::config::{AppConfig, RouteConfig, RouteRule, User};
    use proxyauth::revoke::db::RevokedTokenMap;
    use proxyauth::token::csrf::make_csrf_token;
    use rand_chacha::rand_core;

    // hyper 1.x
    use http_body_util::{Full, combinators::BoxBody};
    use hyper::body::Bytes;
    use hyper::body::Incoming;
    use hyper_http_proxy::{Intercept, Proxy, ProxyConnector};
    use hyper_rustls::HttpsConnectorBuilder;
    use hyper_util::client::legacy::Client;
    use hyper_util::client::legacy::connect::HttpConnector;
    use hyper_util::rt::TokioIo;
    use std::convert::Infallible;

    use argon2::{
        Argon2,
        password_hash::{PasswordHasher, SaltString},
    };
    use std::net::TcpListener;
    use std::sync::Arc;
    use tokio::net::TcpListener as TokioTcpListener;

    // --------- Helpers -------------------------------------------------------

    fn https_client()
    -> Client<hyper_rustls::HttpsConnector<HttpConnector>, BoxBody<Bytes, Infallible>> {
        let https = HttpsConnectorBuilder::new()
            .with_native_roots()
            .unwrap()
            .https_or_http()
            .enable_http1()
            .build();
        Client::builder(hyper_util::rt::TokioExecutor::new())
            .build::<_, BoxBody<Bytes, Infallible>>(https)
    }

    fn proxy_client() -> Client<
        ProxyConnector<hyper_rustls::HttpsConnector<HttpConnector>>,
        BoxBody<Bytes, Infallible>,
    > {
        let https = HttpsConnectorBuilder::new()
            .with_native_roots()
            .unwrap()
            .https_or_http()
            .enable_http1()
            .build();
        let proxy = Proxy::new(Intercept::All, "http://127.0.0.1:1".parse().unwrap());
        let connector = ProxyConnector::from_proxy(https, proxy).unwrap();
        Client::builder(hyper_util::rt::TokioExecutor::new())
            .build::<_, BoxBody<Bytes, Infallible>>(connector)
    }

    fn start_backend(html: &'static str) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        use hyper::Response;
        use hyper::server::conn::http1;
        use hyper::service::service_fn;

        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let local_addr = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let tokio_listener = TokioTcpListener::from_std(listener).unwrap();

        let join = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = tokio_listener.accept().await else {
                    break;
                };
                let io = TokioIo::new(stream);
                tokio::spawn(async move {
                    let svc = service_fn(move |_req: hyper::Request<Incoming>| async move {
                        Ok::<_, std::convert::Infallible>(
                            Response::builder()
                                .status(200)
                                // Utiliser &str au lieu de header::CONTENT_TYPE (actix http 0.2)
                                // pour éviter le conflit de versions du crate `http`
                                .header("content-type", "text/html; charset=utf-8")
                                .body(Full::new(Bytes::from(html)))
                                .unwrap(),
                        )
                    });
                    let _ = http1::Builder::new().serve_connection(io, svc).await;
                });
            }
        });

        (local_addr, join)
    }

    fn hash_pwd(plain: &str) -> String {
        let salt = SaltString::generate(&mut rand_core::OsRng);
        Argon2::default()
            .hash_password(plain.as_bytes(), &salt)
            .unwrap()
            .to_string()
    }

    fn base_config() -> AppConfig {
        AppConfig {
            fast: false,
            token_expiry_seconds: 3600,
            secret: "unit-secret-xyz".into(),
            users: vec![],
            token_admin: String::new(),
            host: vec!["127.0.0.1".to_string()],
            port: 0,
            worker: 1,
            ratelimit_proxy: Default::default(),
            ratelimit_auth: Default::default(),
            log: Default::default(),
            stats: false,
            max_idle_per_host: 16,
            timezone: "UTC".into(),
            login_via_otp: false,
            max_connections: 1024,
            pending_connections_limit: 1024,
            socket_listen: 128,
            client_timeout: 1000,
            keep_alive: 1,
            num_instances: 1,
            redis: None,
            cors_origins: None,
            smtp: None,
            session_cookie: true,
            max_age_session_cookie: 3600,
            login_redirect_url: Some("/home".into()),
            logout_redirect_url: None,
            tls: false,
            csrf_token: true,
            ..Default::default()
        }
    }

    fn mk_state(routes: Vec<RouteRule>, cfg: AppConfig) -> actix_web::web::Data<AppState> {
        let stats = RequestStats::new();
        spawn_stats_ticker(stats.clone());

        let state = AppState {
            config: Arc::new(cfg),
            routes: Arc::new(RouteConfig { routes, ..Default::default() }),
            counter: Arc::new(CounterToken::new()),
            client_normal: https_client(),
            client_with_cert: https_client(),
            client_with_proxy: proxy_client(),
            revoked_tokens: Arc::new(DashMap::new()) as RevokedTokenMap,
            stats,
            otp_overrides: Arc::new(DashMap::new()),
            password_overrides: Arc::new(DashMap::new()),
            must_change_overrides: Arc::new(DashMap::new()),
            ip_blocklist: Arc::new(arc_swap::ArcSwap::from_pointee(Vec::new())),
        };
        actix_web::web::Data::new(state)
    }

    fn rr(prefix: &str, target: &str) -> RouteRule {
        RouteRule {
            prefix: prefix.to_string(),
            target: target.to_string(),
            username: vec![],
            groups: vec![],
            roles: vec![],
            required_login: false,
            proxy: false,
            proxy_config: String::new(),
            cert: std::collections::HashMap::new(),
            backends: vec![],
            need_csrf: Some(false),
            log: None,
            log_file: None,
            compression: None,
            cache: true,
            cache_duration_secs: None,
            secure_path: false,
            preserve_prefix: false,
            allow_methods: None,
            filters: None,
            filters_compiled: None,
            vhost: vec![],
            vhost_cert: std::collections::HashMap::new(),
            certbot_renew: false,
            headers: std::collections::HashMap::new(),
        csrf_token: None,
        session_cookie: None,
        max_age_session_cookie: None,
        login_redirect_url: None,
        logout_redirect_url: None,
        login_via_otp: None,
        page_change_password: None,
        cors_origins: None,
        smtp: None,
        tag_proxyauth: None,
        allow_users: vec![],
        allow_groups: vec![],
        allow_roles: vec![],
        exclude_users: vec![],
            allow_ips: vec![],
            deny_ips: vec![],
            allow_ips_compiled: vec![],
            deny_ips_compiled: vec![],
            static_path: None,
            static_index: "index.html".into(),
            regex: None,
            regex_compiled: None,
            static_rewrite: None,
        }
    }

    // --------- EitherAuth ----------------------------------------------------

    #[tokio::test]
    async fn either_auth_json_and_form_and_unsupported() {
        let payload = r#"{"username":"u","password":"p","csrf_token":"t"}"#;
        let (req, mut pl) = test::TestRequest::default()
            .insert_header((header::CONTENT_TYPE, "application/json"))
            .set_payload(payload)
            .to_http_parts();

        let got = proxyauth::token::auth::EitherAuth::from_request(&req, &mut pl)
            .await
            .unwrap();
        match got {
            proxyauth::token::auth::EitherAuth::Json(j) => {
                assert_eq!(j.username, "u");
                assert_eq!(j.password, "p");
                assert_eq!(j.csrf_token.as_deref(), Some("t"));
            }
            _ => panic!("attendu Json"),
        }

        let (req, mut pl) = test::TestRequest::default()
            .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
            .set_payload("username=u&password=p&csrf_token=t2")
            .to_http_parts();

        let got = proxyauth::token::auth::EitherAuth::from_request(&req, &mut pl)
            .await
            .unwrap();
        match got {
            proxyauth::token::auth::EitherAuth::Form(f) => {
                assert_eq!(f.username, "u");
                assert_eq!(f.password, "p");
                assert_eq!(f.csrf_token.as_deref(), Some("t2"));
            }
            _ => panic!("attendu Form"),
        }

        let (req, mut pl) = test::TestRequest::default()
            .insert_header((header::CONTENT_TYPE, "text/plain"))
            .set_payload("x")
            .to_http_parts();
        assert!(
            proxyauth::token::auth::EitherAuth::from_request(&req, &mut pl)
                .await
                .is_err()
        );
    }

    // --------- validate_csrf -------------------------------------------------

    #[tokio::test]
    async fn validate_csrf_allows_safe_and_checks_post() {
        let secret = "s3cr3t";

        let req_get = test::TestRequest::default()
            .method(actix_web::http::Method::GET)
            .to_http_request();
        let ok = proxyauth::token::auth::validate_csrf(
            &req_get,
            &proxyauth::token::auth::EitherAuth::Json(AuthRequest {
                username: "".into(),
                password: "".into(),
                totp_code: None,
                csrf_token: None,
            }),
            secret,
        );
        assert!(ok);

        let req_post = test::TestRequest::default()
            .method(actix_web::http::Method::POST)
            .to_http_request();
        let bad = proxyauth::token::auth::validate_csrf(
            &req_post,
            &proxyauth::token::auth::EitherAuth::Json(AuthRequest {
                username: "".into(),
                password: "".into(),
                totp_code: None,
                csrf_token: None,
            }),
            secret,
        );
        assert!(!bad);

        let tok = make_csrf_token(secret);
        let good = proxyauth::token::auth::validate_csrf(
            &req_post,
            &proxyauth::token::auth::EitherAuth::Json(AuthRequest {
                username: "".into(),
                password: "".into(),
                totp_code: None,
                csrf_token: Some(tok),
            }),
            secret,
        );
        assert!(good);
    }

    // --------- is_ip_allowed -------------------------------------------------

    #[test]
    async fn is_ip_allowed_variants() {
        let base = || User {
            username: "u".into(),
            password: "h".into(),
            otpkey: None,
            allow: None,
            roles: None,
            groups: None,
            email: None,
            must_change_password: false,
        };

        assert!(proxyauth::token::auth::is_ip_allowed(
            "203.0.113.7",
            &base()
        ));

        let user_empty = User {
            allow: Some(vec![]),
            ..base()
        };
        assert!(proxyauth::token::auth::is_ip_allowed(
            "203.0.113.7",
            &user_empty
        ));

        let user_ipv4 = User {
            allow: Some(vec!["203.0.113.0/24".into()]),
            ..base()
        };
        assert!(proxyauth::token::auth::is_ip_allowed(
            "203.0.113.7",
            &user_ipv4
        ));
        assert!(!proxyauth::token::auth::is_ip_allowed(
            "203.0.114.1",
            &user_ipv4
        ));

        let user_ipv6 = User {
            allow: Some(vec!["2001:db8::/32".into()]),
            ..base()
        };
        assert!(proxyauth::token::auth::is_ip_allowed(
            "2001:db8::1",
            &user_ipv6
        ));
        assert!(!proxyauth::token::auth::is_ip_allowed(
            "2001:dead::1",
            &user_ipv6
        ));
    }

    // --------- verify_password -----------------------------------------------

    #[test]
    async fn verify_password_ok_bad() {
        let hashed = hash_pwd("hunter2");
        assert!(proxyauth::token::auth::verify_password("hunter2", &hashed));
        assert!(!proxyauth::token::auth::verify_password("wrong", &hashed));
    }

    // --------- generate_random_string ----------------------------------------

    #[test]
    async fn generate_random_string_is_hex64() {
        let s = proxyauth::token::auth::generate_random_string(32);
        assert_eq!(s.len(), 64, "blake3 en hex → 64 chars");
        assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // --------- expiry helpers ------------------------------------------------

    #[test]
    async fn expiry_helpers_are_deterministic() {
        let mut cfg = base_config();
        cfg.token_expiry_seconds = 3600;
        cfg.timezone = "Europe/Paris".into();
        let cfg = Arc::new(cfg);

        let ts = 1_700_000_000i64;
        let dt = proxyauth::token::auth::get_expiry_with_timezone(cfg.clone(), Some(ts));
        assert_eq!(dt.timezone().name(), "Europe/Paris");

        let fmt = proxyauth::token::auth::get_expiry_with_timezone_format(cfg, Some(ts));
        assert!(fmt.contains(':'));
        assert!(fmt.len() >= 10);
    }

    // --------- auth_options (CORS) -------------------------------------------

    #[tokio::test]
    async fn auth_options_cors_ok_and_forbidden() {
        let mut cfg_ok = base_config();
        cfg_ok.cors_origins = Some(vec!["https://app.example.com".into()]);
        let state_ok = mk_state(vec![], cfg_ok);

        let req = test::TestRequest::default()
            .insert_header((header::ORIGIN, "https://app.example.com"))
            .to_http_request();

        let resp = proxyauth::token::auth::auth_options(req, state_ok)
            .await
            .respond_to(&test::TestRequest::default().to_http_request());
        assert_eq!(resp.status(), StatusCode::OK);
        let b = actix_to_bytes(resp.into_body()).await.unwrap_or_default();
        assert!(b.is_empty());

        let state_ko = mk_state(vec![], base_config());
        let req2 = test::TestRequest::default()
            .insert_header((header::ORIGIN, "https://not-allowed.example"))
            .to_http_request();
        let resp2 = proxyauth::token::auth::auth_options(req2, state_ko)
            .await
            .respond_to(&test::TestRequest::default().to_http_request());
        assert_eq!(resp2.status(), StatusCode::FORBIDDEN);
    }

    // --------- auth handler --------------------------------------------------

    #[tokio::test]
    async fn auth_success_json_with_csrf_sets_cookie_and_redirects() {
        let user = User {
            username: "alice".into(),
            password: hash_pwd("passw0rd"),
            otpkey: None,
            allow: None,
            roles: Some(vec!["user".into()]),
            groups: None,
            email: None,
            must_change_password: false,
        };

        let mut cfg = base_config();
        cfg.users = vec![user];
        cfg.session_cookie = true;
        cfg.csrf_token = true;
        cfg.login_redirect_url = Some("/home".into());
        let data = mk_state(vec![], cfg);

        let tok = make_csrf_token(&data.config.secret);

        let req = test::TestRequest::default()
            .insert_header((header::CONTENT_TYPE, "application/json"))
            .insert_header(("x-forwarded-for", "203.0.113.7"))
            .set_payload(r#"{"username":"alice","password":"passw0rd","csrf_token":""}"#)
            .to_http_request();

        let payload = proxyauth::token::auth::EitherAuth::Json(AuthRequest {
            username: "alice".into(),
            password: "passw0rd".into(),
            totp_code: None,
            csrf_token: Some(tok),
        });

        let resp = proxyauth::token::auth::auth(req, data.clone(), payload)
            .await
            .respond_to(&test::TestRequest::default().to_http_request());

        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let has_cookie = resp
            .headers()
            .get_all(header::SET_COOKIE)
            .into_iter()
            .any(|v| v.to_str().unwrap_or("").starts_with("session_token="));
        assert!(has_cookie);
        assert_eq!(resp.headers().get(header::LOCATION).unwrap(), "/home");
    }

    #[tokio::test]
    async fn auth_invalid_password_renders_error_page_401() {
        static HTML: &str = r#"<!doctype html>
        <html><head><title>Logout</title></head>
        <body>
        <!-- BEGIN_BLOCK_ERROR -->
        <!-- <div class="err">{{ error }}</div> -->
        <!-- END_BLOCK_ERROR -->
        {{ csrf_token }}
        </body></html>"#;

        let (addr, _join) = start_backend(HTML);

        let routes = vec![rr("/logout", &format!("http://{}/logout", addr))];

        let mut cfg = base_config();
        cfg.users = vec![User {
            username: "bob".into(),
            password: hash_pwd("correct"),
            otpkey: None,
            allow: None,
            roles: None,
            groups: None,
            email: None,
            must_change_password: false,
        }];
        cfg.logout_redirect_url = Some(format!("http://{}/logout", addr));
        let data = mk_state(routes, cfg);

        let tok = make_csrf_token(&data.config.secret);
        let req = test::TestRequest::default()
            .insert_header((header::CONTENT_TYPE, "application/json"))
            .insert_header(("x-forwarded-for", "198.51.100.9"))
            .to_http_request();

        let payload = proxyauth::token::auth::EitherAuth::Json(AuthRequest {
            username: "bob".into(),
            password: "wrong".into(),
            totp_code: None,
            csrf_token: Some(tok),
        });

        let resp = proxyauth::token::auth::auth(req, data.clone(), payload)
            .await
            .respond_to(&test::TestRequest::default().to_http_request());
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let body = actix_to_bytes(resp.into_body()).await.unwrap_or_default();
        let s = String::from_utf8_lossy(&body);
        assert!(s.contains("err"));
    }

    fn build_valid_session_cookie_for_user(
        data: &actix_web::web::Data<AppState>,
        index_user: usize,
        token_id: &str,
        seconds_from_now: i64,
    ) -> String {
        use chrono::Utc;
        let user = &data.config.users[index_user];
        let expiry_ts = (Utc::now() + chrono::Duration::seconds(seconds_from_now))
            .timestamp()
            .to_string();

        let token_plain = generate_token(&user.username, &data.config, &expiry_ts, token_id);
        let cipher_part = calcul_cipher(token_plain);
        let clear = format!("{cipher_part}|{expiry_ts}|{index_user}|{token_id}");
        let key = derive_key_from_secret(&data.config.secret);
        encrypt(&clear, &key)
    }

    // ---------- EitherAuth::Form end-to-end ----------------------------------

    #[tokio::test]
    async fn either_auth_form_end_to_end_with_csrf_ok_redirects_and_sets_cookie() {
        let user = User {
            username: "alice".into(),
            password: hash_pwd("passw0rd"),
            otpkey: None,
            allow: None,
            roles: None,
            groups: None,
            email: None,
            must_change_password: false,
        };
        let mut cfg = base_config();
        cfg.users = vec![user];
        cfg.session_cookie = true;
        cfg.csrf_token = true;
        cfg.login_redirect_url = Some("/home".into());
        let data = mk_state(vec![], cfg);

        let tok = make_csrf_token(&data.config.secret);
        let form = format!(
            "username=alice&password=passw0rd&csrf_token={}",
            urlencoding::encode(&tok)
        );

        let req = test::TestRequest::default()
            .insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
            .insert_header(("x-forwarded-for", "203.0.113.7"))
            .set_payload(form)
            .to_http_request();

        let payload = proxyauth::token::auth::EitherAuth::Form(AuthRequest {
            username: "alice".into(),
            password: "passw0rd".into(),
            totp_code: None,
            csrf_token: Some(tok),
        });

        let resp = proxyauth::token::auth::auth(req, data.clone(), payload)
            .await
            .respond_to(&test::TestRequest::default().to_http_request());

        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(resp.headers().get(header::LOCATION).unwrap(), "/home");
        let has_cookie = resp
            .headers()
            .get_all(header::SET_COOKIE)
            .into_iter()
            .any(|v| v.to_str().unwrap_or("").starts_with("session_token="));
        assert!(has_cookie);
    }

    // ---------- Session cookie déjà présent ----------------------------------

    #[tokio::test]
    async fn auth_with_valid_session_cookie_short_circuits_and_reflects_cors() {
        let user = User {
            username: "alice".into(),
            password: hash_pwd("irrelevant"),
            otpkey: None,
            allow: None,
            roles: None,
            groups: None,
            email: None,
            must_change_password: false,
        };
        let mut cfg = base_config();
        cfg.users = vec![user];
        cfg.session_cookie = true;
        cfg.csrf_token = true;
        cfg.login_redirect_url = Some("/dashboard".into());
        cfg.cors_origins = Some(vec!["https://app.example.com".into()]);
        let data = mk_state(vec![], cfg);

        let token_enc = build_valid_session_cookie_for_user(&data, 0, "tid-cookie", 300);

        let req = test::TestRequest::default()
            .insert_header((header::CONTENT_TYPE, "application/json"))
            .insert_header((header::ORIGIN, "https://app.example.com"))
            .cookie(Cookie::build("session_token", token_enc).finish())
            .to_http_request();

        let payload = proxyauth::token::auth::EitherAuth::Json(AuthRequest {
            username: "alice".into(),
            password: "does-not-matter".into(),
            totp_code: None,
            csrf_token: Some(make_csrf_token(&data.config.secret)),
        });

        let resp = proxyauth::token::auth::auth(req, data.clone(), payload)
            .await
            .respond_to(&test::TestRequest::default().to_http_request());

        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(resp.headers().get(header::LOCATION).unwrap(), "/dashboard");
        assert_eq!(
            resp.headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .and_then(|v| v.to_str().ok()),
            Some("https://app.example.com")
        );
        assert_eq!(
            resp.headers()
                .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
                .and_then(|v| v.to_str().ok()),
            Some("true")
        );
    }

    // ---------- Redirect URL invalide ----------------------------------------

    #[tokio::test]
    async fn auth_session_cookie_redirect_url_must_be_relative() {
        let user = User {
            username: "alice".into(),
            password: hash_pwd("passw0rd"),
            otpkey: None,
            allow: None,
            roles: None,
            groups: None,
            email: None,
            must_change_password: false,
        };
        let mut cfg = base_config();
        cfg.users = vec![user];
        cfg.session_cookie = true;
        cfg.csrf_token = true;
        cfg.login_redirect_url = Some("https://evil.example/path".into());
        let data = mk_state(vec![], cfg);

        let req = test::TestRequest::default()
            .insert_header((header::CONTENT_TYPE, "application/json"))
            .to_http_request();

        let payload = proxyauth::token::auth::EitherAuth::Json(AuthRequest {
            username: "alice".into(),
            password: "passw0rd".into(),
            totp_code: None,
            csrf_token: Some(make_csrf_token(&data.config.secret)),
        });

        let resp = proxyauth::token::auth::auth(req, data.clone(), payload)
            .await
            .respond_to(&test::TestRequest::default().to_http_request());
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // ---------- TOTP ---------------------------------------------------------

    #[tokio::test]
    async fn auth_totp_success_sets_cookie_and_redirects() {
        use base32::Alphabet;
        let raw_secret: [u8; 20] = *b"0123456789ABCDEFGHIJ";
        let b32 = base32::encode(Alphabet::Rfc4648 { padding: false }, &raw_secret);

        let user = User {
            username: "carol".into(),
            password: hash_pwd("otp-pass"),
            otpkey: Some(b32.clone()),
            allow: None,
            roles: None,
            groups: None,
            email: None,
            must_change_password: false,
        };

        let mut cfg = base_config();
        cfg.users = vec![user];
        cfg.session_cookie = true;
        cfg.csrf_token = true;
        cfg.login_via_otp = true;
        cfg.login_redirect_url = Some("/after-otp".into());
        let data = mk_state(vec![], cfg);

        let secret_bytes = base32::decode(Alphabet::Rfc4648 { padding: false }, &b32).unwrap();
        let totp = TOTP::new(Algorithm::SHA512, 6, 0, 30, secret_bytes).unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let code = totp.generate(now);

        let tok = make_csrf_token(&data.config.secret);

        let req = test::TestRequest::default()
            .insert_header((header::CONTENT_TYPE, "application/json"))
            .insert_header(("x-forwarded-for", "203.0.113.9"))
            .to_http_request();

        let payload = proxyauth::token::auth::EitherAuth::Json(AuthRequest {
            username: "carol".into(),
            password: "otp-pass".into(),
            totp_code: Some(code),
            csrf_token: Some(tok),
        });

        let resp = proxyauth::token::auth::auth(req, data.clone(), payload)
            .await
            .respond_to(&test::TestRequest::default().to_http_request());

        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(resp.headers().get(header::LOCATION).unwrap(), "/after-otp");
        let has_cookie = resp
            .headers()
            .get_all(header::SET_COOKIE)
            .into_iter()
            .any(|v| v.to_str().unwrap_or("").starts_with("session_token="));
        assert!(has_cookie);
    }

    // ---------- CORS nouvelle session ----------------------------------------

    #[tokio::test]
    async fn auth_sets_cors_headers_when_origin_allowed_on_new_session() {
        let user = User {
            username: "erin".into(),
            password: hash_pwd("pw"),
            otpkey: None,
            allow: None,
            roles: None,
            groups: None,
            email: None,
            must_change_password: false,
        };

        let mut cfg = base_config();
        cfg.users = vec![user];
        cfg.session_cookie = true;
        cfg.csrf_token = true;
        cfg.cors_origins = Some(vec!["https://front.example".into()]);
        cfg.login_redirect_url = Some("/ok".into());
        let data = mk_state(vec![], cfg);

        let tok = make_csrf_token(&data.config.secret);

        let req = test::TestRequest::default()
            .insert_header((header::CONTENT_TYPE, "application/json"))
            .insert_header((header::ORIGIN, "https://front.example"))
            .insert_header(("x-forwarded-for", "203.0.113.10"))
            .to_http_request();

        let payload = proxyauth::token::auth::EitherAuth::Json(AuthRequest {
            username: "erin".into(),
            password: "pw".into(),
            totp_code: None,
            csrf_token: Some(tok),
        });

        let resp = proxyauth::token::auth::auth(req, data.clone(), payload)
            .await
            .respond_to(&test::TestRequest::default().to_http_request());

        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            resp.headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .and_then(|v| v.to_str().ok()),
            Some("https://front.example")
        );
        assert_eq!(
            resp.headers()
                .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
                .and_then(|v| v.to_str().ok()),
            Some("true")
        );
        assert_eq!(
            resp.headers()
                .get(header::ACCESS_CONTROL_MAX_AGE)
                .and_then(|v| v.to_str().ok()),
            Some("3600")
        );
    }
}

#[cfg(test)]
mod render_error_page_tests {
    use super::*;
    use actix_web::{http::header, test};
    use bytes::Bytes as ActixBytes;
    use dashmap::DashMap;
    use std::net::TcpListener;
    use std::sync::Arc;
    use tokio::net::TcpListener as TokioTcpListener;

    // hyper 1.x
    use http_body_util::{Full, combinators::BoxBody};
    use hyper::Response;
    use hyper::body::Bytes;
    use hyper::body::Incoming;
    use hyper_http_proxy::{Intercept, Proxy, ProxyConnector};
    use hyper_rustls::HttpsConnectorBuilder;
    use hyper_util::client::legacy::Client;
    use hyper_util::client::legacy::connect::HttpConnector;
    use hyper_util::rt::TokioIo;
    use std::convert::Infallible;

    use proxyauth::config::config::{AppConfig, RouteConfig, RouteRule};
    use proxyauth::revoke::db::RevokedTokenMap;

    fn https_client()
    -> Client<hyper_rustls::HttpsConnector<HttpConnector>, BoxBody<Bytes, Infallible>> {
        let https = HttpsConnectorBuilder::new()
            .with_native_roots()
            .unwrap()
            .https_or_http()
            .enable_http1()
            .build();
        Client::builder(hyper_util::rt::TokioExecutor::new())
            .build::<_, BoxBody<Bytes, Infallible>>(https)
    }

    fn proxy_client() -> Client<
        ProxyConnector<hyper_rustls::HttpsConnector<HttpConnector>>,
        BoxBody<Bytes, Infallible>,
    > {
        let https = HttpsConnectorBuilder::new()
            .with_native_roots()
            .unwrap()
            .https_or_http()
            .enable_http1()
            .build();
        let proxy = Proxy::new(Intercept::All, "http://127.0.0.1:1".parse().unwrap());
        let connector = ProxyConnector::from_proxy(https, proxy).unwrap();
        Client::builder(hyper_util::rt::TokioExecutor::new())
            .build::<_, BoxBody<Bytes, Infallible>>(connector)
    }

    fn mk_state(routes: Vec<RouteRule>, mut cfg: AppConfig) -> actix_web::web::Data<AppState> {
        cfg.session_cookie = true;
        cfg.csrf_token = true;

        let stats = RequestStats::new();
        spawn_stats_ticker(stats.clone());

        let state = AppState {
            config: Arc::new(cfg),
            routes: Arc::new(RouteConfig { routes, ..Default::default() }),
            counter: Arc::new(CounterToken::new()),
            client_normal: https_client(),
            client_with_cert: https_client(),
            client_with_proxy: proxy_client(),
            revoked_tokens: Arc::new(DashMap::new()) as RevokedTokenMap,
            stats,
            otp_overrides: Arc::new(DashMap::new()),
            password_overrides: Arc::new(DashMap::new()),
            must_change_overrides: Arc::new(DashMap::new()),
            ip_blocklist: Arc::new(arc_swap::ArcSwap::from_pointee(Vec::new())),
        };
        actix_web::web::Data::new(state)
    }

    fn base_cfg() -> AppConfig {
        AppConfig {
            fast: false,
            token_expiry_seconds: 3600,
            secret: "unit-secret-xyz".into(),
            users: vec![],
            token_admin: String::new(),
            host: vec!["127.0.0.1".to_string()],
            port: 0,
            worker: 1,
            ratelimit_proxy: Default::default(),
            ratelimit_auth: Default::default(),
            log: Default::default(),
            stats: false,
            max_idle_per_host: 16,
            timezone: "UTC".into(),
            login_via_otp: false,
            max_connections: 1024,
            pending_connections_limit: 1024,
            socket_listen: 128,
            client_timeout: 1000,
            keep_alive: 1,
            num_instances: 1,
            redis: None,
            cors_origins: None,
            smtp: None,
            session_cookie: true,
            max_age_session_cookie: 3600,
            login_redirect_url: Some("/home".into()),
            logout_redirect_url: None,
            tls: false,
            csrf_token: true,
            ..Default::default()
        }
    }

    fn rr(prefix: &str, target: &str) -> RouteRule {
        RouteRule {
            prefix: prefix.to_string(),
            target: target.to_string(),
            username: vec![],
            groups: vec![],
            roles: vec![],
            required_login: false,
            proxy: false,
            proxy_config: String::new(),
            cert: std::collections::HashMap::new(),
            backends: vec![],
            need_csrf: Some(false),
            log: None,
            log_file: None,
            compression: None,
            cache: true,
            cache_duration_secs: None,
            secure_path: false,
            preserve_prefix: false,
            allow_methods: None,
            filters: None,
            filters_compiled: None,
            vhost: vec![],
            vhost_cert: std::collections::HashMap::new(),
            certbot_renew: false,
            headers: std::collections::HashMap::new(),
        csrf_token: None,
        session_cookie: None,
        max_age_session_cookie: None,
        login_redirect_url: None,
        logout_redirect_url: None,
        login_via_otp: None,
        page_change_password: None,
        cors_origins: None,
        smtp: None,
        tag_proxyauth: None,
        allow_users: vec![],
        allow_groups: vec![],
        allow_roles: vec![],
        exclude_users: vec![],
            allow_ips: vec![],
            deny_ips: vec![],
            allow_ips_compiled: vec![],
            deny_ips_compiled: vec![],
            static_path: None,
            static_index: "index.html".into(),
            regex: None,
            regex_compiled: None,
            static_rewrite: None,
        }
    }

    fn start_backend(
        html: &'static str,
        status: u16,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        use hyper::server::conn::http1;
        use hyper::service::service_fn;

        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let local_addr = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let tokio_listener = TokioTcpListener::from_std(listener).unwrap();

        let join = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = tokio_listener.accept().await else {
                    break;
                };
                let io = TokioIo::new(stream);
                tokio::spawn(async move {
                    let svc = service_fn(move |_req: hyper::Request<Incoming>| async move {
                        Ok::<_, std::convert::Infallible>(
                            Response::builder()
                                .status(status)
                                // &str pour éviter le conflit http 0.2 / http 1.x
                                .header("content-type", "text/html; charset=utf-8")
                                .body(Full::new(Bytes::from(html)))
                                .unwrap(),
                        )
                    });
                    let _ = http1::Builder::new().serve_connection(io, svc).await;
                });
            }
        });

        (local_addr, join)
    }

    // ------------ tests ------------------------------------------------------

    #[tokio::test]
    async fn render_error_page_missing_logout_config_returns_400() {
        let mut cfg = base_cfg();
        cfg.logout_redirect_url = None;
        let data = mk_state(vec![], cfg);

        let req = test::TestRequest::default().to_http_request();
        let resp = proxyauth::network::error::render_error_page(&req, data, "boom").await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let body = actix_web::body::to_bytes(resp.into_body())
            .await
            .unwrap_or_else(|_| ActixBytes::new());
        assert_eq!(&body[..], b"logout_redirect_url is not configured");
    }

    #[tokio::test]
    async fn render_error_page_no_matching_route_returns_400() {
        let mut cfg = base_cfg();
        cfg.logout_redirect_url = Some("/logout".into());
        let data = mk_state(vec![rr("/only", "http://127.0.0.1:9")], cfg);

        let req = test::TestRequest::default().to_http_request();
        let resp = proxyauth::network::error::render_error_page(&req, data, "x").await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let body = actix_web::body::to_bytes(resp.into_body())
            .await
            .unwrap_or_else(|_| ActixBytes::new());
        assert_eq!(&body[..], b"No matching route for logout_redirect_url path");
    }

    #[tokio::test]
    async fn render_error_page_backend_500_maps_to_400() {
        static HTML_ERR: &str =
            "<html><!-- BEGIN_BLOCK_ERROR -->{{ error }}<!-- END_BLOCK_ERROR --></html>";
        let (addr, _j) = start_backend(HTML_ERR, 500);
        let url = format!("http://{}/logout", addr);

        let mut cfg = base_cfg();
        cfg.logout_redirect_url = Some(url);
        let routes = vec![rr("/logout", &format!("http://{}/logout", addr))];
        let data = mk_state(routes, cfg);

        let req = test::TestRequest::default().to_http_request();
        let resp = proxyauth::network::error::render_error_page(&req, data, "msg").await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn render_error_page_upstream_client_error_maps_to_503() {
        let mut cfg = base_cfg();
        cfg.logout_redirect_url = Some("http://127.0.0.1:1/logout".into());
        let routes = vec![rr("/logout", "http://127.0.0.1:1/logout")];
        let data = mk_state(routes, cfg);

        let req = test::TestRequest::default().to_http_request();
        let resp = proxyauth::network::error::render_error_page(&req, data, "x").await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn render_error_page_happy_path_returns_401_and_is_html() {
        static HTML_OK: &str = r#"<!doctype html>
        <html><head><title>Logout</title></head>
        <body>
        <!-- BEGIN_BLOCK_ERROR --><div class="err">{{ error }}</div><!-- END_BLOCK_ERROR -->
        {{ csrf_token }}
        </body></html>"#;

        let (addr, _j) = start_backend(HTML_OK, 200);
        let url = format!("http://{}/logout?x=1", addr);

        let mut cfg = base_cfg();
        cfg.logout_redirect_url = Some(url);
        let routes = vec![rr("/logout", &format!("http://{}/logout", addr))];
        let data = mk_state(routes, cfg);

        let req = test::TestRequest::default()
            .insert_header((header::ORIGIN, "https://app.example.com"))
            .insert_header((header::USER_AGENT, "UA"))
            .to_http_request();

        let resp =
            proxyauth::network::error::render_error_page(&req, data, "Invalid credentials").await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let ct = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap()
            .to_ascii_lowercase();
        assert!(ct.contains("text/html"));

        let body = actix_web::body::to_bytes(resp.into_body())
            .await
            .unwrap_or_else(|_| ActixBytes::new());
        let s = String::from_utf8_lossy(&body);
        assert!(s.contains("Invalid credentials"));
        assert!(!s.contains("{{ csrf_token }}"));
    }

    #[tokio::test]
    async fn render_error_page_absolute_url_with_query_is_forwarded() {
        static HTML_OK: &str =
            "<html><!-- BEGIN_BLOCK_ERROR -->{{ error }}<!-- END_BLOCK_ERROR -->OK</html>";
        let (addr, _j) = start_backend(HTML_OK, 200);

        let logout = format!("http://{}/logout/path?q=42", addr);
        let routes = vec![rr("/logout", &format!("http://{}/logout", addr))];

        let mut cfg = base_cfg();
        cfg.logout_redirect_url = Some(logout);
        let data = mk_state(routes, cfg);

        let req = test::TestRequest::default().to_http_request();
        let resp = proxyauth::network::error::render_error_page(&req, data, "boom").await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn render_error_page_forces_html_content_type_when_backend_non_html() {
        use hyper::server::conn::http1;
        use hyper::service::service_fn;

        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let addr = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let tokio_listener = TokioTcpListener::from_std(listener).unwrap();

        let _j = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = tokio_listener.accept().await else {
                    break;
                };
                let io = TokioIo::new(stream);
                tokio::spawn(async move {
                    let svc = service_fn(|_req: hyper::Request<Incoming>| async move {
                        Ok::<_, std::convert::Infallible>(
                            Response::builder()
                                .status(200)
                                // &str pour éviter le conflit http 0.2 / http 1.x
                                .header("content-type", "text/plain")
                                .body(Full::new(Bytes::from("NOT HTML {{ csrf_token }}")))
                                .unwrap(),
                        )
                    });
                    let _ = http1::Builder::new().serve_connection(io, svc).await;
                });
            }
        });

        let abs = format!("http://{}/logout", addr);
        let routes = vec![rr("/logout", &format!("http://{}/logout", addr))];

        let mut cfg = base_cfg();
        cfg.logout_redirect_url = Some(abs);
        let data = mk_state(routes, cfg);

        let req = test::TestRequest::default().to_http_request();
        let resp = proxyauth::network::error::render_error_page(&req, data, "x").await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let ct = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap()
            .to_ascii_lowercase();
        assert!(ct.contains("text/html"));
    }
}
