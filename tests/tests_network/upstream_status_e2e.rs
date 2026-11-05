//! Statut renvoyé quand le backend d'une route existante ne répond pas,
//! à travers `global_proxy` :
//! * service arrêté (connexion refusée) → 502 Bad Gateway ;
//! * backend qui ne répond pas à temps → 504 Gateway Timeout ;
//! * pool `backends:` entièrement en échec → 502 Bad Gateway ;
//! * URL qu'aucune route ne couvre → 404 (inchangé).

#[cfg(test)]
mod tests {
    use proxyauth::config::config::{AppConfig, AppState, RouteConfig, load_config};
    use proxyauth::hyper_web::http::{StatusCode, header};
    use proxyauth::hyper_web::test::{self, TestRequest};
    use proxyauth::hyper_web::{App, web};
    use proxyauth::network::proxy::global_proxy;
    use proxyauth::network::stats::RequestStats;
    use proxyauth::stats::tokencount::CounterToken;
    use std::net::{SocketAddr, TcpListener};
    use std::sync::{Arc, OnceLock};

    const HOST: &str = "upstream.example.com";

    /// Un port où plus rien n'écoute : connexion refusée.
    fn dead_backend() -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        drop(l);
        addr
    }

    /// Accepte les connexions mais ne répond jamais.
    fn hanging_backend() -> SocketAddr {
        static ADDR: OnceLock<SocketAddr> = OnceLock::new();
        *ADDR.get_or_init(|| {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = l.local_addr().unwrap();
            std::thread::spawn(move || {
                let mut held = Vec::new();
                for s in l.incoming().flatten() {
                    held.push(s);
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
                    .join(format!("proxyauth-upstream-status-{}", std::process::id()));
                std::fs::create_dir_all(&dir).unwrap();
                let path = dir.join("config.json");
                let json = serde_json::json!({
                    "token_expiry_seconds": 3600,
                    "secret": "upstream-status-e2e-secret-upstream-status-e2e-secret-0123",
                    "users": [ { "username": "admin", "password": "unused" } ],
                    "log": { "type": "disabled" },
                    "smtp": null,
                    "backend_timeout": 300
                });
                std::fs::write(&path, serde_json::to_string_pretty(&json).unwrap()).unwrap();
                let config = load_config(path.to_str().unwrap());
                proxyauth::token::vault::init(&config).expect("initialise the token vault");
                config
            })
            .clone()
    }

    fn state() -> AppState {
        let dead = dead_backend();
        let dead2 = dead_backend();
        let hanging = hanging_backend();
        let yaml = format!(
            r#"
routes:
  - prefix: "/down"
    vhost: ["{HOST}"]
    target: "http://{dead}"
  - prefix: "/slow"
    vhost: ["{HOST}"]
    target: "http://{hanging}"
  - prefix: "/pool"
    vhost: ["{HOST}"]
    target: "http://{dead}"
    backends:
      - "http://{dead}"
      - "http://{dead2}"
"#
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

    async fn status(path: &str) -> (StatusCode, String) {
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(state()))
                .default_service(web::to(global_proxy)),
        )
        .await;
        let req = TestRequest::get()
            .uri(path)
            .peer_addr("127.0.0.1:45000".parse().unwrap())
            .insert_header((header::HOST, HOST))
            .to_request();
        let resp = app.call(req).await.expect("service call");
        let s = resp.status();
        let body = test::read_body(resp).await;
        (s, String::from_utf8_lossy(&body).into_owned())
    }

    #[tokio::test]
    async fn stopped_backend_is_502() {
        let (s, body) = status("/down").await;
        assert_eq!(s, StatusCode::BAD_GATEWAY, "{body}");
    }

    #[tokio::test]
    async fn backend_timeout_is_504() {
        let (s, body) = status("/slow").await;
        assert_eq!(s, StatusCode::GATEWAY_TIMEOUT, "{body}");
    }

    #[tokio::test]
    async fn exhausted_backend_pool_is_502() {
        let (s, body) = status("/pool").await;
        assert_eq!(s, StatusCode::BAD_GATEWAY, "{body}");
    }

    #[tokio::test]
    async fn unrouted_path_is_still_404() {
        let (s, _) = status("/nothing-here").await;
        assert_eq!(s, StatusCode::NOT_FOUND);
    }
}
