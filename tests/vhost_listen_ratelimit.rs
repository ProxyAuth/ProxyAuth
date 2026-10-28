//! Bout en bout sur de vraies sockets : `port`, `protocol` et
//! `ratelimit` déclarés par vhost dans routes.yml.
//!
//! Binaire de test séparé : l'arrêt du serveur est global au processus.

use proxyauth::config::config::{AppConfig, AppState, RouteConfig, load_config};
use proxyauth::hyper_web::server::{ConnProtocol, TlsSelector, trigger_shutdown};
use proxyauth::hyper_web::{App, HttpRequest, HttpResponse, HttpServer, web};
use proxyauth::network::ratelimit::{RateLimiters, VhostRateLimit};
use proxyauth::network::stats::RequestStats;
use proxyauth::network::vhost_listen::{HttpProtocol, ListenPlan, VhostListenGuard, protocol_for_sni};
use proxyauth::stats::tokencount::CounterToken;
use std::collections::HashMap;
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::time::Duration;

async fn hello(req: HttpRequest) -> HttpResponse {
    HttpResponse::Ok().body(format!(
        "{} {:?}",
        req.connection_info().host(),
        req.version()
    ))
}

fn free_listener() -> (TcpListener, u16) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let p = l.local_addr().unwrap().port();
    (l, p)
}

fn config(port: u16) -> Arc<AppConfig> {
    let dir = std::env::temp_dir().join(format!("proxyauth-vhost-listen-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("config.json");
    let json = serde_json::json!({
        "token_expiry_seconds": 3600,
        "secret": "vhost-listen-e2e-secret-vhost-listen-e2e-secret-0123456789",
        "users": [ { "username": "admin", "password": "unused" } ],
        "log": { "type": "disabled" },
        "logging": { "enabled": false },
        "smtp": null,
        "port": port,
        "timezone": "UTC"
    });
    std::fs::write(&path, serde_json::to_string_pretty(&json).unwrap()).unwrap();
    load_config(path.to_str().unwrap())
}

fn state(config: Arc<AppConfig>, yaml: &str) -> AppState {
    let routes: RouteConfig = serde_yaml::from_str::<RouteConfig>(yaml)
        .unwrap()
        .expand_vhost_groups();
    AppState {
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
    }
}

fn tls_selector(routes: Vec<proxyauth::config::config::RouteRule>) -> TlsSelector {
    let ck = rcgen::generate_simple_self_signed(vec![
        "d.test".to_string(),
        "e.test".to_string(),
    ])
    .unwrap();
    let cert = rustls_pki_types::CertificateDer::from(ck.cert.der().to_vec());
    let key_der = ck.key_pair.serialize_der();
    let mut by_proto = HashMap::new();
    for proto in [HttpProtocol::Auto, HttpProtocol::H1, HttpProtocol::H2] {
        let key = rustls_pki_types::PrivateKeyDer::Pkcs8(
            rustls_pki_types::PrivatePkcs8KeyDer::from(key_der.clone()),
        );
        let mut cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert.clone()], key)
            .unwrap();
        cfg.alpn_protocols = proto.alpn();
        by_proto.insert(proto, Arc::new(cfg));
    }
    Arc::new(move |sni| by_proto[&protocol_for_sni(&routes, sni)].clone())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn per_vhost_port_protocol_and_ratelimit() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let (l0, p0) = free_listener(); // port par défaut (config.json)
    let (l1, p1) = free_listener(); // vhost b : h2 seulement
    let (l2, p2) = free_listener(); // vhost c : h1 seulement
    let (l3, p3) = free_listener(); // TLS : d (h2) et e (h1)

    let yaml = format!(
        r#"
vhosts:
  - vhost: ["a.test"]
    routes:
      - prefix: "/"
        target: "http://127.0.0.1:1"
  - vhost: ["r.test"]
    ratelimit:
      limit_req_per_sec: 2
      burst: 2
      timeout: 5
      auth:
        limit_request: 1
        period: 60
    routes:
      - prefix: "/"
        target: "http://127.0.0.1:1"
  - vhost: ["b.test"]
    port: {p1}
    protocol: h2
    routes:
      - prefix: "/"
        target: "http://127.0.0.1:1"
  - vhost: ["c.test"]
    port: {p2}
    protocol: h1
    routes:
      - prefix: "/"
        target: "http://127.0.0.1:1"
  - vhost: ["d.test"]
    port: {p3}
    protocol: h2
    routes:
      - prefix: "/"
        target: "http://127.0.0.1:1"
  - vhost: ["e.test"]
    port: {p3}
    protocol: h1
    routes:
      - prefix: "/"
        target: "http://127.0.0.1:1"
"#
    );
    let state = web::Data::new(state(config(p0), &yaml));
    let routes = state.routes.routes.clone();

    let plan = ListenPlan::build(&routes, p0);
    assert_eq!(plan.ports[0], p0, "default port first");
    let mut others = plan.ports[1..].to_vec();
    others.sort();
    let mut expected = vec![p1, p2, p3];
    expected.sort();
    assert_eq!(others, expected);
    assert_eq!(plan.conn_protocol[&p1], ConnProtocol::Http2);
    assert_eq!(plan.conn_protocol[&p2], ConnProtocol::Http1);

    let limiters = Arc::new(RateLimiters::from_routes(&routes).unwrap());

    let app_state = state.clone();
    let server = HttpServer::new(move || {
        App::new()
            .app_data(app_state.clone())
            .wrap(VhostRateLimit {
                state: app_state.clone(),
                limiters: limiters.clone(),
            })
            .wrap(VhostListenGuard {
                state: app_state.clone(),
            })
            .default_service(web::to(hello))
    })
    .workers(2)
    .listen_protocol(l0, plan.conn_protocol[&p0])
    .unwrap()
    .listen_protocol(l1, plan.conn_protocol[&p1])
    .unwrap()
    .listen_protocol(l2, plan.conn_protocol[&p2])
    .unwrap()
    .listen_rustls_sni(l3, tls_selector(routes.clone()))
    .unwrap()
    .run();
    let server = tokio::spawn(server);

    let local = |p: u16| SocketAddr::from(([127, 0, 0, 1], p));
    let client = |h2: bool| {
        let mut b = reqwest::Client::builder()
            .tls_danger_accept_invalid_certs(true)
            .resolve("a.test", local(0))
            .resolve("r.test", local(0))
            .resolve("b.test", local(0))
            .resolve("c.test", local(0))
            .resolve("d.test", local(0))
            .resolve("e.test", local(0));
        b = if h2 { b.http2_prior_knowledge() } else { b.http1_only() };
        b.build().unwrap()
    };
    let h1 = client(false);
    let h2c = client(true);

    // ── Port ──────────────────────────────────────────────────────
    // a.test n'a pas de port : servi sur le port par défaut seulement.
    let r = h1.get(format!("http://a.test:{p0}/x")).send().await.unwrap();
    assert_eq!(r.status(), 200);
    let r = h1.get(format!("http://a.test:{p2}/x")).send().await.unwrap();
    assert_eq!(r.status(), 421, "a.test must not be served on c.test's port");
    // c.test est sur son port dédié, pas sur le port par défaut.
    let r = h1.get(format!("http://c.test:{p2}/x")).send().await.unwrap();
    assert_eq!(r.status(), 200);
    let r = h1.get(format!("http://c.test:{p0}/x")).send().await.unwrap();
    assert_eq!(r.status(), 421);

    // ── Protocole en clair ───────────────────────────────────────
    let r = h2c.get(format!("http://b.test:{p1}/x")).send().await.unwrap();
    assert_eq!(r.version(), reqwest::Version::HTTP_2);
    assert_eq!(r.status(), 200);
    assert!(
        h1.get(format!("http://b.test:{p1}/x")).send().await.is_err(),
        "an HTTP/2-only port must refuse HTTP/1.1"
    );
    assert!(
        h2c.get(format!("http://c.test:{p2}/x")).send().await.is_err(),
        "an HTTP/1.1-only port must refuse HTTP/2"
    );
    // Port par défaut (auto) : HTTP/2 accepté pour un vhost `auto`.
    let r = h2c.get(format!("http://a.test:{p0}/x")).send().await.unwrap();
    assert_eq!(r.status(), 200, "a.test is auto: h2 accepted");

    // ── Protocole en TLS : ALPN choisi par SNI ───────────────────
    let tls = reqwest::Client::builder()
        .tls_danger_accept_invalid_certs(true)
        .resolve("d.test", local(p3))
        .resolve("e.test", local(p3))
        .build()
        .unwrap();
    let r = tls.get(format!("https://d.test:{p3}/x")).send().await.unwrap();
    assert_eq!(r.version(), reqwest::Version::HTTP_2, "d.test is h2");
    let r = tls.get(format!("https://e.test:{p3}/x")).send().await.unwrap();
    assert_eq!(r.version(), reqwest::Version::HTTP_11, "e.test is h1 even for an h2-capable client");
    assert_eq!(r.status(), 200);

    // ── Rate limit du vhost ──────────────────────────────────────
    for _ in 0..2 {
        let r = h1.get(format!("http://r.test:{p0}/page")).send().await.unwrap();
        assert_eq!(r.status(), 200);
        assert!(r.headers().contains_key("x-ratelimit-remaining"));
    }
    let r = h1.get(format!("http://r.test:{p0}/page")).send().await.unwrap();
    assert_eq!(r.status(), 429);
    assert_eq!(r.headers()["retry-after"], "5", "timeout: 5 blocks for 5 s");
    let body = r.text().await.unwrap();
    assert!(body.contains("TooManyRequests"), "{body}");

    // Le bloc `auth:` a son propre compteur (1 requête / 60 s).
    let r = h1.post(format!("http://r.test:{p0}/auth")).send().await.unwrap();
    assert_ne!(r.status(), 429);
    let r = h1.post(format!("http://r.test:{p0}/auth")).send().await.unwrap();
    assert_eq!(r.status(), 429);
    assert_eq!(r.headers()["retry-after"], "60");

    // Un vhost sans `ratelimit:` n'est pas limité.
    for _ in 0..20 {
        let r = h1.get(format!("http://c.test:{p2}/x")).send().await.unwrap();
        assert_eq!(r.status(), 200);
    }

    trigger_shutdown();
    tokio::time::timeout(Duration::from_secs(10), server)
        .await
        .expect("server must stop")
        .unwrap()
        .unwrap();
}
