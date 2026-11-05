//! WebSocket à travers ProxyAuth, sur de vraies sockets :
//! * client HTTP/1.1 (`Upgrade`) → backend WebSocket ;
//! * client HTTP/2, CONNECT étendu RFC 8441 (`:protocol: websocket`) →
//!   le même backend, qui ne parle que HTTP/1.1.
//!
//! Binaire de test séparé : l'arrêt du serveur est global au processus.

use futures_util::{SinkExt, StreamExt};
use http_body_util::Empty;
use hyper::body::Bytes;
use hyper_util::rt::{TokioExecutor, TokioIo};
use proxyauth::config::config::{AppConfig, AppState, RouteConfig, load_config};
use proxyauth::hyper_web::server::{ConnProtocol, trigger_shutdown};
use proxyauth::hyper_web::{App, HttpServer, web};
use proxyauth::network::proxy::global_proxy;
use proxyauth::network::stats::RequestStats;
use proxyauth::stats::tokencount::CounterToken;
use std::net::TcpListener;
use std::sync::Arc;
use std::time::Duration;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::Role;

/// Backend WebSocket d'écho (HTTP/1.1 seulement), qui annonce d'abord le
/// chemin reçu.
async fn echo_backend() -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((s, _)) = l.accept().await else { return };
            tokio::spawn(async move {
                let mut path = String::new();
                let cb = |req: &tokio_tungstenite::tungstenite::handshake::server::Request,
                          resp| {
                    path = req.uri().to_string();
                    Ok(resp)
                };
                let Ok(mut ws) = tokio_tungstenite::accept_hdr_async(s, cb).await else {
                    return;
                };
                let _ = ws.send(Message::text(format!("hello {path}"))).await;
                while let Some(Ok(m)) = ws.next().await {
                    if m.is_text() || m.is_binary() {
                        if ws.send(m).await.is_err() {
                            break;
                        }
                    }
                }
            });
        }
    });
    port
}

fn config(port: u16) -> Arc<AppConfig> {
    let dir = std::env::temp_dir().join(format!("proxyauth-ws-h2-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("config.json");
    let json = serde_json::json!({
        "token_expiry_seconds": 3600,
        "secret": "ws-h2-e2e-secret-ws-h2-e2e-secret-ws-h2-e2e-secret-012345",
        "users": [ { "username": "admin", "password": "unused" } ],
        "log": { "type": "disabled" },
        "logging": { "enabled": false },
        "smtp": null,
        "port": port
    });
    std::fs::write(&path, serde_json::to_string_pretty(&json).unwrap()).unwrap();
    let config = load_config(path.to_str().unwrap());
    proxyauth::token::vault::init(&config).expect("initialise the token vault");
    config
}

fn state(config: Arc<AppConfig>, backend: u16) -> AppState {
    let yaml = format!(
        r#"
routes:
  - prefix: "/ws"
    target: "ws://127.0.0.1:{backend}"
    forward_websocket: true
  - prefix: "/nows"
    target: "ws://127.0.0.1:{backend}"
"#
    );
    let routes: RouteConfig = serde_yaml::from_str::<RouteConfig>(&yaml)
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

/// Ouvre une WebSocket en HTTP/2 (RFC 8441) et renvoie le flux.
async fn h2_websocket(
    port: u16,
    path: &str,
) -> Result<tokio_tungstenite::WebSocketStream<TokioIo<hyper::upgrade::Upgraded>>, String> {
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let (mut sender, conn) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
        .handshake::<_, Empty<Bytes>>(TokioIo::new(tcp))
        .await
        .unwrap();
    tokio::spawn(conn);
    // Attendre les SETTINGS du serveur (dont ENABLE_CONNECT_PROTOCOL).
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut req = hyper::Request::builder()
        .method(hyper::Method::CONNECT)
        .uri(format!("http://127.0.0.1:{port}{path}"))
        .header("sec-websocket-version", "13")
        .body(Empty::<Bytes>::new())
        .unwrap();
    req.extensions_mut()
        .insert(hyper::ext::Protocol::from_static("websocket"));
    let mut resp = sender.send_request(req).await.map_err(|e| e.to_string())?;
    if resp.status() != hyper::StatusCode::OK {
        return Err(format!("status {}", resp.status()));
    }
    assert!(
        resp.headers().get("content-length").is_none(),
        "a successful CONNECT response carries no Content-Length"
    );
    let upgraded = hyper::upgrade::on(&mut resp)
        .await
        .map_err(|e| e.to_string())?;
    Ok(tokio_tungstenite::WebSocketStream::from_raw_socket(
        TokioIo::new(upgraded),
        Role::Client,
        None,
    )
    .await)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn websocket_over_http1_and_http2() {
    // Comme `main` : fournisseur crypto de rustls (connecteur vers le backend).
    let _ = rustls::crypto::ring::default_provider().install_default();
    let backend = echo_backend().await;
    let lst = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = lst.local_addr().unwrap().port();
    let state = web::Data::new(state(config(port), backend));

    let app_state = state.clone();
    let server = HttpServer::new(move || {
        App::new()
            .app_data(app_state.clone())
            .default_service(web::to(global_proxy))
    })
    .workers(2)
    .listen_protocol(lst, ConnProtocol::Auto)
    .unwrap()
    .run();
    let server = tokio::spawn(server);

    // ── HTTP/1.1 ─────────────────────────────────────────────────
    let (mut ws, _) =
        tokio_tungstenite::connect_async(format!("ws://127.0.0.1:{port}/ws/room?x=1"))
            .await
            .expect("HTTP/1.1 websocket");
    assert_eq!(
        ws.next().await.unwrap().unwrap(),
        Message::text("hello /room?x=1")
    );
    ws.send(Message::text("h1 ping")).await.unwrap();
    assert_eq!(ws.next().await.unwrap().unwrap(), Message::text("h1 ping"));
    ws.close(None).await.ok();
    drop(ws);

    // ── HTTP/2, RFC 8441 ─────────────────────────────────────────
    let mut ws = h2_websocket(port, "/ws/chat")
        .await
        .expect("HTTP/2 websocket");
    assert_eq!(
        ws.next().await.unwrap().unwrap(),
        Message::text("hello /chat")
    );
    ws.send(Message::text("h2 ping")).await.unwrap();
    assert_eq!(ws.next().await.unwrap().unwrap(), Message::text("h2 ping"));
    let big: Vec<u8> = (0..1_000_000u32).map(|i| (i % 251) as u8).collect();
    ws.send(Message::binary(big.clone())).await.unwrap();
    assert_eq!(ws.next().await.unwrap().unwrap(), Message::binary(big));
    ws.close(None).await.ok();
    drop(ws);

    // Deux WebSocket HTTP/2 simultanées ne se mélangent pas.
    let mut a = h2_websocket(port, "/ws/a").await.unwrap();
    let mut b = h2_websocket(port, "/ws/b").await.unwrap();
    assert_eq!(a.next().await.unwrap().unwrap(), Message::text("hello /a"));
    assert_eq!(b.next().await.unwrap().unwrap(), Message::text("hello /b"));
    a.send(Message::text("to a")).await.unwrap();
    b.send(Message::text("to b")).await.unwrap();
    assert_eq!(b.next().await.unwrap().unwrap(), Message::text("to b"));
    assert_eq!(a.next().await.unwrap().unwrap(), Message::text("to a"));
    a.close(None).await.ok();
    b.close(None).await.ok();
    drop((a, b));

    // Route sans forward_websocket : pas de tunnel.
    assert!(
        h2_websocket(port, "/nows").await.is_err(),
        "no tunnel without forward_websocket"
    );

    // Toutes les WebSocket sont fermées : l'arrêt gracieux ne doit pas
    // attendre son délai maximal (30 s).
    let t0 = std::time::Instant::now();
    trigger_shutdown();
    tokio::time::timeout(Duration::from_secs(40), server)
        .await
        .expect("server must stop")
        .unwrap()
        .unwrap();
    assert!(
        t0.elapsed() < Duration::from_secs(10),
        "shutdown took {:?}",
        t0.elapsed()
    );
}
