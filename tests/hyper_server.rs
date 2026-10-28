//! Bout en bout sur de vraies sockets : le serveur hyper qui remplace
//! actix-web (HTTP/1.1, h2c, TLS + ALPN h2, ordre des middlewares,
//! routage, limites de corps, décompression, arrêt gracieux).
//!
//! Binaire de test séparé : l'arrêt gracieux est global au processus.

use proxyauth::hyper_web::dev::{Middleware, Next, ServiceFuture, ServiceRequest};
use proxyauth::hyper_web::http::{Method, header};
use proxyauth::hyper_web::server::trigger_shutdown;
use proxyauth::hyper_web::{App, HttpRequest, HttpResponse, HttpServer, web};
use std::io::Write;
use std::net::TcpListener;
use std::time::Duration;

/// Ajoute son nom à `x-order` : permet de vérifier que le dernier
/// `wrap` est bien le plus extérieur, comme chez actix.
struct Tag(&'static str);

impl Middleware for Tag {
    fn call(&self, req: ServiceRequest, next: Next) -> ServiceFuture {
        let name = self.0;
        let fut = next.call(req);
        Box::pin(async move {
            let mut res = fut.await?;
            let prev = res
                .headers()
                .get("x-order")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            let v = if prev.is_empty() { name.to_string() } else { format!("{prev},{name}") };
            res.headers_mut().insert("x-order", v.parse().unwrap());
            Ok(res)
        })
    }
}

struct State {
    greeting: String,
}

async fn hello(data: web::Data<State>) -> HttpResponse {
    HttpResponse::Ok().body(data.greeting.clone())
}

async fn echo(req: HttpRequest, body: web::Bytes) -> HttpResponse {
    HttpResponse::Ok()
        .insert_header(("x-version", format!("{:?}", req.version())))
        .insert_header(("x-host", req.connection_info().host().to_string()))
        .insert_header(("x-path", req.path().to_string()))
        .body(body)
}

#[derive(serde::Deserialize)]
struct In {
    n: u32,
}

async fn json(body: web::Json<In>) -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({ "double": body.n * 2 }))
}

async fn fallback(req: HttpRequest) -> HttpResponse {
    HttpResponse::Ok().body(format!("default:{}", req.path()))
}

async fn slow() -> HttpResponse {
    tokio::time::sleep(Duration::from_millis(700)).await;
    HttpResponse::Ok().body("slow done")
}

fn self_signed() -> rustls::ServerConfig {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert = rustls_pki_types::CertificateDer::from(ck.cert.der().to_vec());
    let key = rustls_pki_types::PrivateKeyDer::Pkcs8(rustls_pki_types::PrivatePkcs8KeyDer::from(
        ck.key_pair.serialize_der(),
    ));
    let mut cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    cfg
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hyper_server_end_to_end() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let plain = TcpListener::bind("127.0.0.1:0").unwrap();
    let tls = TcpListener::bind("127.0.0.1:0").unwrap();
    let plain_port = plain.local_addr().unwrap().port();
    let tls_port = tls.local_addr().unwrap().port();

    let state = web::Data::new(State {
        greeting: "bonjour".into(),
    });

    let server = HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .app_data(web::PayloadConfig::new(1024))
            .wrap(Tag("inner"))
            .wrap(Tag("outer"))
            .service(web::resource("/hello").route(web::get().to(hello)))
            .service(web::resource("/echo").route(web::post().to(echo)))
            .service(web::resource("/json").route(web::post().to(json)))
            .service(web::resource("/slow").route(web::get().to(slow)))
            .default_service(web::to(fallback))
    })
    .workers(2)
    .listen(plain)
    .unwrap()
    .listen_rustls_0_23(tls, self_signed())
    .unwrap()
    .run();
    let server = tokio::spawn(server);

    let base = format!("http://127.0.0.1:{plain_port}");
    let h1 = reqwest::Client::builder().http1_only().build().unwrap();

    // Routage + app_data + ordre des middlewares (dernier wrap = extérieur).
    let r = h1.get(format!("{base}/hello")).send().await.unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.headers()["x-order"], "inner,outer");
    assert_eq!(r.text().await.unwrap(), "bonjour");

    // Chemin connu, méthode non routée → 405 (pas le service par défaut).
    let r = h1.post(format!("{base}/hello")).send().await.unwrap();
    assert_eq!(r.status(), 405);

    // Service par défaut, et « requote » du chemin pour le routage.
    let r = h1.get(format!("{base}/nowhere")).send().await.unwrap();
    assert_eq!(r.text().await.unwrap(), "default:/nowhere");
    let r = h1.get(format!("{base}/%68ello")).send().await.unwrap();
    assert_eq!(r.text().await.unwrap(), "bonjour");

    // Corps brut, limite, et décompression gzip à la volée.
    let r = h1.post(format!("{base}/echo")).body("ping").send().await.unwrap();
    assert_eq!(r.headers()["x-version"], "HTTP/1.1");
    assert_eq!(r.text().await.unwrap(), "ping");

    let r = h1.post(format!("{base}/echo")).body(vec![b'a'; 2048]).send().await.unwrap();
    assert_eq!(r.status(), 413);

    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(b"compressed hello").unwrap();
    let r = h1
        .post(format!("{base}/echo"))
        .header(header::CONTENT_ENCODING, "gzip")
        .body(gz.finish().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(r.text().await.unwrap(), "compressed hello");

    // Bombe gzip : la limite s'applique aussi APRÈS décompression.
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    gz.write_all(&vec![0u8; 100_000]).unwrap();
    let r = h1
        .post(format!("{base}/echo"))
        .header(header::CONTENT_ENCODING, "gzip")
        .body(gz.finish().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 413);

    // Extracteur JSON.
    let r = h1
        .post(format!("{base}/json"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(r#"{"n":21}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(r.text().await.unwrap(), r#"{"double":42}"#);
    let r = h1.post(format!("{base}/json")).body(r#"{"n":21}"#).send().await.unwrap();
    assert_eq!(r.status(), 400, "missing content-type must be refused");

    // HTTP/2 en clair (prior knowledge) : Host reconstruit depuis :authority,
    // URI ramenée à la forme relative.
    let h2c = reqwest::Client::builder().http2_prior_knowledge().build().unwrap();
    let r = h2c.post(format!("{base}/echo?x=1")).body("h2").send().await.unwrap();
    assert_eq!(r.version(), reqwest::Version::HTTP_2);
    assert_eq!(r.headers()["x-version"], "HTTP/2.0");
    assert_eq!(r.headers()["x-host"], format!("127.0.0.1:{plain_port}").as_str());
    assert_eq!(r.headers()["x-path"], "/echo");

    // TLS + ALPN h2.
    let tls_client = reqwest::Client::builder()
        .tls_danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let r = tls_client
        .post(format!("https://localhost:{tls_port}/echo"))
        .body("secure")
        .send()
        .await
        .unwrap();
    assert_eq!(r.version(), reqwest::Version::HTTP_2);
    assert_eq!(r.text().await.unwrap(), "secure");

    // HEAD : jamais de corps, mais la même taille annoncée que le GET.
    // En HTTP/2, envoyer le corps quand même est une erreur de protocole
    // côté client (curl -I : code 92) — régression constatée en CI.
    for (label, client, url) in [
        ("h1", &h1, format!("{base}/nowhere")),
        ("h2c", &h2c, format!("{base}/nowhere")),
        ("h2+tls", &tls_client, format!("https://localhost:{tls_port}/nowhere")),
    ] {
        let r = client
            .head(&url)
            .send()
            .await
            .unwrap_or_else(|e| panic!("HEAD over {label} failed: {e}"));
        assert_eq!(r.status(), 200, "{label}");
        assert_eq!(r.headers()["content-length"], "16", "{label}: length of \"default:/nowhere\"");
        assert_eq!(r.bytes().await.unwrap().len(), 0, "{label}: HEAD must have no body");
    }

    // Arrêt gracieux : la requête en cours se termine, le serveur s'arrête.
    let pending = {
        let h1 = h1.clone();
        let base = base.clone();
        tokio::spawn(async move { h1.get(format!("{base}/slow")).send().await })
    };
    tokio::time::sleep(Duration::from_millis(200)).await;
    trigger_shutdown();
    let r = pending.await.unwrap().unwrap();
    assert_eq!(r.text().await.unwrap(), "slow done");

    tokio::time::timeout(Duration::from_secs(10), server)
        .await
        .expect("server must stop after shutdown")
        .unwrap()
        .unwrap();

    // Plus personne n'écoute.
    assert!(h1.get(format!("{base}/hello")).send().await.is_err());

    let _ = Method::GET;
}
