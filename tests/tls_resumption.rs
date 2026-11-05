//! La reprise de session TLS fonctionne à travers le serveur hyper,
//! quel que soit le worker qui reçoit la connexion suivante.

use proxyauth::hyper_web::server::TlsSelector;
use proxyauth::hyper_web::{App, HttpResponse, HttpServer, web};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

fn server_config() -> Arc<rustls::ServerConfig> {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert = rustls_pki_types::CertificateDer::from(ck.cert.der().to_vec());
    let key = rustls_pki_types::PrivateKeyDer::Pkcs8(rustls_pki_types::PrivatePkcs8KeyDer::from(
        ck.key_pair.serialize_der(),
    ));
    let mut cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    cfg.session_storage = rustls::server::ServerSessionMemoryCache::new(1024);
    cfg.ticketer = rustls::crypto::ring::Ticketer::new().unwrap();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(cfg)
}

#[derive(Debug)]
struct NoVerify;
impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _: &rustls_pki_types::CertificateDer<'_>,
        _: &[rustls_pki_types::CertificateDer<'_>],
        _: &rustls_pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &rustls_pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &rustls_pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// N connexions successives (une requête chacune) ; renvoie combien ont
/// été reprises.
fn count_resumed(port: u16, version: &'static rustls::SupportedProtocolVersion, n: usize) -> usize {
    let mut cfg = rustls::ClientConfig::builder_with_protocol_versions(&[version])
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let cfg = Arc::new(cfg);
    let mut resumed = 0;
    for _ in 0..n {
        let name = rustls_pki_types::ServerName::try_from("localhost").unwrap();
        let mut conn = rustls::ClientConnection::new(cfg.clone(), name).unwrap();
        let mut sock = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let mut tls = rustls::Stream::new(&mut conn, &mut sock);
        tls.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut buf = Vec::new();
        let _ = tls.read_to_end(&mut buf);
        assert!(
            buf.starts_with(b"HTTP/1.1 200"),
            "{}",
            String::from_utf8_lossy(&buf)
        );
        if conn.handshake_kind() == Some(rustls::HandshakeKind::Resumed) {
            resumed += 1;
        }
    }
    resumed
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_sessions_resume_across_workers() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let fixed = TcpListener::bind("127.0.0.1:0").unwrap();
    let sni = TcpListener::bind("127.0.0.1:0").unwrap();
    let fixed_port = fixed.local_addr().unwrap().port();
    let sni_port = sni.local_addr().unwrap().port();

    let cfg = server_config();
    let selector_cfg = cfg.clone();
    let selector: TlsSelector = Arc::new(move |_sni| selector_cfg.clone());

    let server = HttpServer::new(|| {
        App::new().default_service(web::to(|| async { HttpResponse::Ok().body("ok") }))
    })
    .workers(4)
    .listen_rustls_0_23(fixed, (*cfg).clone())
    .unwrap()
    .listen_rustls_sni(sni, selector)
    .unwrap()
    .run();
    let _server = tokio::spawn(server);

    let results = tokio::task::spawn_blocking(move || {
        [
            (
                "fixed tls1.2",
                count_resumed(fixed_port, &rustls::version::TLS12, 20),
            ),
            (
                "fixed tls1.3",
                count_resumed(fixed_port, &rustls::version::TLS13, 20),
            ),
            (
                "sni tls1.2",
                count_resumed(sni_port, &rustls::version::TLS12, 20),
            ),
            (
                "sni tls1.3",
                count_resumed(sni_port, &rustls::version::TLS13, 20),
            ),
        ]
    })
    .await
    .unwrap();

    for (label, resumed) in results {
        println!("{label}: {resumed}/19 resumed");
        // La première connexion est forcément complète ; toutes les
        // suivantes doivent reprendre la session.
        assert_eq!(resumed, 19, "{label}");
    }
}
