use crate::AppConfig;
use actix_web::body::BoxBody;
use actix_web::dev::{ServiceFactory, ServiceRequest, ServiceResponse};
use actix_web::{App, Error, HttpServer};
use arc_swap::ArcSwap;
use notify::{Config as NotifyConfig, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use rustls::{
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
    ServerConfig,
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use once_cell::sync::Lazy;
use std::{
    fs::File,
    io::BufReader,
    net::TcpListener,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
    time::Instant,
    sync::Mutex,
    collections::HashMap,
};
use tokio::{sync::mpsc, task, time::sleep};
use tracing::{info, warn};

static LAST_LOGS: Lazy<Mutex<HashMap<&'static str, Instant>>> =
Lazy::new(|| Mutex::new(HashMap::new()));

fn rate_limited_log(tag: &'static str, period: Duration, msg: String) {
    let mut logs = LAST_LOGS.lock().unwrap();
    let now = Instant::now();
    let do_log = match logs.get(&tag) {
        Some(&last) => now.duration_since(last) > period,
        None => true,
    };
    if do_log {
        logs.insert(tag, now);
        info!("{msg}");
    }
}

fn load_cert_chain(path: &Path) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let f = File::open(path)?;
    let mut reader = BufReader::new(f);

    // rustls 0.23 : CertificateDer<'static> au lieu de Certificate(der)
    let certs = CertificateDer::pem_reader_iter(&mut reader)
    .filter_map(|r| r.ok())
    .collect::<Vec<_>>();

    anyhow::ensure!(!certs.is_empty(), "no certificates found in {}", path.display());
    Ok(certs)
}

fn load_private_key(path: &Path) -> anyhow::Result<PrivateKeyDer<'static>> {
    let f = File::open(path)?;
    let mut reader = BufReader::new(f);

    // rustls 0.23 : PrivateKeyDer<'static> au lieu de PrivateKey(der)
    let keys = PrivateKeyDer::pem_reader_iter(&mut reader)
    .filter_map(|r| r.ok())
    .collect::<Vec<PrivateKeyDer<'static>>>();

    anyhow::ensure!(!keys.is_empty(), "no private key found in {}", path.display());
    Ok(keys.into_iter().next().unwrap())
}

fn load_certified_key(cert_path: &Path, key_path: &Path) -> anyhow::Result<Arc<CertifiedKey>> {
    let chain = load_cert_chain(cert_path)?;
    let key = load_private_key(key_path)?;

    // rustls 0.23 : crypto_provider().key_provider.load_private_key()
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let sk = provider
    .key_provider
    .load_private_key(key)
    .map_err(|e| anyhow::anyhow!("Failed to load private key: {e}"))?;

    Ok(Arc::new(CertifiedKey::new(chain, sk)))
}

// rustls 0.23 exige Debug sur les implémenteurs de ResolvesServerCert
#[derive(Debug)]
struct HotResolver {
    current: ArcSwap<Arc<CertifiedKey>>,
}

impl HotResolver {
    fn new(initial: Arc<CertifiedKey>) -> Self {
        Self { current: ArcSwap::new(initial.into()) }
    }
    fn swap(&self, ck: Arc<CertifiedKey>) {
        self.current.store(ck.into());
    }
}

impl ResolvesServerCert for HotResolver {
    fn resolve(&self, _hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        let inner = self.current.load();
        Some(inner.as_ref().clone())
    }
}

fn build_rustls_config_with_resolver(resolver: Arc<HotResolver>) -> ServerConfig {
    // rustls 0.23 : with_safe_defaults() supprimé — builder() configure automatiquement
    let mut cfg = ServerConfig::builder()
    .with_no_client_auth()
    .with_cert_resolver(resolver as Arc<dyn ResolvesServerCert>);
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    cfg
}

async fn watch_cert_key(
    resolver: Arc<HotResolver>,
    cert: PathBuf,
    key: PathBuf,
) -> notify::Result<()> {
    let (tx, mut rx) = mpsc::unbounded_channel();
    let mut watcher: RecommendedWatcher =
    Watcher::new(move |e| { let _ = tx.send(e); }, NotifyConfig::default())?;
    watcher.watch(&cert, RecursiveMode::NonRecursive)?;
    watcher.watch(&key,  RecursiveMode::NonRecursive)?;

    rate_limited_log(
        "watch",
        Duration::from_secs(60),
                     format!("TLS hot-reload watching {} and {}", cert.display(), key.display()),
    );

    while let Some(ev) = rx.recv().await {
        match ev {
            Ok(event) => {
                match event.kind {
                    EventKind::Modify(_)
                    | EventKind::Create(_)
                    | EventKind::Remove(_)
                    | EventKind::Any => {
                        let resolver = resolver.clone();
                        let cert = cert.clone();
                        let key  = key.clone();
                        task::spawn(async move {
                            sleep(Duration::from_millis(400)).await;
                            match load_certified_key(&cert, &key) {
                                Ok(ck) => {
                                    resolver.swap(ck);
                                    rate_limited_log(
                                        "reload_ok",
                                        Duration::from_secs(60),
                                                     "Certificat TLS reloaded successfully.".to_string(),
                                    );
                                }
                                Err(e) => {
                                    rate_limited_log(
                                        "reload_err",
                                        Duration::from_secs(60),
                                                     format!("Error reload certificat: {e:?}"),
                                    );
                                }
                            }
                        });
                    }
                    _ => {}
                }
            }
            Err(e) => warn!("Watch TLS: {e:?}"),
        }
    }
    Ok(())
}

pub fn check_port(addr: &str) -> bool {
    TcpListener::bind(addr).is_ok()
}

pub fn bind_server<T, F>(
    app_factory: F,
    listener: TcpListener,
    config: &AppConfig,
) -> std::io::Result<actix_web::dev::Server>
where
T: ServiceFactory<
ServiceRequest,
Config = (),
Response = ServiceResponse<BoxBody>,
Error = Error,
InitError = (),
> + 'static,
F: Fn() -> App<T> + Clone + Send + 'static,
{
    let builder = HttpServer::new(app_factory)
    .workers(config.worker as usize)
    .keep_alive(Duration::from_millis(config.keep_alive))
    .backlog(config.pending_connections_limit)
    .max_connections(config.max_connections)
    .client_request_timeout(Duration::from_millis(config.client_timeout));

    if config.tls {
        let cert_path = PathBuf::from("/etc/proxyauth/certs/cert.pem");
        let key_path  = PathBuf::from("/etc/proxyauth/certs/key.pem");

        let initial = load_certified_key(&cert_path, &key_path)
        .expect("TLS: error initialization cert/key");

        let resolver: Arc<HotResolver> = Arc::new(HotResolver::new(initial));
        let tls_cfg = build_rustls_config_with_resolver(resolver.clone());

        let r2 = resolver.clone();
        tokio::spawn(async move {
            if let Err(e) = watch_cert_key(r2, cert_path, key_path).await {
                warn!("Watch TLS stopped: {e:?}");
            }
        });

        // actix-web 4 avec rustls 0.23 : listen_rustls_0_23
        let server = builder.listen_rustls_0_23(listener, tls_cfg)?;
        return Ok(server.run());
    }

    let server = builder.listen(listener)?;
    Ok(server.run())
}
