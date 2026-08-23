use crate::AppConfig;
use crate::config::config::RouteRule;
use actix_web::body::BoxBody;
use actix_web::dev::{ServiceFactory, ServiceRequest, ServiceResponse};
use actix_web::{App, Error, HttpServer};
use arc_swap::ArcSwap;
use notify::{Config as NotifyConfig, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use once_cell::sync::Lazy;
use rustls::{
    ServerConfig,
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use std::{
    collections::HashMap,
    fs::File,
    io::BufReader,
    net::TcpListener,
    path::{Path, PathBuf},
    sync::Arc,
    sync::Mutex,
    time::Duration,
    time::Instant,
};
use tokio::{sync::mpsc, task, time::sleep};
use tracing::{info, warn};

static LAST_LOGS: Lazy<Mutex<HashMap<String, Instant>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// `tag` identifies *which* watcher is logging (e.g. the cert file
/// path, or "default"), not just which kind of event — otherwise the
/// default certificate's watcher and every vhost certificate's
/// watcher would share the same rate-limit slot and silently mask
/// each other's "watching ..."/"reloaded" messages.
fn rate_limited_log(tag: &str, period: Duration, msg: String) {
    let mut logs = LAST_LOGS.lock().unwrap();
    let now = Instant::now();
    let do_log = match logs.get(tag) {
        Some(&last) => now.duration_since(last) > period,
        None => true,
    };
    if do_log {
        logs.insert(tag.to_string(), now);
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

    anyhow::ensure!(
        !certs.is_empty(),
        "no certificates found in {}",
        path.display()
    );
    Ok(certs)
}

fn load_private_key(path: &Path) -> anyhow::Result<PrivateKeyDer<'static>> {
    let f = File::open(path)?;
    let mut reader = BufReader::new(f);

    // rustls 0.23 : PrivateKeyDer<'static> au lieu de PrivateKey(der)
    let keys = PrivateKeyDer::pem_reader_iter(&mut reader)
        .filter_map(|r| r.ok())
        .collect::<Vec<PrivateKeyDer<'static>>>();

    anyhow::ensure!(
        !keys.is_empty(),
        "no private key found in {}",
        path.display()
    );
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
        Self {
            current: ArcSwap::new(initial.into()),
        }
    }
    fn swap(&self, ck: Arc<CertifiedKey>) {
        self.current.store(ck.into());
    }
    fn get(&self) -> Arc<CertifiedKey> {
        self.current.load().as_ref().clone()
    }
}

impl ResolvesServerCert for HotResolver {
    fn resolve(&self, _hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        Some(self.get())
    }
}

/// SNI-aware resolver sitting in front of the per-vhost certificates:
/// if the ClientHello's SNI hostname matches one of the vhosts a route
/// configured a `vhost_cert` for, that certificate is served; for
/// every other hostname (including plain IP connections with no SNI
/// at all, and any vhost that didn't set its own certificate) the
/// server's single global certificate is served instead, exactly like
/// before per-vhost certificates existed.
#[derive(Debug)]
struct MultiHotResolver {
    default: Arc<HotResolver>,
    by_host: HashMap<String, Arc<HotResolver>>,
}

impl ResolvesServerCert for MultiHotResolver {
    fn resolve(&self, hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        if let Some(sni) = hello.server_name() {
            if let Some(r) = self.by_host.get(&sni.to_ascii_lowercase()) {
                return Some(r.get());
            }
        }
        Some(self.default.get())
    }
}

fn build_rustls_config_with_resolver(resolver: Arc<dyn ResolvesServerCert>) -> ServerConfig {
    // rustls 0.23 : with_safe_defaults() supprimé — builder() configure automatiquement
    let mut cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    cfg
}

/// Loads every distinct `vhost_cert` (cert, key) pair referenced by
/// `routes`, one `HotResolver` per distinct pair (so vhosts sharing a
/// single wildcard/SAN certificate share one loaded copy and one
/// file-watcher instead of duplicating both), and returns a lowercase
/// hostname → resolver map ready to hand to `MultiHotResolver`.
///
/// A route with a `vhost` but no (or an incomplete/unreadable)
/// `vhost_cert` is simply left out of the map — those hostnames fall
/// back to the server's default certificate, and a warning is logged
/// so a typo'd path doesn't fail silently.
fn load_vhost_resolvers(routes: &[RouteRule]) -> HashMap<String, Arc<HotResolver>> {
    let mut resolver_by_files: HashMap<(PathBuf, PathBuf), Arc<HotResolver>> = HashMap::new();
    let mut by_host: HashMap<String, Arc<HotResolver>> = HashMap::new();

    for rule in routes {
        if rule.vhost.is_empty() {
            continue;
        }
        let (Some(cert), Some(key)) = (rule.vhost_cert.get("cert"), rule.vhost_cert.get("key"))
        else {
            continue;
        };

        let cert_path = PathBuf::from(cert);
        let key_path = PathBuf::from(key);
        let file_pair = (cert_path.clone(), key_path.clone());

        let resolver = if let Some(existing) = resolver_by_files.get(&file_pair) {
            existing.clone()
        } else {
            match load_certified_key(&cert_path, &key_path) {
                Ok(ck) => {
                    let resolver = Arc::new(HotResolver::new(ck));
                    resolver_by_files.insert(file_pair, resolver.clone());

                    let watch_resolver = resolver.clone();
                    let watch_cert = cert_path.clone();
                    let watch_key = key_path.clone();
                    let label = format!("vhost cert {}", cert_path.display());
                    tokio::spawn(async move {
                        if let Err(e) =
                            watch_cert_key(watch_resolver, watch_cert, watch_key, label).await
                        {
                            warn!("Watch TLS (vhost) stopped: {e:?}");
                        }
                    });

                    resolver
                }
                Err(e) => {
                    warn!(
                        "vhost_cert for {:?} ({} / {}): failed to load: {e:?} — falling back to the default certificate",
                        rule.vhost, cert, key
                    );
                    continue;
                }
            }
        };

        for host in &rule.vhost {
            by_host.insert(host.to_ascii_lowercase(), resolver.clone());
        }
    }

    by_host
}

async fn watch_cert_key(
    resolver: Arc<HotResolver>,
    cert: PathBuf,
    key: PathBuf,
    label: String,
) -> notify::Result<()> {
    let (tx, mut rx) = mpsc::unbounded_channel();
    let mut watcher: RecommendedWatcher = Watcher::new(
        move |e| {
            let _ = tx.send(e);
        },
        NotifyConfig::default(),
    )?;
    watcher.watch(&cert, RecursiveMode::NonRecursive)?;
    watcher.watch(&key, RecursiveMode::NonRecursive)?;

    rate_limited_log(
        &format!("watch:{label}"),
        Duration::from_secs(60),
        format!(
            "TLS hot-reload watching {} and {} ({label})",
            cert.display(),
            key.display()
        ),
    );

    while let Some(ev) = rx.recv().await {
        match ev {
            Ok(event) => match event.kind {
                EventKind::Modify(_)
                | EventKind::Create(_)
                | EventKind::Remove(_)
                | EventKind::Any => {
                    let resolver = resolver.clone();
                    let cert = cert.clone();
                    let key = key.clone();
                    let label = label.clone();
                    task::spawn(async move {
                        sleep(Duration::from_millis(400)).await;
                        match load_certified_key(&cert, &key) {
                            Ok(ck) => {
                                resolver.swap(ck);
                                rate_limited_log(
                                    &format!("reload_ok:{label}"),
                                    Duration::from_secs(60),
                                    format!("Certificat TLS reloaded successfully ({label})."),
                                );
                            }
                            Err(e) => {
                                rate_limited_log(
                                    &format!("reload_err:{label}"),
                                    Duration::from_secs(60),
                                    format!("Error reload certificat ({label}): {e:?}"),
                                );
                            }
                        }
                    });
                }
                _ => {}
            },
            Err(e) => warn!("Watch TLS ({label}): {e:?}"),
        }
    }
    Ok(())
}

#[allow(dead_code)]
pub fn check_port(addr: &str) -> bool {
    TcpListener::bind(addr).is_ok()
}

pub fn bind_server<T, F>(
    app_factory: F,
    listener: TcpListener,
    config: &AppConfig,
    routes: &[RouteRule],
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
        let key_path = PathBuf::from("/etc/proxyauth/certs/key.pem");

        let initial =
            load_certified_key(&cert_path, &key_path).expect("TLS: error initialization cert/key");

        let default_resolver = Arc::new(HotResolver::new(initial));

        let r2 = default_resolver.clone();
        let default_cert_path = cert_path.clone();
        let default_key_path = key_path.clone();
        tokio::spawn(async move {
            if let Err(e) = watch_cert_key(
                r2,
                default_cert_path,
                default_key_path,
                "default".to_string(),
            )
            .await
            {
                warn!("Watch TLS stopped: {e:?}");
            }
        });

        // One certificate per vhost that declared its own `vhost_cert`
        // in routes.yml, selected via SNI at handshake time; every
        // other hostname (and any connection with no SNI) keeps using
        // the default certificate above, unchanged from before vhosts
        // existed.
        let by_host = load_vhost_resolvers(routes);
        if !by_host.is_empty() {
            info!(
                "TLS: {} vhost certificate(s) loaded ({})",
                by_host.len(),
                by_host.keys().cloned().collect::<Vec<_>>().join(", ")
            );
        }

        let resolver: Arc<dyn ResolvesServerCert> = Arc::new(MultiHotResolver {
            default: default_resolver,
            by_host,
        });
        let tls_cfg = build_rustls_config_with_resolver(resolver);

        // actix-web 4 avec rustls 0.23 : listen_rustls_0_23
        let server = builder.listen_rustls_0_23(listener, tls_cfg)?;
        return Ok(server.run());
    }

    let server = builder.listen(listener)?;
    Ok(server.run())
}
