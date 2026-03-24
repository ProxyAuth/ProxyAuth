use crate::config::config::AppConfig;
use ahash::{AHashMap, RandomState};
use dashmap::DashMap;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use hyper_http_proxy::{Intercept, Proxy, ProxyConnector};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use once_cell::sync::Lazy;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use std::{cell::RefCell, fs::File, io::BufReader, str::FromStr, sync::Arc, time::Duration};
use hyper::body::Bytes;
use std::convert::Infallible;

pub type BoxBody = http_body_util::combinators::BoxBody<Bytes, Infallible>;

type AHashDashMap<K, V> = DashMap<K, V, RandomState>;
type HttpsClient = Client<HttpsConnector<HttpConnector>, BoxBody>;
type ThreadCache = AHashMap<ClientKey, HttpsClient>;

thread_local! {
    static THREAD_CLIENT_CACHE: RefCell<ThreadCache> = RefCell::new(AHashMap::with_capacity(8));
}

#[allow(dead_code)]
static CLIENT_CACHE: Lazy<AHashDashMap<ClientKey, Client<HttpsConnector<HttpConnector>, BoxBody>>> =
Lazy::new(AHashDashMap::default);
static CLIENT_CACHE_PROXY: Lazy<AHashDashMap<ClientKey, Client<ProxyConnector<HttpsConnector<HttpConnector>>, BoxBody>>> =
Lazy::new(AHashDashMap::default);

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct ClientOptions {
    pub use_proxy:  bool,
    pub proxy_addr: Option<String>,
    pub use_cert:   bool,
    pub cert_path:  Option<String>,
    pub key_path:   Option<String>,
}

#[derive(Clone, Hash, Eq, PartialEq, Debug)]
pub struct ClientKey {
    pub use_proxy:  bool,
    pub proxy_addr: Option<String>,
    pub use_cert:   bool,
    pub cert_path:  Option<String>,
    pub key_path:   Option<String>,
}

impl ClientKey {
    pub fn from_options(opts: &ClientOptions) -> Self {
        ClientKey {
            use_proxy:  opts.use_proxy,
            proxy_addr: opts.proxy_addr.clone(),
            use_cert:   opts.use_cert,
            cert_path:  opts.cert_path.clone(),
            key_path:   opts.key_path.clone(),
        }
    }
}

fn build_http_connector(keep: Duration) -> HttpConnector {
    let mut http = HttpConnector::new();
    http.set_connect_timeout(Some(Duration::from_secs(1)));
    http.enforce_http(false);
    http.set_nodelay(true);
    http.set_keepalive(Some(keep));
    http
}

// Construit un connecteur HTTPS sans cert client, en utilisant les racines natives
// On évite rustls::ClientConfig directement pour ne pas créer de conflit de versions
fn build_https_connector_no_auth(keep: Duration) -> HttpsConnector<HttpConnector> {
    HttpsConnectorBuilder::new()
    .with_native_roots()
    .expect("Failed to load native roots")
    .https_or_http()
    .enable_http1()
    .wrap_connector(build_http_connector(keep))
}

pub fn get_or_build_thread_client(opts: &ClientOptions, state: &Arc<AppConfig>) -> HttpsClient {
    let key = ClientKey::from_options(opts);

    THREAD_CLIENT_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        if let Some(client) = cache.get(&key) {
            return client.clone();
        }

        let client = if opts.use_cert {
            build_hyper_client_cert(opts.clone(), state)
        } else {
            build_hyper_client_normal(state)
        };

        cache.insert(key, client.clone());
        client
    })
}

#[allow(dead_code)]
pub fn get_or_build_client(
    opts: ClientOptions,
    state: Arc<AppConfig>,
) -> Client<HttpsConnector<HttpConnector>, BoxBody> {
    let key = ClientKey::from_options(&opts);

    if let Some(client) = CLIENT_CACHE.get(&key) {
        return client.clone();
    }

    let client = if opts.use_cert {
        build_hyper_client_cert(opts.clone(), &state)
    } else {
        build_hyper_client_normal(&state)
    };

    CLIENT_CACHE.insert(key, client.clone());
    client
}

pub fn get_or_build_client_proxy(
    opts: ClientOptions,
    state: Arc<AppConfig>,
) -> Client<ProxyConnector<HttpsConnector<HttpConnector>>, BoxBody> {
    let key = ClientKey::from_options(&opts);

    if let Some(client) = CLIENT_CACHE_PROXY.get(&key) {
        return client.clone();
    }

    let client = build_hyper_client_proxy(opts.clone(), &state);
    CLIENT_CACHE_PROXY.insert(key, client.clone());
    client
}

fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>, Box<dyn std::error::Error>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let certs = CertificateDer::pem_reader_iter(&mut reader)
    .filter_map(|r| r.ok())
    .collect::<Vec<_>>();
    Ok(certs)
}

fn load_keys(path: &str) -> Result<Vec<PrivateKeyDer<'static>>, Box<dyn std::error::Error>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let keys = PrivateKeyDer::pem_reader_iter(&mut reader)
    .filter_map(|r| r.ok())
    .collect::<Vec<_>>();
    Ok(keys)
}

pub fn build_hyper_client_cert(
    opts: ClientOptions,
    state: &Arc<AppConfig>,
) -> Client<HttpsConnector<HttpConnector>, BoxBody> {
    let keep = Duration::from_secs(state.keep_alive);

    let want_cert = opts.use_cert
    && opts.cert_path.as_ref().map(|s| !s.is_empty()).unwrap_or(false)
    && opts.key_path.as_ref().map(|s| !s.is_empty()).unwrap_or(false);

    if !want_cert {
        return build_hyper_client_normal(state);
    }

    let cert_chain = match load_certs(opts.cert_path.as_ref().unwrap()) {
        Ok(c) if !c.is_empty() => c,
        _ => {
            tracing::warn!("TLS: cert chain empty or invalid, fallback to no_client_auth");
            return build_hyper_client_normal(state);
        }
    };

    let mut keys = match load_keys(opts.key_path.as_ref().unwrap()) {
        Ok(k) if !k.is_empty() => k,
        _ => {
            tracing::warn!("TLS: keys empty or invalid, fallback to no_client_auth");
            return build_hyper_client_normal(state);
        }
    };

    // Utiliser rustls 0.23 explicitement via son chemin complet
    // pour éviter le conflit avec rustls 0.21 tiré par d'autres dépendances
    let tls_cfg = match rustls::ClientConfig::builder()
    .with_root_certificates({
        let mut store = rustls::RootCertStore::empty();
        // Charger les racines natives via rustls-native-certs
        if let Ok(native) = rustls_native_certs::load_native_certs() {
            for cert in native {
                let _ = store.add(cert);  // rustls_native_certs 0.7 retourne CertificateDer directement
            }
        }
        // Ajouter les racines WebPKI
        // rustls 0.23 + webpki_roots 0.26 : TrustAnchor implémente Into<TrustAnchor>
        for ta in webpki_roots::TLS_SERVER_ROOTS.iter() {
            store.roots.push(rustls_pki_types::TrustAnchor {
                subject: rustls_pki_types::Der::from_slice(ta.subject.as_ref()),
                             subject_public_key_info: rustls_pki_types::Der::from_slice(ta.subject_public_key_info.as_ref()),
                             name_constraints: ta.name_constraints.as_ref().map(|nc| rustls_pki_types::Der::from_slice(nc.as_ref())),
            });
        }
        store
    })
    .with_client_auth_cert(cert_chain, keys.remove(0))
    {
        Ok(cfg) => cfg,
        Err(e) => {
            tracing::warn!("TLS: invalid cert/key pair ({}), fallback to no_client_auth", e);
            return build_hyper_client_normal(state);
        }
    };

    let https = HttpsConnectorBuilder::new()
    .with_tls_config(tls_cfg)
    .https_or_http()
    .enable_http1()
    .wrap_connector(build_http_connector(keep));

    Client::builder(TokioExecutor::new())
    .pool_idle_timeout(keep)
    .pool_max_idle_per_host(state.max_idle_per_host.into())
    .build::<_, BoxBody>(https)
}

pub fn build_hyper_client_proxy(
    opts: ClientOptions,
    state: &Arc<AppConfig>,
) -> Client<ProxyConnector<HttpsConnector<HttpConnector>>, BoxBody> {
    let keep = Duration::from_secs(state.keep_alive);

    // Utiliser with_native_roots() directement — pas de rustls::ClientConfig manuel
    let https = build_https_connector_no_auth(keep);

    let proxy_addr = opts
    .proxy_addr
    .clone()
    .unwrap_or_else(|| "http://127.0.0.1:8888".to_string());
    let proxy_uri = hyper::Uri::from_str(&proxy_addr).expect("Invalid proxy address");

    let proxy = ProxyConnector::from_proxy(https, Proxy::new(Intercept::All, proxy_uri))
    .expect("Failed to create proxy connector");

    Client::builder(TokioExecutor::new())
    .pool_idle_timeout(keep)
    .pool_max_idle_per_host(state.max_idle_per_host.into())
    .build::<_, BoxBody>(proxy)
}

pub fn build_hyper_client_normal(state: &Arc<AppConfig>) -> Client<HttpsConnector<HttpConnector>, BoxBody> {
    let keep = Duration::from_secs(state.keep_alive);

    // with_native_roots() — hyper-rustls 0.27 gère rustls 0.23 en interne
    let https = build_https_connector_no_auth(keep);

    Client::builder(TokioExecutor::new())
    .pool_idle_timeout(keep)
    .pool_max_idle_per_host(state.max_idle_per_host.into())
    .build::<_, BoxBody>(https)
}
