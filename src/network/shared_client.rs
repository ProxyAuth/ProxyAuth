use crate::config::config::AppConfig;
use ahash::RandomState;
use dashmap::DashMap;
use hyper::body::Bytes;
use hyper_http_proxy::{Intercept, Proxy, ProxyConnector};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use once_cell::sync::Lazy;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use std::convert::Infallible;
use std::{fs::File, io::BufReader, str::FromStr, sync::Arc, time::Duration};

pub type BoxBody = http_body_util::combinators::BoxBody<Bytes, Infallible>;

type AHashDashMap<K, V> = DashMap<K, V, RandomState>;
type HttpsClient = Client<HttpsConnector<HttpConnector>, BoxBody>;
type ProxyClient = Client<ProxyConnector<HttpsConnector<HttpConnector>>, BoxBody>;

static CLIENT_CACHE: Lazy<AHashDashMap<ClientKey, HttpsClient>> =
    Lazy::new(|| DashMap::with_hasher(RandomState::default()));

static CLIENT_CACHE_PROXY: Lazy<AHashDashMap<ClientKey, ProxyClient>> =
    Lazy::new(|| DashMap::with_hasher(RandomState::default()));

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct ClientOptions {
    pub use_proxy: bool,
    pub proxy_addr: Option<String>,
    pub use_cert: bool,
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
}

#[derive(Clone, Hash, Eq, PartialEq, Debug)]
pub struct ClientKey {
    pub use_proxy: bool,
    pub proxy_addr: Option<String>,
    pub use_cert: bool,
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
}

impl ClientKey {
    pub fn from_options(opts: &ClientOptions) -> Self {
        ClientKey {
            use_proxy: opts.use_proxy,
            proxy_addr: opts.proxy_addr.clone(),
            use_cert: opts.use_cert,
            cert_path: opts.cert_path.clone(),
            key_path: opts.key_path.clone(),
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

fn build_https_connector_no_auth(keep: Duration) -> HttpsConnector<HttpConnector> {
    HttpsConnectorBuilder::new()
        .with_native_roots()
        .expect("Failed to load native roots")
        .https_or_http()
        .enable_http1()
        .wrap_connector(build_http_connector(keep))
}

fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>, Box<dyn std::error::Error>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    Ok(CertificateDer::pem_reader_iter(&mut reader)
        .filter_map(|r| r.ok())
        .collect())
}

fn load_keys(path: &str) -> Result<Vec<PrivateKeyDer<'static>>, Box<dyn std::error::Error>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    Ok(PrivateKeyDer::pem_reader_iter(&mut reader)
        .filter_map(|r| r.ok())
        .collect())
}

pub fn get_or_build_client(opts: ClientOptions, state: &Arc<AppConfig>) -> HttpsClient {
    let key = ClientKey::from_options(&opts);

    if let Some(client) = CLIENT_CACHE.get(&key) {
        return client.clone();
    }

    let client = if opts.use_cert {
        build_hyper_client_cert(opts.clone(), state)
    } else {
        build_hyper_client_normal(state)
    };

    CLIENT_CACHE.insert(key, client.clone());
    client
}

pub fn get_or_build_client_proxy(opts: ClientOptions, state: &Arc<AppConfig>) -> ProxyClient {
    let key = ClientKey::from_options(&opts);

    if let Some(client) = CLIENT_CACHE_PROXY.get(&key) {
        return client.clone();
    }

    let client = build_hyper_client_proxy(opts.clone(), state);
    CLIENT_CACHE_PROXY.insert(key, client.clone());
    client
}

// ── Builders ─────────────────────────────────────────────────────────────────

pub fn build_hyper_client_normal(state: &Arc<AppConfig>) -> HttpsClient {
    let keep = Duration::from_millis(state.keep_alive);
    let https = build_https_connector_no_auth(keep);

    Client::builder(TokioExecutor::new())
        .pool_idle_timeout(keep)
        .pool_max_idle_per_host(state.max_idle_per_host.into())
        .build::<_, BoxBody>(https)
}

pub fn build_hyper_client_cert(opts: ClientOptions, state: &Arc<AppConfig>) -> HttpsClient {
    let keep = Duration::from_millis(state.keep_alive);

    let want_cert = opts.use_cert
        && opts
            .cert_path
            .as_ref()
            .map(|s| !s.is_empty())
            .unwrap_or(false)
        && opts
            .key_path
            .as_ref()
            .map(|s| !s.is_empty())
            .unwrap_or(false);

    if !want_cert {
        return build_hyper_client_normal(state);
    }

    let cert_chain = match load_certs(opts.cert_path.as_ref().unwrap()) {
        Ok(c) if !c.is_empty() => c,
        _ => {
            tracing::warn!("TLS: cert chain vide ou invalide, fallback sans client auth");
            return build_hyper_client_normal(state);
        }
    };

    let mut keys = match load_keys(opts.key_path.as_ref().unwrap()) {
        Ok(k) if !k.is_empty() => k,
        _ => {
            tracing::warn!("TLS: clé vide ou invalide, fallback sans client auth");
            return build_hyper_client_normal(state);
        }
    };

    let mut root_store = rustls::RootCertStore::empty();

    if let Ok(native) = rustls_native_certs::load_native_certs() {
        for cert in native {
            let _ = root_store.add(cert);
        }
    }

    for ta in webpki_roots::TLS_SERVER_ROOTS.iter() {
        root_store.roots.push(rustls_pki_types::TrustAnchor {
            subject: rustls_pki_types::Der::from_slice(ta.subject.as_ref()),
            subject_public_key_info: rustls_pki_types::Der::from_slice(
                ta.subject_public_key_info.as_ref(),
            ),
            name_constraints: ta
                .name_constraints
                .as_ref()
                .map(|nc| rustls_pki_types::Der::from_slice(nc.as_ref())),
        });
    }

    let tls_cfg = match rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(cert_chain, keys.remove(0))
    {
        Ok(cfg) => cfg,
        Err(e) => {
            tracing::warn!(
                "TLS: paire cert/key invalide ({}), fallback sans client auth",
                e
            );
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

pub fn build_hyper_client_proxy(opts: ClientOptions, state: &Arc<AppConfig>) -> ProxyClient {
    let keep = Duration::from_millis(state.keep_alive);
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
