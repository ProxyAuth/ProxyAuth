use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use crate::config::config::BackendConfig;
use crate::network::config::{LB_TUNING, LbTuning};
use crate::network::shared_client::BoxBody;
use ahash::{AHashSet, RandomState};
use dashmap::DashMap;
use http_body_util::{BodyExt, Empty, Full, Limited};
use hyper::body::Bytes;
use hyper::{Method, Request, Response, Uri};
use hyper_http_proxy::{Intercept, Proxy, ProxyConnector};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use once_cell::sync::Lazy;
use std::convert::Infallible;
use thiserror::Error;
use tokio::time::timeout;

#[derive(Debug, Error)]
pub enum ForwardError {
    #[error("503 Service Unavailable")]
    AllBackendsFailed,

    // hyper_util::client::legacy::Error au lieu de hyper::Error
    #[error(transparent)]
    Client(#[from] hyper_util::client::legacy::Error),
}

type AHasherDashMap<K, V> = DashMap<K, V, RandomState>;

type ArcClient = Arc<Client<hyper_rustls::HttpsConnector<HttpConnector>, BoxBody>>;
type ClientPool = DashMap<String, ArcClient, RandomState>;
static CLIENT_POOL: Lazy<ClientPool> = Lazy::new(ClientPool::default);

type ProxyArcClient =
    Arc<Client<ProxyConnector<hyper_rustls::HttpsConnector<HttpConnector>>, BoxBody>>;
type ProxyClientPool = DashMap<(String, String), ProxyArcClient, RandomState>;
static PROXY_CLIENT_POOL: Lazy<ProxyClientPool> = Lazy::new(ProxyClientPool::default);

pub static LAST_GOOD_BACKEND: Lazy<AHasherDashMap<String, (String, Instant)>> =
    Lazy::new(Default::default);
pub static BACKEND_COOLDOWN: Lazy<AHasherDashMap<String, CooldownEntry>> =
    Lazy::new(Default::default);
pub static ROUND_ROBIN_COUNTER: Lazy<AtomicUsize> = Lazy::new(|| AtomicUsize::new(0));

pub struct CooldownEntry {
    pub last_failed: Instant,
    pub failures: u32,
}

pub fn lb() -> &'static LbTuning {
    LB_TUNING.get().unwrap_or(&LbTuning {
        request_timeout_ms: 2000,
        pool_max_idle_per_host: 1000,
        keep_alive_secs: 30,
        backend_valid_duration_secs: 2,
        cooldown_base_secs: 2,
        cooldown_max_secs: 5,
        backend_reset_threshold_secs: 10,
        // Same 10 MB default as `config::config::default_max_body_size`
        // — this fallback only applies before `init_loadbalancer` has
        // run (or if it's never called at all), so it can't actually
        // read the configured value; matching the same default keeps
        // this consistent with what a freshly-started instance would
        // otherwise use anyway.
        max_response_body_bytes: 10 * 1024 * 1024,
    })
}

fn backend_valid_duration() -> Duration {
    Duration::from_secs(lb().backend_valid_duration_secs)
}
pub fn cooldown_base() -> Duration {
    Duration::from_secs(lb().cooldown_base_secs)
}
fn cooldown_max() -> Duration {
    Duration::from_secs(lb().cooldown_max_secs)
}
fn backend_reset_threshold() -> Duration {
    Duration::from_secs(lb().backend_reset_threshold_secs)
}

pub fn is_in_cooldown(url: &str) -> bool {
    if let Some(entry) = BACKEND_COOLDOWN.get(url) {
        let mut delay = cooldown_base() * entry.failures.min(10);
        if delay > cooldown_max() {
            delay = cooldown_max();
        }
        return entry.last_failed.elapsed() < delay;
    }
    false
}

#[derive(Clone, Copy, Debug)]
pub struct SwrrState {
    effective: i32,
    current: i32,
}

/// Cache key for the sticky "last good backend" shortcut.
///
/// SECURITY/CORRECTNESS FIX: this used to be `format!("{}|{}", method,
/// host)` — scoped only by HTTP method and the request's own Host
/// header, never by which *route* (or which route's own `backends:`
/// pool) actually matched. Two different routes on the same vhost using
/// the same HTTP method collided on the exact same cache key, meaning
/// one route's "last good backend" could get reused for a completely
/// different route — including sending that route's traffic to a
/// backend that was never even part of *its own* configured pool.
/// `route_key` (built by the caller from the matched route's
/// `vhost`+`prefix`, which together uniquely identify a route) closes
/// that: two different routes now always get different cache entries,
/// even if they share a vhost and method.
fn cache_key(route_key: &str, method: &Method, uri: &Uri, _headers: &hyper::HeaderMap) -> String {
    let host = uri.authority().map(|a| a.as_str()).unwrap_or("default");
    format!("{}|{}|{}", route_key, method, host)
}

pub static SWRR_STATE: Lazy<DashMap<String, SwrrState, RandomState>> = Lazy::new(Default::default);

pub fn build_swrr_order<'a>(cands: &[&'a BackendConfig]) -> Vec<&'a BackendConfig> {
    if cands.is_empty() {
        return Vec::new();
    }

    let mut unique = AHashSet::default();
    let mut total_weight: i32 = 0;
    for b in cands {
        let w = b.weight.max(1) as i32;
        total_weight += w;
        unique.insert(b.url.clone());
        SWRR_STATE
            .entry(b.url.clone())
            .and_modify(|st| st.effective = w)
            .or_insert(SwrrState {
                effective: w,
                current: 0,
            });
    }

    let mut order = Vec::with_capacity(unique.len());
    let mut picked = AHashSet::default();

    for _ in 0..unique.len() {
        let mut best_idx: Option<usize> = None;
        let mut best_val: i32 = i32::MIN;

        for (i, b) in cands.iter().enumerate() {
            if picked.contains(&b.url) {
                continue;
            }
            if let Some(mut st) = SWRR_STATE.get_mut(&b.url) {
                st.current += st.effective;
                if st.current > best_val {
                    best_val = st.current;
                    best_idx = Some(i);
                }
            }
        }

        if let Some(i) = best_idx {
            let chosen = cands[i];
            if let Some(mut st) = SWRR_STATE.get_mut(&chosen.url) {
                st.current -= total_weight;
            }
            picked.insert(chosen.url.clone());
            order.push(chosen);
        } else {
            break;
        }
    }

    let len = order.len();
    if len > 0 {
        let shift = ROUND_ROBIN_COUNTER.fetch_add(1, Ordering::Relaxed) % len;
        if shift != 0 {
            order.rotate_left(shift);
        }
    }

    order
}

pub async fn get_or_build_client(backend: &str) -> ArcClient {
    let key = backend.trim().to_lowercase();
    if let Some(client) = CLIENT_POOL.get(&key) {
        return Arc::clone(&client);
    }

    let mut connector = HttpConnector::new();
    connector.set_nodelay(true);
    connector.set_reuse_address(true);
    connector.set_keepalive(Some(Duration::from_secs(lb().keep_alive_secs)));

    // hyper-rustls 0.27 : with_native_roots() retourne Result → .expect()
    let https = HttpsConnectorBuilder::new()
        .with_native_roots()
        .expect("Failed to load native roots")
        .https_or_http()
        .enable_http1()
        .wrap_connector(connector);

    let client = Client::builder(TokioExecutor::new())
        .pool_max_idle_per_host(lb().pool_max_idle_per_host)
        .build::<_, BoxBody>(https);

    let arc_client = Arc::new(client);
    CLIENT_POOL.insert(key, Arc::clone(&arc_client));
    arc_client
}

pub async fn get_or_build_client_with_proxy(proxy_addr: &str, backend: &str) -> ProxyArcClient {
    let key = (proxy_addr.to_string(), backend.to_string());
    if let Some(client) = PROXY_CLIENT_POOL.get(&key) {
        return Arc::clone(&client);
    }

    let proxy_uri: Uri = proxy_addr.parse().expect("Invalid proxy URI");
    let proxy = Proxy::new(Intercept::All, proxy_uri);

    let mut connector = HttpConnector::new();
    connector.set_nodelay(true);
    connector.set_reuse_address(true);
    connector.set_keepalive(Some(Duration::from_secs(lb().keep_alive_secs)));

    // hyper-rustls 0.27 : with_native_roots() retourne Result → .expect()
    let https = HttpsConnectorBuilder::new()
        .with_native_roots()
        .expect("Failed to load native roots")
        .https_or_http()
        .enable_http1()
        .wrap_connector(connector);

    let proxy_connector =
        ProxyConnector::from_proxy(https, proxy).expect("Failed to create proxy connector");

    let client = Client::builder(TokioExecutor::new())
        .pool_max_idle_per_host(lb().pool_max_idle_per_host)
        .build(proxy_connector);

    let arc_client = Arc::new(client);
    PROXY_CLIENT_POOL.insert(key, Arc::clone(&arc_client));
    arc_client
}

/// `is_idempotent_method` — GET/HEAD/PUT/DELETE/OPTIONS are safe to
/// silently retry against a different backend on failure (repeating
/// them has the same effect as doing it once). POST and PATCH are not:
/// a POST that reached a backend, was fully processed, and only *then*
/// produced a 5xx (e.g. a downstream dependency failing after the
/// write already committed) would otherwise get retried against a
/// second backend with the exact same body, risking a genuine
/// duplicate write. See `forward_failover`'s own doc comment.
fn is_idempotent_method(method: &Method) -> bool {
    matches!(
        *method,
        Method::GET | Method::HEAD | Method::PUT | Method::DELETE | Method::OPTIONS
    )
}

/// Forwards a request to one of `backends`, with sticky-backend caching
/// and automatic failover to the next backend on failure.
///
/// `route_key` must uniquely identify the *route* this call is being
/// made on behalf of (the caller passes something derived from the
/// matched route's `vhost`+`prefix`) — see `cache_key`'s doc comment
/// for why this matters: without it, the sticky-backend cache and the
/// backend pool it's scoped to can silently diverge across routes.
///
/// SECURITY/CORRECTNESS FIX: for a non-idempotent method (POST/PATCH),
/// failover is now skipped entirely — a single failed attempt returns
/// an error rather than retrying the same write against a second
/// backend. Retrying was previously unconditional for every method,
/// including on a 5xx a backend returned after fully processing the
/// request.
pub async fn forward_failover(
    req: Request<BoxBody>,
    backends: &[BackendConfig],
    proxy_addr: Option<&str>,
    route_key: &str,
) -> Result<Response<BoxBody>, ForwardError> {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();

    let body_bytes = req
        .into_body()
        .collect()
        .await
        .map_err(|_| ForwardError::AllBackendsFailed)?
        .to_bytes();

    let now = Instant::now();
    BACKEND_COOLDOWN
        .retain(|_, entry| now.duration_since(entry.last_failed) < backend_reset_threshold());

    let ctx_key = cache_key(route_key, &method, &uri, &headers);
    let retry_on_failure = is_idempotent_method(&method);

    if let Some((cached_url, when)) = LAST_GOOD_BACKEND.get(&ctx_key).map(|e| e.clone()) {
        // SECURITY/CORRECTNESS FIX: previously used `cached_url`
        // unconditionally, without checking it's actually a member of
        // *this* route's own `backends` pool. Even with `route_key`
        // now scoping the cache correctly, a stale entry from a route
        // whose backend list changed (a config reload) could otherwise
        // still point somewhere no longer valid for this route — this
        // check makes that structurally impossible rather than merely
        // unlikely.
        let cached_is_valid_for_route = backends.iter().any(|b| b.url == cached_url);
        if cached_is_valid_for_route
            && when.elapsed() <= backend_valid_duration()
            && !is_in_cooldown(&cached_url)
        {
            match try_forward_to_backend(
                &cached_url,
                proxy_addr,
                &body_bytes,
                &method,
                &uri,
                &headers,
            )
            .await
            {
                Ok(resp) => return Ok(resp),
                Err(_) => {
                    BACKEND_COOLDOWN
                        .entry(cached_url.clone())
                        .and_modify(|e| {
                            e.failures += 1;
                            e.last_failed = Instant::now();
                        })
                        .or_insert(CooldownEntry {
                            failures: 1,
                            last_failed: Instant::now(),
                        });
                    if !retry_on_failure {
                        return Err(ForwardError::AllBackendsFailed);
                    }
                }
            }
        }
    }

    if !retry_on_failure {
        // Non-idempotent method and the sticky-backend shortcut above
        // either wasn't applicable or already failed once — a single
        // attempt against the first candidate backend, no failover.
        let active: Vec<&BackendConfig> = backends.iter().filter(|b| b.weight != -1).collect();
        let order_active = build_swrr_order(&active);
        if let Some(backend) = order_active.first() {
            return try_forward_to_backend(
                &backend.url,
                proxy_addr,
                &body_bytes,
                &method,
                &uri,
                &headers,
            )
            .await
            .inspect(|_| {
                LAST_GOOD_BACKEND.insert(ctx_key.clone(), (backend.url.clone(), Instant::now()));
                BACKEND_COOLDOWN.remove(&backend.url);
            });
        }
        return Err(ForwardError::AllBackendsFailed);
    }

    let active: Vec<&BackendConfig> = backends.iter().filter(|b| b.weight != -1).collect();
    let disabled: Vec<&BackendConfig> = backends.iter().filter(|b| b.weight == -1).collect();
    let order_active = build_swrr_order(&active);
    let mut already_checked = AHashSet::default();

    if let Some(resp) = try_backends(
        route_key,
        &order_active,
        &mut already_checked,
        &body_bytes,
        &method,
        &uri,
        &headers,
        proxy_addr,
    )
    .await
    {
        return Ok(resp);
    }
    if let Some(resp) = try_backends(
        route_key,
        &disabled,
        &mut already_checked,
        &body_bytes,
        &method,
        &uri,
        &headers,
        proxy_addr,
    )
    .await
    {
        return Ok(resp);
    }

    Err(ForwardError::AllBackendsFailed)
}

async fn try_backends(
    route_key: &str,
    backends: &[&BackendConfig],
    already_checked: &mut AHashSet<String>,
    body_bytes: &Bytes,
    method: &Method,
    uri: &Uri,
    headers: &hyper::HeaderMap,
    proxy_addr: Option<&str>,
) -> Option<Response<BoxBody>> {
    for backend in backends {
        let url = &backend.url;

        if !already_checked.insert(url.clone()) {
            continue;
        }

        if is_in_cooldown(url) {
            tracing::warn!("Skipping backend {} (cooldown active)", url);
            continue;
        }

        match try_forward_to_backend(url, proxy_addr, body_bytes, method, uri, headers).await {
            Ok(resp) => {
                LAST_GOOD_BACKEND.insert(
                    cache_key(route_key, method, uri, headers),
                    (url.clone(), Instant::now()),
                );
                BACKEND_COOLDOWN.remove(url);
                return Some(resp);
            }
            Err(_) => {
                BACKEND_COOLDOWN
                    .entry(url.clone())
                    .and_modify(|e| {
                        e.failures += 1;
                        e.last_failed = Instant::now();
                    })
                    .or_insert(CooldownEntry {
                        failures: 1,
                        last_failed: Instant::now(),
                    });
            }
        }
    }
    None
}

async fn try_forward_to_backend(
    backend: &str,
    proxy_addr: Option<&str>,
    body_bytes: &Bytes,
    method: &Method,
    uri: &Uri,
    headers: &hyper::HeaderMap,
) -> Result<Response<BoxBody>, ForwardError> {
    let uri_backend: Uri = backend
        .parse()
        .map_err(|_| ForwardError::AllBackendsFailed)?;

    let mut parts = uri.clone().into_parts();
    parts.scheme = uri_backend.scheme().cloned();
    parts.authority = uri_backend.authority().cloned();
    parts.path_and_query = uri.path_and_query().cloned();

    let full_uri = Uri::from_parts(parts).map_err(|_| ForwardError::AllBackendsFailed)?;
    let mut builder = Request::builder().method(method.clone()).uri(full_uri);

    // SECURITY/CORRECTNESS FIX: previously only excluded "Host" here —
    // every other header, including hop-by-hop ones (Connection,
    // Transfer-Encoding, TE, Trailer, Upgrade, Keep-Alive, Proxy-*),
    // was relayed verbatim to the failover backend. `is_hop_by_hop_header`
    // is the exact same check the main proxied-request path already
    // uses (`network/proxy.rs`) — reused here rather than duplicated,
    // so the two paths can't drift out of sync on what counts as
    // hop-by-hop.
    for (key, value) in headers.iter() {
        let key_str = key.as_str();
        if key_str.to_ascii_lowercase() != "host"
            && !crate::network::proxy::is_hop_by_hop_header(key_str)
        {
            builder = builder.header(key, value);
        }
    }

    builder = builder.header(
        "Host",
        uri_backend
            .authority()
            .map(|a| a.as_str())
            .unwrap_or("127.0.0.1"),
    );

    let new_req = if *method == Method::GET || *method == Method::HEAD {
        builder
            .body(Empty::<Bytes>::new().boxed())
            .expect("Failed to build GET/HEAD request")
    } else {
        builder
            .body(Full::new(body_bytes.clone()).boxed())
            .expect("Failed to build request with body")
    };

    let response_result = match proxy_addr {
        Some(proxy) => {
            let client = get_or_build_client_with_proxy(proxy, backend).await;
            timeout(
                Duration::from_millis(lb().request_timeout_ms),
                client.request(new_req),
            )
            .await
        }
        None => {
            let client = get_or_build_client(backend).await;
            timeout(
                Duration::from_millis(lb().request_timeout_ms),
                client.request(new_req),
            )
            .await
        }
    };

    match response_result {
        Ok(Ok(resp)) => {
            let status = resp.status();
            if status.is_server_error() {
                tracing::warn!(
                    "Failover: backend {} returned server error {}",
                    backend,
                    status
                );
                Err(ForwardError::AllBackendsFailed)
            } else {
                let (parts, body) = resp.into_parts();
                // SECURITY FIX: previously an unconditional
                // `body.collect()` — a single backend returning an
                // unbounded response body could grow ProxyAuth's own
                // memory usage without limit, since the whole point of
                // this failover path (deciding whether to retry a
                // different backend) requires the full body before a
                // decision can be made either way. `Limited` enforces
                // `lb().max_response_body_bytes` (reusing the same
                // budget already applied to request bodies) and fails
                // cleanly, the same as any other backend failure —
                // triggering the normal cooldown/retry path — instead
                // of buffering without bound.
                let bytes = Limited::new(body, lb().max_response_body_bytes)
                    .collect()
                    .await
                    .map_err(|e| {
                        tracing::warn!(
                            "Failover: backend {} response body rejected: {}",
                            backend,
                            e
                        );
                        ForwardError::AllBackendsFailed
                    })?
                    .to_bytes();
                let boxed: BoxBody = Full::new(bytes).map_err(|e: Infallible| e).boxed();
                Ok(Response::from_parts(parts, boxed))
            }
        }
        Ok(Err(e)) => {
            tracing::warn!("Failover: backend {} failed: {}", backend, e);
            // e est hyper_util::client::legacy::Error — converti via #[from]
            Err(ForwardError::Client(e))
        }
        Err(_) => {
            tracing::warn!("Failover: backend {} timed out", backend);
            Err(ForwardError::AllBackendsFailed)
        }
    }
}
