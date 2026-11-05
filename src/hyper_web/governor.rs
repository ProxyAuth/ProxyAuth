//! Limiteur de débit par clé — remplace `actix-governor` avec la même
//! API (`GovernorConfigBuilder`, `Governor::new`, `KeyExtractor`) et les
//! mêmes réponses, posé directement sur le crate `governor`.

pub use ::governor;

use super::app::{Middleware, Next, ServiceFuture, ServiceRequest};
use super::error::ResponseError;
use super::http::StatusCode;
use super::response::{ContentType, HttpResponse, HttpResponseBuilder};
use governor::clock::{Clock, DefaultClock, QuantaInstant};
use governor::middleware::StateInformationMiddleware;
use governor::state::keyed::DefaultKeyedStateStore;
use governor::{NotUntil, Quota, RateLimiter};
use std::fmt;
use std::hash::Hash;
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

type Limiter<K> = RateLimiter<K, DefaultKeyedStateStore<K>, DefaultClock, StateInformationMiddleware>;

// ─── Extraction de clé ───────────────────────────────────────────────

pub trait KeyExtractor: Clone + 'static {
    type Key: Clone + Hash + Eq + Send + Sync + 'static;
    type KeyExtractionError: ResponseError + 'static;

    fn extract(&self, req: &ServiceRequest) -> Result<Self::Key, Self::KeyExtractionError>;

    fn exceed_rate_limit_response(
        &self,
        negative: &NotUntil<QuantaInstant>,
        mut response: HttpResponseBuilder,
    ) -> HttpResponse {
        let wait_time = negative
            .wait_time_from(DefaultClock::default().now())
            .as_secs();
        response
            .content_type(ContentType::plaintext())
            .body(format!("Too many requests, retry in {wait_time}s"))
    }

    fn whitelisted_keys(&self) -> Vec<Self::Key> {
        Vec::new()
    }
}

/// Clé = IP du pair TCP (défaut d'actix-governor).
#[derive(Clone, Copy, Debug, Default)]
pub struct PeerIpKeyExtractor;

impl KeyExtractor for PeerIpKeyExtractor {
    type Key = IpAddr;
    type KeyExtractionError = SimpleKeyExtractionError<&'static str>;

    fn extract(&self, req: &ServiceRequest) -> Result<IpAddr, Self::KeyExtractionError> {
        req.peer_addr().map(|a| a.ip()).ok_or_else(|| {
            SimpleKeyExtractionError::new("Could not extract peer IP address from request")
        })
    }
}

/// Erreur d'extraction minimale : un message et un statut (500 par défaut).
pub struct SimpleKeyExtractionError<T: fmt::Display + fmt::Debug> {
    body: T,
    status: StatusCode,
}

impl<T: fmt::Display + fmt::Debug> SimpleKeyExtractionError<T> {
    pub fn new(body: T) -> Self {
        SimpleKeyExtractionError {
            body,
            status: StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn set_status_code(mut self, status: StatusCode) -> Self {
        self.status = status;
        self
    }
}

impl<T: fmt::Display + fmt::Debug> fmt::Debug for SimpleKeyExtractionError<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SimpleKeyExtractionError")
            .field("body", &self.body)
            .field("status", &self.status)
            .finish()
    }
}

impl<T: fmt::Display + fmt::Debug> fmt::Display for SimpleKeyExtractionError<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.body, f)
    }
}

impl<T: fmt::Display + fmt::Debug> ResponseError for SimpleKeyExtractionError<T> {
    fn status_code(&self) -> StatusCode {
        self.status
    }

    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status)
            .content_type(ContentType::plaintext())
            .body(self.body.to_string())
    }
}

// ─── Configuration ───────────────────────────────────────────────────

pub struct GovernorConfigBuilder<K: KeyExtractor> {
    period: Duration,
    burst_size: u32,
    key_extractor: K,
    use_headers: bool,
}

impl Default for GovernorConfigBuilder<PeerIpKeyExtractor> {
    fn default() -> Self {
        GovernorConfigBuilder {
            period: Duration::from_millis(500),
            burst_size: 8,
            key_extractor: PeerIpKeyExtractor,
            use_headers: false,
        }
    }
}

impl<K: KeyExtractor> GovernorConfigBuilder<K> {
    pub fn period(&mut self, period: Duration) -> &mut Self {
        self.period = period;
        self
    }

    pub fn seconds_per_request(&mut self, seconds: u64) -> &mut Self {
        self.period = Duration::from_secs(seconds);
        self
    }

    pub fn milliseconds_per_request(&mut self, ms: u64) -> &mut Self {
        self.period = Duration::from_millis(ms);
        self
    }

    pub fn burst_size(&mut self, burst: u32) -> &mut Self {
        self.burst_size = burst;
        self
    }

    pub fn key_extractor<K2: KeyExtractor>(&mut self, key_extractor: K2) -> GovernorConfigBuilder<K2> {
        GovernorConfigBuilder {
            period: self.period,
            burst_size: self.burst_size,
            key_extractor,
            use_headers: self.use_headers,
        }
    }

    /// Ajoute les en-têtes `x-ratelimit-*` aux réponses.
    pub fn use_headers(&mut self) -> &mut Self {
        self.use_headers = true;
        self
    }

    /// `None` si `burst_size` ou `period` vaut zéro (comme actix-governor).
    pub fn finish(&mut self) -> Option<GovernorConfig<K>> {
        let burst = NonZeroU32::new(self.burst_size)?;
        if self.period.is_zero() {
            return None;
        }
        let quota = Quota::with_period(self.period)?.allow_burst(burst);
        let limiter: Arc<Limiter<K::Key>> =
            Arc::new(RateLimiter::keyed(quota).with_middleware::<StateInformationMiddleware>());
        spawn_cleanup(&limiter);
        Some(GovernorConfig {
            key_extractor: self.key_extractor.clone(),
            limiter,
            burst_size: self.burst_size,
            use_headers: self.use_headers,
        })
    }
}

/// Purge périodique des clés inactives : sans elle, chaque IP/utilisateur
/// jamais revu garderait son état en mémoire indéfiniment.
fn spawn_cleanup<K: Clone + Hash + Eq + Send + Sync + 'static>(limiter: &Arc<Limiter<K>>) {
    let weak = Arc::downgrade(limiter);
    let task = async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        tick.tick().await;
        loop {
            tick.tick().await;
            let Some(l) = weak.upgrade() else { break };
            l.retain_recent();
            l.shrink_to_fit();
        }
    };
    if let Ok(h) = tokio::runtime::Handle::try_current() {
        h.spawn(task);
    }
}

pub struct GovernorConfig<K: KeyExtractor> {
    key_extractor: K,
    limiter: Arc<Limiter<K::Key>>,
    burst_size: u32,
    use_headers: bool,
}

impl<K: KeyExtractor> Clone for GovernorConfig<K> {
    fn clone(&self) -> Self {
        GovernorConfig {
            key_extractor: self.key_extractor.clone(),
            limiter: self.limiter.clone(),
            burst_size: self.burst_size,
            use_headers: self.use_headers,
        }
    }
}

// ─── Middleware ──────────────────────────────────────────────────────

/// Middleware de route ; toutes les instances créées depuis la même
/// configuration partagent le même compteur.
pub struct Governor<K: KeyExtractor> {
    config: GovernorConfig<K>,
}

impl<K: KeyExtractor> Governor<K> {
    pub fn new(config: &GovernorConfig<K>) -> Self {
        Governor {
            config: config.clone(),
        }
    }
}

impl<K: KeyExtractor> Middleware for Governor<K> {
    fn call(&self, req: ServiceRequest, next: Next) -> ServiceFuture {
        let cfg = &self.config;
        let key = match cfg.key_extractor.extract(&req) {
            Ok(k) => k,
            Err(e) => {
                let res = e.error_response();
                return Box::pin(async move { Ok(req.into_response(res)) });
            }
        };

        if cfg.key_extractor.whitelisted_keys().contains(&key) {
            return next.call(req);
        }

        match cfg.limiter.check_key(&key) {
            Ok(snapshot) => {
                let fut = next.call(req);
                if !cfg.use_headers {
                    return fut;
                }
                let limit = cfg.burst_size;
                let remaining = snapshot.remaining_burst_capacity();
                Box::pin(async move {
                    let mut res = fut.await?;
                    let h = res.headers_mut();
                    h.insert("x-ratelimit-limit", limit.into());
                    h.insert("x-ratelimit-remaining", remaining.into());
                    Ok(res)
                })
            }
            Err(negative) => {
                let wait_time = negative
                    .wait_time_from(DefaultClock::default().now())
                    .as_secs();
                let mut builder = HttpResponseBuilder::new(StatusCode::TOO_MANY_REQUESTS);
                if cfg.use_headers {
                    builder
                        .insert_header(("x-ratelimit-after", wait_time))
                        .insert_header(("x-ratelimit-limit", cfg.burst_size))
                        .insert_header(("x-ratelimit-remaining", 0u32));
                }
                let res = cfg.key_extractor.exceed_rate_limit_response(&negative, builder);
                Box::pin(async move { Ok(req.into_response(res)) })
            }
        }
    }
}
