use actix_service::{Service, Transform};
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::http::header;
use actix_web::http::header::{ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue, SERVER};
use actix_web::{Error, web};
use futures_util::future::{LocalBoxFuture, Ready, ok};
use std::task::{Context, Poll};

use crate::AppState;

pub struct CorsMiddleware {
    pub config: web::Data<AppState>,
}

impl<S, B> Transform<S, ServiceRequest> for CorsMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = CorsMiddlewareService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(CorsMiddlewareService {
            service,
            config: self.config.clone(),
        })
    }
}

pub struct CorsMiddlewareService<S> {
    service: S,
    config: web::Data<AppState>,
}

impl<S, B> Service<ServiceRequest> for CorsMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let config = self.config.clone();
        let origin = req
            .headers()
            .get("origin")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string());
        // Captured now, alongside `origin` — `req` moves into
        // `self.service.call(req)` below and isn't available anymore
        // once the response is being awaited.
        let host = crate::network::proxy::request_host(req.request());

        let fut = self.service.call(req);

        Box::pin(async move {
            let mut res = fut.await?;

            if let Some(origin_str) = origin {
                let vhost_route = crate::network::proxy::find_vhost_route(
                    host.as_deref(),
                    &config.routes.routes,
                );
                let cors_origins = vhost_route
                    .and_then(|r| r.resolved_cors_origins(&config.config))
                    .or(config.config.cors_origins.as_ref());
                if let Some(cors) = cors_origins {
                    let origin_trimmed = origin_str.trim_end_matches('/').to_ascii_lowercase();
                    if cors.iter().any(|allowed| {
                        allowed.trim_end_matches('/').to_ascii_lowercase() == origin_trimmed
                    }) {
                        if let Ok(hval) = HeaderValue::from_str(&origin_str) {
                            res.headers_mut().insert(ACCESS_CONTROL_ALLOW_ORIGIN, hval);
                        }
                    }
                }
            }

            res.headers_mut()
                .insert(SERVER, HeaderValue::from_static("ProxyAuth"));

            // SECURITY/CORRECTNESS: `Access-Control-Allow-Origin: *` and
            // `Access-Control-Allow-Credentials: true` together is an
            // invalid combination per the Fetch/CORS spec — browsers
            // reject it outright, treating the whole response as if
            // CORS had failed. A handler that's already set `*` itself
            // (the OIDC provider's own discovery/JWKS endpoints, meant
            // to be publicly fetchable from any origin with no
            // credentials involved at all — see
            // `proto::oidc_provider::discovery`) means exactly that:
            // no credentials, any origin. Adding `Allow-Credentials:
            // true` unconditionally on top, as this used to, would
            // silently break the one thing those endpoints exist for.
            let already_wildcard = res
                .headers()
                .get(ACCESS_CONTROL_ALLOW_ORIGIN)
                .map(|v| v.as_bytes() == b"*")
                .unwrap_or(false);
            if !already_wildcard {
                res.headers_mut().insert(
                    header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
                    HeaderValue::from_static("true"),
                );
            }
            Ok(res)
        })
    }
}
