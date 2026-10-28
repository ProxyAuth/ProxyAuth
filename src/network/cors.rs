use crate::hyper_web::dev::{Middleware, Next, ServiceFuture, ServiceRequest};
use crate::hyper_web::http::header;
use crate::hyper_web::http::header::{ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue, SERVER};
use crate::hyper_web::web;

use crate::AppState;

pub struct CorsMiddleware {
    pub config: web::Data<AppState>,
}

impl Middleware for CorsMiddleware {
    fn call(&self, req: ServiceRequest, next: Next) -> ServiceFuture {
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

        let fut = next.call(req);

        Box::pin(async move {
            let mut res = fut.await?;

            if let Some(origin_str) = origin {
                let vhost_route =
                    crate::network::proxy::find_vhost_route(host.as_deref(), &config.routes.routes);
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
