use proxyauth::stats::stats::stats;
use proxyauth::AppState;
use proxyauth::CounterToken;
use proxyauth::AppConfig;
use proxyauth::RouteConfig;
use proxyauth::network::stats::{RequestStats, spawn_stats_ticker};

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, http::header, HttpResponse, Responder, web};
    use std::sync::Arc;
    use dashmap::DashMap;

    // hyper 1.x
    use hyper_util::client::legacy::Client;
    use hyper_util::client::legacy::connect::HttpConnector;
    use hyper_util::rt::TokioExecutor;
    use hyper_rustls::HttpsConnectorBuilder;
    use http_body_util::combinators::BoxBody;
    use std::convert::Infallible;
    use hyper::body::Bytes;
    use hyper_http_proxy::{Proxy, ProxyConnector, Intercept};

    type RoutesWrapper = RouteConfig;

    fn dummy_https_client() -> Client<hyper_rustls::HttpsConnector<HttpConnector>, BoxBody<Bytes, Infallible>> {
        let https = HttpsConnectorBuilder::new()
        .with_native_roots()
        .unwrap()
        .https_or_http()
        .enable_http1()
        .build();
        Client::builder(TokioExecutor::new()).build::<_, BoxBody<Bytes, Infallible>>(https)
    }

    fn dummy_proxy_client() -> Client<ProxyConnector<hyper_rustls::HttpsConnector<HttpConnector>>, BoxBody<Bytes, Infallible>> {
        let https = HttpsConnectorBuilder::new()
        .with_native_roots()
        .unwrap()
        .https_or_http()
        .enable_http1()
        .build();
        let proxy = Proxy::new(Intercept::All, "http://127.0.0.1:1".parse().unwrap());
        let connector = ProxyConnector::from_proxy(https, proxy).unwrap();
        Client::builder(TokioExecutor::new()).build::<_, BoxBody<Bytes, Infallible>>(connector)
    }

    fn make_state(stats_enabled: bool) -> web::Data<AppState> {
        let mut cfg = AppConfig::default();
        cfg.stats = stats_enabled;
        cfg.token_admin = "adm-token".to_string();

        let routes = Arc::new(RoutesWrapper { routes: vec![] });
        let counter = Arc::new(CounterToken::new());
        let revoked_tokens = Arc::new(DashMap::<String, u64>::new());

        let stats = RequestStats::new();
        spawn_stats_ticker(stats.clone());

        web::Data::new(AppState {
            config: Arc::new(cfg),
                       routes,
                       counter,
                       client_normal:     dummy_https_client(),
                       client_with_cert:  dummy_https_client(),
                       client_with_proxy: dummy_proxy_client(),
                       revoked_tokens,
                       stats,
        })
    }

    #[actix_web::test]
    async fn stats_returns_200_json_when_enabled_and_token_ok() {
        let state = make_state(true);

        let req = test::TestRequest::default()
        .insert_header(("X-Auth-Token", "adm-token"))
        .to_http_request();

        let resp_impl = super::stats(req, state).await;
        let resp: HttpResponse = resp_impl
        .respond_to(&test::TestRequest::default().to_http_request())
        .map_into_boxed_body();

        assert_eq!(resp.status(), actix_web::http::StatusCode::OK);
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).unwrap(),
                   "application/json"
        );
    }

    #[actix_web::test]
    async fn stats_returns_401_on_missing_or_bad_token() {
        let state = make_state(true);

        let req_no_hdr = test::TestRequest::default().to_http_request();
        let resp_impl1 = super::stats(req_no_hdr, state.clone()).await;
        let resp1: HttpResponse = resp_impl1
        .respond_to(&test::TestRequest::default().to_http_request())
        .map_into_boxed_body();
        assert_eq!(resp1.status(), actix_web::http::StatusCode::UNAUTHORIZED);

        let req_bad = test::TestRequest::default()
        .insert_header(("X-Auth-Token", "wrong"))
        .to_http_request();
        let resp_impl2 = super::stats(req_bad, state).await;
        let resp2: HttpResponse = resp_impl2
        .respond_to(&test::TestRequest::default().to_http_request())
        .map_into_boxed_body();
        assert_eq!(resp2.status(), actix_web::http::StatusCode::UNAUTHORIZED);
    }

    #[actix_web::test]
    async fn stats_returns_message_when_feature_disabled() {
        let state = make_state(false);

        let req = test::TestRequest::default()
        .insert_header(("X-Auth-Token", "adm-token"))
        .to_http_request();

        let resp_impl = super::stats(req, state).await;
        let resp: HttpResponse = resp_impl
        .respond_to(&test::TestRequest::default().to_http_request())
        .map_into_boxed_body();

        assert_eq!(resp.status(), actix_web::http::StatusCode::OK);
        let body_bytes = actix_web::body::to_bytes(resp.into_body()).await.unwrap();
        let body_str = std::str::from_utf8(&body_bytes).unwrap();
        assert!(body_str.contains("Stats is disabled"));
    }
}
