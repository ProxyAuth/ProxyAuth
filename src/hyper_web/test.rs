//! Outils de test, calqués sur `actix_web::test`.

use super::app::{App, AppService, ServiceRequest, ServiceResponse};
use super::body::{Body, to_bytes};
use super::error::Error;
use super::extract::Payload;
use super::request::{Extensions, HttpRequest};
use super::response::TryIntoHeaderPair;
use bytes::Bytes;
use cookie::Cookie;
use http::header::{self, HeaderMap, HeaderValue};
use http::{Method, Uri, Version};
use serde::Serialize;
use std::net::SocketAddr;
use std::rc::Rc;

pub struct TestRequest {
    method: Method,
    uri: Uri,
    version: Version,
    headers: HeaderMap,
    peer_addr: Option<SocketAddr>,
    secure: bool,
    payload: Bytes,
    app_data: Extensions,
}

impl Default for TestRequest {
    fn default() -> Self {
        TestRequest {
            method: Method::GET,
            uri: Uri::from_static("/"),
            version: Version::HTTP_11,
            headers: HeaderMap::new(),
            peer_addr: None,
            secure: false,
            payload: Bytes::new(),
            app_data: Extensions::new(),
        }
    }
}

/// Requête prête à être passée à [`TestService::call`].
pub struct TestHttpRequest {
    inner: TestRequest,
}

impl TestRequest {
    pub fn get() -> Self {
        Self::default().method(Method::GET)
    }
    pub fn post() -> Self {
        Self::default().method(Method::POST)
    }
    pub fn put() -> Self {
        Self::default().method(Method::PUT)
    }
    pub fn patch() -> Self {
        Self::default().method(Method::PATCH)
    }
    pub fn delete() -> Self {
        Self::default().method(Method::DELETE)
    }
    pub fn with_uri(path: &str) -> Self {
        Self::default().uri(path)
    }

    pub fn method(mut self, m: Method) -> Self {
        self.method = m;
        self
    }

    pub fn uri(mut self, path: &str) -> Self {
        self.uri = path.parse().unwrap_or_else(|_| Uri::from_static("/"));
        self
    }

    pub fn version(mut self, v: Version) -> Self {
        self.version = v;
        self
    }

    pub fn insert_header(mut self, pair: impl TryIntoHeaderPair) -> Self {
        if let Some((k, v)) = pair.try_into_pair() {
            self.headers.insert(k, v);
        }
        self
    }

    pub fn append_header(mut self, pair: impl TryIntoHeaderPair) -> Self {
        if let Some((k, v)) = pair.try_into_pair() {
            self.headers.append(k, v);
        }
        self
    }

    pub fn peer_addr(mut self, addr: SocketAddr) -> Self {
        self.peer_addr = Some(addr);
        self
    }

    pub fn secure(mut self, secure: bool) -> Self {
        self.secure = secure;
        self
    }

    pub fn cookie(mut self, cookie: Cookie<'_>) -> Self {
        let pair = format!("{}={}", cookie.name(), cookie.value());
        let merged = match self.headers.get(header::COOKIE).and_then(|v| v.to_str().ok()) {
            Some(existing) if !existing.is_empty() => format!("{existing}; {pair}"),
            _ => pair,
        };
        if let Ok(v) = HeaderValue::from_str(&merged) {
            self.headers.insert(header::COOKIE, v);
        }
        self
    }

    pub fn app_data<T: 'static>(mut self, data: T) -> Self {
        self.app_data.insert(data);
        self
    }

    pub fn set_payload(mut self, data: impl Into<Bytes>) -> Self {
        self.payload = data.into();
        let len = self.payload.len();
        self.headers.insert(header::CONTENT_LENGTH, HeaderValue::from(len));
        self
    }

    pub fn set_json(self, data: impl Serialize) -> Self {
        let body = serde_json::to_vec(&data).unwrap_or_default();
        self.insert_header((header::CONTENT_TYPE, "application/json"))
            .set_payload(body)
    }

    pub fn set_form(self, data: impl Serialize) -> Self {
        let body = serde_urlencoded::to_string(&data).unwrap_or_default();
        self.insert_header((header::CONTENT_TYPE, "application/x-www-form-urlencoded"))
            .set_payload(body)
    }

    fn build(self, app_data: Rc<Extensions>) -> (HttpRequest, Payload) {
        let req = HttpRequest::new(
            self.method,
            self.uri,
            self.version,
            self.headers,
            self.peer_addr,
            None,
            self.secure,
            app_data,
        );
        (req, Payload::new(Body::from(self.payload)))
    }

    pub fn to_http_request(mut self) -> HttpRequest {
        let data = Rc::new(std::mem::take(&mut self.app_data));
        self.build(data).0
    }

    pub fn to_http_parts(mut self) -> (HttpRequest, Payload) {
        let data = Rc::new(std::mem::take(&mut self.app_data));
        self.build(data)
    }

    pub fn to_srv_request(mut self) -> ServiceRequest {
        let data = Rc::new(std::mem::take(&mut self.app_data));
        let (req, payload) = self.build(data);
        ServiceRequest::new(req, payload)
    }

    pub fn to_request(self) -> TestHttpRequest {
        TestHttpRequest { inner: self }
    }
}

/// Application de test (une seule instance, exécutée sur la tâche courante).
pub struct TestService {
    app: AppService,
}

impl TestService {
    pub async fn call(&self, req: TestHttpRequest) -> Result<ServiceResponse, Error> {
        let mut t = req.inner;
        // Les app_data propres à la requête passent avant celles de l'App.
        let extra = std::mem::take(&mut t.app_data);
        let (mut req, payload) = t.build(self.app.app_data());
        if !extra.is_empty() {
            req = req.with_app_data_override(Rc::new(extra));
        }
        Ok(self.app.call(ServiceRequest::new(req, payload)).await)
    }
}

pub async fn init_service(app: App) -> TestService {
    TestService {
        app: app.into_service(),
    }
}

pub async fn call_service(app: &TestService, req: TestHttpRequest) -> ServiceResponse {
    app.call(req).await.expect("test service call failed")
}

pub async fn read_body(res: ServiceResponse) -> Bytes {
    to_bytes(res.into_body()).await.expect("error reading test response body")
}

pub async fn call_and_read_body(app: &TestService, req: TestHttpRequest) -> Bytes {
    read_body(call_service(app, req).await).await
}

pub async fn read_body_json<T: serde::de::DeserializeOwned>(res: ServiceResponse) -> T {
    let body = read_body(res).await;
    serde_json::from_slice(&body).expect("response body is not valid JSON")
}
