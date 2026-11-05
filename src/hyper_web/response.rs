//! `HttpResponse` / `HttpResponseBuilder` — même surface qu'actix pour
//! ce que ProxyAuth en utilise, posée directement sur les types `http` 1.x
//! qu'hyper consomme (plus de conversion `http` 0.2 ↔ 1.x).

use super::body::{Body, BoxError};
use super::error::Error;
use super::request::HttpRequest;
use bytes::Bytes;
use cookie::Cookie;
use futures_util::Stream;
use http::header::{self, HeaderMap, HeaderName, HeaderValue};
use http::{StatusCode, Version};
use serde::Serialize;

// ─── Conversions vers les en-têtes ───────────────────────────────────

pub trait TryIntoHeaderName {
    fn try_into_header_name(self) -> Option<HeaderName>;
}

impl TryIntoHeaderName for HeaderName {
    fn try_into_header_name(self) -> Option<HeaderName> {
        Some(self)
    }
}
impl TryIntoHeaderName for &HeaderName {
    fn try_into_header_name(self) -> Option<HeaderName> {
        Some(self.clone())
    }
}
impl TryIntoHeaderName for &str {
    fn try_into_header_name(self) -> Option<HeaderName> {
        HeaderName::from_bytes(self.as_bytes()).ok()
    }
}
impl TryIntoHeaderName for String {
    fn try_into_header_name(self) -> Option<HeaderName> {
        HeaderName::from_bytes(self.as_bytes()).ok()
    }
}
impl TryIntoHeaderName for &String {
    fn try_into_header_name(self) -> Option<HeaderName> {
        HeaderName::from_bytes(self.as_bytes()).ok()
    }
}

pub trait TryIntoHeaderValue {
    fn try_into_value(self) -> Option<HeaderValue>;
}

impl TryIntoHeaderValue for HeaderValue {
    fn try_into_value(self) -> Option<HeaderValue> {
        Some(self)
    }
}
impl TryIntoHeaderValue for &HeaderValue {
    fn try_into_value(self) -> Option<HeaderValue> {
        Some(self.clone())
    }
}
impl TryIntoHeaderValue for &str {
    fn try_into_value(self) -> Option<HeaderValue> {
        HeaderValue::from_str(self).ok()
    }
}
impl TryIntoHeaderValue for String {
    fn try_into_value(self) -> Option<HeaderValue> {
        HeaderValue::from_str(&self).ok()
    }
}
impl TryIntoHeaderValue for &String {
    fn try_into_value(self) -> Option<HeaderValue> {
        HeaderValue::from_str(self).ok()
    }
}
impl TryIntoHeaderValue for std::borrow::Cow<'_, str> {
    fn try_into_value(self) -> Option<HeaderValue> {
        HeaderValue::from_str(&self).ok()
    }
}
impl TryIntoHeaderValue for Vec<u8> {
    fn try_into_value(self) -> Option<HeaderValue> {
        HeaderValue::from_bytes(&self).ok()
    }
}
impl TryIntoHeaderValue for &[u8] {
    fn try_into_value(self) -> Option<HeaderValue> {
        HeaderValue::from_bytes(self).ok()
    }
}
impl TryIntoHeaderValue for mime::Mime {
    fn try_into_value(self) -> Option<HeaderValue> {
        HeaderValue::from_str(self.as_ref()).ok()
    }
}
impl TryIntoHeaderValue for ContentType {
    fn try_into_value(self) -> Option<HeaderValue> {
        HeaderValue::from_str(self.0.as_ref()).ok()
    }
}
macro_rules! int_header_value {
    ($($t:ty),*) => {$(
        impl TryIntoHeaderValue for $t {
            fn try_into_value(self) -> Option<HeaderValue> {
                Some(HeaderValue::from(self))
            }
        }
    )*};
}
int_header_value!(u16, i16, u32, i32, u64, i64, usize, isize);

/// Paire (nom, valeur) acceptée par `insert_header` / `append_header`.
pub trait TryIntoHeaderPair {
    fn try_into_pair(self) -> Option<(HeaderName, HeaderValue)>;
}

impl<K: TryIntoHeaderName, V: TryIntoHeaderValue> TryIntoHeaderPair for (K, V) {
    fn try_into_pair(self) -> Option<(HeaderName, HeaderValue)> {
        Some((self.0.try_into_header_name()?, self.1.try_into_value()?))
    }
}

impl TryIntoHeaderPair for ContentType {
    fn try_into_pair(self) -> Option<(HeaderName, HeaderValue)> {
        Some((header::CONTENT_TYPE, self.try_into_value()?))
    }
}

/// Équivalent de `actix_web::http::header::ContentType`.
#[derive(Debug, Clone, PartialEq)]
pub struct ContentType(pub mime::Mime);

impl ContentType {
    pub fn json() -> Self {
        ContentType(mime::APPLICATION_JSON)
    }
    pub fn plaintext() -> Self {
        ContentType(mime::TEXT_PLAIN_UTF_8)
    }
    pub fn html() -> Self {
        ContentType(mime::TEXT_HTML_UTF_8)
    }
    pub fn xml() -> Self {
        ContentType(mime::TEXT_XML)
    }
    pub fn form_url_encoded() -> Self {
        ContentType(mime::APPLICATION_WWW_FORM_URLENCODED)
    }
    pub fn octet_stream() -> Self {
        ContentType(mime::APPLICATION_OCTET_STREAM)
    }
}

impl std::fmt::Display for ContentType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

// ─── HttpResponse ────────────────────────────────────────────────────

pub struct HttpResponse {
    status: StatusCode,
    version: Option<Version>,
    headers: HeaderMap,
    body: Body,
}

impl std::fmt::Debug for HttpResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpResponse")
            .field("status", &self.status)
            .field("headers", &self.headers)
            .field("body", &self.body)
            .finish()
    }
}

macro_rules! status_constructors {
    ($($name:ident => $status:ident),* $(,)?) => {
        $(
            #[allow(non_snake_case)]
            pub fn $name() -> HttpResponseBuilder {
                HttpResponseBuilder::new(StatusCode::$status)
            }
        )*
    };
}

impl HttpResponse {
    /// Réponse au statut donné, corps vide.
    pub fn new(status: StatusCode) -> Self {
        HttpResponse {
            status,
            version: None,
            headers: HeaderMap::new(),
            body: Body::empty(),
        }
    }

    pub fn with_body(status: StatusCode, body: impl Into<Body>) -> Self {
        HttpResponse {
            status,
            version: None,
            headers: HeaderMap::new(),
            body: body.into(),
        }
    }

    pub fn build(status: StatusCode) -> HttpResponseBuilder {
        HttpResponseBuilder::new(status)
    }

    pub fn from_error(err: impl Into<Error>) -> Self {
        err.into().error_response()
    }

    status_constructors! {
        Continue => CONTINUE,
        SwitchingProtocols => SWITCHING_PROTOCOLS,
        Ok => OK,
        Created => CREATED,
        Accepted => ACCEPTED,
        NoContent => NO_CONTENT,
        PartialContent => PARTIAL_CONTENT,
        MovedPermanently => MOVED_PERMANENTLY,
        Found => FOUND,
        SeeOther => SEE_OTHER,
        NotModified => NOT_MODIFIED,
        TemporaryRedirect => TEMPORARY_REDIRECT,
        PermanentRedirect => PERMANENT_REDIRECT,
        BadRequest => BAD_REQUEST,
        Unauthorized => UNAUTHORIZED,
        PaymentRequired => PAYMENT_REQUIRED,
        Forbidden => FORBIDDEN,
        NotFound => NOT_FOUND,
        MethodNotAllowed => METHOD_NOT_ALLOWED,
        NotAcceptable => NOT_ACCEPTABLE,
        RequestTimeout => REQUEST_TIMEOUT,
        Conflict => CONFLICT,
        Gone => GONE,
        LengthRequired => LENGTH_REQUIRED,
        PayloadTooLarge => PAYLOAD_TOO_LARGE,
        UriTooLong => URI_TOO_LONG,
        UnsupportedMediaType => UNSUPPORTED_MEDIA_TYPE,
        RangeNotSatisfiable => RANGE_NOT_SATISFIABLE,
        UnprocessableEntity => UNPROCESSABLE_ENTITY,
        TooManyRequests => TOO_MANY_REQUESTS,
        InternalServerError => INTERNAL_SERVER_ERROR,
        NotImplemented => NOT_IMPLEMENTED,
        BadGateway => BAD_GATEWAY,
        ServiceUnavailable => SERVICE_UNAVAILABLE,
        GatewayTimeout => GATEWAY_TIMEOUT,
    }

    pub fn status(&self) -> StatusCode {
        self.status
    }

    pub fn status_mut(&mut self) -> &mut StatusCode {
        &mut self.status
    }

    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    pub fn headers_mut(&mut self) -> &mut HeaderMap {
        &mut self.headers
    }

    pub fn body(&self) -> &Body {
        &self.body
    }

    pub fn into_body(self) -> Body {
        self.body
    }

    /// Retire le corps (remplacé par un corps vide).
    pub fn take_body(&mut self) -> Body {
        std::mem::take(&mut self.body)
    }

    pub fn set_body(mut self, body: impl Into<Body>) -> Self {
        self.body = body.into();
        self
    }

    /// Conservé pour compatibilité : il n'y a qu'un type de corps ici.
    pub fn map_into_boxed_body(self) -> Self {
        self
    }

    /// Ajoute un `Set-Cookie`.
    pub fn add_cookie(
        &mut self,
        cookie: &Cookie<'_>,
    ) -> Result<(), http::header::InvalidHeaderValue> {
        let v = HeaderValue::from_str(&cookie.to_string())?;
        self.headers.append(header::SET_COOKIE, v);
        Ok(())
    }

    /// Les cookies posés par cette réponse.
    pub fn cookies(&self) -> impl Iterator<Item = Cookie<'static>> + '_ {
        self.headers
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .filter_map(|s| Cookie::parse_encoded(s.to_string()).ok())
    }

    /// Conversion vers le type consommé par hyper.
    pub fn into_hyper(self) -> hyper::Response<Body> {
        let mut res = hyper::Response::new(self.body);
        *res.status_mut() = self.status;
        *res.headers_mut() = self.headers;
        if let Some(v) = self.version {
            *res.version_mut() = v;
        }
        res
    }

    /// Conversion depuis une réponse hyper quelconque (corps relayé en flux).
    pub fn from_hyper<B>(res: hyper::Response<B>) -> Self
    where
        B: http_body::Body<Data = Bytes> + 'static,
        B::Error: Into<BoxError>,
    {
        let (parts, body) = res.into_parts();
        let stream = http_body_util::BodyStream::new(body);
        use futures_util::StreamExt;
        let stream = stream.filter_map(|frame| async move {
            match frame {
                Ok(f) => f.into_data().ok().map(Ok::<Bytes, BoxError>),
                Err(e) => Some(Err(e.into())),
            }
        });
        HttpResponse {
            status: parts.status,
            version: None,
            headers: parts.headers,
            body: Body::from_stream(stream),
        }
    }
}

// ─── HttpResponseBuilder ─────────────────────────────────────────────

pub struct HttpResponseBuilder {
    status: StatusCode,
    headers: HeaderMap,
    version: Option<Version>,
}

impl HttpResponseBuilder {
    pub fn new(status: StatusCode) -> Self {
        HttpResponseBuilder {
            status,
            headers: HeaderMap::new(),
            version: None,
        }
    }

    pub fn status(&mut self, status: StatusCode) -> &mut Self {
        self.status = status;
        self
    }

    pub fn version(&mut self, version: Version) -> &mut Self {
        self.version = Some(version);
        self
    }

    /// Remplace l'en-tête. Une paire invalide est ignorée (et journalisée),
    /// là où actix transformait la réponse entière en 500.
    pub fn insert_header(&mut self, pair: impl TryIntoHeaderPair) -> &mut Self {
        match pair.try_into_pair() {
            Some((k, v)) => {
                self.headers.insert(k, v);
            }
            None => tracing::warn!("hyper_web: invalid header ignored in response"),
        }
        self
    }

    pub fn append_header(&mut self, pair: impl TryIntoHeaderPair) -> &mut Self {
        match pair.try_into_pair() {
            Some((k, v)) => {
                self.headers.append(k, v);
            }
            None => tracing::warn!("hyper_web: invalid header ignored in response"),
        }
        self
    }

    pub fn content_type(&mut self, value: impl TryIntoHeaderValue) -> &mut Self {
        if let Some(v) = value.try_into_value() {
            self.headers.insert(header::CONTENT_TYPE, v);
        }
        self
    }

    pub fn cookie(&mut self, cookie: Cookie<'_>) -> &mut Self {
        if let Ok(v) = HeaderValue::from_str(&cookie.to_string()) {
            self.headers.append(header::SET_COOKIE, v);
        }
        self
    }

    /// Sans effet ici (hyper gère la persistance de connexion) ; gardé
    /// pour compatibilité de source.
    pub fn keep_alive(&mut self) -> &mut Self {
        self
    }

    /// `Connection: close`.
    pub fn force_close(&mut self) -> &mut Self {
        self.headers
            .insert(header::CONNECTION, HeaderValue::from_static("close"));
        self
    }

    pub fn headers_mut(&mut self) -> Option<&mut HeaderMap> {
        Some(&mut self.headers)
    }

    fn take(&mut self) -> HttpResponse {
        HttpResponse {
            status: self.status,
            version: self.version,
            headers: std::mem::take(&mut self.headers),
            body: Body::empty(),
        }
    }

    pub fn body(&mut self, body: impl Into<Body>) -> HttpResponse {
        let mut res = self.take();
        res.body = body.into();
        res
    }

    pub fn finish(&mut self) -> HttpResponse {
        self.take()
    }

    pub fn json(&mut self, value: impl Serialize) -> HttpResponse {
        match serde_json::to_vec(&value) {
            Ok(body) => {
                if !self.headers.contains_key(header::CONTENT_TYPE) {
                    self.headers.insert(
                        header::CONTENT_TYPE,
                        HeaderValue::from_static("application/json"),
                    );
                }
                self.body(body)
            }
            Err(e) => HttpResponse::from_error(e),
        }
    }

    pub fn streaming<S, E>(&mut self, stream: S) -> HttpResponse
    where
        S: Stream<Item = Result<Bytes, E>> + 'static,
        E: Into<BoxError> + 'static,
    {
        let mut res = self.take();
        res.body = Body::from_stream(stream);
        res
    }
}

// ─── Responder ───────────────────────────────────────────────────────

/// Ce qu'un handler peut renvoyer.
pub trait Responder {
    fn respond_to(self, req: &HttpRequest) -> HttpResponse;
}

impl Responder for HttpResponse {
    fn respond_to(self, _req: &HttpRequest) -> HttpResponse {
        self
    }
}

impl Responder for HttpResponseBuilder {
    fn respond_to(mut self, _req: &HttpRequest) -> HttpResponse {
        self.finish()
    }
}

impl Responder for &'static str {
    fn respond_to(self, _req: &HttpRequest) -> HttpResponse {
        HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body(self)
    }
}

impl Responder for String {
    fn respond_to(self, _req: &HttpRequest) -> HttpResponse {
        HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body(self)
    }
}

impl<R: Responder, E: Into<Error>> Responder for Result<R, E> {
    fn respond_to(self, req: &HttpRequest) -> HttpResponse {
        match self {
            Ok(r) => r.respond_to(req),
            Err(e) => HttpResponse::from_error(e),
        }
    }
}

impl<R: Responder> Responder for (R, StatusCode) {
    fn respond_to(self, req: &HttpRequest) -> HttpResponse {
        let mut res = self.0.respond_to(req);
        *res.status_mut() = self.1;
        res
    }
}

impl<T: Serialize> Responder for super::extract::Json<T> {
    fn respond_to(self, _req: &HttpRequest) -> HttpResponse {
        HttpResponse::Ok().json(self.0)
    }
}
