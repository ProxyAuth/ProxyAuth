//! Extracteurs d'arguments de handler : `HttpRequest`, `web::Data<T>`,
//! `web::Bytes`, `web::Json<T>`, `web::Form<T>`, `web::Query<T>`.

use super::body::{Body, to_bytes_limited};
use super::error::{Error, ResponseError};
use super::http::StatusCode;
use super::request::HttpRequest;
use bytes::Bytes;
use futures_util::future::LocalBoxFuture;
use http::header;
use serde::de::DeserializeOwned;
use std::io::Read;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;

/// Corps de la requête, consommable une seule fois.
pub struct Payload(Option<Body>);

impl Payload {
    pub fn new(body: Body) -> Self {
        Payload(Some(body))
    }
    pub fn empty() -> Self {
        Payload(None)
    }
    pub fn take(&mut self) -> Option<Body> {
        self.0.take()
    }
}

/// Même forme que `actix_web::FromRequest` : la future renvoyée ne
/// borrowe ni la requête ni le corps (le corps est *pris* de `payload`
/// de façon synchrone).
pub trait FromRequest: Sized + 'static {
    type Error: Into<Error>;
    type Future: std::future::Future<Output = Result<Self, Self::Error>> + 'static;

    fn from_request(req: &HttpRequest, payload: &mut Payload) -> Self::Future;

    /// Variante pratique : extraction seule depuis la requête.
    fn extract(req: &HttpRequest) -> Self::Future {
        Self::from_request(req, &mut Payload::empty())
    }
}

type ExtractFuture<T> = LocalBoxFuture<'static, Result<T, Error>>;

// ─── Erreurs d'extraction ────────────────────────────────────────────

#[derive(Debug)]
pub enum PayloadError {
    Overflow,
    UnsupportedEncoding(String),
    Decode(String),
    Incomplete(String),
}

impl std::fmt::Display for PayloadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PayloadError::Overflow => f.write_str("Payload reached size limit."),
            PayloadError::UnsupportedEncoding(e) => {
                write!(f, "Unsupported content encoding: {e}")
            }
            PayloadError::Decode(e) => write!(f, "Can not decode content-encoding: {e}"),
            PayloadError::Incomplete(e) => {
                write!(f, "A payload reached EOF, but is not complete: {e}")
            }
        }
    }
}

impl ResponseError for PayloadError {
    fn status_code(&self) -> StatusCode {
        match self {
            PayloadError::Overflow => StatusCode::PAYLOAD_TOO_LARGE,
            PayloadError::UnsupportedEncoding(_) => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            _ => StatusCode::BAD_REQUEST,
        }
    }
}

#[derive(Debug)]
pub struct ExtractError {
    status: StatusCode,
    msg: String,
}

impl std::fmt::Display for ExtractError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.msg)
    }
}

impl ResponseError for ExtractError {
    fn status_code(&self) -> StatusCode {
        self.status
    }
}

fn extract_err(status: StatusCode, msg: impl Into<String>) -> Error {
    ExtractError {
        status,
        msg: msg.into(),
    }
    .into()
}

// ─── Configuration ───────────────────────────────────────────────────

/// Limite de taille du corps (`App::app_data(web::PayloadConfig::new(n))`).
#[derive(Debug, Clone, Copy)]
pub struct PayloadConfig {
    limit: usize,
}

impl PayloadConfig {
    pub fn new(limit: usize) -> Self {
        PayloadConfig { limit }
    }
    pub fn limit(mut self, limit: usize) -> Self {
        self.limit = limit;
        self
    }
}

impl Default for PayloadConfig {
    fn default() -> Self {
        // Même défaut qu'actix.
        PayloadConfig { limit: 262_144 }
    }
}

const JSON_LIMIT: usize = 2_097_152;
const FORM_LIMIT: usize = 16_384;

/// Lit le corps en mémoire, décompresse selon `Content-Encoding`
/// (comme le faisait actix) et applique `limit` avant ET après
/// décompression.
pub(crate) async fn read_body(
    req: HttpRequest,
    body: Option<Body>,
    limit: usize,
) -> Result<Bytes, Error> {
    if let Some(len) = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<usize>().ok())
    {
        if len > limit {
            return Err(PayloadError::Overflow.into());
        }
    }

    let Some(body) = body else {
        return Ok(Bytes::new());
    };

    let raw = match to_bytes_limited(body, limit).await {
        Ok(Ok(b)) => b,
        Ok(Err(e)) => return Err(PayloadError::Incomplete(e.to_string()).into()),
        Err(()) => return Err(PayloadError::Overflow.into()),
    };

    let encoding = req
        .headers()
        .get(header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_ascii_lowercase())
        .unwrap_or_default();

    decode_body(raw, &encoding, limit)
}

fn read_limited<R: Read>(reader: R, limit: usize) -> Result<Bytes, Error> {
    let mut out = Vec::new();
    let mut limited = reader.take(limit as u64 + 1);
    limited
        .read_to_end(&mut out)
        .map_err(|e| Error::from(PayloadError::Decode(e.to_string())))?;
    if out.len() > limit {
        return Err(PayloadError::Overflow.into());
    }
    Ok(Bytes::from(out))
}

fn decode_body(raw: Bytes, encoding: &str, limit: usize) -> Result<Bytes, Error> {
    match encoding {
        "" | "identity" => Ok(raw),
        "gzip" | "x-gzip" => read_limited(flate2::read::GzDecoder::new(&raw[..]), limit),
        "deflate" => read_limited(flate2::read::ZlibDecoder::new(&raw[..]), limit),
        "br" => read_limited(brotli::Decompressor::new(&raw[..], 4096), limit),
        other => Err(PayloadError::UnsupportedEncoding(other.to_string()).into()),
    }
}

// ─── Implémentations ─────────────────────────────────────────────────

impl FromRequest for HttpRequest {
    type Error = Error;
    type Future = ExtractFuture<Self>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let req = req.clone();
        Box::pin(async move { Ok(req) })
    }
}

impl FromRequest for Bytes {
    type Error = Error;
    type Future = ExtractFuture<Self>;

    fn from_request(req: &HttpRequest, payload: &mut Payload) -> Self::Future {
        let limit = req
            .app_data::<PayloadConfig>()
            .copied()
            .unwrap_or_default()
            .limit;
        let req = req.clone();
        let body = payload.take();
        Box::pin(read_body(req, body, limit))
    }
}

impl FromRequest for String {
    type Error = Error;
    type Future = ExtractFuture<Self>;

    fn from_request(req: &HttpRequest, payload: &mut Payload) -> Self::Future {
        let fut = Bytes::from_request(req, payload);
        Box::pin(async move {
            let bytes = fut.await?;
            String::from_utf8(bytes.to_vec())
                .map_err(|_| extract_err(StatusCode::BAD_REQUEST, "Can not decode body"))
        })
    }
}

impl<T: FromRequest> FromRequest for Option<T> {
    type Error = Error;
    type Future = ExtractFuture<Self>;

    fn from_request(req: &HttpRequest, payload: &mut Payload) -> Self::Future {
        let fut = T::from_request(req, payload);
        Box::pin(async move { Ok(fut.await.ok()) })
    }
}

// ─── web::Data ───────────────────────────────────────────────────────

/// État applicatif partagé (`Arc`), identique à `actix_web::web::Data`.
#[derive(Debug, Default)]
pub struct Data<T: ?Sized>(Arc<T>);

impl<T> Data<T> {
    pub fn new(state: T) -> Self {
        Data(Arc::new(state))
    }
}

impl<T: ?Sized> Data<T> {
    pub fn get_ref(&self) -> &T {
        self.0.as_ref()
    }
    pub fn into_inner(self) -> Arc<T> {
        self.0
    }
}

impl<T: ?Sized> Clone for Data<T> {
    fn clone(&self) -> Self {
        Data(self.0.clone())
    }
}

impl<T: ?Sized> Deref for Data<T> {
    type Target = Arc<T>;
    fn deref(&self) -> &Arc<T> {
        &self.0
    }
}

impl<T: ?Sized> From<Arc<T>> for Data<T> {
    fn from(arc: Arc<T>) -> Self {
        Data(arc)
    }
}

impl<T: ?Sized + 'static> FromRequest for Data<T> {
    type Error = Error;
    type Future = ExtractFuture<Self>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let found = req.app_data::<Data<T>>().cloned();
        Box::pin(async move {
            match found {
                Some(d) => Ok(d),
                None => {
                    tracing::error!(
                        "hyper_web: app data `{}` is not configured",
                        std::any::type_name::<T>()
                    );
                    Err(extract_err(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Requested application data is not configured correctly.",
                    ))
                }
            }
        })
    }
}

// ─── web::Json / web::Form / web::Query ──────────────────────────────

macro_rules! wrapper {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, Default)]
        pub struct $name<T>(pub T);

        impl<T> $name<T> {
            pub fn into_inner(self) -> T {
                self.0
            }
        }

        impl<T> Deref for $name<T> {
            type Target = T;
            fn deref(&self) -> &T {
                &self.0
            }
        }

        impl<T> DerefMut for $name<T> {
            fn deref_mut(&mut self) -> &mut T {
                &mut self.0
            }
        }
    };
}

wrapper!(Json);
wrapper!(Form);
wrapper!(Query);

fn is_json_content_type(req: &HttpRequest) -> bool {
    let Ok(mime) = req.content_type().parse::<mime::Mime>() else {
        return false;
    };
    mime.subtype() == mime::JSON || mime.suffix() == Some(mime::JSON)
}

impl<T: DeserializeOwned + 'static> FromRequest for Json<T> {
    type Error = Error;
    type Future = ExtractFuture<Self>;

    fn from_request(req: &HttpRequest, payload: &mut Payload) -> Self::Future {
        let ok_type = is_json_content_type(req);
        let req = req.clone();
        let body = payload.take();
        Box::pin(async move {
            if !ok_type {
                return Err(extract_err(StatusCode::BAD_REQUEST, "Content type error"));
            }
            let body = read_body(req, body, JSON_LIMIT).await?;
            serde_json::from_slice::<T>(&body).map(Json).map_err(|e| {
                extract_err(
                    StatusCode::BAD_REQUEST,
                    format!("Json deserialize error: {e}"),
                )
            })
        })
    }
}

impl<T: DeserializeOwned + 'static> FromRequest for Form<T> {
    type Error = Error;
    type Future = ExtractFuture<Self>;

    fn from_request(req: &HttpRequest, payload: &mut Payload) -> Self::Future {
        let ok_type = req
            .content_type()
            .eq_ignore_ascii_case("application/x-www-form-urlencoded");
        let req = req.clone();
        let body = payload.take();
        Box::pin(async move {
            if !ok_type {
                return Err(extract_err(StatusCode::BAD_REQUEST, "Content type error"));
            }
            let body = read_body(req, body, FORM_LIMIT).await?;
            serde_urlencoded::from_bytes::<T>(&body)
                .map(Form)
                .map_err(|e| extract_err(StatusCode::BAD_REQUEST, format!("Parse error: {e}")))
        })
    }
}

impl<T: DeserializeOwned + 'static> FromRequest for Query<T> {
    type Error = Error;
    type Future = ExtractFuture<Self>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let res = serde_urlencoded::from_str::<T>(req.query_string())
            .map(Query)
            .map_err(|e| {
                extract_err(
                    StatusCode::BAD_REQUEST,
                    format!("Query deserialize error: {e}"),
                )
            });
        Box::pin(async move { res })
    }
}

impl<T: DeserializeOwned> Query<T> {
    pub fn from_query(query: &str) -> Result<Self, Error> {
        serde_urlencoded::from_str::<T>(query)
            .map(Query)
            .map_err(|e| {
                extract_err(
                    StatusCode::BAD_REQUEST,
                    format!("Query deserialize error: {e}"),
                )
            })
    }
}

// ─── Tuples d'extracteurs ────────────────────────────────────────────

macro_rules! tuple_from_req {
    ($($T:ident),*) => {
        impl<$($T: FromRequest),*> FromRequest for ($($T,)*) {
            type Error = Error;
            type Future = ExtractFuture<Self>;

            #[allow(non_snake_case, unused_variables)]
            fn from_request(req: &HttpRequest, payload: &mut Payload) -> Self::Future {
                $(let $T = $T::from_request(req, payload);)*
                Box::pin(async move {
                    $(let $T = $T.await.map_err(Into::into)?;)*
                    Ok(($($T,)*))
                })
            }
        }
    };
}

tuple_from_req!();
tuple_from_req!(A);
tuple_from_req!(A, B);
tuple_from_req!(A, B, C);
tuple_from_req!(A, B, C, D);
tuple_from_req!(A, B, C, D, E);
