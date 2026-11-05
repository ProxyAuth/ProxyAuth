//! Erreurs converties en réponses HTTP — même modèle qu'actix :
//! tout type implémentant [`ResponseError`] se convertit en [`Error`],
//! qui sait produire sa propre réponse.

use super::http::StatusCode;
use super::http::header::{CONTENT_TYPE, HeaderValue};
use super::response::HttpResponse;
use std::cell::RefCell;
use std::fmt;

pub trait ResponseError: fmt::Debug + fmt::Display {
    fn status_code(&self) -> StatusCode {
        StatusCode::INTERNAL_SERVER_ERROR
    }

    fn error_response(&self) -> HttpResponse {
        let mut res = HttpResponse::with_body(self.status_code(), self.to_string());
        res.headers_mut().insert(
            CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        );
        res
    }
}

pub struct Error {
    cause: Box<dyn ResponseError>,
}

impl Error {
    pub fn as_response_error(&self) -> &dyn ResponseError {
        self.cause.as_ref()
    }

    pub fn error_response(&self) -> HttpResponse {
        self.cause.error_response()
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.cause, f)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.cause, f)
    }
}

impl std::error::Error for Error {}

impl<T: ResponseError + 'static> From<T> for Error {
    fn from(err: T) -> Self {
        Error {
            cause: Box::new(err),
        }
    }
}

// ─── Conversions usuelles (mêmes statuts qu'actix) ──────────────────

impl ResponseError for std::io::Error {}

impl ResponseError for serde_json::Error {
    fn status_code(&self) -> StatusCode {
        StatusCode::BAD_REQUEST
    }
}

impl ResponseError for serde_urlencoded::de::Error {
    fn status_code(&self) -> StatusCode {
        StatusCode::BAD_REQUEST
    }
}

impl ResponseError for std::str::Utf8Error {
    fn status_code(&self) -> StatusCode {
        StatusCode::BAD_REQUEST
    }
}

impl ResponseError for http::Error {}

impl ResponseError for http::header::InvalidHeaderValue {}

impl ResponseError for hyper::Error {
    fn status_code(&self) -> StatusCode {
        StatusCode::BAD_GATEWAY
    }
}

impl ResponseError for tokio::time::error::Elapsed {
    fn status_code(&self) -> StatusCode {
        StatusCode::GATEWAY_TIMEOUT
    }
}

impl ResponseError for Box<dyn std::error::Error> {}
impl ResponseError for Box<dyn std::error::Error + Send + Sync> {}
impl ResponseError for anyhow::Error {}

// ─── InternalError ───────────────────────────────────────────────────

enum InternalErrorType {
    Status(StatusCode),
    Response(RefCell<Option<HttpResponse>>),
}

/// Erreur portant un message et, soit un statut, soit une réponse
/// déjà construite (`InternalError::from_response`).
pub struct InternalError<T> {
    cause: T,
    status: InternalErrorType,
}

impl<T> InternalError<T> {
    pub fn new(cause: T, status: StatusCode) -> Self {
        InternalError {
            cause,
            status: InternalErrorType::Status(status),
        }
    }

    pub fn from_response(cause: T, response: HttpResponse) -> Self {
        InternalError {
            cause,
            status: InternalErrorType::Response(RefCell::new(Some(response))),
        }
    }
}

impl<T: fmt::Debug> fmt::Debug for InternalError<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.cause, f)
    }
}

impl<T: fmt::Display> fmt::Display for InternalError<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.cause, f)
    }
}

impl<T: fmt::Debug + fmt::Display> ResponseError for InternalError<T> {
    fn status_code(&self) -> StatusCode {
        match &self.status {
            InternalErrorType::Status(s) => *s,
            InternalErrorType::Response(r) => r
                .borrow()
                .as_ref()
                .map(|r| r.status())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        }
    }

    fn error_response(&self) -> HttpResponse {
        match &self.status {
            InternalErrorType::Status(s) => {
                let mut res = HttpResponse::with_body(*s, self.cause.to_string());
                res.headers_mut().insert(
                    CONTENT_TYPE,
                    HeaderValue::from_static("text/plain; charset=utf-8"),
                );
                res
            }
            InternalErrorType::Response(r) => r
                .borrow_mut()
                .take()
                .unwrap_or_else(|| HttpResponse::new(StatusCode::INTERNAL_SERVER_ERROR)),
        }
    }
}

macro_rules! error_helpers {
    ($($name:ident => $status:ident),* $(,)?) => {
        $(
            #[allow(non_snake_case)]
            pub fn $name<T: fmt::Debug + fmt::Display + 'static>(err: T) -> Error {
                InternalError::new(err, StatusCode::$status).into()
            }
        )*
    };
}

error_helpers! {
    ErrorBadRequest => BAD_REQUEST,
    ErrorUnauthorized => UNAUTHORIZED,
    ErrorForbidden => FORBIDDEN,
    ErrorNotFound => NOT_FOUND,
    ErrorMethodNotAllowed => METHOD_NOT_ALLOWED,
    ErrorPayloadTooLarge => PAYLOAD_TOO_LARGE,
    ErrorUnsupportedMediaType => UNSUPPORTED_MEDIA_TYPE,
    ErrorTooManyRequests => TOO_MANY_REQUESTS,
    ErrorInternalServerError => INTERNAL_SERVER_ERROR,
    ErrorBadGateway => BAD_GATEWAY,
    ErrorServiceUnavailable => SERVICE_UNAVAILABLE,
    ErrorGatewayTimeout => GATEWAY_TIMEOUT,
}
