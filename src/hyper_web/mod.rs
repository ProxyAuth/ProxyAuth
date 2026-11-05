//! Couche web de ProxyAuth, construite directement sur hyper 1.x.
//!
//! Elle remplace actix-web en reprenant exactement la partie de son API
//! que ProxyAuth utilise (`HttpRequest`, `HttpResponse`, `web::Data`,
//! `App`, middlewares, `HttpServer`…), pour que le code métier n'ait
//! changé que par ses `use`. Voir chaque sous-module pour les choix de
//! comportement repris d'actix.

pub mod app;
pub mod body;
pub mod error;
pub mod extract;
pub mod request;
pub mod response;
pub mod server;
pub mod test;

pub use app::App;
pub use error::{Error, ResponseError};
pub use extract::FromRequest;
pub use request::{ConnectionInfo, HttpMessage, HttpRequest};
pub use response::{HttpResponse, HttpResponseBuilder, Responder};
pub use server::HttpServer;

pub use ::cookie;

/// Types HTTP (crate `http` 1.x, celui d'hyper).
pub mod http {
    pub use ::http::{Extensions, HeaderMap, Method, StatusCode, Uri, Version};
    pub mod header {
        pub use super::super::response::{
            ContentType, TryIntoHeaderName, TryIntoHeaderPair, TryIntoHeaderValue,
        };
        pub use ::http::header::*;
    }
}

/// Équivalent de `actix_web::web`.
pub mod web {
    pub use super::app::{
        Resource, Route, delete, get, head, method, patch, post, put, resource, to,
    };
    pub use super::extract::{Data, Form, Json, Payload, PayloadConfig, Query};
    pub use bytes::Bytes;
    pub use bytes::BytesMut;
}

/// Types « internes » utilisés par les middlewares.
pub mod dev {
    pub use super::app::{
        AppService, Middleware, Next, ServiceFuture, ServiceRequest, ServiceResponse,
    };
    pub use super::body::BodySize;
    pub use super::extract::Payload;
    pub use super::server::Server;
}

pub mod rt {
    pub use tokio::time;
}
