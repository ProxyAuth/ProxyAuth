//! `HttpRequest` : tête de requête immuable + extensions mutables,
//! partagée à moindre coût (`Rc`) entre middlewares et handler — même
//! modèle qu'actix, qui exécute lui aussi chaque requête sur un seul
//! thread worker.

use cookie::Cookie;
use http::header::{self, HeaderMap};
use http::{Method, Uri, Version};
use std::any::{Any, TypeId};
use std::cell::{OnceCell, Ref, RefCell, RefMut};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::rc::Rc;

// ─── Extensions ──────────────────────────────────────────────────────

/// Carte type → valeur, sans contrainte `Send`/`Clone` (contrairement à
/// `http::Extensions`).
#[derive(Default)]
pub struct Extensions {
    map: HashMap<TypeId, Box<dyn Any>>,
}

impl Extensions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert<T: 'static>(&mut self, val: T) -> Option<T> {
        self.map
            .insert(TypeId::of::<T>(), Box::new(val))
            .and_then(|b| b.downcast::<T>().ok().map(|b| *b))
    }

    pub fn get<T: 'static>(&self) -> Option<&T> {
        self.map
            .get(&TypeId::of::<T>())
            .and_then(|b| b.downcast_ref::<T>())
    }

    pub fn get_mut<T: 'static>(&mut self) -> Option<&mut T> {
        self.map
            .get_mut(&TypeId::of::<T>())
            .and_then(|b| b.downcast_mut::<T>())
    }

    pub fn contains<T: 'static>(&self) -> bool {
        self.map.contains_key(&TypeId::of::<T>())
    }

    pub fn remove<T: 'static>(&mut self) -> Option<T> {
        self.map
            .remove(&TypeId::of::<T>())
            .and_then(|b| b.downcast::<T>().ok().map(|b| *b))
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn clear(&mut self) {
        self.map.clear();
    }
}

impl std::fmt::Debug for Extensions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Extensions({} entries)", self.map.len())
    }
}

// ─── HttpRequest ─────────────────────────────────────────────────────

struct Inner {
    method: Method,
    uri: Uri,
    version: Version,
    headers: HeaderMap,
    peer_addr: Option<SocketAddr>,
    local_addr: Option<SocketAddr>,
    secure: bool,
    app_data: Rc<Extensions>,
    app_data_override: Option<Rc<Extensions>>,
    extensions: RefCell<Extensions>,
    /// Calculés à la première demande puis réutilisés : le chemin d'une
    /// requête (garde de vhost, rate limit, routage, journal…) les
    /// interroge plusieurs fois.
    conn_info: OnceCell<ConnectionInfo>,
    cookies: OnceCell<Vec<Cookie<'static>>>,
}

#[derive(Clone)]
pub struct HttpRequest(Rc<Inner>);

impl std::fmt::Debug for HttpRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpRequest")
            .field("method", &self.0.method)
            .field("uri", &self.0.uri)
            .field("version", &self.0.version)
            .field("peer_addr", &self.0.peer_addr)
            .field("headers", &self.0.headers)
            .finish()
    }
}

/// Paramètres de connexion (`req.app_config()` chez actix).
#[derive(Debug, Clone)]
pub struct AppConfig {
    secure: bool,
    host: String,
    local_addr: Option<SocketAddr>,
}

impl AppConfig {
    pub fn secure(&self) -> bool {
        self.secure
    }
    pub fn host(&self) -> &str {
        &self.host
    }
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }
}

impl HttpRequest {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        method: Method,
        uri: Uri,
        version: Version,
        headers: HeaderMap,
        peer_addr: Option<SocketAddr>,
        local_addr: Option<SocketAddr>,
        secure: bool,
        app_data: Rc<Extensions>,
    ) -> Self {
        HttpRequest(Rc::new(Inner {
            method,
            uri,
            version,
            headers,
            peer_addr,
            local_addr,
            secure,
            app_data,
            app_data_override: None,
            extensions: RefCell::new(Extensions::new()),
            conn_info: OnceCell::new(),
            cookies: OnceCell::new(),
        }))
    }

    /// Requête dont `app_data` regarde d'abord `extra` (tests).
    pub(crate) fn with_app_data_override(self, extra: Rc<Extensions>) -> Self {
        match Rc::try_unwrap(self.0) {
            Ok(mut inner) => {
                inner.app_data_override = Some(extra);
                HttpRequest(Rc::new(inner))
            }
            Err(rc) => HttpRequest(rc),
        }
    }

    pub fn method(&self) -> &Method {
        &self.0.method
    }

    pub fn uri(&self) -> &Uri {
        &self.0.uri
    }

    pub fn path(&self) -> &str {
        self.0.uri.path()
    }

    pub fn query_string(&self) -> &str {
        self.0.uri.query().unwrap_or("")
    }

    pub fn version(&self) -> Version {
        self.0.version
    }

    pub fn headers(&self) -> &HeaderMap {
        &self.0.headers
    }

    /// Adresse du pair TCP (jamais déduite d'un en-tête).
    pub fn peer_addr(&self) -> Option<SocketAddr> {
        self.0.peer_addr
    }

    /// Adresse locale (et donc port) du socket qui a reçu la requête.
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.0.local_addr
    }

    pub fn app_config(&self) -> AppConfig {
        AppConfig {
            secure: self.0.secure,
            host: "localhost:8080".to_string(),
            local_addr: self.0.local_addr,
        }
    }

    pub fn connection_info(&self) -> &ConnectionInfo {
        self.0.conn_info.get_or_init(|| ConnectionInfo::new(self))
    }

    pub fn extensions(&self) -> Ref<'_, Extensions> {
        self.0.extensions.borrow()
    }

    pub fn extensions_mut(&self) -> RefMut<'_, Extensions> {
        self.0.extensions.borrow_mut()
    }

    /// Donnée enregistrée via `App::app_data`.
    pub fn app_data<T: 'static>(&self) -> Option<&T> {
        self.0
            .app_data_override
            .as_ref()
            .and_then(|o| o.get::<T>())
            .or_else(|| self.0.app_data.get::<T>())
    }

    /// Le cookie `name`, cherché dans toutes les lignes `Cookie`.
    pub fn cookie(&self, name: &str) -> Option<Cookie<'static>> {
        self.cookies().iter().find(|c| c.name() == name).cloned()
    }

    pub fn cookies(&self) -> &[Cookie<'static>] {
        self.0.cookies.get_or_init(|| self.parse_cookies())
    }

    fn parse_cookies(&self) -> Vec<Cookie<'static>> {
        let mut out = Vec::new();
        for hdr in self.0.headers.get_all(header::COOKIE) {
            let Ok(s) = hdr.to_str() else { continue };
            for part in s.split(';') {
                let part = part.trim();
                if part.is_empty() {
                    continue;
                }
                if let Ok(c) = Cookie::parse_encoded(part.to_owned()) {
                    out.push(c);
                }
            }
        }
        out
    }

    pub fn content_type(&self) -> &str {
        self.0
            .headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.split(';').next().unwrap_or("").trim())
            .unwrap_or("")
    }
}

/// Accès aux extensions — trait gardé pour les `use ...::HttpMessage`
/// existants.
pub trait HttpMessage {
    fn extensions(&self) -> Ref<'_, Extensions>;
    fn extensions_mut(&self) -> RefMut<'_, Extensions>;
}

impl HttpMessage for HttpRequest {
    fn extensions(&self) -> Ref<'_, Extensions> {
        HttpRequest::extensions(self)
    }
    fn extensions_mut(&self) -> RefMut<'_, Extensions> {
        HttpRequest::extensions_mut(self)
    }
}

// ─── ConnectionInfo ──────────────────────────────────────────────────

/// Même ordre de résolution qu'actix-web 4 : `Forwarded`, puis
/// `X-Forwarded-*`, puis la requête elle-même.
#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    host: String,
    scheme: String,
    realip_remote_addr: Option<String>,
    peer_addr: Option<String>,
}

fn first_header_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
}

fn unquote(s: &str) -> &str {
    s.trim().trim_matches('"')
}

impl ConnectionInfo {
    fn new(req: &HttpRequest) -> Self {
        let headers = req.headers();

        let mut fwd_host = None;
        let mut fwd_proto = None;
        let mut fwd_for = None;
        for hdr in headers.get_all(header::FORWARDED) {
            let Ok(val) = hdr.to_str() else { continue };
            for pair in val.split(';').flat_map(|s| s.split(',')) {
                let Some((name, value)) = pair.trim().split_once('=') else {
                    continue;
                };
                let value = unquote(value);
                match name.trim().to_ascii_lowercase().as_str() {
                    "for" if fwd_for.is_none() => fwd_for = Some(value.to_string()),
                    "proto" if fwd_proto.is_none() => fwd_proto = Some(value.to_ascii_lowercase()),
                    "host" if fwd_host.is_none() => fwd_host = Some(value.to_string()),
                    _ => {}
                }
            }
        }

        let scheme = fwd_proto
            .or_else(|| first_header_value(headers, "x-forwarded-proto").map(str::to_string))
            .or_else(|| req.uri().scheme_str().map(str::to_string))
            .unwrap_or_else(|| {
                if req.0.secure {
                    "https".to_string()
                } else {
                    "http".to_string()
                }
            });

        let host = fwd_host
            .or_else(|| first_header_value(headers, "x-forwarded-host").map(str::to_string))
            .or_else(|| {
                headers
                    .get(header::HOST)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string)
            })
            .or_else(|| req.uri().authority().map(|a| a.as_str().to_string()))
            .unwrap_or_else(|| req.app_config().host().to_string());

        let peer_addr = req.peer_addr().map(|a| a.ip().to_string());
        let realip_remote_addr = fwd_for
            .or_else(|| first_header_value(headers, "x-forwarded-for").map(str::to_string))
            .or_else(|| peer_addr.clone());

        ConnectionInfo {
            host,
            scheme,
            realip_remote_addr,
            peer_addr,
        }
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    /// ⚠️ Déduit d'en-têtes falsifiables — à n'utiliser que pour de
    /// l'affichage/journalisation, comme chez actix.
    pub fn realip_remote_addr(&self) -> Option<&str> {
        self.realip_remote_addr.as_deref()
    }

    pub fn peer_addr(&self) -> Option<&str> {
        self.peer_addr.as_deref()
    }
}
