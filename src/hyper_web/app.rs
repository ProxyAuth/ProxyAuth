//! Routage et chaîne de middlewares.
//!
//! `App` reproduit le sous-ensemble d'actix dont ProxyAuth se sert :
//! ressources à chemin exact, une route par méthode, un service par
//! défaut, des middlewares d'application (`wrap`) et de route
//! (`Route::wrap`, pour les limiteurs de débit).
//!
//! Sémantique conservée d'actix :
//! * les middlewares d'application s'exécutent dans l'ordre inverse de
//!   leur enregistrement (le dernier `wrap` est le plus extérieur) ;
//! * la première ressource enregistrée pour un chemin l'emporte ;
//! * un chemin connu avec une méthode non routée répond 405 (il ne
//!   tombe PAS dans le service par défaut) ;
//! * le chemin est comparé après « requote » (décodage des `%XX` sauf
//!   `%`, `/`, `+`), comme le routeur d'actix.

use super::error::Error;
use super::extract::{FromRequest, Payload};
use super::request::{Extensions, HttpRequest};
use super::response::{HttpResponse, Responder};
use futures_util::future::LocalBoxFuture;
use http::{HeaderMap, Method, StatusCode, Uri, Version};
use std::future::Future;
use std::ops::Deref;
use std::rc::Rc;

// ─── ServiceRequest / ServiceResponse ────────────────────────────────

/// Requête vue par un middleware : la requête + son corps non lu.
pub struct ServiceRequest {
    req: HttpRequest,
    payload: Payload,
}

impl ServiceRequest {
    pub fn new(req: HttpRequest, payload: Payload) -> Self {
        ServiceRequest { req, payload }
    }

    pub fn request(&self) -> &HttpRequest {
        &self.req
    }

    pub fn into_parts(self) -> (HttpRequest, Payload) {
        (self.req, self.payload)
    }

    pub fn from_parts(req: HttpRequest, payload: Payload) -> Self {
        ServiceRequest { req, payload }
    }

    /// Répond sans appeler la suite de la chaîne.
    pub fn into_response(self, res: HttpResponse) -> ServiceResponse {
        ServiceResponse::new(self.req, res)
    }

    pub fn error_response(self, err: impl Into<Error>) -> ServiceResponse {
        let res = err.into().error_response();
        ServiceResponse::new(self.req, res)
    }
}

impl Deref for ServiceRequest {
    type Target = HttpRequest;
    fn deref(&self) -> &HttpRequest {
        &self.req
    }
}

pub struct ServiceResponse {
    req: HttpRequest,
    res: HttpResponse,
}

impl ServiceResponse {
    pub fn new(req: HttpRequest, res: HttpResponse) -> Self {
        ServiceResponse { req, res }
    }
    pub fn request(&self) -> &HttpRequest {
        &self.req
    }
    pub fn response(&self) -> &HttpResponse {
        &self.res
    }
    pub fn response_mut(&mut self) -> &mut HttpResponse {
        &mut self.res
    }
    pub fn status(&self) -> StatusCode {
        self.res.status()
    }
    pub fn headers(&self) -> &HeaderMap {
        self.res.headers()
    }
    pub fn headers_mut(&mut self) -> &mut HeaderMap {
        self.res.headers_mut()
    }
    pub fn into_parts(self) -> (HttpRequest, HttpResponse) {
        (self.req, self.res)
    }
    pub fn into_response(self) -> HttpResponse {
        self.res
    }
    pub fn into_body(self) -> super::body::Body {
        self.res.into_body()
    }
    pub fn map_into_boxed_body(self) -> Self {
        self
    }
}

// ─── Middleware ──────────────────────────────────────────────────────

pub type ServiceFuture = LocalBoxFuture<'static, Result<ServiceResponse, Error>>;

type ServiceFn = dyn Fn(ServiceRequest) -> ServiceFuture;

/// La suite de la chaîne, appelable depuis un middleware.
#[derive(Clone)]
pub struct Next(Rc<ServiceFn>);

impl Next {
    pub fn call(&self, req: ServiceRequest) -> ServiceFuture {
        (self.0)(req)
    }

    fn from_fn(f: impl Fn(ServiceRequest) -> ServiceFuture + 'static) -> Self {
        Next(Rc::new(f))
    }
}

/// Un middleware reçoit la requête et `next`, et décide quand (et si)
/// appeler la suite. C'est l'équivalent compact du couple
/// `Transform`/`Service` d'actix.
pub trait Middleware: 'static {
    fn call(&self, req: ServiceRequest, next: Next) -> ServiceFuture;
}

fn wrap_with(mw: Rc<dyn Middleware>, inner: Next) -> Next {
    Next::from_fn(move |req| mw.call(req, inner.clone()))
}

// ─── Handlers ────────────────────────────────────────────────────────

/// Fonction asynchrone dont chaque argument est un extracteur.
pub trait Handler<Args>: Clone + 'static {
    type Output;
    type Future: Future<Output = Self::Output>;
    fn call(&self, args: Args) -> Self::Future;
}

macro_rules! handler_tuple {
    ($($T:ident),*) => {
        impl<Func, Fut, $($T,)*> Handler<($($T,)*)> for Func
        where
            Func: Fn($($T),*) -> Fut + Clone + 'static,
            Fut: Future,
        {
            type Output = Fut::Output;
            type Future = Fut;
            #[allow(non_snake_case)]
            fn call(&self, ($($T,)*): ($($T,)*)) -> Fut {
                (self)($($T),*)
            }
        }
    };
}

handler_tuple!();
handler_tuple!(A);
handler_tuple!(A, B);
handler_tuple!(A, B, C);
handler_tuple!(A, B, C, D);
handler_tuple!(A, B, C, D, E);

fn handler_service<F, Args>(handler: F) -> Next
where
    F: Handler<Args>,
    Args: FromRequest,
    F::Output: Responder,
{
    Next::from_fn(move |sreq: ServiceRequest| {
        let handler = handler.clone();
        Box::pin(async move {
            let (req, mut payload) = sreq.into_parts();
            let res = match Args::from_request(&req, &mut payload)
                .await
                .map_err(Into::<Error>::into)
            {
                Ok(args) => handler.call(args).await.respond_to(&req),
                Err(e) => e.error_response(),
            };
            Ok(ServiceResponse::new(req, res))
        })
    })
}

// ─── Route / Resource ────────────────────────────────────────────────

pub struct Route {
    method: Option<Method>,
    service: Option<Next>,
    middlewares: Vec<Rc<dyn Middleware>>,
}

impl Route {
    fn with_method(method: Option<Method>) -> Self {
        Route {
            method,
            service: None,
            middlewares: Vec::new(),
        }
    }

    pub fn to<F, Args>(mut self, handler: F) -> Self
    where
        F: Handler<Args>,
        Args: FromRequest,
        F::Output: Responder,
    {
        self.service = Some(handler_service(handler));
        self
    }

    pub fn wrap<M: Middleware>(mut self, mw: M) -> Self {
        self.middlewares.push(Rc::new(mw));
        self
    }

    fn build(self) -> Next {
        let mut svc = self.service.unwrap_or_else(|| {
            Next::from_fn(|req: ServiceRequest| {
                Box::pin(
                    async move { Ok(req.into_response(HttpResponse::new(StatusCode::NOT_FOUND))) },
                )
            })
        });
        for mw in self.middlewares {
            svc = wrap_with(mw, svc);
        }
        svc
    }
}

pub fn to<F, Args>(handler: F) -> Route
where
    F: Handler<Args>,
    Args: FromRequest,
    F::Output: Responder,
{
    Route::with_method(None).to(handler)
}

pub fn method(method: Method) -> Route {
    Route::with_method(Some(method))
}
pub fn get() -> Route {
    method(Method::GET)
}
pub fn post() -> Route {
    method(Method::POST)
}
pub fn put() -> Route {
    method(Method::PUT)
}
pub fn patch() -> Route {
    method(Method::PATCH)
}
pub fn delete() -> Route {
    method(Method::DELETE)
}
pub fn head() -> Route {
    method(Method::HEAD)
}

pub struct Resource {
    path: String,
    routes: Vec<Route>,
}

pub fn resource(path: &str) -> Resource {
    Resource {
        path: path.to_string(),
        routes: Vec::new(),
    }
}

impl Resource {
    pub fn route(mut self, route: Route) -> Self {
        self.routes.push(route);
        self
    }

    pub fn to<F, Args>(self, handler: F) -> Self
    where
        F: Handler<Args>,
        Args: FromRequest,
        F::Output: Responder,
    {
        self.route(to(handler))
    }
}

struct BuiltResource {
    path: String,
    routes: Vec<(Option<Method>, Next)>,
}

// ─── App ─────────────────────────────────────────────────────────────

pub struct App {
    app_data: Extensions,
    resources: Vec<Resource>,
    default: Option<Route>,
    middlewares: Vec<Rc<dyn Middleware>>,
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

impl App {
    pub fn new() -> Self {
        App {
            app_data: Extensions::new(),
            resources: Vec::new(),
            default: None,
            middlewares: Vec::new(),
        }
    }

    /// Donnée accessible par `req.app_data::<T>()` et par l'extracteur
    /// `web::Data<T>` (à enregistrer sous la forme `web::Data<T>`).
    pub fn app_data<T: 'static>(mut self, data: T) -> Self {
        self.app_data.insert(data);
        self
    }

    pub fn service(mut self, resource: Resource) -> Self {
        self.resources.push(resource);
        self
    }

    pub fn route(self, path: &str, route: Route) -> Self {
        self.service(resource(path).route(route))
    }

    pub fn default_service(mut self, route: Route) -> Self {
        self.default = Some(route);
        self
    }

    pub fn wrap<M: Middleware>(mut self, mw: M) -> Self {
        self.middlewares.push(Rc::new(mw));
        self
    }

    /// Fige l'application : à faire une fois par worker.
    pub fn into_service(self) -> AppService {
        let resources: Vec<BuiltResource> = self
            .resources
            .into_iter()
            .map(|r| BuiltResource {
                path: r.path,
                routes: r
                    .routes
                    .into_iter()
                    .map(|route| (route.method.clone(), route.build()))
                    .collect(),
            })
            .collect();
        let default = self.default.map(Route::build).unwrap_or_else(|| {
            Next::from_fn(|req: ServiceRequest| {
                Box::pin(
                    async move { Ok(req.into_response(HttpResponse::new(StatusCode::NOT_FOUND))) },
                )
            })
        });

        let router = Rc::new(Router { resources, default });
        let mut svc = Next::from_fn(move |req: ServiceRequest| router.dispatch(req));
        // Premier enregistré = plus intérieur ; dernier = plus extérieur.
        for mw in self.middlewares {
            svc = wrap_with(mw, svc);
        }

        AppService {
            app_data: Rc::new(self.app_data),
            service: svc,
        }
    }
}

struct Router {
    resources: Vec<BuiltResource>,
    default: Next,
}

impl Router {
    fn dispatch(&self, req: ServiceRequest) -> ServiceFuture {
        let path = requote_path(req.path());
        if let Some(res) = self.resources.iter().find(|r| r.path == path) {
            let method = req.method().clone();
            return match res
                .routes
                .iter()
                .find(|(m, _)| m.as_ref().is_none_or(|m| *m == method))
            {
                Some((_, svc)) => svc.call(req),
                None => Box::pin(async move {
                    Ok(req.into_response(HttpResponse::new(StatusCode::METHOD_NOT_ALLOWED)))
                }),
            };
        }
        self.default.call(req)
    }
}

/// Décode les `%XX` sauf ceux qui changeraient la structure du chemin
/// (`%`, `/`, `+`) — même règle que le `Quoter` du routeur d'actix.
pub(crate) fn requote_path(path: &str) -> std::borrow::Cow<'_, str> {
    if !path.contains('%') {
        return std::borrow::Cow::Borrowed(path);
    }
    let bytes = path.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = |b: u8| (b as char).to_digit(16).map(|d| d as u8);
            if let (Some(h), Some(l)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                let c = h * 16 + l;
                if c != b'%' && c != b'/' && c != b'+' {
                    out.push(c);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    match String::from_utf8(out) {
        Ok(s) => std::borrow::Cow::Owned(s),
        Err(_) => std::borrow::Cow::Borrowed(path),
    }
}

/// Application figée d'un worker.
#[derive(Clone)]
pub struct AppService {
    app_data: Rc<Extensions>,
    service: Next,
}

impl AppService {
    pub fn app_data(&self) -> Rc<Extensions> {
        self.app_data.clone()
    }

    /// Construit la `HttpRequest` liée à cette application.
    #[allow(clippy::too_many_arguments)]
    pub fn make_request(
        &self,
        method: Method,
        uri: Uri,
        version: Version,
        headers: HeaderMap,
        peer_addr: Option<std::net::SocketAddr>,
        local_addr: Option<std::net::SocketAddr>,
        secure: bool,
    ) -> HttpRequest {
        HttpRequest::new(
            method,
            uri,
            version,
            headers,
            peer_addr,
            local_addr,
            secure,
            self.app_data.clone(),
        )
    }

    pub async fn call(&self, req: ServiceRequest) -> ServiceResponse {
        let http_req = req.request().clone();
        match self.service.call(req).await {
            Ok(res) => res,
            Err(e) => ServiceResponse::new(http_req, e.error_response()),
        }
    }
}
