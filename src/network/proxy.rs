use crate::config::config::BackendConfig;
use crate::config::config::BackendInput;
use crate::config::config::RouteRule;
use crate::network::canonical_url::canonicalize_path_for_match;
use crate::network::loadbalancing::forward_failover;
use crate::network::shared_client::{
    BoxBody, ClientOptions, get_or_build_client, get_or_build_client_proxy,
};
use crate::token::csrf::{fix_mime_actix, inject_csrf_token, validate_csrf_token};
use crate::token::security::apply_filters_regex_allow_only;
use crate::token::security::validate_token;
use crate::{AppConfig, AppState};
use actix_web::{
    Error, HttpRequest, HttpResponse, HttpResponseBuilder, error, http::StatusCode, http::header,
    web,
};
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::{Bytes, Incoming};
use hyper::header::USER_AGENT;
use hyper::http::request::Builder;
use hyper::{Method, Request, Uri};
use ipnet::IpNet;
use once_cell::sync::Lazy;
use regex::Regex;
use std::convert::Infallible;
use std::net::IpAddr;
use std::path::Path;
use std::str::FromStr;
use std::sync::RwLock;
use tokio::time::{Duration, timeout};
use tracing::{info, warn};

static ORDERED_ROUTE_IDX: Lazy<RwLock<Option<Vec<usize>>>> = Lazy::new(|| RwLock::new(None));

fn to_actix_status(s: hyper::StatusCode) -> actix_web::http::StatusCode {
    actix_web::http::StatusCode::from_u16(s.as_u16())
        .unwrap_or(actix_web::http::StatusCode::INTERNAL_SERVER_ERROR)
}

fn norm_len(prefix: &str) -> usize {
    if prefix == "/" {
        0
    } else {
        prefix.trim_end_matches('/').len()
    }
}

fn is_method_allowed(allowed: Option<&[String]>, method: &str) -> bool {
    match allowed {
        None => true,
        Some(list) => list.iter().any(|s| {
            let t = s.trim();
            t == "*" || t.eq_ignore_ascii_case(method)
        }),
    }
}

// Localhost is always trusted, regardless of config — this covers the
// common case where nginx runs on the same host as proxyauth, and avoids
// a misconfiguration (empty/missing trust_proxy_forward_for) from silently
// breaking local setups.
static ALWAYS_TRUSTED: Lazy<Vec<IpNet>> = Lazy::new(|| {
    vec![
        "127.0.0.0/8".parse().unwrap(), // IPv4 loopback range
        "::1/128".parse().unwrap(),     // IPv6 loopback
    ]
});

fn build_allow_header(allowed: Option<&[String]>) -> String {
    const ALL: &str = "GET, HEAD, POST, PUT, DELETE, PATCH, OPTIONS";
    match allowed {
        None => ALL.to_string(),
        Some(list) => {
            if list.iter().any(|s| s.trim() == "*") {
                return ALL.to_string();
            }
            let mut v: Vec<String> = list
                .iter()
                .map(|s| s.trim().to_ascii_uppercase())
                .filter(|s| !s.is_empty())
                .collect();
            v.sort();
            v.dedup();
            if !v.iter().any(|s| s == "OPTIONS") {
                v.push("OPTIONS".into());
                v.sort();
                v.dedup();
            }
            v.join(", ")
        }
    }
}

fn canonicalize_prefix(prefix: &str) -> String {
    let p = if prefix.is_empty() { "/" } else { prefix };
    let p = p.trim_end_matches('/');
    if p.is_empty() {
        "/".to_string()
    } else {
        canonicalize_path_for_match(p)
    }
}

pub fn compile_filters_on_routes(routes: &mut [RouteRule]) {
    for r in routes.iter_mut() {
        r.filters_compiled = match &r.filters {
            Some(cfg) => cfg.compile().ok(),
            None => None,
        };
    }
}

/// Parses `allow_ips`/`deny_ips` into `IpNet`s once at startup, so the
/// hot request path just does a `.contains()` check instead of
/// re-parsing strings on every proxied request.
///
/// An entry that fails to parse is a **fatal** config error (panics
/// with the offending route/field/value) rather than a warning the
/// entry gets silently dropped for: a `routes.yml` typo in a CIDR
/// should never boot up with that restriction quietly not applied —
/// that would expose a route its author explicitly meant to lock down,
/// which is worse than refusing to start.
pub fn compile_ip_lists_on_routes(routes: &mut [RouteRule]) {
    fn parse_all(prefix: &str, field: &str, entries: &[String]) -> Vec<IpNet> {
        entries
            .iter()
            .map(|entry| {
                entry
                    .parse::<IpNet>()
                    .or_else(|_| entry.parse::<IpAddr>().map(IpNet::from))
                    .unwrap_or_else(|_| {
                        panic!(
                            "routes.yml: route \"{prefix}\": invalid entry \"{entry}\" in `{field}` — expected an IP address (e.g. \"10.0.0.5\") or a CIDR network (e.g. \"192.168.1.0/24\")"
                        )
                    })
            })
            .collect()
    }

    for r in routes.iter_mut() {
        r.allow_ips_compiled = parse_all(&r.prefix, "allow_ips", &r.allow_ips);
        r.deny_ips_compiled = parse_all(&r.prefix, "deny_ips", &r.deny_ips);
    }
}

/// `deny_ips` wins over `allow_ips`: a client matching a deny entry is
/// always rejected, even if it would also match an allow entry. An
/// empty `allow_ips` means "no allow-list restriction" — everyone not
/// denied gets through, exactly like every route behaved before these
/// fields existed. If the route configured either list but the
/// client's IP couldn't be determined at all, this fails closed
/// (rejects) rather than silently letting an unidentifiable client in.
fn ip_allowed(ip: Option<IpAddr>, rule: &RouteRule) -> bool {
    if rule.allow_ips_compiled.is_empty() && rule.deny_ips_compiled.is_empty() {
        return true;
    }
    let Some(ip) = ip else {
        return false;
    };
    if rule.deny_ips_compiled.iter().any(|net| net.contains(&ip)) {
        return false;
    }
    if rule.allow_ips_compiled.is_empty() {
        return true;
    }
    rule.allow_ips_compiled.iter().any(|net| net.contains(&ip))
}

pub fn init_routes_order(routes: &[RouteRule]) {
    *ORDERED_ROUTE_IDX.write().unwrap() = Some(build_route_order(routes));
}

pub fn init_routes(routes: &mut [RouteRule]) {
    compile_filters_on_routes(routes);
    compile_ip_lists_on_routes(routes);
    compile_regex_on_routes(routes);
    init_routes_order(routes);
}

fn matches_prefix(path: &str, prefix: &str) -> bool {
    let path_norm = canonicalize_path_for_match(path);
    let pref_norm = canonicalize_prefix(prefix);
    if pref_norm == "/" {
        return true;
    }
    path_norm == pref_norm || path_norm.starts_with(&(pref_norm.clone() + "/"))
}

/// Parses `regex` (when set) into a compiled `Regex`, so the hot
/// request path just matches against it instead of recompiling the
/// pattern on every request — ProxyAuth's equivalent of nginx's
/// `location ~ pattern { ... }`. Like `allow_ips`/`deny_ips`, an
/// invalid pattern is a fatal startup error rather than a silently
/// disabled route.
pub fn compile_regex_on_routes(routes: &mut [RouteRule]) {
    for r in routes.iter_mut() {
        r.regex_compiled = r.regex.as_deref().map(|pattern| {
            Regex::new(pattern).unwrap_or_else(|e| {
                panic!(
                    "routes.yml: route \"{}\": invalid `regex` \"{pattern}\": {e}",
                    r.prefix
                )
            })
        });
    }
}

/// Whether `rule` matches `path` — a compiled `regex` takes over
/// entirely for a regex route (searched anywhere in the path, same as
/// nginx's PCRE locations; anchor with `^`/`$` yourself for an exact
/// match), otherwise the usual longest-prefix rule applies.
/// Substitutes `{name}` placeholders in `template` with `re`'s named
/// capture groups matched against `path`. A placeholder whose group
/// didn't participate in the match (or isn't a named group at all) is
/// left as literal text — makes a misconfigured template obvious in
/// the resulting URL/path instead of silently vanishing.
fn build_regex_target(re: &Regex, template: &str, path: &str) -> String {
    let Some(caps) = re.captures(path) else {
        return template.to_string();
    };
    let mut result = template.to_string();
    for name in re.capture_names().flatten() {
        if let Some(m) = caps.name(name) {
            result = result.replace(&format!("{{{name}}}"), m.as_str());
        }
    }
    result
}

/// The scheme+host+port `s` would resolve to, applying the same
/// "assume http:// if no scheme was given" normalization the rest of
/// the target-building code uses. `None` if `s` doesn't parse as a URI
/// at all.
fn authority_of(s: &str) -> Option<String> {
    let normalized = if s.starts_with("http://") || s.starts_with("https://") {
        s.to_string()
    } else {
        format!("http://{s}")
    };
    Uri::from_str(&normalized)
        .ok()
        .and_then(|u| u.authority().map(|a| a.to_string()))
}

/// Guards against a regex capture smuggling a *different host* into a
/// rewritten `target` — e.g. a capture containing `@evil.com` landing
/// right after the authority turns `http://backend/{x}` into
/// `http://backend@evil.com/...`, which a URI parser reads as
/// "userinfo=backend, host=evil.com": a captured value from the
/// client's own request path ends up choosing where the request is
/// sent. Comparing the rewritten URL's authority against the
/// template's own literal authority catches this regardless of which
/// special character (`@`, a stray `:port`, ...) did it — a capture is
/// only ever allowed to affect the *path*, never the host.
fn target_authority_tampered(original_target: &str, rewritten: &str) -> bool {
    authority_of(rewritten) != authority_of(original_target)
}

fn matches_route(path: &str, rule: &RouteRule) -> bool {
    match &rule.regex_compiled {
        Some(re) => re.is_match(path),
        None => matches_prefix(path, &rule.prefix),
    }
}

/// Route evaluation order: every `regex` route is tried first, in the
/// order it appears in `routes.yml` (first match wins, like nginx
/// tries regex locations in file order and takes the first that
/// matches) — then every plain-prefix route, longest prefix first,
/// exactly as before `regex` existed. Shared by `init_routes_order`
/// (the common case, precomputed once) and `match_route_idx`'s
/// fallback for when that cache isn't ready yet.
fn build_route_order(routes: &[RouteRule]) -> Vec<usize> {
    let mut idx: Vec<usize> = (0..routes.len()).collect();
    idx.sort_by(|&i, &j| {
        let ri = routes[i].regex_compiled.is_some();
        let rj = routes[j].regex_compiled.is_some();
        match (ri, rj) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            (true, true) => i.cmp(&j),
            (false, false) => {
                let pi = routes[i].prefix.as_str();
                let pj = routes[j].prefix.as_str();
                let root_i = pi == "/";
                let root_j = pj == "/";
                match (root_i, root_j) {
                    (true, false) => std::cmp::Ordering::Greater,
                    (false, true) => std::cmp::Ordering::Less,
                    _ => {
                        let li = norm_len(pi);
                        let lj = norm_len(pj);
                        if li != lj { lj.cmp(&li) } else { pi.cmp(pj) }
                    }
                }
            }
        }
    });
    idx
}

/// Strips a trailing `:port` from a `Host` header value and lowercases
/// the result, so `App.Example.com:8443` and `app.example.com` compare
/// equal. IPv6 literals (`[::1]:8443`) are left as-is except for the
/// trailing port, since hostnames in `vhost` are never expected to be
/// bracketed IPv6 addresses.
fn normalize_host(host: &str) -> String {
    let without_port = if host.starts_with('[') {
        match host.rfind(']') {
            Some(end) => &host[..=end],
            None => host,
        }
    } else {
        match host.rfind(':') {
            Some(pos) => &host[..pos],
            None => host,
        }
    };
    without_port.trim().to_ascii_lowercase()
}

/// A route with an empty `vhost` list is a catch-all — it matches
/// regardless of the request's `Host` header, preserving the behavior
/// every `routes.yml` had before `vhost` existed. A non-empty list
/// requires an exact (case-insensitive, port-stripped) match against
/// one of its entries.
fn vhost_matches(host: Option<&str>, vhosts: &[String]) -> bool {
    if vhosts.is_empty() {
        return true;
    }
    let Some(host) = host else {
        return false;
    };
    let host_norm = normalize_host(host);
    vhosts.iter().any(|v| normalize_host(v) == host_norm)
}

/// Extracts and normalizes the `Host` the request came in on, from
/// either the `Host` header or the request's connection info (which
/// also accounts for `X-Forwarded-Host` when actix is configured to
/// trust it). Returns `None` when no host is present at all, in which
/// case only vhost-less (catch-all) routes can match.
pub fn request_host(req: &HttpRequest) -> Option<String> {
    let host = req.connection_info().host().to_string();
    if host.is_empty() { None } else { Some(host) }
}

/// Finds the best route for `raw_path`/`host`.
///
/// Candidates are first narrowed to routes whose `vhost` matches the
/// request's `Host` header (or that have no `vhost` at all, i.e.
/// catch-all routes) — then, among those, the existing longest-prefix
/// rule picks the winner, in the precomputed order from
/// `init_routes_order` when available. A vhost-scoped route and a
/// catch-all route can share the same prefix: whichever is reached
/// first in prefix-length order wins, so put the more specific one
/// first in `routes.yml` if both could otherwise match.
pub fn match_route_idx(raw_path: &str, host: Option<&str>, routes: &[RouteRule]) -> Option<usize> {
    {
        let guard = ORDERED_ROUTE_IDX.read().unwrap();
        if let Some(order) = guard.as_ref() {
            if order.iter().all(|&i| i < routes.len()) {
                for &i in order {
                    if vhost_matches(host, &routes[i].vhost) && matches_route(raw_path, &routes[i])
                    {
                        return Some(i);
                    }
                }
                return None;
            }
        }
    }

    let idx = build_route_order(routes);
    for &i in &idx {
        if vhost_matches(host, &routes[i].vhost) && matches_route(raw_path, &routes[i]) {
            return Some(i);
        }
    }
    None
}

#[allow(dead_code)]
pub fn match_route<'a>(
    raw_path: &str,
    host: Option<&str>,
    routes: &'a [RouteRule],
) -> Option<&'a RouteRule> {
    match_route_idx(raw_path, host, routes).map(|i| &routes[i])
}

pub fn inject_header(mut builder: Builder, username: &str, config: &AppConfig) -> Builder {
    if username.is_empty() {
        return builder;
    }
    if let Ok(val) = hyper::header::HeaderValue::from_str(username) {
        builder = builder.header("x-user", val);
    }
    // Looked up directly by username — does NOT clone the whole user
    // list (unlike combined_users()), since this runs on every proxied
    // request and only ever needs a single user's roles.
    if let Some(roles) = config.roles_for_username(username) {
        let roles_str = roles.join(",");
        if let Ok(val) = hyper::header::HeaderValue::from_str(&roles_str) {
            builder = builder.header("x-user-roles", val);
        }
    }
    // Same lookup, for group membership — lets the backend see which
    // of a user's groups granted them access (or just use it for its
    // own authorization), the same way it already can with roles.
    if let Some(groups) = config.groups_for_username(username) {
        let groups_str = groups.join(",");
        if let Ok(val) = hyper::header::HeaderValue::from_str(&groups_str) {
            builder = builder.header("x-groups", val);
        }
    }
    builder
}

fn is_secure_request(req: &HttpRequest, config: &AppConfig) -> bool {
    if is_trusted_peer(req, config) {
        // Trusted proxy (e.g. local nginx) already terminated TLS and is
        // telling us the original scheme was https — trust it.
        req.connection_info().scheme() == "https"
    } else {
        // Untrusted / direct connection: ignore all forwarding headers.
        // Use the actual TLS state of the socket proxyauth is listening on.
        req.app_config().secure()
    }
}

/// RFC 9110 §7.6.1 hop-by-hop / connection-framing headers. These must
/// never be relayed as-is across a proxy boundary — each hop is expected
/// to generate its own framing headers based on how it actually sends the
/// message, not copy them from the previous hop. Comparison is
/// case-insensitive by construction since callers already pass
/// `HeaderName::as_str()`, which is always lowercase.
pub(crate) fn is_hop_by_hop_header(name: &str) -> bool {
    matches!(
        name,
        "connection"
            | "content-length"
            | "transfer-encoding"
            | "te"
            | "trailer"
            | "upgrade"
            | "keep-alive"
            | "proxy-connection"
            | "proxy-authenticate"
            | "proxy-authorization"
    )
}

fn is_trusted_peer(req: &HttpRequest, config: &AppConfig) -> bool {
    let Some(peer_ip) = req.peer_addr().map(|addr| addr.ip()) else {
        return false;
    };

    // Always trust loopback, no matter what the config says
    if ALWAYS_TRUSTED.iter().any(|net| net.contains(&peer_ip)) {
        return true;
    }

    // Then check the configurable list for anything beyond localhost
    // (e.g. an internal LB/nginx host on a different machine)
    match &config.trust_proxy_forward_for {
        None => false,
        Some(trusted) => trusted.iter().any(|entry| {
            entry.parse::<IpAddr>().map_or(false, |ip| ip == peer_ip)
                || entry
                    .parse::<IpNet>()
                    .map_or(false, |net| net.contains(&peer_ip))
        }),
    }
}

pub fn client_ip(req: &HttpRequest, config: &AppConfig) -> Option<IpAddr> {
    let peer_ip = req.peer_addr().map(|addr| addr.ip());

    if is_trusted_peer(req, config) {
        if let Some(ip) = req
            .headers()
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.split(',').next())
            .and_then(|s| s.trim().parse::<IpAddr>().ok())
        {
            return Some(ip);
        }
        if let Some(ip) = req
            .headers()
            .get("x-real-ip")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.trim().parse::<IpAddr>().ok())
        {
            return Some(ip);
        }
    }

    peer_ip
}

async fn incoming_to_boxbody(
    res: hyper::Response<Incoming>,
) -> Result<hyper::Response<BoxBody>, hyper::Error> {
    let (parts, body) = res.into_parts();
    let bytes = body.collect().await?.to_bytes();
    let boxed: BoxBody = Full::new(bytes).map_err(|e: Infallible| e).boxed();
    Ok(hyper::Response::from_parts(parts, boxed))
}

/// Very small extension → MIME map, good enough for the kind of static
/// assets `static` is meant for (docs sites, SPA builds, downloads).
/// Anything unrecognized falls back to `application/octet-stream`
/// rather than a guess — serving an unknown file as `text/*` risks the
/// browser sniffing it as HTML and executing it (stored XSS via file
/// upload/download endpoints), which a wrong-but-inert binary MIME type
/// avoids.
fn guess_content_type(path: &Path) -> &'static str {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    match ext.as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "json" | "map" => "application/json; charset=utf-8",
        "xml" => "application/xml; charset=utf-8",
        "txt" => "text/plain; charset=utf-8",
        "csv" => "text/csv; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        "wasm" => "application/wasm",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        "gz" => "application/gzip",
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        _ => "application/octet-stream",
    }
}

/// Resolves `req_path` against `rule.static_path` and serves the
/// file(s) — ProxyAuth's equivalent of nginx's `root`/`alias`. Uses
/// `tokio::fs` (which itself runs the blocking syscalls on a
/// background thread pool), so this never blocks the async worker.
///
/// `static_path` can point at a single file — served as-is for every
/// request under this route, ignoring the rest of the path — or at a
/// directory, in which case the remainder of the request path (after
/// stripping this route's `prefix`) is resolved inside it, falling
/// back to `static_index` for directory-shaped requests.
///
/// Path-traversal safety (directory mode): the root is canonicalized
/// once up front; the candidate file is canonicalized too (resolving
/// any `..`/symlinks), and the result must still start with the
/// canonical root or the request is rejected outright. A raw `..`
/// segment is also rejected before ever touching the filesystem, as a
/// cheap first line of defense.
/// Turns a filesystem error from serving a static file into the right
/// response, and — for the case actually worth an admin's attention —
/// a log line that says so plainly. A permission error almost always
/// means the `proxyauth` user itself can't read the path (missing
/// read, or missing execute/traverse on a parent directory), which
/// looks identical to a 404 otherwise and is easy to mistake for a
/// typo'd path instead of a permissions problem.
fn static_read_error_response(prefix: &str, path: &Path, e: &std::io::Error) -> HttpResponse {
    if e.kind() == std::io::ErrorKind::PermissionDenied {
        warn!(
            "static route \"{prefix}\": permission denied reading {} — the \"proxyauth\" user needs read (and, for directories, execute/traverse) access to this path",
            path.display()
        );
        HttpResponse::InternalServerError()
            .append_header(("server", "ProxyAuth"))
            .body("500 Internal Server Error")
    } else {
        HttpResponse::NotFound()
            .append_header(("server", "ProxyAuth"))
            .body("404 Not Found")
    }
}

async fn serve_static_file(rule: &RouteRule, req_path: &str) -> HttpResponse {
    let Some(static_path) = rule.static_path.as_deref() else {
        return HttpResponse::InternalServerError()
            .append_header(("server", "ProxyAuth"))
            .body("500 Internal Server Error");
    };

    let root = match tokio::fs::canonicalize(static_path).await {
        Ok(p) => p,
        Err(e) => {
            warn!(
                "static \"{}\" (route \"{}\") is not readable: {e}",
                static_path, rule.prefix
            );
            return HttpResponse::InternalServerError()
                .append_header(("server", "ProxyAuth"))
                .body("500 Internal Server Error");
        }
    };

    let root_is_file = match tokio::fs::metadata(&root).await {
        Ok(m) => m.is_file(),
        Err(e) => {
            return static_read_error_response(&rule.prefix, &root, &e);
        }
    };

    // Single-file mode: this route always serves exactly this file,
    // whatever the request path under `prefix` looks like — like
    // nginx's `alias` pointing straight at one file (e.g. a fixed
    // `/robots.txt` or `/favicon.ico` route).
    if root_is_file {
        return match tokio::fs::read(&root).await {
            Ok(bytes) => HttpResponse::Ok()
                .append_header(("server", "ProxyAuth"))
                .content_type(guess_content_type(&root))
                .body(bytes),
            Err(e) => static_read_error_response(&rule.prefix, &root, &e),
        };
    }

    // Directory mode.
    let remainder_owned;
    let remainder: &str = if let Some(re) = &rule.regex_compiled {
        // Regex route: there's no `prefix` to strip — the subpath under
        // `static` comes from `static_rewrite`, filled in from the
        // regex's named captures (nginx's `$name` rewrite equivalent).
        // No template configured just means "serve the directory
        // itself" (falls through to `static_index` below).
        match &rule.static_rewrite {
            Some(tpl) => {
                remainder_owned = build_regex_target(re, tpl, req_path);
                remainder_owned
                    .trim_start_matches('/')
                    .trim_end_matches('/')
            }
            None => "",
        }
    } else {
        let prefix_norm = canonicalize_prefix(&rule.prefix);
        if prefix_norm == "/" {
            req_path.trim_start_matches('/')
        } else {
            req_path
                .strip_prefix(&prefix_norm)
                .unwrap_or(req_path)
                .trim_start_matches('/')
        }
    };

    if remainder.split('/').any(|seg| seg == "..") {
        return HttpResponse::Forbidden()
            .append_header(("server", "ProxyAuth"))
            .body("403 Forbidden");
    }

    let mut candidate = root.join(remainder);

    let is_dir = tokio::fs::metadata(&candidate)
        .await
        .map(|m| m.is_dir())
        .unwrap_or(false);
    if is_dir || remainder.is_empty() {
        candidate = candidate.join(&rule.static_index);
    }

    let resolved = match tokio::fs::canonicalize(&candidate).await {
        Ok(p) => p,
        Err(e) => {
            return static_read_error_response(&rule.prefix, &candidate, &e);
        }
    };

    if !resolved.starts_with(&root) {
        warn!(
            "blocked path-traversal attempt on route \"{}\": {} resolved outside {}",
            rule.prefix,
            candidate.display(),
            root.display()
        );
        return HttpResponse::Forbidden()
            .append_header(("server", "ProxyAuth"))
            .body("403 Forbidden");
    }

    match tokio::fs::read(&resolved).await {
        Ok(bytes) => HttpResponse::Ok()
            .append_header(("server", "ProxyAuth"))
            .content_type(guess_content_type(&resolved))
            .body(bytes),
        Err(e) => static_read_error_response(&rule.prefix, &resolved, &e),
    }
}

/// Minimal `required_login` gate for static routes: the same
/// Bearer-token / session-cookie extraction and
/// `AppConfig::route_access_decision` check the proxied routes use,
/// trimmed down — no CSRF (irrelevant to serving a file) and no "/"
/// login-redirect special case. `Ok(())` means the request may proceed;
/// `Err(resp)` is the response to send back instead.
async fn check_static_auth(
    req: &HttpRequest,
    data: &web::Data<AppState>,
    rule: &RouteRule,
    ip: &str,
) -> Result<(), HttpResponse> {
    if !rule.required_login {
        return Ok(());
    }

    let token_header = req
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .or_else(|| {
            if !is_secure_request(req, &data.config) {
                return None;
            }
            req.headers()
                .get(header::COOKIE)
                .and_then(|val| val.to_str().ok())
                .and_then(|cookie_str| {
                    cookie_str.split(';').find_map(|cookie| {
                        let cookie = cookie.trim();
                        let (key, value) = cookie.split_once('=')?;
                        if key.trim() == "session_token" {
                            Some(value.trim())
                        } else {
                            None
                        }
                    })
                })
        });

    let Some(token_header) = token_header else {
        return Err(HttpResponse::Unauthorized()
            .append_header(("server", "ProxyAuth"))
            .body("401 Unauthorized"));
    };

    let username = match validate_token(token_header, data, &data.config, ip).await {
        Ok((username, _token_id, _expiry)) => username,
        Err(_) => {
            return Err(HttpResponse::Unauthorized()
                .append_header(("server", "ProxyAuth"))
                .append_header((
                    "Set-Cookie",
                    "session_token=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict",
                ))
                .body("401 Unauthorized"));
        }
    };

    if !data
        .config
        .route_access_decision(rule, &username)
        .is_allowed()
    {
        return Err(HttpResponse::Unauthorized()
            .append_header(("server", "ProxyAuth"))
            .body("401 Unauthorized"));
    }

    Ok(())
}

pub async fn global_proxy(
    req: HttpRequest,
    body: web::Bytes,
    data: web::Data<AppState>,
) -> Result<HttpResponse, Error> {
    // Checked before anything else — including CORS preflight — so a
    // known-abusive IP never gets any response beyond a flat 403,
    // regardless of which route or method it's trying.
    if let Some(ip) = client_ip(&req, &data.config) {
        if data.ip_blocklist.load().iter().any(|net| net.contains(&ip)) {
            warn!(
                "{} 403 {} {} — blocked by ip_blocklist",
                ip,
                req.method(),
                req.path()
            );
            return Ok(HttpResponse::Forbidden()
                .append_header(("server", "ProxyAuth"))
                .body("403 Forbidden"));
        }
    }

    if req.method() == actix_web::http::Method::OPTIONS {
        let origin_header = req.headers().get(header::ORIGIN);
        let origin = origin_header.and_then(|v| v.to_str().ok());
        let allowed = data.config.cors_origins.as_ref();
        let is_allowed = match (origin, allowed) {
            (Some(o), Some(list)) => {
                let origin_normalized = o.trim_end_matches('/');
                list.iter()
                    .any(|allowed| allowed.trim_end_matches('/') == origin_normalized)
            }
            _ => false,
        };

        if let (Some(origin_str), true) = (origin, is_allowed) {
            return Ok(HttpResponse::Ok()
                .insert_header((header::ACCESS_CONTROL_ALLOW_ORIGIN, origin_str))
                .insert_header((
                    header::ACCESS_CONTROL_ALLOW_METHODS,
                    "GET, HEAD, POST, PUT, DELETE, OPTIONS",
                ))
                .insert_header((
                    header::ACCESS_CONTROL_ALLOW_HEADERS,
                    "Authorization, Content-Type, Accept",
                ))
                .insert_header((header::ACCESS_CONTROL_MAX_AGE, "3600"))
                .finish());
        } else {
            return Ok(HttpResponse::Forbidden().body("CORS origin not allowed"));
        }
    }

    let path = req.path();
    let method = req.method().as_str();
    let ip = req
        .peer_addr()
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|| "-".to_string());
    let user_agent = req
        .headers()
        .get("User-Agent")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("-");

    // UX: session_cookie mode only. If the visitor already has a valid
    // session and lands on the home page or wherever logout_redirect_url
    // points, skip straight into the app instead of showing that page as
    // if they were logged out — landing on a "logged out"/home page while
    // still actually authenticated is confusing. Any other path is left
    // completely untouched (still goes through normal routes.yml matching
    // below), so this only affects these two specific landing pages.
    if data.config.session_cookie {
        let is_home_or_logout_page =
            path == "/" || data.config.logout_redirect_url.as_deref() == Some(path);
        if is_home_or_logout_page {
            if let Some(resp) =
                crate::token::auth::existing_session_response(&req, &data, &ip).await
            {
                return Ok(resp);
            }
        }
    }

    data.stats.incr();

    let host = request_host(&req);
    if let Some(idx) = match_route_idx(path, host.as_deref(), &data.routes.routes) {
        let rule = &data.routes.routes[idx];
        let has_ip_restriction =
            !rule.allow_ips_compiled.is_empty() || !rule.deny_ips_compiled.is_empty();
        if has_ip_restriction {
            let resolved_ip = client_ip(&req, &data.config);
            if !ip_allowed(resolved_ip, rule) {
                warn!(
                    "{} 403 {} {} {} — blocked by allow_ips/deny_ips on route \"{}\"",
                    resolved_ip
                        .map(|i| i.to_string())
                        .unwrap_or_else(|| "-".to_string()),
                    method,
                    path,
                    user_agent,
                    rule.prefix
                );
                return Ok(HttpResponse::Forbidden()
                    .append_header(("server", "ProxyAuth"))
                    .body("403 Forbidden"));
            }
        }

        let use_proxy = rule.proxy;
        if rule.static_path.is_some() {
            let ip_str = client_ip(&req, &data.config)
                .map(|i| i.to_string())
                .unwrap_or_else(|| "-".to_string());
            if let Err(resp) = check_static_auth(&req, &data, rule, &ip_str).await {
                return Ok(resp);
            }
            if method != "GET" && method != "HEAD" {
                return Ok(HttpResponse::MethodNotAllowed()
                    .append_header(("server", "ProxyAuth"))
                    .append_header(("Allow", "GET, HEAD"))
                    .body("405 Method Not Allowed"));
            }
            return Ok(serve_static_file(rule, path).await);
        }
        if use_proxy {
            proxy_with_proxy(req, body, data, idx).await
        } else {
            proxy_without_proxy(req, body, data, idx).await
        }
    } else {
        info!("{} 404 {} {} {}", ip, method, path, user_agent);
        Ok(HttpResponse::NotFound()
            .append_header(("server", "ProxyAuth"))
            .body("404 Not Found"))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Proxy SOCKS/HTTP upstream proxy
// ─────────────────────────────────────────────────────────────────────────────
pub async fn proxy_with_proxy(
    req: HttpRequest,
    body: web::Bytes,
    data: web::Data<AppState>,
    route_idx: usize,
) -> Result<HttpResponse, Error> {
    let rule = &data.routes.routes[route_idx];

    let path = req.path();
    let ip = client_ip(&req, &data.config)
        .unwrap_or(IpAddr::from([127, 0, 0, 1]))
        .to_string();
    let method_str = req.method().as_str();
    let user_agent = req
        .headers()
        .get("User-Agent")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("-");

    let add_cors_headers = |resp: &mut HttpResponseBuilder, req: &HttpRequest| {
        if let Some(origin) = req
            .headers()
            .get(header::ORIGIN)
            .and_then(|v| v.to_str().ok())
        {
            let origin_trimmed = origin.trim_end_matches('/');
            let is_allowed = data
                .config
                .cors_origins
                .as_ref()
                .map(|list| {
                    list.iter()
                        .any(|allowed| allowed.trim_end_matches('/') == origin_trimmed)
                })
                .unwrap_or(false);
            if is_allowed {
                resp.insert_header((header::ACCESS_CONTROL_ALLOW_ORIGIN, origin));
                resp.insert_header((header::ACCESS_CONTROL_ALLOW_METHODS, req.method().as_str()));
                resp.insert_header((
                    header::ACCESS_CONTROL_ALLOW_HEADERS,
                    "Authorization, Content-Type, Accept",
                ));
                resp.insert_header((header::ACCESS_CONTROL_MAX_AGE, "3600"));
            }
        }
    };

    // ── ACL ─────────────────────────────────────────────────────────
    if let Some(status) = apply_filters_regex_allow_only(rule, &req, &body) {
        let mut resp = HttpResponse::build(status);
        resp.insert_header(("server", "ProxyAuth"));
        add_cors_headers(&mut resp, &req);
        warn!(
            "[{}] - {} {} {} {}",
            ip, path, method_str, "403 acl no match", user_agent
        );
        return Ok(resp.body("403 Forbidden"));
    }

    // ── Allow Method ───────────────────────────────────────────────────
    if !is_method_allowed(rule.allow_methods.as_deref(), method_str) {
        let allow = build_allow_header(rule.allow_methods.as_deref());
        let mut resp = HttpResponse::build(StatusCode::METHOD_NOT_ALLOWED);
        resp.insert_header(("Allow", allow));
        resp.insert_header(("server", "ProxyAuth"));
        add_cors_headers(&mut resp, &req);
        warn!(
            "[{}] - {} {} {} {}",
            ip, path, method_str, "405 method not allowed", user_agent
        );
        return Ok(resp.body("405 Method Not Allowed"));
    }

    // ── CSRF ────────────────────────────────────────────────────────────────
    if data.config.session_cookie && data.config.csrf_token && rule.requires_csrf() {
        if !validate_csrf_token(req.method(), &req, &body, &data.config.secret) {
            let html = r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><title>401 Unauthorized</title></head><body><h1>invalid csrf request</h1></body></html>"#;
            let mut resp = HttpResponse::build(StatusCode::UNAUTHORIZED);
            resp.insert_header(("server", "ProxyAuth"));
            resp.insert_header((header::CONTENT_TYPE, "text/html; charset=utf-8"));
            resp.insert_header((
                header::CACHE_CONTROL,
                "no-store, no-cache, must-revalidate, max-age=0",
            ));
            resp.insert_header(("Pragma", "no-cache"));
            resp.insert_header(("Expires", "0"));
            add_cors_headers(&mut resp, &req);
            warn!(
                "[{}] - {} {} {} {}",
                ip, path, method_str, "401 invalid csrf", user_agent
            );
            return Ok(resp.body(html));
        }
    }

    // ── URL TARGET ─────────────────────────────────────────
    let mut user_agent_fwd = "";

    let original_uri = req.uri();
    let path_no_query = original_uri.path();
    let prefix_norm = rule.prefix.trim_end_matches('/');
    let raw_forward = path_no_query
        .strip_prefix(prefix_norm)
        .unwrap_or(path_no_query);
    let cleaned_remainder = raw_forward.trim_start_matches('/').trim_end_matches('/');

    let forward_path = if !rule.secure_path {
        if rule.preserve_prefix {
            let p = path_no_query.trim_start_matches('/');
            if p.is_empty() {
                String::new()
            } else {
                format!("/{}", p)
            }
        } else {
            if cleaned_remainder.is_empty() {
                String::new()
            } else {
                format!("/{}", cleaned_remainder)
            }
        }
    } else {
        String::new()
    };

    let mut target_url = if let Some(re) = &rule.regex_compiled {
        if rule.target.contains('{') {
            let rewritten = build_regex_target(re, &rule.target, path_no_query);
            if target_authority_tampered(&rule.target, &rewritten) {
                warn!(
                    "[{}] {} {} 502 blocked: regex capture on route \"{}\" tried to change the target host ({} -> {})",
                    ip, path, method_str, rule.prefix, rule.target, rewritten
                );
                return Ok(HttpResponse::BadGateway()
                    .append_header(("server", "ProxyAuth"))
                    .body("502 Bad Gateway"));
            }
            rewritten
        } else {
            let mut t = rule.target.trim_end_matches('/').to_string();
            t.push_str(path_no_query);
            t
        }
    } else {
        let mut t = rule.target.trim_end_matches('/').to_string();
        t.push_str(&forward_path);
        t
    };
    if let Some(q) = original_uri.query() {
        if target_url.contains('?') {
            target_url.push('&');
        } else {
            target_url.push('?');
        }
        target_url.push_str(q);
    }
    let full_url = if target_url.starts_with("http://") || target_url.starts_with("https://") {
        target_url
    } else {
        format!("http://{}", target_url)
    };

    let client = get_or_build_client_proxy(
        ClientOptions {
            use_proxy: true,
            proxy_addr: Some(rule.proxy_config.clone()),
            use_cert: false,
            cert_path: None,
            key_path: None,
        },
        &data.config,
    );

    let uri = Uri::from_str(&full_url)
        .map_err(|e| error::ErrorBadRequest(format!("Invalid proxy URI: {}", e)))?;

    // ── Auth ────────────────────────────────────────────────────
    let (username, token_id) = if rule.required_login {
        let token_header = req
            .headers()
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .or_else(|| {
                if !is_secure_request(&req, &data.config) {
                    return None;
                }
                req.headers()
                    .get(header::COOKIE)
                    .and_then(|val| val.to_str().ok())
                    .and_then(|cookie_str| {
                        cookie_str.split(';').find_map(|cookie| {
                            let cookie = cookie.trim();
                            if let Some((key, value)) = cookie.split_once('=') {
                                if key.trim() == "session_token" {
                                    return Some(value.trim());
                                }
                            }
                            None
                        })
                    })
            })
            .ok_or_else(|| {
                let mut resp = HttpResponse::Unauthorized();
                resp.append_header(("server", "ProxyAuth"));
                add_cors_headers(&mut resp, &req);
                error::InternalError::from_response("Missing token", resp.finish())
            })?;

        let (username, token_id, _expiry) =
            match validate_token(token_header, &data, &data.config, &ip).await {
                Ok(result) => result,
                Err(_err) => {
                    warn!(
                        "[{}] {} {} 401 Unauthorized token attempt {} {}",
                        ip, path, method_str, user_agent, _err
                    );
                    let mut resp = HttpResponse::Unauthorized();
                    resp.append_header(("server", "ProxyAuth"));
                    resp.append_header((
                        "Set-Cookie",
                        "session_token=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict",
                    ));
                    if req.uri() != "/" || req.uri() != "" {
                        resp.append_header(("location", "/"));
                    }
                    add_cors_headers(&mut resp, &req);
                    return Ok(resp.body("401 Unauthorized"));
                }
            };

        // Single source of truth for "does this username get through
        // this route" — see `AppConfig::route_access_decision`. Also
        // what `proxyauth routes-audit`/`check-access` call, so that
        // tool can never silently disagree with what's enforced here.
        if !data
            .config
            .route_access_decision(rule, &username)
            .is_allowed()
        {
            warn!(client_ip = %ip, username = %username, path = %forward_path, target = %full_url, "This username is not authorized to access");
            let mut resp = HttpResponse::Unauthorized();
            resp.append_header(("server", "ProxyAuth"));
            add_cors_headers(&mut resp, &req);
            return Ok(resp.body("403 Forbidden"));
        }

        if req.uri() == "/" || req.uri() == "" {
            let redirect_target = data.config.login_redirect_url.as_deref().unwrap_or("/");
            return Ok(HttpResponse::SeeOther()
                .append_header(("server", "ProxyAuth"))
                .append_header(("location", redirect_target))
                .finish());
        }

        (username, token_id)
    } else {
        (String::new(), String::new())
    };

    // ── Build hyper request ────────────────────────────────────
    let hyper_method = Method::from_bytes(method_str.as_bytes()).unwrap_or(Method::GET);
    let mut request_builder = Request::builder().method(&hyper_method).uri(&uri);

    // SECURITY: hop-by-hop / connection-framing headers (RFC 9110 §7.6.1)
    // must never be relayed across a proxy boundary as-is. Forwarding them
    // verbatim (previously only `authorization`/`user-agent`/`x-user*` were
    // excluded) let a client's own Content-Length/Transfer-Encoding/TE/
    // Trailer/Upgrade/Keep-Alive/Proxy-* headers ride along with a request
    // whose body we always re-serialize as fixed-length — inconsistent
    // framing metadata is exactly the kind of thing that enables HTTP
    // request/response smuggling between two independent HTTP
    // implementations that disagree on how to interpret it. It also let a
    // client-supplied `Connection` header get copied here and then
    // *duplicated* by the `.header("Connection", "close")` call below,
    // since `http::request::Builder::header()` appends rather than
    // replaces.
    for (key, value) in req.headers() {
        let key_str = key.as_str();

        if key_str == "user-agent" {
            user_agent_fwd = value.to_str().unwrap_or("");
        }

        // Authorization is consumed by ProxyAuth only when
        // the route itself requires ProxyAuth authentication.
        if key_str == "authorization" && rule.required_login {
            continue;
        }

        if key_str != "user-agent"
            && key_str != "x-user"
            && key_str != "x-user-roles"
            && key_str != "x-groups"
            {
                if let Ok(hv) =
                    hyper::header::HeaderValue::from_bytes(value.as_bytes())
                    {
                        request_builder = request_builder.header(key_str, hv);
                    }
            }
    }
    request_builder = request_builder
        .header("Connection", "close")
        .header(USER_AGENT, "ProxyAuth");
    request_builder = inject_header(request_builder, &username, &data.config);

    let hyper_req = if hyper_method == Method::GET || hyper_method == Method::HEAD {
        match request_builder.body(Empty::<Bytes>::new().boxed()) {
            Ok(req) => req,
            Err(e) => {
                warn!(client_ip = %ip, target = %full_url, "Request build failed (GET): {}", e);
                let mut resp = HttpResponse::InternalServerError();
                resp.append_header(("server", "ProxyAuth"));
                add_cors_headers(&mut resp, &req);
                return Ok(resp.finish());
            }
        }
    } else {
        match request_builder.body(Full::new(Bytes::from(body.to_vec())).boxed()) {
            Ok(req) => req,
            Err(e) => {
                warn!(client_ip = %ip, target = %full_url, "Request build failed: {}", e);
                let mut resp = HttpResponse::InternalServerError();
                resp.append_header(("server", "ProxyAuth"));
                add_cors_headers(&mut resp, &req);
                return Ok(resp.finish());
            }
        }
    };

    // ── send upstream ───────────────────────────────────────────────
    let response_result: hyper::Response<BoxBody> = if !rule.backends.is_empty() {
        let backends: Vec<BackendConfig> = rule
            .backends
            .iter()
            .map(|b| match b {
                BackendInput::Simple(url) => BackendConfig {
                    url: url.clone(),
                    weight: 1,
                },
                BackendInput::Detailed(cfg) => cfg.clone(),
            })
            .collect();

        forward_failover(hyper_req, &backends, Some(&rule.proxy_config))
            .await
            .map_err(|e| {
                warn!(client_ip = %ip, target = %full_url, "Failover failed: {}", e);
                error::ErrorServiceUnavailable("503 Service Unavailable")
            })?
    } else {
        match timeout(Duration::from_millis(10000), client.request(hyper_req)).await {
            Ok(Ok(res)) => incoming_to_boxbody(res).await.map_err(|e| {
                warn!(client_ip = %ip, target = %full_url, "Body collect error: {}", e);
                error::ErrorServiceUnavailable("503 Service Unavailable")
            })?,
            Ok(Err(e)) => {
                warn!(client_ip = %ip, target = %full_url, "Upstream error: {}", e);
                let mut resp = HttpResponse::ServiceUnavailable();
                resp.append_header(("server", "ProxyAuth"));
                add_cors_headers(&mut resp, &req);
                return Ok(resp.finish());
            }
            Err(e) => {
                warn!(client_ip = %ip, target = %full_url, "Timeout error: {}", e);
                let mut resp = HttpResponse::ServiceUnavailable();
                resp.append_header(("server", "ProxyAuth"));
                add_cors_headers(&mut resp, &req);
                return Ok(resp.finish());
            }
        }
    };

    let status = response_result.status();
    if status.is_server_error() {
        warn!(client_ip = %ip, target = %full_url, "Upstream returned server error: {}", status);
        let mut resp = HttpResponse::InternalServerError();
        resp.append_header(("server", "ProxyAuth"));
        add_cors_headers(&mut resp, &req);
        return Ok(resp.finish());
    }

    let mut client_resp = HttpResponse::build(to_actix_status(status));

    for (key, value) in response_result.headers() as &hyper::HeaderMap {
        let k = key.as_str();
        if k != "user-agent" && k != "authorization" && k != "server" {
            client_resp.append_header((k, value.as_bytes()));
        }
    }

    let headers = response_result.headers().clone();

    let mut body_bytes: Bytes = response_result
        .into_body()
        .collect()
        .await
        .map_err(|e| {
            warn!(client_ip = %ip, target = %full_url, "Body read error: {}", e);
            let mut resp = HttpResponse::InternalServerError();
            resp.append_header(("server", "ProxyAuth"));
            add_cors_headers(&mut resp, &req);
            error::InternalError::from_response("500 Internal Server Error", resp.finish())
        })?
        .to_bytes();

    if !rule.cache {
        client_resp.insert_header((header::CONTENT_TYPE, "text/html; charset=utf-8"));
        client_resp.insert_header((
            header::CACHE_CONTROL,
            "no-store, no-cache, must-revalidate, max-age=0",
        ));
        client_resp.insert_header(("Pragma", "no-cache"));
        client_resp.insert_header(("Expires", "0"));
    }

    if data.config.session_cookie && data.config.csrf_token {
        if let Some((new_body, new_len)) =
            inject_csrf_token(&headers, &body_bytes, &data.config.secret)
        {
            body_bytes = new_body;
            client_resp.insert_header((header::CONTENT_LENGTH, new_len.to_string()));
        }
    }

    info!(
        "{} - {} {} {} {} {} [tid:{}] {}",
        ip,
        path,
        method_str,
        status.as_u16(),
        body_bytes.len(),
        username,
        token_id,
        user_agent_fwd
    );

    add_cors_headers(&mut client_resp, &req);
    fix_mime_actix(req.uri().path(), &mut client_resp, to_actix_status(status));
    Ok(client_resp
        .append_header(("server", "ProxyAuth"))
        .body(body_bytes))
}

// ─────────────────────────────────────────────────────────────────────────────
// Proxy direct (no upstream proxy)
// ─────────────────────────────────────────────────────────────────────────────
pub async fn proxy_without_proxy(
    req: HttpRequest,
    body: web::Bytes,
    data: web::Data<AppState>,
    route_idx: usize,
) -> Result<HttpResponse, Error> {
    let rule = &data.routes.routes[route_idx];

    let path = req.path();
    let ip = client_ip(&req, &data.config)
        .unwrap_or(IpAddr::from([127, 0, 0, 1]))
        .to_string();

    let method_str = req.method().as_str();

    let user_agent = req
        .headers()
        .get("User-Agent")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("-");

    let is_head = req.method() == actix_web::http::Method::HEAD;

    let add_cors_headers = |resp: &mut HttpResponseBuilder, req: &HttpRequest| {
        if let Some(origin) = req
            .headers()
            .get(header::ORIGIN)
            .and_then(|v| v.to_str().ok())
        {
            let origin_trimmed = origin.trim_end_matches('/');

            let is_allowed = data
                .config
                .cors_origins
                .as_ref()
                .map(|list| {
                    list.iter()
                        .any(|allowed| allowed.trim_end_matches('/') == origin_trimmed)
                })
                .unwrap_or(false);

            if is_allowed {
                resp.insert_header((header::ACCESS_CONTROL_ALLOW_ORIGIN, origin));

                resp.insert_header((
                    header::ACCESS_CONTROL_ALLOW_METHODS,
                    "GET, HEAD, POST, PUT, DELETE, OPTIONS",
                ));

                resp.insert_header((
                    header::ACCESS_CONTROL_ALLOW_HEADERS,
                    "Authorization, Content-Type, Accept",
                ));

                resp.insert_header((header::ACCESS_CONTROL_MAX_AGE, "3600"));
            }
        }
    };

    // ── ACL ─────────────────────────────────────────────────────────
    if let Some(status) = apply_filters_regex_allow_only(rule, &req, &body) {
        let mut resp = HttpResponse::build(status);

        resp.insert_header(("server", "ProxyAuth"));

        add_cors_headers(&mut resp, &req);

        warn!(
            "[{}] - {} {} {} {}",
            ip, path, method_str, "403 acl no match", user_agent
        );

        return Ok(resp.body("403 Forbidden"));
    }

    // ── Allow method ─────────────────────────────────────────────────
    if !is_method_allowed(rule.allow_methods.as_deref(), method_str) {
        let allow = build_allow_header(rule.allow_methods.as_deref());

        let mut resp = HttpResponse::build(StatusCode::METHOD_NOT_ALLOWED);

        resp.insert_header(("Allow", allow));
        resp.insert_header(("server", "ProxyAuth"));

        add_cors_headers(&mut resp, &req);

        warn!(
            "[{}] - {} {} {} {}",
            ip, path, method_str, "405 method not allowed", user_agent
        );

        return Ok(resp.body("405 Method Not Allowed"));
    }

    // ── CSRF ─────────────────────────────────────────────────────────
    if data.config.session_cookie && data.config.csrf_token && rule.requires_csrf() {
        if !validate_csrf_token(req.method(), &req, &body, &data.config.secret) {
            let html = r#"<!doctype html>
                <html lang="en">
                <head>
                <meta charset="utf-8">
                <title>401 Unauthorized</title>
                </head>
                <body>
                <h1>invalid csrf request</h1>
                </body>
                </html>"#;

            let mut resp = HttpResponse::build(StatusCode::UNAUTHORIZED);

            resp.insert_header(("server", "ProxyAuth"));
            resp.insert_header((header::CONTENT_TYPE, "text/html; charset=utf-8"));

            resp.insert_header((
                header::CACHE_CONTROL,
                "no-store, no-cache, must-revalidate, max-age=0",
            ));

            resp.insert_header(("Pragma", "no-cache"));
            resp.insert_header(("Expires", "0"));

            add_cors_headers(&mut resp, &req);

            warn!(
                "[{}] - {} {} {} {}",
                ip, path, method_str, "401 invalid csrf", user_agent
            );

            return Ok(resp.body(html));
        }
    }

    // ── Build URL target ─────────────────────────────────────────────
    let mut user_agent_fwd = "";

    let original_uri = req.uri();
    let path_no_query = original_uri.path();

    let prefix_norm = rule.prefix.trim_end_matches('/');

    let raw_forward = path_no_query
        .strip_prefix(prefix_norm)
        .unwrap_or(path_no_query);

    let cleaned_remainder = raw_forward.trim_start_matches('/').trim_end_matches('/');

    let forward_path = if !rule.secure_path {
        if rule.preserve_prefix {
            let p = path_no_query.trim_start_matches('/');

            if p.is_empty() {
                String::new()
            } else {
                format!("/{}", p)
            }
        } else {
            if cleaned_remainder.is_empty() {
                String::new()
            } else {
                format!("/{}", cleaned_remainder)
            }
        }
    } else {
        String::new()
    };

    let mut target_url = if let Some(re) = &rule.regex_compiled {
        if rule.target.contains('{') {
            let rewritten = build_regex_target(re, &rule.target, path_no_query);

            if target_authority_tampered(&rule.target, &rewritten) {
                warn!(
                    "[{}] {} {} 502 blocked: regex capture on route \"{}\" tried to change the target host ({} -> {})",
                    ip, path, method_str, rule.prefix, rule.target, rewritten
                );

                return Ok(HttpResponse::BadGateway()
                    .append_header(("server", "ProxyAuth"))
                    .body("502 Bad Gateway"));
            }

            rewritten
        } else {
            let mut t = rule.target.trim_end_matches('/').to_string();

            t.push_str(path_no_query);

            t
        }
    } else {
        let mut t = rule.target.trim_end_matches('/').to_string();

        t.push_str(&forward_path);

        t
    };

    if let Some(q) = original_uri.query() {
        if target_url.contains('?') {
            target_url.push('&');
        } else {
            target_url.push('?');
        }

        target_url.push_str(q);
    }

    let full_url = if target_url.starts_with("http://") || target_url.starts_with("https://") {
        target_url
    } else {
        format!("http://{}", target_url)
    };

    // ── Client : cache global partagé ────────────────────────────────
    let client_opts = if !rule.cert.is_empty() {
        ClientOptions {
            use_proxy: false,
            proxy_addr: None,
            use_cert: true,
            cert_path: rule.cert.get("file").cloned(),
            key_path: rule.cert.get("key").cloned(),
        }
    } else {
        ClientOptions {
            use_proxy: false,
            proxy_addr: None,
            use_cert: false,
            cert_path: None,
            key_path: None,
        }
    };

    let client = get_or_build_client(client_opts, &data.config);

    let uri = Uri::from_str(&full_url)
        .map_err(|e| error::ErrorBadRequest(format!("Invalid URI: {}", e)))?;

    // ── Auth ─────────────────────────────────────────────────────────
    let (username, token_id) = if rule.required_login {
        let token_header = req
            .headers()
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .or_else(|| {
                if !is_secure_request(&req, &data.config) {
                    return None;
                }

                req.headers()
                    .get(header::COOKIE)
                    .and_then(|val| val.to_str().ok())
                    .and_then(|cookie_str| {
                        cookie_str.split(';').find_map(|cookie| {
                            let cookie = cookie.trim();

                            if let Some((key, value)) = cookie.split_once('=') {
                                if key.trim() == "session_token" {
                                    return Some(value.trim());
                                }
                            }

                            None
                        })
                    })
            })
            .ok_or_else(|| {
                info!(
                    "[{}] {} {} 401 Unauthorized token attempt {}",
                    ip, path, method_str, user_agent
                );

                let mut resp = HttpResponse::Unauthorized();

                resp.append_header(("server", "ProxyAuth"));

                add_cors_headers(&mut resp, &req);

                error::InternalError::from_response("Missing token", resp.finish())
            })?;

        let (username, token_id, _expiry) =
            match validate_token(token_header, &data, &data.config, &ip).await {
                Ok(result) => result,

                Err(_err) => {
                    warn!(
                        "[{}] {} {} 401 Unauthorized token attempt {} {}",
                        ip, path, method_str, user_agent, _err
                    );

                    let mut resp = HttpResponse::Unauthorized();

                    resp.append_header(("server", "ProxyAuth"));

                    resp.append_header((
                        "Set-Cookie",
                        "session_token=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict",
                    ));

                    if req.uri() != "/" || req.uri() != "" {
                        resp.append_header(("location", "/"));
                    }

                    add_cors_headers(&mut resp, &req);

                    return Ok(resp.body("401 Unauthorized"));
                }
            };

        if !data
            .config
            .route_access_decision(rule, &username)
            .is_allowed()
        {
            info!(
                "[{}] {} {} 401 Unauthorized token attempt {}",
                ip, path, method_str, user_agent
            );

            let mut resp = HttpResponse::Unauthorized();

            resp.append_header(("server", "ProxyAuth"));

            resp.append_header((
                "Set-Cookie",
                "session_token=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict",
            ));

            add_cors_headers(&mut resp, &req);

            return Ok(resp.body("401 Unauthorized"));
        }

        if req.uri() == "/" || req.uri() == "" {
            let redirect_target = data.config.login_redirect_url.as_deref().unwrap_or("/");

            return Ok(HttpResponse::SeeOther()
                .append_header(("server", "ProxyAuth"))
                .append_header(("location", redirect_target))
                .finish());
        }

        (username, token_id)
    } else {
        (String::new(), String::new())
    };

    // ── Build request Hyper ──────────────────────────────────────────
    //
    // IMPORTANT:
    // Preserve the original HTTP method.
    //
    // GET  -> GET upstream
    // HEAD -> HEAD upstream
    // POST -> POST upstream
    // etc.
    //
    let hyper_method = Method::from_bytes(method_str.as_bytes()).unwrap_or(Method::GET);

    let mut request_builder = Request::builder().method(&hyper_method).uri(&uri);

    for (key, value) in req.headers() {
        let key_str = key.as_str();

        if key_str == "user-agent" {
            user_agent_fwd = value.to_str().unwrap_or("");
        }

        // Authorization is consumed by ProxyAuth only when
        // the route itself requires ProxyAuth authentication.
        if key_str == "authorization" && rule.required_login {
            continue;
        }

        if key_str != "user-agent"
            && key_str != "x-user"
            && key_str != "x-user-roles"
            && key_str != "x-groups"
            {
                if let Ok(hv) =
                    hyper::header::HeaderValue::from_bytes(value.as_bytes())
                    {
                        request_builder = request_builder.header(key_str, hv);
                    }
            }
    }

    request_builder = request_builder.header(USER_AGENT, "ProxyAuth");

    request_builder = inject_header(request_builder, &username, &data.config);

    // ── Build request body ───────────────────────────────────────────
    //
    // HEAD MUST NOT have a request body.
    //
    let hyper_req = if hyper_method == Method::GET || hyper_method == Method::HEAD {
        match request_builder.body(Empty::<Bytes>::new().boxed()) {
            Ok(req) => req,

            Err(e) => {
                warn!(
                    client_ip = %ip,
                    target = %full_url,
                    "Route fallback: 500 Internal error (GET/HEAD): {}",
                      e
                );

                let mut builder = HttpResponse::InternalServerError();

                builder.append_header(("server", "ProxyAuth"));

                add_cors_headers(&mut builder, &req);

                return Ok(builder.finish());
            }
        }
    } else {
        match request_builder.body(Full::new(Bytes::from(body.to_vec())).boxed()) {
            Ok(req) => req,

            Err(e) => {
                warn!(
                    client_ip = %ip,
                    target = %full_url,
                    "Route fallback: 500 Internal error reason: {}",
                    e
                );

                let mut builder = HttpResponse::InternalServerError();

                builder.append_header(("server", "ProxyAuth"));

                add_cors_headers(&mut builder, &req);

                return Ok(builder.finish());
            }
        }
    };

    // ── Send upstream ────────────────────────────────────────────────
    let response_result: hyper::Response<BoxBody> = if !rule.backends.is_empty() {
        let backends: Vec<BackendConfig> = rule
            .backends
            .iter()
            .map(|b| match b {
                BackendInput::Simple(url) => BackendConfig {
                    url: url.clone(),
                    weight: 1,
                },

                BackendInput::Detailed(cfg) => cfg.clone(),
            })
            .collect();

        match forward_failover(hyper_req, &backends, None).await {
            Ok(res) => res,

            Err(e) => {
                warn!(
                    client_ip = %ip,
                    target = %full_url,
                    "Failover failed: {}",
                    e
                );

                let mut builder = HttpResponse::ServiceUnavailable();

                builder.append_header(("server", "ProxyAuth"));

                add_cors_headers(&mut builder, &req);

                return Ok(builder.finish());
            }
        }
    } else {
        match timeout(Duration::from_millis(10000), client.request(hyper_req)).await {
            Ok(Ok(res)) => incoming_to_boxbody(res).await.map_err(|e| {
                warn!(
                    client_ip = %ip,
                    target = %full_url,
                    "Body collect error: {}",
                    e
                );

                error::ErrorServiceUnavailable("503 Service Unavailable")
            })?,

            Ok(Err(e)) => {
                warn!(
                    client_ip = %ip,
                    target = %full_url,
                    "Route fallback reason (client error): {}",
                      e
                );

                let mut resp = HttpResponse::ServiceUnavailable();

                resp.append_header(("server", "ProxyAuth"));

                add_cors_headers(&mut resp, &req);

                return Ok(resp.finish());
            }

            Err(e) => {
                warn!(
                    client_ip = %ip,
                    target = %full_url,
                    "Route fallback reason (timeout): {}",
                      e
                );

                let mut resp = HttpResponse::ServiceUnavailable();

                resp.append_header(("server", "ProxyAuth"));

                add_cors_headers(&mut resp, &req);

                return Ok(resp.finish());
            }
        }
    };

    // ── Upstream status ──────────────────────────────────────────────
    let status = response_result.status();

    if status.is_server_error() {
        warn!(
            client_ip = %ip,
            target = %full_url,
            "Upstream returned server error: {}",
            status
        );

        let mut resp = HttpResponse::InternalServerError();

        resp.append_header(("server", "ProxyAuth"));

        add_cors_headers(&mut resp, &req);

        return Ok(resp.finish());
    }

    // ── Split response ──────────────────────────────────────────────
    let (parts, resp_body) = response_result.into_parts();

    let status = parts.status;
    let headers: hyper::HeaderMap = parts.headers;

    let mut client_resp = HttpResponse::build(to_actix_status(status));

    // Preserve upstream response headers.
    //
    // Content-Length is intentionally preserved for HEAD.
    // The client needs to know the size the corresponding GET
    // response would have had.
    for (key, value) in &headers {
        let k = key.as_str();

        if k != "user-agent" && k != "authorization" && k != "server" {
            client_resp.append_header((k, value.as_bytes()));
        }
    }

    // ── Response body ───────────────────────────────────────────────
    //
    // HEAD:
    //   Do NOT collect/download the upstream body.
    //
    // GET/other:
    //   Collect normally.
    //
    let mut body_bytes: Bytes = if is_head {
        Bytes::new()
    } else {
        resp_body
            .collect()
            .await
            .map_err(|e| {
                warn!(
                    client_ip = %ip,
                    target = %full_url,
                    "Body read error: {}",
                    e
                );

                error::ErrorInternalServerError("500 Internal Server Error")
            })?
            .to_bytes()
    };

    // ── Cache policy ────────────────────────────────────────────────
    if !rule.cache {
        client_resp.insert_header((header::CONTENT_TYPE, "text/html; charset=utf-8"));

        client_resp.insert_header((
            header::CACHE_CONTROL,
            "no-store, no-cache, must-revalidate, max-age=0",
        ));

        client_resp.insert_header(("Pragma", "no-cache"));

        client_resp.insert_header(("Expires", "0"));
    }

    // ── CSRF injection ──────────────────────────────────────────────
    //
    // Never modify a HEAD response body.
    //
    if !is_head && data.config.session_cookie && data.config.csrf_token {
        if let Some((new_body, new_len)) =
            inject_csrf_token(&headers, &body_bytes, &data.config.secret)
        {
            body_bytes = new_body;

            client_resp.insert_header((header::CONTENT_LENGTH, new_len.to_string()));
        }
    }

    // ── Logging ─────────────────────────────────────────────────────
    info!(
        "[{}] - {} {} {} {} {} [tid:{}] {}",
        ip,
        path,
        method_str,
        status.as_u16(),
        body_bytes.len(),
        username,
        token_id,
        user_agent_fwd
    );

    add_cors_headers(&mut client_resp, &req);

    fix_mime_actix(req.uri().path(), &mut client_resp, to_actix_status(status));

    // ── Final response ──────────────────────────────────────────────
    //
    // For HEAD, Actix receives an empty body while all relevant
    // response headers (including Content-Length from upstream)
    // remain intact.
    //
    Ok(client_resp
        .append_header(("server", "ProxyAuth"))
        .body(body_bytes))
}
