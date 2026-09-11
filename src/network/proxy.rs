use crate::config::config::BackendConfig;
use crate::config::config::BackendInput;
use crate::config::config::CheckReturnType;
use crate::config::config::RouteRule;
use crate::network::accesslog::LogContext;
use crate::network::canonical_url::canonicalize_path_for_match;
use crate::network::loadbalancing::forward_failover;
use crate::network::shared_client::{
    BoxBody, ClientOptions, get_or_build_client, get_or_build_client_proxy,
};
use crate::token::csrf::{fix_mime_actix, inject_csrf_token, validate_csrf_token};
use crate::token::security::apply_filters_regex_allow_only;
use crate::token::security::validate_token;
use crate::{AppConfig, AppState};
use actix_web::body::{BodySize, MessageBody};
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
use std::pin::Pin;
use std::str::FromStr;
use std::sync::RwLock;
use std::task::{Context, Poll};
use tokio::time::{Duration, timeout};
use tracing::warn;

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
        if let Some(rp) = r.redirect_protect.as_mut() {
            rp.allow_ip_compiled = parse_all(&r.prefix, "redirect_protect.allow_ip", &rp.allow_ip);
        }
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

/// Validates every `log_file` in routes: must be a simple filename
/// (no `../`, no absolute path).  Panics on the first invalid entry
/// so a typo is caught at startup rather than silently ignored.
pub fn validate_route_log_files(routes: &[RouteRule]) {
    for rule in routes {
        if let Some(ref lf) = rule.log_file {
            if lf.is_empty() {
                continue;
            }
            let p = std::path::Path::new(lf);
            if p.is_absolute() {
                panic!(
                    "routes.yml: route \"{}\": log_file must be a relative filename, not an absolute path (got \"{}\")",
                    rule.prefix, lf
                );
            }
            if lf.contains("..") {
                panic!(
                    "routes.yml: route \"{}\": log_file must not contain path traversal (got \"{}\")",
                    rule.prefix, lf
                );
            }
            if p.components().count() > 1 {
                panic!(
                    "routes.yml: route \"{}\": log_file must be a single filename, not a path (got \"{}\")",
                    rule.prefix, lf
                );
            }
        }
    }
}

pub fn init_routes(routes: &mut [RouteRule]) {
    compile_filters_on_routes(routes);
    compile_ip_lists_on_routes(routes);
    compile_regex_on_routes(routes);
    validate_route_log_files(routes);
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

        if let Some(rp) = r.redirect_protect.as_mut() {
            for pp in rp.paths.iter_mut() {
                pp.regex_compiled = Some(Regex::new(&pp.regex).unwrap_or_else(|e| {
                    panic!(
                        "routes.yml: route \"{}\": invalid `redirect_protect.paths` regex \"{}\": {e}",
                        r.prefix, pp.regex
                    )
                }));
            }
        }
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
pub fn normalize_host(host: &str) -> String {
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

/// Adds every entry in `rule.headers` to a response still being built
/// (the two proxy response paths below, which build via
/// `HttpResponse::build(...)` and only finalize with `.body(...)` at
/// the very end) — CSP, HSTS, or any other custom header an operator
/// configured for this route in `routes.yml`. Deliberately the very
/// last thing set before the response goes out, so a custom header
/// here always wins over anything the backend itself might have sent
/// for the same header name (`insert_header` replaces rather than
/// appending a duplicate).
fn apply_custom_headers_builder(builder: &mut actix_web::HttpResponseBuilder, rule: &RouteRule) {
    for (name, value) in &rule.headers {
        // Validated explicitly rather than handed straight to
        // `insert_header`: actix doesn't panic on a malformed
        // name/value, but it does record the failure as the
        // builder's stored error, which turns the *entire* response
        // into a 500 once `.body()`/`.finish()` runs — far worse than
        // a single bad header (e.g. a routes.yml typo) getting
        // skipped on its own with a warning logged, which is what
        // this achieves instead.
        if let (Ok(header_name), Ok(header_value)) = (
            actix_web::http::header::HeaderName::from_bytes(name.as_bytes()),
            actix_web::http::header::HeaderValue::from_str(value),
        ) {
            builder.insert_header((header_name, header_value));
        } else {
            warn!(
                "route \"{}\": custom header \"{name}\" or its value isn't valid for an HTTP header, skipping it",
                rule.prefix
            );
        }
    }
}

/// Same as `apply_custom_headers_builder`, for a response that's
/// already been finalized into a concrete `HttpResponse` (the static
/// file path, whose many internal early-returns make applying headers
/// once at its single call site simpler than touching every one of
/// them).
/// Whether an authenticated visit to "/" has somewhere meaningful to
/// redirect to — i.e., whether `login_redirect_url` resolves to
/// anything other than "/" itself. See the two call sites' own
/// comments for why this guard exists: `login_redirect_url` defaults
/// to "/" when unconfigured, and without this check, that default
/// turns a visit to "/" into a redirect to "/", forever
/// (`NS_ERROR_REDIRECT_LOOP` in the browser) — discovered on an
/// oidc-enabled vhost specifically, but the underlying bug applies to
/// any vhost with `required_login: true` on "/" and no
/// `login_redirect_url` configured, oidc or not.
fn redirect_target_is_meaningful(config: &AppConfig) -> bool {
    config.login_redirect_url.as_deref().unwrap_or("/") != "/"
}

fn apply_custom_headers(resp: &mut HttpResponse, rule: &RouteRule) {
    for (name, value) in &rule.headers {
        if let (Ok(header_name), Ok(header_value)) = (
            actix_web::http::header::HeaderName::from_bytes(name.as_bytes()),
            actix_web::http::header::HeaderValue::from_str(value),
        ) {
            resp.headers_mut().insert(header_name, header_value);
        } else {
            warn!(
                "route \"{}\": custom header \"{name}\" or its value isn't valid for an HTTP header, skipping it",
                rule.prefix
            );
        }
    }
}

/// Best-effort session lookup for `{{ username }}` tag substitution —
/// deliberately independent of `check_static_auth`'s own token
/// extraction/validation (which *gates access* to a route when
/// `required_login: true`): this looks for a valid session
/// regardless of whether the current route requires one at all, since
/// a *public* static page can still reasonably want to show "signed
/// in as X" if the visitor happens to already have a valid session
/// from elsewhere on the same vhost. Returns `None` — silently, no
/// error response — for anything short of a fully valid session
/// (missing, malformed, expired token): this is a display nicety, not
/// a security gate, so there's nothing to reject here.
pub async fn extract_username_for_tags(
    req: &HttpRequest,
    data: &web::Data<AppState>,
    ip: &str,
) -> Option<String> {
    let token = req
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(str::to_string)
        .or_else(|| {
            if !is_secure_request(req, &data.config) {
                return None;
            }
            req.headers()
                .get(header::COOKIE)
                .and_then(|v| v.to_str().ok())
                .and_then(|cookie_str| {
                    cookie_str.split(';').find_map(|cookie| {
                        let cookie = cookie.trim();
                        let (key, value) = cookie.split_once('=')?;
                        if key.trim() == "session_token" {
                            Some(value.trim().to_string())
                        } else {
                            None
                        }
                    })
                })
        })?;

    match crate::token::security::validate_token(&token, data, &data.config, ip).await {
        Ok((username, _token_id, time_expire)) if time_expire > 0 => Some(username),
        _ => None,
    }
}

/// Substitutes `{{ username }}`, `{{ csrf_token }}`,
/// `{{ proxyauth_version }}`, and `{{ proxyauth_id }}` (each spelled
/// with or without the inner spaces, matching the existing
/// `inject_csrf_token`'s own convention for `csrf_token`) in `content`
/// with `username`/`csrf_token`/the running build's version and
/// instance ID, when present. A tag with no available value (e.g.
/// `{{ username }}` on a page nobody is signed into) is left exactly
/// as-is in the output, unreplaced — showing the literal tag text is
/// a more honest, debuggable outcome for a misconfigured page than
/// silently replacing it with an empty string, which would look like
/// a blank rendering bug rather than a missing value. Unlike
/// `username`/`csrf_token` (genuinely request-specific, so callers
/// pass them in), `proxyauth_version`/`proxyauth_id` are the same for
/// every call in this process — read directly from `crate::VERSION`/
/// `crate::ID` rather than needing to be threaded through as
/// parameters too.
pub fn substitute_proxyauth_tags(content: &str, username: Option<&str>, csrf_token: Option<&str>) -> String {
    let mut out = content.to_string();
    if let Some(u) = username {
        out = out.replace("{{ username }}", u).replace("{{username}}", u);
    }
    if let Some(t) = csrf_token {
        out = out
            .replace("{{ csrf_token }}", t)
            .replace("{{csrf_token}}", t);
    }
    out = out
        .replace("{{ proxyauth_version }}", crate::VERSION)
        .replace("{{proxyauth_version}}", crate::VERSION);
    out = out
        .replace("{{ proxyauth_id }}", crate::ID)
        .replace("{{proxyauth_id}}", crate::ID);
    out
}

/// Pulls the tag name out of an opening tag string — `"div"` from
/// `<div id="toto" class="admin-only">`, `"section"` from `<section
/// id="panel">`, and so on for any tag name at all. Used so
/// `find_matching_tag` can track nesting of whatever element the
/// configured `html_tag` actually is, not just `<div>` specifically.
fn extract_tag_name(html_tag: &str) -> Option<String> {
    let trimmed = html_tag.trim();
    let re = regex::Regex::new(r"^<\s*([a-zA-Z][a-zA-Z0-9-]*)").ok()?;
    re.captures(trimmed).map(|c| c[1].to_string())
}

/// Finds `html_tag` — the exact opening tag text a `HiddenBlockRule`
/// was configured with — searched for verbatim in `html`, and the
/// byte range its element spans, opening tag through its matching
/// closing tag. The tag name (`div`, `section`, whatever) is worked
/// out from `html_tag` itself, so this works for any element, not
/// just `<div>`. Nested elements of the *same* tag name in between are
/// tracked by depth, so an element with its own nested same-name
/// children isn't cut short at the first closing tag encountered.
/// Returns `None` if `html_tag`'s literal text isn't found in `html`
/// at all, or (rare, malformed HTML) no matching close tag exists.
fn find_matching_tag(html: &str, html_tag: &str) -> Option<(usize, usize)> {
    let html_tag = html_tag.trim();
    let tag_name = extract_tag_name(html_tag)?;

    let start = html.find(html_tag)?;
    let scan_pos = start + html_tag.len();

    let tag_pattern = regex::RegexBuilder::new(&format!(
        r"<{0}\b[^>]*>|</{0}\s*>",
        regex::escape(&tag_name)
    ))
    .case_insensitive(true)
    .build()
    .ok()?;

    let close_prefix = format!("</{}", tag_name.to_lowercase());
    let mut depth: i32 = 1;
    for tm in tag_pattern.find_iter(&html[scan_pos..]) {
        if tm.as_str().to_lowercase().starts_with(&close_prefix) {
            depth -= 1;
            if depth == 0 {
                return Some((start, scan_pos + tm.end()));
            }
        } else {
            depth += 1;
        }
    }
    None
}

/// Applies every `hidden_blocks` rule from every `redirect_protect.paths`
/// entry whose `regex` matches the current request path. One backend
/// check per matching `paths` entry — that entry's own `check_path`/
/// `type_return`/etc., the exact same check already deciding whether
/// the path itself is reachable — reused for every `hidden_blocks`
/// rule under it, rather than a separate request per element. Each
/// rule's targeted element (found by its literal `html_tag` — see
/// that field's own doc comment) gets replaced with `fallback_html`
/// (or removed outright if unset) when that check fails, left
/// untouched when it passes. A `paths` entry whose regex doesn't
/// match this request, or that has no `hidden_blocks` at all,
/// contributes nothing — no check is even made for it. A rule whose
/// `html_tag` isn't found anywhere in `html` is a silent no-op, not
/// an error.
async fn apply_hidden_blocks(
    mut html: String,
    rule: &RouteRule,
    req: &HttpRequest,
    data: &web::Data<AppState>,
) -> String {
    let Some(rp) = rule.redirect_protect.as_ref() else {
        return html;
    };
    let request_path = req.uri().path();

    for pp in &rp.paths {
        let matches = pp
            .regex_compiled
            .as_ref()
            .is_some_and(|re| re.is_match(request_path));
        if !matches || pp.hidden_blocks.is_empty() {
            continue;
        }
        // One check per matching `paths` entry, reused for every
        // `hidden_blocks` rule under it — not one backend request
        // per element. Skipped entirely when there's nothing to
        // apply it to.
        let session_valid = check_backend_session(
            &rule.target,
            &pp.check_path,
            pp.type_return,
            pp.expected_status,
            pp.expected_field.as_deref(),
            pp.expected_value.as_deref(),
            req,
            data,
        )
        .await;
        for hb in &pp.hidden_blocks {
            let Some((start, end)) = find_matching_tag(&html, &hb.html_tag) else {
                continue;
            };
            if !session_valid {
                let replacement = hb.fallback_html.as_deref().unwrap_or("");
                html.replace_range(start..end, replacement);
            }
        }
    }
    html
}

/// Resolves the token to pass as `substitute_proxyauth_tags`'s
/// `csrf_token` argument under the `tag_proxyauth` mechanism
/// specifically — `None` (leaving `{{ csrf_token }}` untouched in the
/// output) whenever CSRF protection itself is off for this route's
/// vhost (`rule.csrf_enabled` false), rather than generating and
/// splicing in a token regardless.
///
/// This exists as its own named function specifically because it's a
/// regression guard: an earlier version of every call site below
/// generated a token unconditionally whenever `tag_proxyauth` was on,
/// whether or not `csrf_token`/CSRF protection was actually enabled
/// for that vhost — meaning `csrf_token: false` didn't fully disable
/// CSRF-related behavior the way an operator would reasonably expect,
/// since `/auth` never checks a token nobody asked ProxyAuth to
/// generate. See `tests_network/proxy.rs` for the regression test.
pub fn resolve_tag_csrf_token(rule: &RouteRule, config: &AppConfig) -> Option<String> {
    rule.csrf_enabled(config)
        .then(|| crate::token::csrf::make_csrf_token(&config.secret))
}

/// A route with an empty `vhost` list is a catch-all — it matches
/// regardless of the request's `Host` header, preserving the behavior
/// every `routes.yml` had before `vhost` existed. A non-empty list
/// requires an exact (case-insensitive, port-stripped) match against
/// one of its entries.
pub fn vhost_matches(host: Option<&str>, vhosts: &[String]) -> bool {
    if vhosts.is_empty() {
        return true;
    }
    let Some(host) = host else {
        return false;
    };
    let host_norm = normalize_host(host);
    vhosts.iter().any(|v| normalize_host(v) == host_norm)
}

/// Finds the first route that explicitly declares `host` in its
/// `vhost` list — used to resolve vhost-level settings
/// (`session_cookie`, `csrf_token`, the redirect URLs, ...) for
/// requests that aren't matched against `routes.yml` by path/prefix
/// the way proxied requests are: `/auth`, `/logout`, and error pages.
///
/// Deliberately excludes catch-all routes (an empty `vhost` list,
/// which `vhost_matches` alone treats as "matches everything") —
/// unlike proxying a specific path, there's no path here to break a
/// tie with, so including catch-alls would make the result depend on
/// routes.yml's ordering (whichever route — vhost-specific or
/// catch-all — happens to come first) rather than genuinely reflect
/// "does a vhost-scoped config exist for this host". No match already
/// correctly falls back to the global default via every
/// `RouteRule::resolved_*`/`*_enabled` method's own `.unwrap_or(...)`.
pub fn find_vhost_route<'a>(host: Option<&str>, routes: &'a [RouteRule]) -> Option<&'a RouteRule> {
    let host = host?;
    routes
        .iter()
        .find(|r| !r.vhost.is_empty() && vhost_matches(Some(host), &r.vhost))
}

/// Finds the route that should actually *serve* `path` on `host` —
/// unlike `find_vhost_route` (which deliberately excludes catch-all
/// routes to resolve vhost-level *settings*), this matches like real
/// request routing does: by path prefix, filtered to routes whose
/// `vhost` either matches `host` or is empty (a catch-all, matching
/// any host). Used by `render_error_page` to find the route backing
/// `logout_redirect_url`'s path — this exists as its own named,
/// tested function specifically because of a real bug this fixed:
/// matching by path prefix alone, with no vhost filtering at all,
/// meant that on a multi-vhost instance where more than one vhost has
/// its own route at the same prefix (e.g. every vhost's own "/"), the
/// *first one in routes.yml* would win regardless of which vhost the
/// current request was actually for — silently serving one vhost's
/// content (or, worse, a completely unrelated site's) on another
/// vhost's error/logout page.
/// Finds the route that should actually *serve* `path` on `host` —
/// used by `render_error_page` to find the route backing
/// `logout_redirect_url`'s path. Reuses `match_route` (the same
/// longest-prefix-first, root-goes-last ordering real request routing
/// uses via `match_route_idx`/`build_route_order`) rather than a
/// naive `path.starts_with(&r.prefix)` scan in list order — an
/// earlier version of this fix did exactly that naive scan, and while
/// it *did* fix the original bug (no vhost filtering at all), writing
/// real tests for it surfaced a subtler one: a plain first-match scan
/// lets a route's `/` prefix or an earlier-listed catch-all shadow a
/// more specific route like `/app`, depending purely on routes.yml's
/// ordering — inconsistent with how every other request actually
/// gets routed, and confusing to debug since it'd only misbehave for
/// specific orderings.
#[allow(dead_code)] // genuinely called (render_error_page -> auth(), registered via .to(auth) in main.rs) — the bin target's dead-code check can't prove reachability through actix's handler-wrapping indirection, even though the lib target's own check (satisfied by pub-ness, confirmed by tests_network/proxy.rs) shows no such warning
pub fn find_route_for_redirect_path<'a>(
    path: &str,
    host: Option<&str>,
    routes: &'a [RouteRule],
) -> Option<&'a RouteRule> {
    match_route(path, host, routes)
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

#[allow(dead_code)] // same reason as find_route_for_redirect_path just above — genuinely used (by that same function), the bin target's check just can't prove it through actix's handler indirection
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

pub(crate) fn is_secure_request(req: &HttpRequest, config: &AppConfig) -> bool {
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

/// Where a proxied response's body comes from: already read fully
/// into memory (`Buffered` — the failover path, which has to buffer
/// so it can still retry another backend, and every response
/// ProxyAuth may rewrite), or still arriving from the backend
/// (`Streaming` — relayed to the client as it arrives, see
/// `can_stream_response`).
enum UpstreamBody {
    Buffered(BoxBody),
    Streaming(Incoming),
}

/// Whether a backend response can be relayed to the client as it
/// arrives instead of being read fully into memory first.
///
/// Only HTML is ever rewritten on its way back — `inject_csrf_token`,
/// `substitute_proxyauth_tags` and `apply_hidden_blocks` all check
/// for an HTML content type before touching the body — so every other
/// response (package files, archives, images, video, JSON…) can be
/// streamed. A large download then costs a few network buffers of
/// memory instead of its full size, and the client starts receiving
/// bytes before the backend has finished sending them.
///
/// HEAD responses, bodiless statuses (1xx, 204, 304) and server errors
/// (which get replaced by ProxyAuth's own 500 anyway) keep the
/// buffered path, exactly as before.
fn can_stream_response(headers: &hyper::HeaderMap, status: hyper::StatusCode, is_head: bool) -> bool {
    if is_head
        || status.is_informational()
        || status == hyper::StatusCode::NO_CONTENT
        || status == hyper::StatusCode::NOT_MODIFIED
        || status.is_server_error()
    {
        return false;
    }

    let content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    let main_type = content_type.split(';').next().unwrap_or("").trim();

    !(main_type.starts_with("text/html") || main_type.ends_with("+html"))
}

/// The backend's `Content-Length`, when it sent a valid one.
fn upstream_content_length(headers: &hyper::HeaderMap) -> Option<u64> {
    headers
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u64>().ok())
}

/// Relays a backend's response body to the client chunk by chunk, as
/// it arrives. `size` is the backend's `Content-Length` when it sent
/// one, so the client still receives a length rather than a chunked
/// response (and download progress bars keep working). If the backend
/// connection fails midway, actix aborts the client connection — the
/// client sees a truncated transfer, never a silently incomplete one.
struct StreamedUpstreamBody {
    inner: Pin<Box<Incoming>>,
    size: Option<u64>,
}

impl MessageBody for StreamedUpstreamBody {
    type Error = hyper::Error;

    fn size(&self) -> BodySize {
        match self.size {
            Some(n) => BodySize::Sized(n),
            None => BodySize::Stream,
        }
    }

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Bytes, Self::Error>>> {
        let this = self.get_mut();

        loop {
            match hyper::body::Body::poll_frame(this.inner.as_mut(), cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Some(Err(e))),
                Poll::Ready(Some(Ok(frame))) => {
                    // Trailer frames and empty data frames carry nothing
                    // actix can relay through a body — skip to the next
                    // frame.
                    if let Ok(data) = frame.into_data() {
                        if !data.is_empty() {
                            return Poll::Ready(Some(Ok(data)));
                        }
                    }
                }
            }
        }
    }
}

/// Very small extension → MIME map, good enough for the kind of static
/// assets `static` is meant for (docs sites, SPA builds, downloads).
/// Anything unrecognized falls back to `application/octet-stream`
/// rather than a guess — serving an unknown file as `text/*` risks the
/// browser sniffing it as HTML and executing it (stored XSS via file
/// upload/download endpoints), which a wrong-but-inert binary MIME type
/// avoids.
/// Serves the maintenance-mode page for `RedirectProtectConfig` —
/// reads `path` fresh on every call (see that field's own doc comment
/// for why), guessing the content type the same way `serve_static_file`
/// does. `503 Service Unavailable` regardless of what's being served —
/// the correct HTTP semantics for "temporarily unavailable," so caches
/// and crawlers don't treat this as the route's real content.
///
/// A read failure here (missing file, bad permissions) fails *closed*
/// — a `500` rather than silently falling through to this route's
/// normal content — since the entire point of this gate is to keep
/// matched visitors away from that content; quietly letting them
/// through because the maintenance page itself is misconfigured would
/// defeat the feature at exactly the moment it's needed.
async fn serve_redirect_protect_page(path: &str) -> HttpResponse {
    let path_ref = Path::new(path);
    match tokio::fs::read(path_ref).await {
        Ok(bytes) => {
            let content_type = guess_content_type(path_ref);
            HttpResponse::ServiceUnavailable()
                .append_header(("server", "ProxyAuth"))
                .content_type(content_type)
                .body(bytes)
        }
        Err(e) => {
            warn!("redirect_protect: path {path:?} is not readable: {e}");
            HttpResponse::InternalServerError()
                .append_header(("server", "ProxyAuth"))
                .body("500 Internal Server Error")
        }
    }
}

/// Proxies the original request — method, path/query, headers (minus
/// hop-by-hop), and body — to `target`, for
/// `RedirectProtectConfig.target`. Returns `None` on any failure
/// (invalid resulting URI, unreachable backend, timeout), letting the
/// caller fall back to serving `path` as a static file instead — see
/// `RedirectProtectConfig.target`'s own doc comment.
async fn proxy_to_redirect_protect_target(
    target: &str,
    req: &HttpRequest,
    body: &web::Bytes,
    data: &web::Data<AppState>,
) -> Option<HttpResponse> {
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let uri_str = format!("{}{}", target.trim_end_matches('/'), path_and_query);
    let uri = match Uri::from_str(&uri_str) {
        Ok(uri) => uri,
        Err(e) => {
            warn!("redirect_protect: invalid target URI \"{uri_str}\": {e}");
            return None;
        }
    };

    let method = Method::from_bytes(req.method().as_str().as_bytes()).unwrap_or(Method::GET);
    let mut request_builder = Request::builder().method(&method).uri(&uri);
    for (name, value) in req.headers().iter() {
        let name_str = name.as_str();
        // Same exclusions the normal proxying path applies to a
        // client's own copy-through — `x-user`/`x-user-roles`/
        // `x-groups` are ProxyAuth-asserted values elsewhere, never
        // meant to be trusted verbatim from whatever a client sent.
        // This function doesn't set them itself, but a naive backend
        // on the other end might still trust them if they arrived at
        // all — excluding them here is the same discipline, not an
        // oversight to skip just because this path is different.
        if is_hop_by_hop_header(name_str)
            || name_str == "x-user"
            || name_str == "x-user-roles"
            || name_str == "x-groups"
        {
            continue;
        }
        // `name`/`value` are actix_web's own header types, backed by
        // a different major version of the `http` crate than hyper
        // uses here — no direct conversion exists between the two,
        // so this goes through raw bytes instead, the same way the
        // normal proxied-request path already does elsewhere in this
        // file.
        if let Ok(hv) = hyper::header::HeaderValue::from_bytes(value.as_bytes()) {
            request_builder = request_builder.header(name_str, hv);
        }
    }

    let hyper_req = request_builder
        .body(Full::new(body.clone()).boxed())
        .ok()?;

    let client_opts = ClientOptions {
        use_proxy: false,
        proxy_addr: None,
        use_cert: false,
        cert_path: None,
        key_path: None,
    };
    let client = get_or_build_client(client_opts, &data.config).ok()?;

    // Same shape as a normal proxied request's own timeout — this is
    // meant to actually serve the response body a blocked visitor
    // sees, not a quick internal check, so it gets the same budget a
    // real backend request would.
    let resp = match timeout(data.config.backend_timeout_duration(), client.request(hyper_req)).await {
        Ok(Ok(resp)) => resp,
        _ => return None,
    };

    let status = resp.status();
    let mut client_resp = HttpResponse::build(to_actix_status(status));
    for (key, value) in resp.headers() {
        let k = key.as_str();
        if is_hop_by_hop_header(k) || k == "server" {
            continue;
        }
        client_resp.append_header((k, value.as_bytes()));
    }
    client_resp.append_header(("server", "ProxyAuth"));

    let body_bytes = resp.into_body().collect().await.ok()?.to_bytes();
    Some(client_resp.body(body_bytes))
}

/// Resolves the actual response a blocked `redirect_protect` visitor
/// gets — `rp.target` if it's set and reaching it succeeds, `rp.path`
/// as a static file otherwise, or a bare `503` if neither is set (or
/// usable). Centralizes the "try target, fall back to path, fall back
/// to a plain response" logic in one place rather than duplicating it
/// at both `redirect_protect` call sites (the IP check and the
/// `paths` session check).
async fn resolve_redirect_protect_response(
    rp: &crate::config::config::RedirectProtectConfig,
    req: &HttpRequest,
    body: &web::Bytes,
    data: &web::Data<AppState>,
) -> HttpResponse {
    if let Some(target) = &rp.target {
        if let Some(resp) = proxy_to_redirect_protect_target(target, req, body, data).await {
            return resp;
        }
        warn!("redirect_protect: target \"{target}\" unreachable, falling back");
    }

    match &rp.path {
        Some(path) => serve_redirect_protect_page(path).await,
        // Neither `target` (unset, or set but unreachable) nor `path`
        // gives this gate anything to actually show — a generic `503`
        // rather than serving the route's real content, which would
        // defeat the entire point of the gate having matched at all.
        None => HttpResponse::ServiceUnavailable()
            .append_header(("server", "ProxyAuth"))
            .body("503 Service Unavailable"),
    }
}

/// Issues a real request to `target`'s own backend at `check_path`,
/// forwarding the original request's `Cookie` header unchanged, and
/// reports whether the session is genuinely valid — see
/// `ProtectedPathRule::check_path`'s own doc comment for the full
/// reasoning. Any failure at all — an invalid resulting URI, an
/// unreachable backend, a timeout, a non-2xx status, a body that
/// doesn't parse as JSON or doesn't carry the expected field/value
/// when one was configured — is treated as "not authenticated." Fails
/// *closed*, same discipline as the IP check right next to where this
/// is called: a backend that can't be reached, or doesn't answer the
/// way it's expected to, is not the same as one that confirmed the
/// session is valid.
async fn check_backend_session(
    target: &str,
    check_path: &str,
    type_return: CheckReturnType,
    expected_status: Option<u16>,
    expected_field: Option<&str>,
    expected_value: Option<&str>,
    req: &HttpRequest,
    data: &web::Data<AppState>,
) -> bool {
    let uri_str = format!("{}{}", target.trim_end_matches('/'), check_path);
    let Ok(uri) = Uri::from_str(&uri_str) else {
        warn!("redirect_protect: invalid check_path URI \"{uri_str}\"");
        return false;
    };

    let mut request_builder = Request::builder().method(Method::GET).uri(&uri);
    if let Some(cookie_header) = req.headers().get(header::COOKIE) {
        // Same cross-crate `http` type mismatch as in
        // `proxy_to_redirect_protect_target` — actix_web's
        // `HeaderValue` doesn't convert directly into hyper's, so
        // this goes through raw bytes. `hyper::header::COOKIE` is
        // used directly for the name, sidestepping the same issue on
        // that side entirely since it's a plain constant in both
        // crates.
        if let Ok(hv) = hyper::header::HeaderValue::from_bytes(cookie_header.as_bytes()) {
            request_builder = request_builder.header(hyper::header::COOKIE, hv);
        }
    }

    let Ok(hyper_req) = request_builder.body(Empty::<Bytes>::new().boxed()) else {
        return false;
    };

    let client_opts = ClientOptions {
        use_proxy: false,
        proxy_addr: None,
        use_cert: false,
        cert_path: None,
        key_path: None,
    };
    let Ok(client) = get_or_build_client(client_opts, &data.config) else {
        return false;
    };

    // Deliberately short — this check runs ahead of every matching
    // request, and a slow backend here shouldn't make every one of
    // them wait as long as a normal proxied request would.
    let resp = match timeout(Duration::from_millis(3000), client.request(hyper_req)).await {
        Ok(Ok(resp)) => resp,
        _ => return false,
    };
    let status = resp.status();

    match type_return {
        CheckReturnType::StatusCode => match expected_status {
            // A specific code was asked for: exact match only —
            // stricter than "any 2xx", so a route whose real success
            // case is e.g. exactly 200 doesn't also quietly accept a
            // 201 or 204 it never meant to.
            Some(expected) => status.as_u16() == expected,
            // No specific code: the common case — any 2xx counts, a
            // redirect to a login page (302/303) or a 401 correctly
            // doesn't.
            None => status.is_success(),
        },
        CheckReturnType::Json => {
            // A non-2xx response body isn't worth parsing at all —
            // an error page's JSON (if any) was never going to carry
            // a meaningful `expected_field` anyway.
            if !status.is_success() {
                return false;
            }
            // `Json` mode with nothing to actually check is treated
            // as always-false rather than always-true — silently
            // reducing to "any 2xx" would be a surprising, easy to
            // miss downgrade from what the config visibly asked for.
            let Some(field) = expected_field else {
                warn!(
                    "check_backend_session: type_return: json but no expected_field set — treating as never satisfied"
                );
                return false;
            };

            // A hard cap on how much of the body we'll ever read for
            // this — meant to be a small status response
            // (`{"authenticated": true}`, not a page of content), and
            // an operator-configured backend behaving unexpectedly
            // (or, worse, something else entirely answering at that
            // address) shouldn't be able to hold an unbounded amount
            // of memory open on ProxyAuth's side just because a
            // maintenance-mode check happened to hit it.
            const MAX_CHECK_BODY_BYTES: u64 = 65536;
            let body_bytes = match timeout(
                Duration::from_millis(2000),
                http_body_util::Limited::new(resp.into_body(), MAX_CHECK_BODY_BYTES as usize)
                    .collect(),
            )
            .await
            {
                Ok(Ok(collected)) => collected.to_bytes(),
                _ => return false,
            };

            let Ok(json) = serde_json::from_slice::<serde_json::Value>(&body_bytes) else {
                return false;
            };

            let Some(actual) = json.get(field).and_then(json_value_as_flat_string) else {
                return false;
            };

            match expected_value {
                Some(expected) => actual == expected,
                // A field named but no expected_value given:
                // presence (with a scalar value at all) is enough on
                // its own.
                None => true,
            }
        }
    }
}

/// Renders a JSON scalar the way an operator would naturally write it
/// in `expected_value` — a string by its own content (no added
/// quotes), a bool/number by their ordinary display form. Arrays,
/// objects, and `null` have no sensible flat form, so they're not
/// something `expected_value` can match against at all.
fn json_value_as_flat_string(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

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

async fn serve_static_file(
    rule: &RouteRule,
    req_path: &str,
    cache_duration_secs: u64,
    req: &HttpRequest,
    data: &web::Data<AppState>,
    ip: &str,
) -> HttpResponse {
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
    let max_age = rule.cache_duration_secs.unwrap_or(cache_duration_secs);
    if root_is_file {
        return match tokio::fs::read(&root).await {
            Ok(bytes) => {
                let content_type = guess_content_type(&root);
                let bytes = if (rule.tag_proxyauth_enabled() || rule.has_hidden_blocks())
                    && content_type.starts_with("text/html")
                {
                    match String::from_utf8(bytes) {
                        Ok(text) => {
                            let username = extract_username_for_tags(req, data, ip).await;
                            // Independent of `username` — a login page,
                            // where nobody is authenticated yet, is
                            // exactly the case that most needs a CSRF
                            // token (for the login form's own POST).
                            // But NOT independent of csrf_token itself —
                            // injecting a token when CSRF protection is
                            // deliberately off for this vhost would be a
                            // pointless, confusing no-op at best (the
                            // token gets generated and spliced in, but
                            // /auth never actually checks it).
                            let csrf_token = resolve_tag_csrf_token(rule, &data.config);
                            let tagged = if rule.tag_proxyauth_enabled() {
                                substitute_proxyauth_tags(&text, username.as_deref(), csrf_token.as_deref())
                            } else {
                                text
                            };
                            apply_hidden_blocks(tagged, rule, req, data)
                                .await
                                .into_bytes()
                        }
                        Err(e) => e.into_bytes(),
                    }
                } else {
                    bytes
                };
                let mut resp = HttpResponse::Ok();
                resp.append_header(("server", "ProxyAuth"))
                    .content_type(content_type);
                if rule.cache_enabled() {
                    resp.append_header((header::CACHE_CONTROL, format!("public, max-age={}", max_age)));
                } else {
                    resp.append_header((
                        header::CACHE_CONTROL,
                        "no-store, no-cache, must-revalidate, max-age=0",
                    ));
                    resp.append_header(("Pragma", "no-cache"));
                    resp.append_header(("Expires", "0"));
                }
                resp.body(bytes)
            }
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
        Ok(bytes) => {
            let content_type = guess_content_type(&resolved);
            let bytes = if (rule.tag_proxyauth_enabled() || rule.has_hidden_blocks())
                && content_type.starts_with("text/html")
            {
                match String::from_utf8(bytes) {
                    Ok(text) => {
                        let username = extract_username_for_tags(req, data, ip).await;
                        let csrf_token = resolve_tag_csrf_token(rule, &data.config);
                        let tagged = if rule.tag_proxyauth_enabled() {
                            substitute_proxyauth_tags(&text, username.as_deref(), csrf_token.as_deref())
                        } else {
                            text
                        };
                        apply_hidden_blocks(tagged, rule, req, data)
                            .await
                            .into_bytes()
                    }
                    Err(e) => e.into_bytes(),
                }
            } else {
                bytes
            };
            let mut resp = HttpResponse::Ok();
            resp.append_header(("server", "ProxyAuth"))
                .content_type(content_type);
            if rule.cache_enabled() {
                resp.append_header((header::CACHE_CONTROL, format!("public, max-age={}", max_age)));
            } else {
                resp.append_header((
                    header::CACHE_CONTROL,
                    "no-store, no-cache, must-revalidate, max-age=0",
                ));
                resp.append_header(("Pragma", "no-cache"));
                resp.append_header(("Expires", "0"));
            }
            resp.body(bytes)
        }
        Err(e) => static_read_error_response(&rule.prefix, &resolved, &e),
    }
}

/// Minimal `required_login` gate for static routes: the same
/// Bearer-token / session-cookie extraction and
/// `AppConfig::route_access_decision` check the proxied routes use,
/// trimmed down — no CSRF (irrelevant to serving a file) and no "/"
/// login-redirect special case. `Ok(())` means the request may proceed;
/// `Err(resp)` is the response to send back instead.
/// Enforces `required_login` for a static route, the same way the
/// proxied-route handlers do — and, on success, returns the resolved
/// `(username, token_id)` so the caller can pass it to
/// `LogContext::set_user`. Static routes used to authenticate correctly
/// here but silently drop the resolved identity (`_token_id` was
/// discarded, `username` never reached the log context at all) — the
/// access log's `[username]`/`[tid]` fields showed `-` for every static
/// route even with `required_login: true` correctly enforced. Empty
/// strings are returned when `required_login` is `false`, matching the
/// same "nothing to log" convention `proxy_with_proxy`/
/// `proxy_without_proxy` already use.
async fn check_static_auth(
    req: &HttpRequest,
    data: &web::Data<AppState>,
    rule: &RouteRule,
    ip: &str,
) -> Result<(String, String), HttpResponse> {
    // SECURITY/CORRECTNESS: same gap already found and fixed three
    // times elsewhere in this file (the two `required_login` checks
    // in `proxy_with_proxy`/`proxy_without_proxy`, and the early
    // "already has a session" check for "/") — a static route on an
    // oidc-enabled vhost was never meant to have ProxyAuth's own
    // required_login enforcement apply at all; the backend makes its
    // own auth decision via the OIDC token it receives instead.
    if !rule.required_login || rule.oidc.is_some() {
        return Ok((String::new(), String::new()));
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

    let (username, token_id) = match validate_token(token_header, data, &data.config, ip).await {
        Ok((username, token_id, _expiry)) => (username, token_id),
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

    Ok((username, token_id))
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

    // ACME HTTP-01 challenge responses — checked ahead of everything
    // else (auth, CSRF, normal routing) so an in-flight certificate
    // renewal is never blocked by unrelated route config. Only ever
    // matches while `acme::renew_certificate` has actually published
    // something for this exact (vhost, token) pair — see
    // `acme::challenge`'s module doc comment for why this is a
    // separate overlay rather than a real routes.yml entry.
    if req.method() == actix_web::http::Method::GET {
        if let Some(token) = crate::acme::challenge::extract_token(req.path()) {
            let host = req.connection_info().host().to_string();
            let vhost = normalize_host(&host);
            if let Some(key_authorization) = crate::acme::challenge::lookup(&vhost, token) {
                return Ok(HttpResponse::Ok()
                    .content_type("application/octet-stream")
                    .body(key_authorization));
            }
        }
    }

    // `redirect_protect` — maintenance-mode gate, see
    // `RedirectProtectConfig`'s own doc comment for the full
    // semantics. Checked ahead of everything else below (OIDC
    // discovery, normal routing, auth) so a matched visitor never
    // reaches any of it — but after IP blocklisting and ACME above,
    // since a certificate renewal must never be blocked by this, and
    // a genuinely blocklisted IP should still just get a flat 403
    // rather than seeing a maintenance page.
    if let Some(rule) = find_vhost_route(request_host(&req).as_deref(), &data.routes.routes) {
        if let Some(rp) = &rule.redirect_protect {
            // Fails *closed*: a visitor whose IP couldn't be
            // determined at all is treated the same as one that's
            // simply not on `allow_ip` — redirected, not let through.
            // The entire point of this gate is "only these IPs get
            // normal access"; silently allowing an unidentifiable
            // visitor through would contradict that.
            let is_allowed = client_ip(&req, &data.config).is_some_and(|ip| {
                // `redirect_protect_url_ips` only ever has an entry
                // for a route that configured `allow_url_ips`/
                // `deny_url_ips` at all — everything else here reduces
                // to exactly the pre-existing `allow_ip`-only check.
                let (url_allow, url_deny) = data
                    .redirect_protect_url_ips
                    .get(&rule.redirect_protect_route_key())
                    .map(|entry| entry.value().clone())
                    .unwrap_or_default();

                // Deny wins, unconditionally — checked first, same
                // discipline `is_ip_allowed`'s own deny-before-allow
                // ordering already uses elsewhere in this codebase.
                if url_deny.iter().any(|net| net.contains(&ip)) {
                    return false;
                }
                rp.allow_ip_compiled.iter().any(|net| net.contains(&ip))
                    || url_allow.iter().any(|net| net.contains(&ip))
            });
            if !is_allowed {
                return Ok(resolve_redirect_protect_response(rp, &req, &body, &data).await);
            }

            // Path-scoped session gates, layered on top of the IP
            // check above — a request already past `is_allowed` still
            // has to prove its session is actually valid, for every
            // `paths` rule whose regex matches this
            // specific path. Delegated to the backend itself via
            // `check_backend_session`, rather than checked against
            // ProxyAuth's own `session_token` — this way it works
            // regardless of what the backend's own auth scheme
            // actually is, including on an `oidc:`-enabled vhost where
            // ProxyAuth's own session cookie isn't the authority to
            // begin with.
            let request_path = req.uri().path();
            for pp in &rp.paths {
                let Some(re) = &pp.regex_compiled else {
                    continue;
                };
                if !re.is_match(request_path) {
                    continue;
                }
                // A `paths` entry with `hidden_blocks` configured
                // doesn't gate the whole path — its check is deferred
                // entirely to `apply_hidden_blocks`, run against the
                // actual response once the request has already gone
                // through. Redirecting/blocking here would mean the
                // page never gets far enough to have anything for
                // `hidden_blocks` to act on in the first place.
                if !pp.hidden_blocks.is_empty() {
                    continue;
                }
                let session_valid =
                    check_backend_session(
                        &rule.target,
                        &pp.check_path,
                        pp.type_return,
                        pp.expected_status,
                        pp.expected_field.as_deref(),
                        pp.expected_value.as_deref(),
                        &req,
                        &data,
                    )
                    .await;
                if !session_valid {
                    if let Some(location) = &rp.redirect_url {
                        return Ok(HttpResponse::SeeOther()
                            .append_header(("server", "ProxyAuth"))
                            .append_header(("location", location.as_str()))
                            .finish());
                    }
                    return Ok(resolve_redirect_protect_response(rp, &req, &body, &data).await);
                }
            }
        }
    }

    // OIDC provider endpoints — same interception style as the ACME
    // block above, checked ahead of normal routing. Only matches on a
    // vhost that actually has `oidc:` configured on at least one of
    // its routes; every other vhost's traffic falls through to
    // normal routing unaffected, even if a request happens to hit
    // these exact paths. Full flow: discovery/jwks (read-only) below,
    // then `/oidc/authorize` (browser-facing) and `POST /oidc/token`
    // (server-to-server) further down, `/oidc/userinfo` alongside
    // discovery/jwks since it's also Bearer-token-only with no
    // session/browser involvement.
    if req.method() == actix_web::http::Method::GET {
        let path = req.path();
        if path == "/.well-known/openid-configuration" || path == "/oidc/jwks.json" {
            if let Some(host) = request_host(&req) {
                if let Some(rule) = find_vhost_route(Some(&host), &data.routes.routes) {
                    if rule.oidc.is_some() {
                        let issuer = format!("https://{host}");
                        let mut resp = if path == "/oidc/jwks.json" {
                            crate::proto::oidc_provider::discovery::jwks_handler()
                        } else {
                            crate::proto::oidc_provider::discovery::discovery_handler(&issuer)
                        };
                        apply_custom_headers(&mut resp, rule);
                        return Ok(resp);
                    }
                }
            }
        }

        // `/oidc/userinfo` — Bearer-token-only, no browser/session
        // involvement, so (unlike `/oidc/authorize`) it can be dispatched
        // inline here the same way discovery/JWKS are, rather than
        // needing its own block below.
        if path == "/oidc/userinfo" {
            if let Some(host) = request_host(&req) {
                if let Some(rule) = find_vhost_route(Some(&host), &data.routes.routes) {
                    if rule.oidc.is_some() {
                        let mut resp = crate::proto::oidc_provider::userinfo::userinfo_handler(
                            req.clone(),
                            data.clone(),
                        )
                        .await;
                        apply_custom_headers(&mut resp, rule);
                        return Ok(resp);
                    }
                }
            }
        }

        // `/oidc/end-session` — RP-Initiated Logout, also Bearer/query-only,
        // no request body needed, dispatched inline the same way.
        if path == "/oidc/end-session" {
            if let Some(host) = request_host(&req) {
                if let Some(rule) = find_vhost_route(Some(&host), &data.routes.routes) {
                    if rule.oidc.is_some() {
                        let mut resp = crate::proto::oidc_provider::logout::end_session_handler(
                            req.clone(),
                            data.clone(),
                        )
                        .await;
                        apply_custom_headers(&mut resp, rule);
                        return Ok(resp);
                    }
                }
            }
        }

    }

    // `/oidc/authorize` needs the full request (query params, request
    // body, session cookie/Authorization header) rather than just the
    // path, so it's handled by its own function instead of inline
    // here — but the vhost-has-oidc-configured gate is checked first,
    // the same way, so a vhost without `oidc:` is completely
    // unaffected even if something on it happens to be named
    // `/oidc/authorize`.
    //
    // Unlike discovery/JWKS/userinfo/end-session above, this checks
    // *both* GET (the browser landing here from the relying party)
    // and POST (the login form `/oidc/authorize` itself renders submitting
    // back to this same URL — see `authorize::render_login_form`) —
    // it can't live inside the GET-only block above for that reason.
    if req.path() == "/oidc/authorize"
        && (req.method() == actix_web::http::Method::GET
            || req.method() == actix_web::http::Method::POST)
    {
        if let Some(host) = request_host(&req) {
            if let Some(rule) = find_vhost_route(Some(&host), &data.routes.routes) {
                if rule.oidc.is_some() {
                    let mut resp = crate::proto::oidc_provider::authorize::authorize_handler(
                        req.clone(),
                        body,
                        data.clone(),
                    )
                    .await;
                    apply_custom_headers(&mut resp, rule);
                    return Ok(resp);
                }
            }
        }
    }

    // `POST /token` — server-to-server, called by the relying party
    // directly (never via the browser), so there's no return_to/login
    // detour to consider here the way `/oidc/authorize` has. Same
    // oidc-configured-vhost gate as every other interception in this
    // block.
    if req.method() == actix_web::http::Method::POST && req.path() == "/oidc/token" {
        if let Some(host) = request_host(&req) {
            if let Some(rule) = find_vhost_route(Some(&host), &data.routes.routes) {
                if rule.oidc.is_some() {
                    let mut resp = crate::proto::oidc_provider::token::token_handler(
                        req.clone(),
                        body,
                        data.clone(),
                    )
                    .await;
                    apply_custom_headers(&mut resp, rule);
                    return Ok(resp);
                }
            }
        }
    }

    if req.method() == actix_web::http::Method::OPTIONS {
        // The OIDC provider's own discovery/JWKS documents are meant
        // to be publicly, universally fetchable — see
        // `proto::oidc_provider::discovery`'s own reasoning for why
        // their actual GET responses always carry
        // `Access-Control-Allow-Origin: *` unconditionally, regardless
        // of this vhost's own `cors_origins` allow-list. This preflight
        // handler didn't know about that special case at all: it
        // checked every path against the same vhost-wide allow-list,
        // rejecting a genuinely legitimate preflight from any caller
        // whose origin wasn't explicitly listed — exactly the callers
        // these two endpoints exist to serve.
        if req.path() == "/.well-known/openid-configuration" || req.path() == "/oidc/jwks.json" {
            if let Some(rule) = find_vhost_route(request_host(&req).as_deref(), &data.routes.routes) {
                if rule.oidc.is_some() {
                    return Ok(HttpResponse::Ok()
                        .insert_header((header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"))
                        .insert_header((header::ACCESS_CONTROL_ALLOW_METHODS, "GET, OPTIONS"))
                        .insert_header((header::ACCESS_CONTROL_ALLOW_HEADERS, "Authorization, Content-Type, Accept"))
                        .insert_header((header::ACCESS_CONTROL_MAX_AGE, "3600"))
                        .finish());
                }
            }
        }

        let origin_header = req.headers().get(header::ORIGIN);
        let origin = origin_header.and_then(|v| v.to_str().ok());
        let preflight_vhost_route =
            find_vhost_route(request_host(&req).as_deref(), &data.routes.routes);

        // A same-origin request must never be blocked by CORS — CORS
        // is fundamentally a *cross*-origin mechanism; enforcing it
        // against the origin a request is already legitimately coming
        // from was blocking a backend's own frontend from calling its
        // own API (browsers send `Origin` even for a same-origin
        // POST/PUT/DELETE, not just genuinely cross-origin ones), for
        // no security benefit — nothing was ever being protected
        // *from* the origin itself. Compares scheme too, not just
        // host: `Origin` embeds both, and a request actually arriving
        // over https shouldn't treat a same-host `http://` origin as
        // equivalent — those are different origins per the Fetch
        // spec's own definition, even though this vhost isn't
        // expected to ever legitimately see one in practice.
        let same_origin = origin.and_then(|o| request_host(&req).map(|h| (o, h))).is_some_and(
            |(o, host)| {
                let expected_scheme = if is_secure_request(&req, &data.config) { "https://" } else { "http://" };
                o.strip_prefix(expected_scheme)
                    .map(|rest| rest.trim_end_matches('/').eq_ignore_ascii_case(&host))
                    .unwrap_or(false)
            },
        );

        let allowed = preflight_vhost_route
            .and_then(|r| r.resolved_cors_origins(&data.config))
            .or(data.config.cors_origins.as_ref());
        let is_allowed = same_origin || match (origin, allowed) {
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
    //
    // No route has been matched yet at this point (that happens further
    // down) — find_vhost_route resolves this vhost's own
    // session_cookie/logout_redirect_url override, if routes.yml sets
    // one, the same way the auth flow itself does.
    let early_vhost_route =
        find_vhost_route(request_host(&req).as_deref(), &data.routes.routes);
    // SECURITY/CORRECTNESS: same gap as the two `required_login`
    // checks in `proxy_with_proxy`/`proxy_without_proxy` — this "skip
    // the logged-out landing page if there's already a session" check
    // was never meant to run at all on an oidc-enabled vhost (its
    // backend has its own, entirely separate session/landing-page
    // logic), but never had a code-level bypass added either. Left
    // unfixed: it ran for every "/" visit regardless, and its own
    // `existing_session_response` call can end up at
    // `render_error_page`, which requires the *global*
    // `logout_redirect_url` (a different setting from this vhost's
    // own `oidc.logout_redirect_uris`) to be configured — failing
    // with "logout_redirect_url is not configured" on a vhost that
    // was never meant to need it in the first place.
    let early_oidc_enabled = early_vhost_route.map(|r| r.oidc.is_some()).unwrap_or(false);
    let early_session_cookie_enabled = !early_oidc_enabled
        && early_vhost_route
            .map(|r| r.session_cookie_enabled(&data.config))
            .unwrap_or(data.config.session_cookie);
    if early_session_cookie_enabled {
        let early_logout_redirect_url = early_vhost_route
            .and_then(|r| r.resolved_logout_redirect_url(&data.config))
            .or(data.config.logout_redirect_url.as_deref());
        let is_home_or_logout_page = path == "/" || early_logout_redirect_url == Some(path);
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
        // Lets the access-log and compression middlewares resolve this
        // route's settings without redoing the match themselves.
        LogContext::set_route(&req, idx);
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
            let (username, token_id) = match check_static_auth(&req, &data, rule, &ip_str).await {
                Ok(identity) => identity,
                Err(resp) => return Ok(resp),
            };
            // Same as the proxied-route handlers: publishes the resolved
            // identity for the access log's [username]/[tid] fields. Was
            // previously missing entirely on this path — static routes
            // correctly enforced `required_login`, but the resolved
            // identity never reached the access log, so it always showed
            // `-` regardless.
            LogContext::set_user(&req, &username, &token_id);
            if method != "GET" && method != "HEAD" {
                return Ok(HttpResponse::MethodNotAllowed()
                    .append_header(("server", "ProxyAuth"))
                    .append_header(("Allow", "GET, HEAD"))
                    .body("405 Method Not Allowed"));
            }
            let mut static_resp =
                serve_static_file(rule, path, data.config.cache_duration_secs, &req, &data, &ip_str)
                    .await;
            apply_custom_headers(&mut static_resp, rule);
            return Ok(static_resp);
        }
        if use_proxy {
            proxy_with_proxy(req, body, data, idx).await
        } else {
            proxy_without_proxy(req, body, data, idx).await
        }
    } else {
        // No ad-hoc line here any more: the access-log middleware logs
        // this 404 in the configured format, like everything else. That
        // is the point of the rework — not a fourth logger alongside
        // the others, but the removal of the ones that emitted
        // divergent formats on a subset of code paths.
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
            let is_allowed = rule
                .resolved_cors_origins(&data.config)
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
        LogContext::set_error_detail(&req, "acl filter rejected");
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
        LogContext::set_error_detail(&req, "method not allowed");
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
    // `rule.oidc.is_none()`: on an oidc-enabled vhost, the backend's
    // own frontend has no knowledge of ProxyAuth's CSRF mechanism at
    // all — it was never issued a ProxyAuth CSRF token, and never
    // will be. Without this gate, every state-changing request the
    // backend's own app makes to itself (through ProxyAuth) would be
    // rejected as an invalid CSRF request, breaking the backend
    // entirely rather than just the parts ProxyAuth itself handles.
    if rule.session_cookie_enabled(&data.config) && rule.csrf_enabled(&data.config) && rule.requires_csrf() && rule.oidc.is_none() {
        if !validate_csrf_token(req.method(), &req, &body, &data.config.secret) {
            LogContext::set_error_detail(&req, "invalid csrf token");
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
    // SECURITY/CORRECTNESS: `oidc:` means this vhost's backend makes
    // its own auth decision via the token it receives from the OIDC
    // flow — ProxyAuth's own required_login/session enforcement was
    // always meant to step aside entirely here (see `RouteRule::oidc`'s
    // own doc comment), but this specific check never actually had a
    // code-level bypass added for it, only the 5 dedicated OIDC
    // endpoints did. Left unfixed, this was reachable even on an
    // oidc-enabled vhost, and its own root-path redirect below could
    // self-loop when `login_redirect_url` isn't configured (defaults
    // to "/", redirecting "/" to "/" — exactly what it looks like).
    let (username, token_id) = if rule.required_login && rule.oidc.is_none() {
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
        //
        // `rule.oidc.is_none()`: on an oidc-enabled vhost,
        // `required_login` was already bypassed above, leaving
        // `username` empty — checking that empty username against
        // `allow_users`/`allow_groups`/`allow_roles` here would reject
        // every single request regardless of who the backend's own
        // OIDC-based auth actually let through, since ProxyAuth itself
        // never resolved a real username to check in the first place.
        if rule.oidc.is_none()
            && !data
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

        // SECURITY/CORRECTNESS: `login_redirect_url` defaults to "/"
        // when unconfigured — without this check, an authenticated
        // visitor hitting "/" on a vhost that never set its own
        // `login_redirect_url` gets redirected to "/", which redirects
        // to "/", forever (`NS_ERROR_REDIRECT_LOOP` in the browser).
        // Redirecting only when there's genuinely somewhere else to
        // go turns "misconfigured" into "just proxies '/' through
        // normally" instead of a hard failure.
        if (req.uri() == "/" || req.uri() == "") && redirect_target_is_meaningful(&data.config) {
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

    // Publishes the resolved identity for the access log's [username]
    // and [token-id] placeholders. Takes and releases `extensions_mut`
    // inside its own body — the `RefMut` must not be held across an
    // `.await`, or the next borrow panics.
    LogContext::set_user(&req, &username, &token_id);

    // ── Build hyper request ────────────────────────────────────
    // Resolved once, ahead of the header loop. Without this, the
    // `compression` block would look like it does nothing on proxied
    // routes: the client's `Accept-Encoding` is relayed to the backend
    // verbatim, the backend compresses first, and the compression
    // middleware then (correctly) refuses to re-encode a body that
    // already carries a `Content-Encoding`. Asking upstream for
    // `identity` is what lets ProxyAuth apply the configured algorithm
    // and level itself — nginx's `proxy_set_header Accept-Encoding ""`.
    let route_compression = match &rule.compression {
        Some(c) => c.merged_over(&data.config.compression),
        None => data.config.compression.clone(),
    };
    let strip_accept_encoding =
        route_compression.is_enabled() && route_compression.strips_upstream_accept_encoding();

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

        // Authorization is consumed by ProxyAuth only when the
        // route itself requires ProxyAuth authentication — and on an
        // oidc-enabled vhost, ProxyAuth never actually consumes it
        // for that purpose at all (see the `required_login` gate
        // above), regardless of what `required_login` is literally
        // set to, so it should always reach the backend transparently
        // there.
        if key_str == "authorization" && rule.required_login && rule.oidc.is_none() {
            continue;
        }

        // `is_hop_by_hop_header` existed and was documented, but was
        // never actually called — the SECURITY note above described a
        // fix that had only half landed. Without this test, a client's
        // own Content-Length / Transfer-Encoding / TE / Trailer /
        // Upgrade / Keep-Alive / Proxy-* headers were relayed verbatim
        // to the backend, alongside a body this proxy always
        // re-serializes as fixed-length. Two HTTP implementations
        // disagreeing on framing metadata is precisely what enables
        // request smuggling.
        // SECURITY: a client-supplied X-Forwarded-Host/X-Forwarded-Proto/
        // X-Real-IP/X-Forwarded-For must never reach the backend
        // unfiltered — `http::request::Builder::header()` appends
        // rather than replaces, so when `forward_proxy_headers` is on,
        // failing to exclude these here would have sent the backend
        // *two* values for the same header (the client's own,
        // potentially spoofed one, immediately followed by ProxyAuth's
        // trusted one) rather than replacing it outright. Excluded
        // unconditionally, not just when `forward_proxy_headers` is
        // on: even with it off, a backend that naively trusts these
        // headers shouldn't be able to be fed an attacker-chosen IP
        // or host through ProxyAuth by simply asking.
        if !is_hop_by_hop_header(key_str)
            && key_str != "user-agent"
            && key_str != "x-user"
            && key_str != "x-user-roles"
            && key_str != "x-groups"
            && key_str != "x-forwarded-host"
            && key_str != "x-forwarded-proto"
            && key_str != "x-real-ip"
            && key_str != "x-forwarded-for"
            // `host` is excluded from the copy-through only when
            // `forward_proxy_headers` is on — the existing, unchanged
            // default behavior (copy the client's own Host through
            // as-is) is preserved for every route that doesn't opt
            // into this, so this doesn't silently change what backends
            // already receive today. When it *is* on, `host` is set
            // explicitly and deliberately further below instead — see
            // that block's own comment for why it still needs
            // excluding here (same append-not-replace reasoning as the
            // four `X-Forwarded-*`/`X-Real-IP` headers above).
            && !(rule.forward_proxy_headers_enabled() && key_str == "host")
            && !(strip_accept_encoding && key_str == "accept-encoding")
            {
                if let Ok(hv) =
                    hyper::header::HeaderValue::from_bytes(value.as_bytes())
                    {
                        request_builder = request_builder.header(key_str, hv);
                    }
            }
    }

    if strip_accept_encoding {
        request_builder = request_builder.header(hyper::header::ACCEPT_ENCODING, "identity");
    }

    // Standard reverse-proxy headers — see `RouteRule::forward_proxy_headers`'s
    // own doc comment. `X-Real-IP`/`X-Forwarded-For` are built from
    // `ip`, ProxyAuth's own already-resolved and trusted client IP
    // (`client_ip`, which itself respects `trust_proxy_forward_for`),
    // never copied from anything the client sent directly.
    if rule.forward_proxy_headers_enabled() {
        if let Some(original_host) = request_host(&req) {
            // Explicit `Host` too, matching the nginx
            // `proxy_set_header Host $host;` idiom this setting is
            // meant to replace — real end-to-end testing (a raw TCP
            // listener, no HTTP library on the receiving end to
            // introduce any ambiguity) confirmed hyper genuinely
            // respects an explicitly-set Host header rather than
            // silently overriding it with the connection target, so
            // this reaches the backend exactly as set here.
            if let Ok(hv) = hyper::header::HeaderValue::from_str(&original_host) {
                request_builder = request_builder.header("Host", hv);
            }
            if let Ok(hv) = hyper::header::HeaderValue::from_str(&original_host) {
                request_builder = request_builder.header("X-Forwarded-Host", hv);
            }
        }
        let proto = if is_secure_request(&req, &data.config) { "https" } else { "http" };
        request_builder = request_builder.header("X-Forwarded-Proto", proto);
        if let Ok(hv) = hyper::header::HeaderValue::from_str(&ip) {
            request_builder = request_builder.header("X-Real-IP", hv);
        }
        if let Ok(hv) = hyper::header::HeaderValue::from_str(&ip) {
            request_builder = request_builder.header("X-Forwarded-For", hv);
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
        match request_builder.body(Full::new(body.clone()).boxed()) {
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
    let response_result: hyper::Response<UpstreamBody> = if !rule.backends.is_empty() {
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

        // Uniquely identifies this route for the sticky-backend cache —
        // see `forward_failover`'s doc comment. `vhost` alone isn't
        // enough (a vhost can have many routes), `prefix` alone isn't
        // enough either (two different vhosts can both have a route at
        // the same prefix) — the pair together is exactly what
        // `routes.yml` itself uses to distinguish routes.
        let route_key = format!("{}|{}", rule.vhost.join(","), rule.prefix);
        forward_failover(hyper_req, &backends, Some(&rule.proxy_config), &route_key)
            .await
            .map_err(|e| {
                warn!(client_ip = %ip, target = %full_url, "Failover failed: {}", e);
                error::ErrorServiceUnavailable("503 Service Unavailable")
            })?
            .map(UpstreamBody::Buffered)
    } else {
        match timeout(data.config.backend_timeout_duration(), client.request(hyper_req)).await {
            Ok(Ok(res))
                if can_stream_response(
                    res.headers(),
                    res.status(),
                    method_str.eq_ignore_ascii_case("HEAD"),
                ) =>
            {
                res.map(UpstreamBody::Streaming)
            }
            Ok(Ok(res)) => incoming_to_boxbody(res)
                .await
                .map_err(|e| {
                    warn!(client_ip = %ip, target = %full_url, "Body collect error: {}", e);
                    error::ErrorServiceUnavailable("503 Service Unavailable")
                })?
                .map(UpstreamBody::Buffered),
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
        // Hop-by-hop headers are per-connection and must not be
        // forwarded to the client (RFC 9110 §7.6.1). Letting the
        // upstream's `connection`, `transfer-encoding`,
        // `content-length` or `keep-alive` through means the backend
        // dictates the framing of a connection it is not part of,
        // which is the classic source of response desynchronisation
        // and request smuggling. The request-building paths in this
        // file already filter these through `is_hop_by_hop_header`;
        // the response paths did not, which was an asymmetry rather
        // than a decision. actix recomputes the framing headers it
        // needs from the body it is actually sending.
        //
        // `content-length` is the same deliberate exception as in
        // `proxy_without_proxy`: on HEAD the body is empty, so actix
        // would emit 0, but the client is entitled to the length the
        // matching GET would have returned. Kept identical here so the
        // two proxy paths do not answer HEAD differently.
        let keep_head_content_length =
            method_str.eq_ignore_ascii_case("HEAD") && k.eq_ignore_ascii_case("content-length");
        if is_hop_by_hop_header(k) && !keep_head_content_length {
            continue;
        }
        if k != "user-agent" && k != "authorization" && k != "server" {
            client_resp.append_header((k, value.as_bytes()));
        }
    }

    let headers = response_result.headers().clone();

    let (streaming, mut body_bytes): (Option<Incoming>, Bytes) = match response_result.into_body() {
        UpstreamBody::Streaming(incoming) => (Some(incoming), Bytes::new()),
        UpstreamBody::Buffered(body) => {
            let bytes = body
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
            (None, bytes)
        }
    };

    // ── Cache policy ────────────────────────────────────────────────
    if rule.cache_enabled() {
        let max_age = rule
            .cache_duration_secs
            .unwrap_or(data.config.cache_duration_secs);
        let cc = format!("public, max-age={}", max_age);
        client_resp.insert_header((header::CACHE_CONTROL, cc));
    } else {
        // Deliberately NOT touching Content-Type here — it's already
        // been forwarded from the upstream's real response headers a
        // few lines up. Forcing it to text/html regardless of what the
        // response actually is (JSON, an image, anything else) would
        // corrupt every non-HTML response on a route with cache: false.
        client_resp.insert_header((
            header::CACHE_CONTROL,
            "no-store, no-cache, must-revalidate, max-age=0",
        ));
        client_resp.insert_header(("Pragma", "no-cache"));
        client_resp.insert_header(("Expires", "0"));
    }

    // `rule.oidc.is_none()`: no point rewriting the backend's own
    // response body looking for `{{ csrf_token }}` tags it was never
    // going to contain — the backend doesn't speak ProxyAuth's own
    // templating on an oidc-enabled vhost, same reasoning as the CSRF
    // validation gate above.
    if streaming.is_none()
        && rule.session_cookie_enabled(&data.config)
        && rule.csrf_enabled(&data.config)
        && rule.oidc.is_none()
    {
        if let Some((new_body, new_len)) =
            inject_csrf_token(&headers, &body_bytes, &data.config.secret)
        {
            body_bytes = new_body;
            client_resp.insert_header((header::CONTENT_LENGTH, new_len.to_string()));
        }
    }

    // `{{ username }}`/`{{ proxyauth_version }}`/`{{ proxyauth_id }}`
    // (and `{{ csrf_token }}` too, independent of whatever
    // session_cookie/csrf_token resolved to just above — tag_proxyauth
    // is its own, separate opt-in) — same tags as static files, now
    // also available in whatever HTML the backend itself returns, so
    // a target's own page can use them too, not just ProxyAuth's own
    // static content.
    if streaming.is_none() && (rule.tag_proxyauth_enabled() || rule.has_hidden_blocks()) {
        let ct = headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if ct.to_ascii_lowercase().starts_with("text/html") {
            if let Ok(text) = String::from_utf8(body_bytes.to_vec()) {
                let username = extract_username_for_tags(&req, &data, &ip).await;
                let csrf_token = resolve_tag_csrf_token(rule, &data.config);
                let substituted = if rule.tag_proxyauth_enabled() {
                    substitute_proxyauth_tags(&text, username.as_deref(), csrf_token.as_deref())
                } else {
                    text
                };
                let substituted = apply_hidden_blocks(substituted, rule, &req, &data).await;
                let new_len = substituted.len();
                body_bytes = Bytes::from(substituted.into_bytes());
                client_resp.insert_header((header::CONTENT_LENGTH, new_len.to_string()));
            }
        }
    }

    add_cors_headers(&mut client_resp, &req);
    fix_mime_actix(req.uri().path(), &mut client_resp, to_actix_status(status));
    apply_custom_headers_builder(&mut client_resp, rule);
    client_resp.append_header(("server", "ProxyAuth"));

    if let Some(incoming) = streaming {
        return Ok(client_resp.body(StreamedUpstreamBody {
            inner: Box::pin(incoming),
            size: upstream_content_length(&headers),
        }));
    }

    Ok(client_resp.body(body_bytes))
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

            let is_allowed = rule
                .resolved_cors_origins(&data.config)
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
        LogContext::set_error_detail(&req, "acl filter rejected");
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
        LogContext::set_error_detail(&req, "method not allowed");

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
    if rule.session_cookie_enabled(&data.config) && rule.csrf_enabled(&data.config) && rule.requires_csrf() && rule.oidc.is_none() {
        if !validate_csrf_token(req.method(), &req, &body, &data.config.secret) {
            LogContext::set_error_detail(&req, "invalid csrf token");
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

    let client = get_or_build_client(client_opts, &data.config).map_err(|e| {
        tracing::error!("mTLS client build failed: {e}");
        error::ErrorBadGateway("502 Bad Gateway")
    })?;

    let uri = Uri::from_str(&full_url)
        .map_err(|e| error::ErrorBadRequest(format!("Invalid URI: {}", e)))?;

    // ── Auth ─────────────────────────────────────────────────────────
    // SECURITY/CORRECTNESS: `oidc:` means this vhost's backend makes
    // its own auth decision via the token it receives from the OIDC
    // flow — ProxyAuth's own required_login/session enforcement was
    // always meant to step aside entirely here (see `RouteRule::oidc`'s
    // own doc comment), but this specific check never actually had a
    // code-level bypass added for it, only the 5 dedicated OIDC
    // endpoints did. Left unfixed, this was reachable even on an
    // oidc-enabled vhost, and its own root-path redirect below could
    // self-loop when `login_redirect_url` isn't configured (defaults
    // to "/", redirecting "/" to "/" — exactly what it looks like).
    let (username, token_id) = if rule.required_login && rule.oidc.is_none() {
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

        // `rule.oidc.is_none()`: same reasoning as the twin check in
        // `proxy_with_proxy` above — an oidc-enabled vhost already
        // bypassed `required_login`, leaving `username` empty; without
        // this gate, that empty username would fail
        // `allow_users`/`allow_groups`/`allow_roles` unconditionally.
        if rule.oidc.is_none()
            && !data
                .config
                .route_access_decision(rule, &username)
                .is_allowed()
        {

            let mut resp = HttpResponse::Unauthorized();

            resp.append_header(("server", "ProxyAuth"));

            resp.append_header((
                "Set-Cookie",
                "session_token=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict",
            ));

            add_cors_headers(&mut resp, &req);

            return Ok(resp.body("401 Unauthorized"));
        }

        // SECURITY/CORRECTNESS: same guard as the twin check in
        // `proxy_with_proxy` above — `login_redirect_url` defaulting
        // to "/" when unconfigured otherwise makes an authenticated
        // visit to "/" redirect to "/", forever.
        if (req.uri() == "/" || req.uri() == "") && redirect_target_is_meaningful(&data.config) {
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

    // See the matching call in `proxy_with_proxy`.
    LogContext::set_user(&req, &username, &token_id);

    // Resolved once, ahead of the header loop. Without this, the
    // `compression` block would look like it does nothing on proxied
    // routes: the client's `Accept-Encoding` is relayed to the backend
    // verbatim, the backend compresses first, and the compression
    // middleware then (correctly) refuses to re-encode a body that
    // already carries a `Content-Encoding`. Asking upstream for
    // `identity` is what lets ProxyAuth apply the configured algorithm
    // and level itself — nginx's `proxy_set_header Accept-Encoding ""`.
    let route_compression = match &rule.compression {
        Some(c) => c.merged_over(&data.config.compression),
        None => data.config.compression.clone(),
    };
    let strip_accept_encoding =
        route_compression.is_enabled() && route_compression.strips_upstream_accept_encoding();

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

        // Authorization is consumed by ProxyAuth only when the
        // route itself requires ProxyAuth authentication — and on an
        // oidc-enabled vhost, ProxyAuth never actually consumes it
        // for that purpose at all (see the `required_login` gate
        // above), regardless of what `required_login` is literally
        // set to, so it should always reach the backend transparently
        // there.
        if key_str == "authorization" && rule.required_login && rule.oidc.is_none() {
            continue;
        }

        // `is_hop_by_hop_header` existed and was documented, but was
        // never actually called — the SECURITY note above described a
        // fix that had only half landed. Without this test, a client's
        // own Content-Length / Transfer-Encoding / TE / Trailer /
        // Upgrade / Keep-Alive / Proxy-* headers were relayed verbatim
        // to the backend, alongside a body this proxy always
        // re-serializes as fixed-length. Two HTTP implementations
        // disagreeing on framing metadata is precisely what enables
        // request smuggling.
        // SECURITY: a client-supplied X-Forwarded-Host/X-Forwarded-Proto/
        // X-Real-IP/X-Forwarded-For must never reach the backend
        // unfiltered — `http::request::Builder::header()` appends
        // rather than replaces, so when `forward_proxy_headers` is on,
        // failing to exclude these here would have sent the backend
        // *two* values for the same header (the client's own,
        // potentially spoofed one, immediately followed by ProxyAuth's
        // trusted one) rather than replacing it outright. Excluded
        // unconditionally, not just when `forward_proxy_headers` is
        // on: even with it off, a backend that naively trusts these
        // headers shouldn't be able to be fed an attacker-chosen IP
        // or host through ProxyAuth by simply asking.
        if !is_hop_by_hop_header(key_str)
            && key_str != "user-agent"
            && key_str != "x-user"
            && key_str != "x-user-roles"
            && key_str != "x-groups"
            && key_str != "x-forwarded-host"
            && key_str != "x-forwarded-proto"
            && key_str != "x-real-ip"
            && key_str != "x-forwarded-for"
            // `host` is excluded from the copy-through only when
            // `forward_proxy_headers` is on — the existing, unchanged
            // default behavior (copy the client's own Host through
            // as-is) is preserved for every route that doesn't opt
            // into this, so this doesn't silently change what backends
            // already receive today. When it *is* on, `host` is set
            // explicitly and deliberately further below instead — see
            // that block's own comment for why it still needs
            // excluding here (same append-not-replace reasoning as the
            // four `X-Forwarded-*`/`X-Real-IP` headers above).
            && !(rule.forward_proxy_headers_enabled() && key_str == "host")
            && !(strip_accept_encoding && key_str == "accept-encoding")
            {
                if let Ok(hv) =
                    hyper::header::HeaderValue::from_bytes(value.as_bytes())
                    {
                        request_builder = request_builder.header(key_str, hv);
                    }
            }
    }

    if strip_accept_encoding {
        request_builder = request_builder.header(hyper::header::ACCEPT_ENCODING, "identity");
    }

    // Standard reverse-proxy headers — see `RouteRule::forward_proxy_headers`'s
    // own doc comment. `X-Real-IP`/`X-Forwarded-For` are built from
    // `ip`, ProxyAuth's own already-resolved and trusted client IP
    // (`client_ip`, which itself respects `trust_proxy_forward_for`),
    // never copied from anything the client sent directly.
    if rule.forward_proxy_headers_enabled() {
        if let Some(original_host) = request_host(&req) {
            // Explicit `Host` too, matching the nginx
            // `proxy_set_header Host $host;` idiom this setting is
            // meant to replace — real end-to-end testing (a raw TCP
            // listener, no HTTP library on the receiving end to
            // introduce any ambiguity) confirmed hyper genuinely
            // respects an explicitly-set Host header rather than
            // silently overriding it with the connection target, so
            // this reaches the backend exactly as set here.
            if let Ok(hv) = hyper::header::HeaderValue::from_str(&original_host) {
                request_builder = request_builder.header("Host", hv);
            }
            if let Ok(hv) = hyper::header::HeaderValue::from_str(&original_host) {
                request_builder = request_builder.header("X-Forwarded-Host", hv);
            }
        }
        let proto = if is_secure_request(&req, &data.config) { "https" } else { "http" };
        request_builder = request_builder.header("X-Forwarded-Proto", proto);
        if let Ok(hv) = hyper::header::HeaderValue::from_str(&ip) {
            request_builder = request_builder.header("X-Real-IP", hv);
        }
        if let Ok(hv) = hyper::header::HeaderValue::from_str(&ip) {
            request_builder = request_builder.header("X-Forwarded-For", hv);
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
        match request_builder.body(Full::new(body.clone()).boxed()) {
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
    let response_result: hyper::Response<UpstreamBody> = if !rule.backends.is_empty() {
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

        let route_key = format!("{}|{}", rule.vhost.join(","), rule.prefix);
        match forward_failover(hyper_req, &backends, None, &route_key).await {
            Ok(res) => res.map(UpstreamBody::Buffered),

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
        match timeout(data.config.backend_timeout_duration(), client.request(hyper_req)).await {
            Ok(Ok(res)) if can_stream_response(res.headers(), res.status(), is_head) => {
                res.map(UpstreamBody::Streaming)
            }

            Ok(Ok(res)) => incoming_to_boxbody(res)
                .await
                .map_err(|e| {
                    warn!(
                        client_ip = %ip,
                        target = %full_url,
                        "Body collect error: {}",
                        e
                    );

                    error::ErrorServiceUnavailable("503 Service Unavailable")
                })?
                .map(UpstreamBody::Buffered),

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

        // Hop-by-hop headers are per-connection and must not reach the
        // client (RFC 9110 §7.6.1) — forwarding the upstream's
        // `connection`, `transfer-encoding` or `keep-alive` lets the
        // backend dictate the framing of a connection it is not part
        // of, which is how response desynchronisation happens. The
        // request-building path above already filters these through
        // `is_hop_by_hop_header`; this response path did not.
        //
        // `content-length` is the deliberate exception noted above:
        // on HEAD the body is empty, so actix would emit 0, but the
        // client is entitled to the length the matching GET would
        // have returned.
        let keep_head_content_length = is_head && k.eq_ignore_ascii_case("content-length");
        if is_hop_by_hop_header(k) && !keep_head_content_length {
            continue;
        }

        if k != "user-agent" && k != "authorization" && k != "server" {
            client_resp.append_header((k, value.as_bytes()));
        }
    }

    // ── Response body ───────────────────────────────────────────────
    //
    // HEAD:
    //   Do NOT collect/download the upstream body.
    //
    // Streaming (see `can_stream_response`):
    //   Leave the body with the backend connection — it is relayed to
    //   the client as it arrives, at the very end.
    //
    // GET/other:
    //   Collect normally.
    //
    let (streaming, mut body_bytes): (Option<Incoming>, Bytes) = match resp_body {
        _ if is_head => (None, Bytes::new()),
        UpstreamBody::Streaming(incoming) => (Some(incoming), Bytes::new()),
        UpstreamBody::Buffered(body) => {
            let bytes = body
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
                .to_bytes();
            (None, bytes)
        }
    };

    // ── Cache policy ────────────────────────────────────────────────
    if rule.cache_enabled() {
        let max_age = rule
            .cache_duration_secs
            .unwrap_or(data.config.cache_duration_secs);
        let cc = format!("public, max-age={}", max_age);
        client_resp.insert_header((header::CACHE_CONTROL, cc));
    } else {
        // Deliberately NOT touching Content-Type here — see the same
        // comment at the other cache:false site above.
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
    if !is_head
        && streaming.is_none()
        && rule.session_cookie_enabled(&data.config)
        && rule.csrf_enabled(&data.config)
        && rule.oidc.is_none()
    {
        if let Some((new_body, new_len)) =
            inject_csrf_token(&headers, &body_bytes, &data.config.secret)
        {
            body_bytes = new_body;

            client_resp.insert_header((header::CONTENT_LENGTH, new_len.to_string()));
        }
    }

    // `{{ username }}`/`{{ csrf_token }}`/`{{ proxyauth_version }}`/
    // `{{ proxyauth_id }}` — same tag_proxyauth-gated substitution as
    // static files and the other proxied-response path, so a target's
    // own HTML can use these tags too, not just ProxyAuth's own static
    // content.
    if !is_head && streaming.is_none() && (rule.tag_proxyauth_enabled() || rule.has_hidden_blocks()) {
        let ct = headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if ct.to_ascii_lowercase().starts_with("text/html") {
            if let Ok(text) = String::from_utf8(body_bytes.to_vec()) {
                let username = extract_username_for_tags(&req, &data, &ip).await;
                let csrf_token = resolve_tag_csrf_token(rule, &data.config);
                let substituted = if rule.tag_proxyauth_enabled() {
                    substitute_proxyauth_tags(&text, username.as_deref(), csrf_token.as_deref())
                } else {
                    text
                };
                let substituted = apply_hidden_blocks(substituted, rule, &req, &data).await;
                let new_len = substituted.len();
                body_bytes = Bytes::from(substituted.into_bytes());
                client_resp.insert_header((header::CONTENT_LENGTH, new_len.to_string()));
            }
        }
    }

    add_cors_headers(&mut client_resp, &req);

    fix_mime_actix(req.uri().path(), &mut client_resp, to_actix_status(status));

    // ── Final response ──────────────────────────────────────────────
    //
    // For HEAD, Actix receives an empty body while all relevant
    // response headers (including Content-Length from upstream)
    // remain intact.
    //
    apply_custom_headers_builder(&mut client_resp, rule);
    client_resp.append_header(("server", "ProxyAuth"));

    if let Some(incoming) = streaming {
        return Ok(client_resp.body(StreamedUpstreamBody {
            inner: Box::pin(incoming),
            size: upstream_content_length(&headers),
        }));
    }

    Ok(client_resp.body(body_bytes))
}
