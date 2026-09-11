// Copyright 2025 Vladimir Souchet
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Centralized access logging.
//!
//! # Why this exists
//!
//! Before this module, "the access log" was a handful of `info!` calls
//! scattered at the *end* of `proxy_with_proxy` / `proxy_without_proxy`,
//! plus a few ad-hoc lines on some (not all) of the early-return paths.
//! That design has three structural problems, all of which this module
//! is meant to fix:
//!
//! 1. **A log line is only reached if the handler runs to completion.**
//!    Every early `return` before those calls — CORS preflight, the
//!    `ip_blocklist` 403, `allow_ips`/`deny_ips` 403, static-route
//!    405/401, the session-cookie landing-page shortcut, the `/` login
//!    redirect, upstream timeouts, body-read errors — produced no
//!    access-log line at all. Anything returning `Err(actix::Error)`
//!    (the `error::ErrorInternalServerError(...)` paths) skipped it
//!    twice over.
//!
//! 2. **Whole handlers were never covered.** `/auth`, `/logout`,
//!    `/reset-password`, `/adm/*` are registered as their own services
//!    in `build_app!`, so they never enter `global_proxy` and were
//!    invisible to the access log — including failed logins.
//!
//! 3. **Static routes were never logged**, success or failure.
//!
//! Adding a fourth logger next to the other three would not have fixed
//! any of that. Instead, logging now lives in **one middleware wrapped
//! around the whole `App`**, so it observes the final status of every
//! request no matter which service produced it, including responses
//! synthesized by other middleware (the 429 from `actix-governor`) and
//! errors converted by actix itself.
//!
//! # Cost on the hot path
//!
//! The format string is parsed **once**, at startup, into a
//! `Vec<Segment>` (see `compile_format`). Per request the middleware
//! does: one `Instant::now()`, a handful of header lookups, and one
//! `String` build. Nothing is parsed, no regex runs, no lock is taken
//! (the `tracing` subscriber owns its own writer synchronization).
//!
//! `[cpu-usage]`/`[memory-usage]` are *sampled by a background ticker*
//! into two atomics and read with a `Relaxed` load — reading
//! `/proc/self/stat` on every request would put a syscall and a file
//! parse on the critical path. The ticker is only spawned when the
//! configured format actually references one of those two placeholders.

use crate::AppState;
use crate::config::config::AppConfig;
use crate::config::logging::LOG_DIR;
use crate::network::proxy::client_ip;
use actix_service::{Service, Transform};
use actix_web::body::{BodySize, MessageBody};
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::http::header;
use actix_web::{Error, HttpMessage, HttpRequest, web};
use futures_util::future::{LocalBoxFuture, Ready, ok};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Instant;
use tracing::info;

// ─────────────────────────────────────────────────────────────────────
// Per-request context handed from the handlers to this middleware
// ─────────────────────────────────────────────────────────────────────

/// Written into the request's extensions by `global_proxy` (and the
/// proxy handlers) so the middleware can resolve **route-level** log
/// settings and render `[username]`/`[route]` without redoing the
/// route match itself.
///
/// Absent for anything that never reaches `global_proxy` (`/auth`,
/// `/adm/*`, a 404 with no matching route, a request rejected by an
/// outer middleware) — in that case only the global and per-vhost
/// settings apply, which is the correct fallback: a request that never
/// matched a route can't be governed by a route's `log:` flag.
#[derive(Clone, Default)]
pub struct LogContext {
    /// Index into `AppState.routes.routes` of the matched route.
    pub route_idx: Option<usize>,
    pub username: Option<String>,
    pub token_id: Option<String>,
    /// Optional error detail string set by handlers when a request
    /// results in an error response (4xx/5xx). Rendered as
    /// `[error_detail]` in the access log format.
    pub error_detail: Option<String>,
}

impl LogContext {
    /// Records the matched route on the request. Kept in its own
    /// function so the `RefMut` from `extensions_mut()` is dropped
    /// before the caller's next `.await` — holding it across an await
    /// point would panic on the next borrow.
    pub fn set_route(req: &HttpRequest, idx: usize) {
        let mut ext = req.extensions_mut();
        match ext.get_mut::<LogContext>() {
            Some(ctx) => ctx.route_idx = Some(idx),
            None => {
                ext.insert(LogContext {
                    route_idx: Some(idx),
                    ..Default::default()
                });
            }
        }
    }

    /// Records the authenticated identity, once the handler has one.
    /// Empty strings (the "no login required" sentinel the proxy
    /// handlers use) are stored as `None` so the formatter renders `-`
    /// rather than a blank field.
    pub fn set_user(req: &HttpRequest, username: &str, token_id: &str) {
        let mut ext = req.extensions_mut();
        let entry = ext.get_mut::<LogContext>();
        let (u, t) = (
            (!username.is_empty()).then(|| username.to_string()),
            (!token_id.is_empty()).then(|| token_id.to_string()),
        );
        match entry {
            Some(ctx) => {
                ctx.username = u;
                ctx.token_id = t;
            }
            None => {
                ext.insert(LogContext {
                    route_idx: None,
                    username: u,
                    token_id: t,
                    ..Default::default()
                });
            }
        }
    }

    /// Records an error detail string for the access log.
    pub fn set_error_detail(req: &HttpRequest, detail: &str) {
        let mut ext = req.extensions_mut();
        match ext.get_mut::<LogContext>() {
            Some(ctx) => ctx.error_detail = Some(detail.to_string()),
            None => {
                ext.insert(LogContext {
                    error_detail: Some(detail.to_string()),
                    ..Default::default()
                });
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// Format compilation
// ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    Vhost,
    Ip,
    Path,
    Method,
    Status,
    Length,
    UserAgent,
    XForwardedFor,
    Host,
    Protocol,
    Query,
    Referer,
    RequestTime,
    RequestTimeNs,
    CpuUsage,
    MemoryUsage,
    Username,
    TokenId,
    Route,
    Time,
    ErrorDetail,
}

impl Field {
    fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "vhost" => Field::Vhost,
            "ip" => Field::Ip,
            "path" => Field::Path,
            "method" => Field::Method,
            "status" => Field::Status,
            "length" => Field::Length,
            "user-agent" | "user_agent" => Field::UserAgent,
            "x-forwarded-for" | "x_forwarded_for" => Field::XForwardedFor,
            "host" => Field::Host,
            "protocol" => Field::Protocol,
            "query" => Field::Query,
            "referer" | "referrer" => Field::Referer,
            "request-time" | "request_time" => Field::RequestTime,
            "request-time-ns" | "request_time_ns" => Field::RequestTimeNs,
            "cpu-usage" | "cpu_usage" => Field::CpuUsage,
            "memory-usage" | "memory_usage" => Field::MemoryUsage,
            "username" | "user" => Field::Username,
            "token-id" | "tid" => Field::TokenId,
            "route" => Field::Route,
            "time" | "timestamp" => Field::Time,
            "error_detail" | "error-detail" | "error" => Field::ErrorDetail,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone)]
pub enum Segment {
    Literal(String),
    Field(Field),
}

/// Splits a format string into literals and placeholders, once.
///
/// An unrecognized `[name]` is deliberately **kept verbatim as a
/// literal** rather than dropped or rejected: a typo'd placeholder then
/// shows up plainly in the log output (`[stauts]`), which is far easier
/// to notice and fix than a silently missing column, and it also means
/// a format containing literal square brackets still round-trips.
pub fn compile_format(fmt: &str) -> Vec<Segment> {
    let mut out: Vec<Segment> = Vec::new();
    let mut literal = String::new();
    let bytes = fmt.as_bytes();
    let mut i = 0usize;

    while i < bytes.len() {
        if bytes[i] == b'[' {
            if let Some(rel_end) = fmt[i + 1..].find(']') {
                let name = &fmt[i + 1..i + 1 + rel_end];
                if let Some(field) = Field::from_name(&name.to_ascii_lowercase()) {
                    if !literal.is_empty() {
                        out.push(Segment::Literal(std::mem::take(&mut literal)));
                    }
                    out.push(Segment::Field(field));
                    i += rel_end + 2;
                    continue;
                }
            }
        }
        // Push one char (not one byte) so multi-byte UTF-8 separators
        // in a custom format survive intact.
        let ch = fmt[i..].chars().next().unwrap();
        literal.push(ch);
        i += ch.len_utf8();
    }

    if !literal.is_empty() {
        out.push(Segment::Literal(literal));
    }
    out
}

/// Compiled once at startup by `init`, read by every worker.
static FORMAT: OnceLock<Vec<Segment>> = OnceLock::new();

/// Per-vhost log-file writers, initialized once at startup.
static VHOST_WRITERS: OnceLock<VhostLogWriter> = OnceLock::new();

/// Bit-flags of fields actually present in the compiled format,
/// computed once at startup so the middleware can skip capturing
/// data that would never be rendered.
#[derive(Debug, Clone, Copy, Default)]
pub struct RequiredFields {
    pub ip: bool,
    pub user_agent: bool,
    pub xff: bool,
    pub referer: bool,
    pub query: bool,
    pub protocol: bool,
    pub host: bool,
    pub cpu_usage: bool,
    pub memory_usage: bool,
}

static REQUIRED: OnceLock<RequiredFields> = OnceLock::new();

pub fn required_fields() -> RequiredFields {
    REQUIRED.get().copied().unwrap_or_default()
}

fn format_segments() -> &'static [Segment] {
    FORMAT.get().map(|v| v.as_slice()).unwrap_or(&[])
}

// ─────────────────────────────────────────────────────────────────────
// CPU / memory sampling
// ─────────────────────────────────────────────────────────────────────

/// Process CPU usage over the last sampling interval, in per-mille
/// (1000 = one core fully busy). Written by the ticker, read with a
/// `Relaxed` load on the request path.
static CPU_PERMILLE: AtomicU64 = AtomicU64::new(0);
/// Resident set size in KiB, same lifecycle as `CPU_PERMILLE`.
static MEM_KIB: AtomicU64 = AtomicU64::new(0);

#[cfg(target_os = "linux")]
fn read_proc_sample() -> Option<(u64, u64)> {
    // utime + stime, in clock ticks: fields 14 and 15 of
    // /proc/self/stat. The comm field (2) may itself contain spaces
    // and parentheses, so split after the last ')' rather than
    // whitespace-splitting the whole line.
    let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
    let after_comm = &stat[stat.rfind(')')? + 1..];
    let mut it = after_comm.split_whitespace();
    // after_comm starts at field 3 (state), so utime is the 12th token.
    let utime: u64 = it.nth(11)?.parse().ok()?;
    let stime: u64 = it.next()?.parse().ok()?;

    // Field 2 of /proc/self/statm is the resident set size in pages.
    let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
    let rss_pages: u64 = statm.split_whitespace().nth(1)?.parse().ok()?;

    Some((utime + stime, rss_pages))
}

#[cfg(not(target_os = "linux"))]
fn read_proc_sample() -> Option<(u64, u64)> {
    None
}

/// Samples `/proc/self/{stat,statm}` on a fixed interval and publishes
/// the result into the two atomics above. Spawned only when the
/// configured format actually uses `[cpu-usage]` or `[memory-usage]`.
async fn resource_sampler(interval_secs: u64) {
    // sysconf(_SC_CLK_TCK) is 100 on every mainstream Linux build; the
    // kernel's USER_HZ is fixed at 100 regardless of CONFIG_HZ, so this
    // doesn't need libc.
    const CLK_TCK: u64 = 100;
    let page_kib: u64 = 4; // 4 KiB pages; see the note in `init`.

    let mut last_ticks = read_proc_sample().map(|(t, _)| t).unwrap_or(0);
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
    ticker.tick().await;

    loop {
        ticker.tick().await;
        let Some((ticks, rss_pages)) = read_proc_sample() else {
            continue;
        };
        let delta = ticks.saturating_sub(last_ticks);
        last_ticks = ticks;

        // delta ticks over `interval_secs` seconds, as per-mille of one
        // core: (delta / CLK_TCK) / interval * 1000.
        let permille = delta.saturating_mul(1000) / (CLK_TCK * interval_secs).max(1);
        CPU_PERMILLE.store(permille, Ordering::Relaxed);
        MEM_KIB.store(rss_pages.saturating_mul(page_kib), Ordering::Relaxed);
    }
}

fn fmt_cpu(out: &mut String) {
    let permille = CPU_PERMILLE.load(Ordering::Relaxed);
    out.push_str(&format!("{}.{}%", permille / 10, permille % 10));
}

fn fmt_mem(out: &mut String) {
    let kib = MEM_KIB.load(Ordering::Relaxed);
    if kib >= 1024 {
        out.push_str(&format!("{}.{}MB", kib / 1024, (kib % 1024) * 10 / 1024));
    } else {
        out.push_str(&format!("{}KB", kib));
    }
}

// ─────────────────────────────────────────────────────────────────────
// Per-vhost log-file writers
// ─────────────────────────────────────────────────────────────────────

/// Thread-safe, per-vhost file writer.  Each unique `log_file`
/// filename gets its own `BufWriter<File>` behind a `Mutex`.
/// Keys are the full path so writers are shared across vhosts/routes
/// that resolve to the same file.
pub struct VhostLogWriter {
    writers: std::sync::RwLock<HashMap<String, Mutex<BufWriter<File>>>>,
}

impl VhostLogWriter {
    /// Creates an empty writer map.  Actual files are opened lazily on
    /// first write so that per-route `log_file` values from
    /// `routes.yml` don't all need to be known at startup.
    pub fn new() -> Self {
        Self {
            writers: std::sync::RwLock::new(HashMap::new()),
        }
    }

    /// Writes a pre-rendered log line to the file for `log_path`.
    /// Opens the file lazily on first use.  The trailing newline is
    /// added here.
    ///
    /// Deliberately does **not** flush on every call — that would turn
    /// every log line into its own `write(2)` syscall, defeating the
    /// point of the `BufWriter`. Lines are flushed periodically instead
    /// (see `spawn_flush_ticker`) and on shutdown (see `flush_all`
    /// called from `main`'s shutdown path) — bounding how long a line
    /// can sit unwritten to a small, known window instead of "until the
    /// buffer happens to fill up", which for a quiet vhost's log file
    /// could otherwise be minutes, or forever if the process is
    /// killed before the buffer ever fills.
    pub fn write(&self, log_path: &str, line: &str) {
        if log_path.is_empty() {
            return;
        }
        let full = format!("{}/{}", LOG_DIR, log_path);

        // Fast path: file already opened.
        {
            if let Ok(map) = self.writers.read() {
                if let Some(writer) = map.get(&full) {
                    if let Ok(mut w) = writer.lock() {
                        let _ = writeln!(w, "{}", line);
                    }
                    return;
                }
            }
        }

        // Slow path: open and insert.
        if let Ok(mut map) = self.writers.write() {
            if !map.contains_key(&full) {
                let path = PathBuf::from(&full);
                if let Some(parent) = path.parent() {
                    let _ = fs::create_dir_all(parent);
                }
                match File::options().create(true).append(true).open(&path) {
                    Ok(file) => {
                        map.insert(
                            full.clone(),
                            Mutex::new(BufWriter::with_capacity(8192, file)),
                        );
                    }
                    Err(e) => {
                        eprintln!("[accesslog] failed to open log file {full}: {e}");
                        return;
                    }
                }
            }
            if let Some(writer) = map.get(&full) {
                if let Ok(mut w) = writer.lock() {
                    let _ = writeln!(w, "{}", line);
                }
            }
        }
    }

    /// Flushes every open writer. Called periodically by
    /// `spawn_flush_ticker`, and once more on shutdown so a line
    /// written just before exit isn't silently dropped.
    pub fn flush_all(&self) {
        let Ok(map) = self.writers.read() else {
            return;
        };
        for writer in map.values() {
            if let Ok(mut w) = writer.lock() {
                let _ = w.flush();
            }
        }
    }
}

/// Flushes every per-vhost/route log writer, if any exist. Safe to call
/// even when no `log_file` was ever configured (the writer map is just
/// empty) — used both by the periodic ticker below and by the
/// shutdown path in `main`.
pub fn flush_vhost_writers() {
    if let Some(writers) = VHOST_WRITERS.get() {
        writers.flush_all();
    }
}

/// Flushes `VHOST_WRITERS` on a fixed interval so a buffered line never
/// sits unwritten for longer than `interval_secs`, without paying a
/// syscall on every single log line the way flushing inside `write`
/// would. Spawned unconditionally by `init` — cheap to run even when no
/// vhost/route ever sets a `log_file` (the writer map is simply empty,
/// so each tick is a fast no-op).
async fn flush_ticker(interval_ms: u64) {
    let mut ticker = tokio::time::interval(std::time::Duration::from_millis(interval_ms.max(1)));
    ticker.tick().await;
    loop {
        ticker.tick().await;
        flush_vhost_writers();
    }
}

// ─────────────────────────────────────────────────────────────────────
// Startup
// ─────────────────────────────────────────────────────────────────────

/// Compiles the configured format and, if needed, starts the resource
/// sampler. Call once from `main`, **after** `init_logging` (so the
/// `tracing` subscriber exists) and before the servers are bound.
///
/// Note the `page_kib` constant in `resource_sampler` assumes 4 KiB
/// pages. That holds on x86-64 and on aarch64 with the standard 4K
/// granule; on a 16K/64K-page kernel `[memory-usage]` would read low by
/// that factor. Left as a constant rather than a `sysconf` call to keep
/// this module free of a libc dependency — it only affects a cosmetic
/// log field.
pub fn init(config: &AppConfig) {
    let segments = compile_format(&config.logging.format);

    let needs_sampler = segments.iter().any(|s| {
        matches!(
            s,
            Segment::Field(Field::CpuUsage) | Segment::Field(Field::MemoryUsage)
        )
    });

    let mut req = RequiredFields::default();
    for seg in &segments {
        if let Segment::Field(f) = seg {
            match f {
                Field::Ip => req.ip = true,
                Field::UserAgent => req.user_agent = true,
                Field::XForwardedFor => req.xff = true,
                Field::Referer => req.referer = true,
                Field::Query => req.query = true,
                Field::Protocol => req.protocol = true,
                Field::Host => req.host = true,
                Field::CpuUsage => req.cpu_usage = true,
                Field::MemoryUsage => req.memory_usage = true,
                _ => {}
            }
        }
    }

    let _ = FORMAT.set(segments);
    let _ = REQUIRED.set(req);

    // Validate per-vhost log file paths before opening anything.
    if let Err(e) = config.logging.validate_log_paths() {
        panic!("logging config error: {e}");
    }

    // Create per-vhost/route log file writers (files opened lazily).
    let _ = VHOST_WRITERS.set(VhostLogWriter::new());

    // Periodic flush so a buffered line never sits unwritten for
    // longer than `logging.flush_interval_ms` (default 500ms) — see
    // `flush_ticker`'s doc comment for why this isn't just "flush on
    // every write" instead.
    tokio::spawn(flush_ticker(config.logging.flush_interval_ms));

    if needs_sampler && config.logging.enabled {
        let interval = config.logging.resource_sample_interval_secs.max(1);
        tokio::spawn(resource_sampler(interval));
    }
}

// ─────────────────────────────────────────────────────────────────────
// Middleware
// ─────────────────────────────────────────────────────────────────────

pub struct AccessLogger {
    pub state: web::Data<AppState>,
}

impl<S, B> Transform<S, ServiceRequest> for AccessLogger
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = AccessLoggerMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(AccessLoggerMiddleware {
            service,
            state: self.state.clone(),
        })
    }
}

pub struct AccessLoggerMiddleware<S> {
    service: S,
    state: web::Data<AppState>,
}

/// Everything the formatter needs that must be captured **before** the
/// request is consumed by the inner service. Kept as owned `String`s
/// because the request is moved into `service.call` and the response
/// future outlives this scope.
///
/// Fields are only populated when the compiled format actually
/// references them (see `RequiredFields`), keeping the cost on the
/// hot path proportional to the data that will be rendered.
struct Captured {
    method: String,
    path: String,
    query: String,
    protocol: String,
    host: String,
    vhost: String,
    ip: String,
    user_agent: String,
    xff: String,
    referer: String,
}

fn header_str(req: &ServiceRequest, name: &str) -> String {
    req.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("-")
        .to_string()
}

impl<S, B> Service<ServiceRequest> for AccessLoggerMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let state = self.state.clone();

        // Global kill switch, checked first: when logging is off
        // proxy-wide this middleware costs one boolean load and a
        // pass-through future — no captures, no timer, no allocation.
        if !state.config.logging.enabled {
            let fut = self.service.call(req);
            return Box::pin(async move { fut.await });
        }

        // Resolved once here rather than in the formatter so the
        // `connection_info()` borrow (a `Ref`) is released before the
        // request moves into the inner service.
        let host = req.connection_info().host().to_string();
        let vhost = normalize_vhost(&host);

        // Per-vhost kill switch. Route-level is resolved after the
        // call, since the matched route isn't known until the handler
        // has run.
        if !state.config.logging.vhost_enabled(&vhost) {
            let fut = self.service.call(req);
            return Box::pin(async move { fut.await });
        }

        let captured = {
            let req_fields = required_fields();
            Captured {
                method: req.method().as_str().to_string(),
                path: req.path().to_string(),
                query: if req_fields.query {
                    let q = req.query_string();
                    if q.is_empty() {
                        "-".into()
                    } else {
                        q.to_string()
                    }
                } else {
                    String::new()
                },
                protocol: if req_fields.protocol {
                    format!("{:?}", req.version())
                } else {
                    String::new()
                },
                vhost,
                host: if req_fields.host { host } else { String::new() },
                ip: if req_fields.ip {
                    client_ip(req.request(), &state.config)
                        .map(|i| i.to_string())
                        .unwrap_or_else(|| "-".to_string())
                } else {
                    String::new()
                },
                user_agent: if req_fields.user_agent {
                    header_str(&req, "user-agent")
                } else {
                    String::new()
                },
                xff: if req_fields.xff {
                    header_str(&req, "x-forwarded-for")
                } else {
                    String::new()
                },
                referer: if req_fields.referer {
                    header_str(&req, "referer")
                } else {
                    String::new()
                },
            }
        };

        let started = Instant::now();
        let fut = self.service.call(req);

        Box::pin(async move {
            // Deliberately not `fut.await?`: an `Err(actix::Error)` is
            // still a response the client received (a 4xx/5xx), and
            // those are precisely the failures that most need to show
            // up in the log — the `?` in the old code is one reason
            // they never did.
            match fut.await {
                Ok(res) => {
                    let ctx = res.request().extensions().get::<LogContext>().cloned();
                    if route_logging_enabled(&state, ctx.as_ref()) {
                        let status = res.status().as_u16();
                        let len = body_len(&res);
                        let lf = resolve_log_file(&state, ctx.as_ref(), &captured.vhost);
                        emit(&captured, ctx.as_ref(), status, len, started, &lf);
                    }
                    Ok(res)
                }
                Err(e) => {
                    let response = e.as_response_error().error_response();
                    let status = response.status().as_u16();
                    let len = match response.body().size() {
                        BodySize::Sized(n) => n,
                        _ => 0,
                    };
                    let lf = resolve_log_file(&state, None, &captured.vhost);
                    emit(&captured, None, status, len, started, &lf);
                    Err(e)
                }
            }
        })
    }
}

/// Response size as it will go out on the wire.
///
/// Every response ProxyAuth produces is fully buffered (`Bytes`) by the
/// time it reaches here, so `BodySize::Sized` is the normal case and
/// this costs nothing — the body is never touched, let alone consumed.
/// `Content-Length` is the fallback for anything streamed, and `0` for
/// a body whose length genuinely isn't known yet.
///
/// Because this middleware sits **outside** the compression middleware,
/// the value logged is the compressed, on-the-wire length — matching
/// nginx's `$body_bytes_sent` rather than `$upstream_response_length`.
fn body_len<B: MessageBody>(res: &ServiceResponse<B>) -> u64 {
    match res.response().body().size() {
        BodySize::Sized(n) => n,
        BodySize::None => 0,
        BodySize::Stream => res
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0),
    }
}

fn normalize_vhost(host: &str) -> String {
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
    let trimmed = without_port.trim();
    if trimmed.is_empty() {
        "-".to_string()
    } else {
        trimmed.to_ascii_lowercase()
    }
}

/// Route-level opt-out, resolved after the handler ran.
///
/// A request with no `LogContext` never matched a route (404, `/auth`,
/// `/adm/*`, rejected by an outer middleware) — it is logged, since
/// only a route can carry a route-level `log: false` and there is no
/// route here to have set one.
fn route_logging_enabled(state: &web::Data<AppState>, ctx: Option<&LogContext>) -> bool {
    let Some(idx) = ctx.and_then(|c| c.route_idx) else {
        return true;
    };
    let Some(rule) = state.routes.routes.get(idx) else {
        return true;
    };

    // The route's own `log:` in routes.yml wins — it's the more
    // specific of the two, and it's the one that sits next to the route
    // it governs. `logging.routes` in config.json is the fallback, for
    // operators who'd rather keep every logging decision in one file
    // than spread across two.
    match rule.log {
        Some(explicit) => explicit,
        None => state
            .config
            .logging
            .route_enabled(&rule.prefix)
            .unwrap_or(true),
    }
}

/// Resolves the per-vhost/route log file for this request.  Priority
/// order: route `log_file` (from `routes.yml`) → vhost group
/// `log_file` → `logging.vhosts[vhost].log_file` (from `config.json`)
/// → `logging.log_file` (global default).
fn resolve_log_file(state: &web::Data<AppState>, ctx: Option<&LogContext>, vhost: &str) -> String {
    // Per-route override (set in routes.yml).
    if let Some(idx) = ctx.and_then(|c| c.route_idx) {
        if let Some(rule) = state.routes.routes.get(idx) {
            if let Some(ref lf) = rule.log_file {
                if !lf.is_empty() {
                    return lf.clone();
                }
            }
        }
    }

    // Per-vhost override (from config.json).
    if let Some(entry) = state.config.logging.vhosts.get(vhost) {
        if let Some(ref lf) = entry.log_file {
            if !lf.is_empty() {
                return lf.clone();
            }
        }
    }

    // Global default.
    state.config.logging.log_file.clone()
}

fn emit(
    c: &Captured,
    ctx: Option<&LogContext>,
    status: u16,
    len: u64,
    started: Instant,
    log_file: &str,
) {
    let segments = format_segments();
    if segments.is_empty() {
        return;
    }

    // Roughly the length of a rendered line, to avoid regrowing.
    let mut line = String::with_capacity(160);

    for seg in segments {
        match seg {
            Segment::Literal(s) => line.push_str(s),
            Segment::Field(f) => match f {
                Field::Vhost => line.push_str(&c.vhost),
                Field::Ip => line.push_str(&c.ip),
                Field::Path => line.push_str(&c.path),
                Field::Method => line.push_str(&c.method),
                Field::Status => line.push_str(itoa(status as u64).as_str()),
                Field::Length => line.push_str(itoa(len).as_str()),
                Field::UserAgent => line.push_str(&c.user_agent),
                Field::XForwardedFor => line.push_str(&c.xff),
                Field::Host => line.push_str(&c.host),
                Field::Protocol => line.push_str(&c.protocol),
                Field::Query => line.push_str(&c.query),
                Field::Referer => line.push_str(&c.referer),
                Field::RequestTime => {
                    let micros = started.elapsed().as_micros() as u64;
                    line.push_str(&format!("{}.{:03}ms", micros / 1000, micros % 1000));
                }
                Field::RequestTimeNs => {
                    // Bare integer, no unit suffix — deliberately, for
                    // compatibility with log analyzers (e.g. GoAccess)
                    // that expect a raw numeric value for a
                    // time-taken field rather than one with embedded
                    // units, and do their own unit interpretation via
                    // their own format config instead.
                    line.push_str(&started.elapsed().as_nanos().to_string());
                }
                Field::CpuUsage => fmt_cpu(&mut line),
                Field::MemoryUsage => fmt_mem(&mut line),
                Field::Username => {
                    line.push_str(ctx.and_then(|c| c.username.as_deref()).unwrap_or("-"))
                }
                Field::TokenId => {
                    line.push_str(ctx.and_then(|c| c.token_id.as_deref()).unwrap_or("-"))
                }
                Field::Route => line.push_str(
                    &ctx.and_then(|c| c.route_idx)
                        .map(|i| i.to_string())
                        .unwrap_or_else(|| "-".to_string()),
                ),
                Field::ErrorDetail => {
                    line.push_str(ctx.and_then(|c| c.error_detail.as_deref()).unwrap_or("-"))
                }
                Field::Time => {
                    line.push_str(&chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string())
                }
            },
        }
    }

    // One `info!` with the whole pre-rendered line: the `tracing`
    // subscriber (local / loki / http, per `config.log.type`) decides
    // where it goes, so this module stays transport-agnostic and the
    // existing `/adm/logs` endpoint keeps working unchanged.
    info!(target: "proxyauth::access", "{}", line);

    // Per-vhost/route file writer: if this request resolved to a
    // dedicated log file, also write the same pre-rendered line there.
    if !log_file.is_empty() {
        if let Some(writers) = VHOST_WRITERS.get() {
            writers.write(log_file, &line);
        }
    }
}

/// Tiny integer-to-string helper that avoids `format!`'s machinery for
/// the two numeric fields present in essentially every format string.
fn itoa(mut n: u64) -> String {
    if n == 0 {
        return "0".to_string();
    }
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    while n > 0 {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    // Safe: every byte written is an ASCII digit.
    String::from_utf8_lossy(&buf[i..]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiles_known_placeholders() {
        let segs = compile_format("[vhost] [ip] [status]");
        assert_eq!(segs.len(), 5); // field, " ", field, " ", field
        assert!(matches!(segs[0], Segment::Field(Field::Vhost)));
        assert!(matches!(segs[1], Segment::Literal(ref s) if s == " "));
        assert!(matches!(segs[4], Segment::Field(Field::Status)));
    }

    #[test]
    fn unknown_placeholder_survives_as_literal() {
        let segs = compile_format("[stauts]");
        assert_eq!(segs.len(), 1);
        assert!(matches!(segs[0], Segment::Literal(ref s) if s == "[stauts]"));
    }

    #[test]
    fn empty_format_compiles_to_nothing() {
        assert!(compile_format("").is_empty());
    }

    #[test]
    fn placeholder_names_are_case_insensitive() {
        let segs = compile_format("[VHost]");
        assert!(matches!(segs[0], Segment::Field(Field::Vhost)));
    }

    #[test]
    fn multibyte_literals_survive() {
        let segs = compile_format("→[ip]←");
        assert!(matches!(segs[0], Segment::Literal(ref s) if s == "→"));
        assert!(matches!(segs[2], Segment::Literal(ref s) if s == "←"));
    }

    #[test]
    fn unterminated_bracket_is_literal() {
        let segs = compile_format("[ip");
        assert!(matches!(segs[0], Segment::Literal(ref s) if s == "[ip"));
    }

    #[test]
    fn itoa_matches_std() {
        for n in [0u64, 1, 9, 10, 200, 404, 65535, u64::MAX] {
            assert_eq!(itoa(n), n.to_string());
        }
    }

    #[test]
    fn vhost_normalization_strips_port_and_case() {
        assert_eq!(normalize_vhost("Example.COM:8443"), "example.com");
        assert_eq!(normalize_vhost("[::1]:8080"), "[::1]");
        assert_eq!(normalize_vhost(""), "-");
    }
}
