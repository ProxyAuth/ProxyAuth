use crate::AppState;
use crate::adm::stats::is_valid_admin_token;
use actix_web::{HttpRequest, HttpResponse, Responder, web};
use once_cell::sync::Lazy;
use std::collections::VecDeque;
use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tracing_subscriber::fmt::MakeWriter;

/// Default global application log — everything that goes through
/// `tracing` under the `log.type = "local"` transport (the default when
/// `log` isn't configured at all): database/reset/revoke module
/// diagnostics, startup messages, warnings, everything except the
/// per-request access log lines, which have their own destination (see
/// `network::accesslog` and its `logging.log_file`).
///
/// Without this, the "local" transport had no explicit writer at all —
/// `tracing_subscriber::fmt::Layer` defaulted to stdout, which only
/// ever reached a real file if whatever launched the process happened
/// to redirect it there (e.g. an init script's `output_log=`). Opening
/// this file directly means ProxyAuth's own logging behavior doesn't
/// depend on how it happens to be started.
pub const PROXYAUTH_LOG_PATH: &str = "/var/log/proxyauth/proxyauth.log";

static PROXYAUTH_LOG_FILE: OnceLock<Mutex<BufWriter<File>>> = OnceLock::new();

fn open_proxyauth_log() -> io::Result<BufWriter<File>> {
    let path = Path::new(PROXYAUTH_LOG_PATH);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let file = File::options().create(true).append(true).open(path)?;
    Ok(BufWriter::with_capacity(8192, file))
}

/// The actual `io::Write` handed to `tracing_subscriber` per write
/// call. Writes go into the shared `BufWriter`'s buffer — deliberately
/// not flushed here on every call, same reasoning as
/// `network::accesslog::VhostLogWriter`: flushing on every line would
/// turn each one into its own syscall. `spawn_proxyauth_log_flusher`
/// flushes on a fixed interval instead, and `flush_proxyauth_log` once
/// more on shutdown.
#[derive(Clone)]
pub struct ProxyAuthFileWriter;

impl Write for ProxyAuthFileWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let lock = PROXYAUTH_LOG_FILE.get_or_init(|| match open_proxyauth_log() {
            Ok(w) => Mutex::new(w),
            Err(e) => {
                // The real file couldn't be opened (permissions,
                // missing parent that create_dir_all also failed on,
                // etc.) — fall back to /dev/null so every subsequent
                // write is a harmless no-op instead of panicking the
                // logging path itself. The error is at least visible
                // once, here, on stderr. /dev/null is expected to
                // always be openable on any Unix system this runs on.
                eprintln!(
                    "[logging] failed to open {PROXYAUTH_LOG_PATH}: {e} — application log lines will be dropped"
                );
                let null = File::options()
                    .write(true)
                    .open("/dev/null")
                    .expect("/dev/null must be openable");
                Mutex::new(BufWriter::new(null))
            }
        });
        match lock.lock() {
            Ok(mut w) => w.write(buf),
            Err(_) => Ok(buf.len()), // poisoned — drop the line, don't panic the logger
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        // Real flushing happens via the periodic ticker/shutdown hook,
        // not per call — see the struct doc comment.
        Ok(())
    }
}

#[derive(Clone, Default)]
pub struct ProxyAuthFileMakeWriter;

impl<'a> MakeWriter<'a> for ProxyAuthFileMakeWriter {
    type Writer = ProxyAuthFileWriter;

    fn make_writer(&'a self) -> Self::Writer {
        ProxyAuthFileWriter
    }
}

/// Flushes the buffered writer onto disk, if it's ever been opened.
/// Safe to call even if no "local"-transport log line was ever written
/// (the `OnceLock` is simply still empty).
pub fn flush_proxyauth_log() {
    if let Some(lock) = PROXYAUTH_LOG_FILE.get() {
        if let Ok(mut w) = lock.lock() {
            let _ = w.flush();
        }
    }
}

/// Periodic flush, same interval and reasoning as
/// `network::accesslog`'s per-vhost writer flusher — bounds how long a
/// buffered line can sit unwritten to a couple seconds instead of
/// "whenever the 8 KiB buffer happens to fill up".
pub async fn spawn_proxyauth_log_flusher(interval_ms: u64) {
    let mut ticker = tokio::time::interval(std::time::Duration::from_millis(interval_ms.max(1)));
    ticker.tick().await;
    loop {
        ticker.tick().await;
        flush_proxyauth_log();
    }
}

/// PERF: `VecDeque`, not `Vec` — eviction is an O(1) `pop_front()`.
/// With a `Vec` + `remove(0)`, every line written past `max_logs`
/// shifted the entire buffer down by one, under the global mutex: at a
/// `write_max_logs` of a few tens of thousands, that's tens of
/// thousands of `String` moves *per logged line*. Tolerable while only
/// a fraction of requests produced a line; not once the access-log
/// middleware logs all of them.
pub static LOG_BUFFER: Lazy<Arc<Mutex<VecDeque<String>>>> =
    Lazy::new(|| Arc::new(Mutex::new(VecDeque::new())));

#[derive(Clone)]
pub struct ChannelWriter {
    sender: Arc<UnboundedSender<String>>,
}

impl Write for ChannelWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let s = String::from_utf8_lossy(buf).to_string();
        let _ = self.sender.send(s);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Clone)]
pub struct ChannelLogWriter {
    pub sender: Arc<UnboundedSender<String>>,
}

impl<'a> MakeWriter<'a> for ChannelLogWriter {
    type Writer = ChannelWriter;

    fn make_writer(&'a self) -> Self::Writer {
        ChannelWriter {
            sender: self.sender.clone(),
        }
    }
}

pub async fn log_collector(mut rx: UnboundedReceiver<String>, max_logs: usize) {
    while let Some(log) = rx.recv().await {
        let mut logs = LOG_BUFFER.lock().unwrap();
        logs.push_back(log);
        while logs.len() > max_logs {
            logs.pop_front();
        }
    }
}

pub async fn get_logs(req: HttpRequest, data: web::Data<AppState>) -> impl Responder {
    // SECURITY: constant-time comparison (was a plain `==`, vulnerable to a
    // timing side-channel on the admin token — same pattern as adm/stats.rs).
    if !is_valid_admin_token(&req, &data) {
        return HttpResponse::Unauthorized().body("Invalid or missing token");
    }

    // Concatenated while the lock is held, then released before the
    // response is built — `VecDeque` has no `join`, and holding the
    // mutex across response construction would block every worker
    // trying to write a log line.
    let body: String = {
        let logs = LOG_BUFFER.lock().unwrap();
        logs.iter().map(|s| s.as_str()).collect()
    };

    HttpResponse::Ok().content_type("text/plain").body(body)
}
