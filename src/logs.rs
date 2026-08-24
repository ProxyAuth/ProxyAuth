use crate::AppState;
use crate::adm::stats::is_valid_admin_token;
use actix_web::{HttpRequest, HttpResponse, Responder, web};
use once_cell::sync::Lazy;
use std::collections::VecDeque;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tracing_subscriber::fmt::MakeWriter;

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
