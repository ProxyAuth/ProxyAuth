use serde::Serialize;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use tokio::time::{Duration as TokioDuration, interval};

const HISTORY_LEN: usize = 60;
const NUM_SHARDS: usize = 16; // puissance de 2, >= nombre de cœurs typiques

/// Padding to avoid false sharing between adjacent shard counters
/// (each shard lands on its own cache line).
#[repr(align(64))]
struct PaddedCounter(AtomicU64);

pub struct RequestStats {
    shards: [PaddedCounter; NUM_SHARDS],
    total: AtomicU64,
    history: [AtomicU64; HISTORY_LEN],
    history_idx: std::sync::atomic::AtomicUsize,
    history_filled: std::sync::atomic::AtomicUsize,
    started_at: Instant,
}

impl RequestStats {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            shards: std::array::from_fn(|_| PaddedCounter(AtomicU64::new(0))),
            total: AtomicU64::new(0),
            history: std::array::from_fn(|_| AtomicU64::new(0)),
            history_idx: std::sync::atomic::AtomicUsize::new(0),
            history_filled: std::sync::atomic::AtomicUsize::new(0),
            started_at: Instant::now(),
        })
    }

    /// Hot path. Picks a shard based on the current thread, so concurrent
    /// requests on different workers almost never contend on the same cache line.
    #[inline]
    pub fn incr(&self) {
        let shard = Self::shard_index();
        self.shards[shard].0.fetch_add(1, Ordering::Relaxed);
        self.total.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    fn shard_index() -> usize {
        thread_local! {
            static SHARD_ID: usize = {
                // Derive a stable per-thread shard from the thread id's hash.
                use std::hash::{Hash, Hasher};
                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                std::thread::current().id().hash(&mut hasher);
                (hasher.finish() as usize) % NUM_SHARDS
            };
        }
        SHARD_ID.with(|id| *id)
    }

    pub fn uptime_secs(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }

    pub fn total_requests(&self) -> u64 {
        self.total.load(Ordering::Relaxed)
    }

    /// Sums all shards. Only called by the ticker, once per second — cheap even
    /// with the extra reads, since it's off the hot path.
    fn drain_and_sum(&self) -> u64 {
        self.shards
            .iter()
            .map(|s| s.0.swap(0, Ordering::Relaxed))
            .sum()
    }

    fn push_sample(&self, value: u64) {
        let idx = self.history_idx.fetch_add(1, Ordering::Relaxed) % HISTORY_LEN;
        self.history[idx].store(value, Ordering::Relaxed);
        let filled = self.history_filled.load(Ordering::Relaxed);
        if filled < HISTORY_LEN {
            self.history_filled.store(filled + 1, Ordering::Relaxed);
        }
    }

    fn recent_sum(&self, k: usize) -> (u64, usize) {
        let filled = self.history_filled.load(Ordering::Relaxed).min(HISTORY_LEN);
        let n = k.min(filled);
        if n == 0 {
            return (0, 0);
        }
        let write_idx = self.history_idx.load(Ordering::Relaxed);
        let mut sum = 0u64;
        for i in 0..n {
            let idx = (write_idx + HISTORY_LEN - 1 - i) % HISTORY_LEN;
            sum += self.history[idx].load(Ordering::Relaxed);
        }
        (sum, n)
    }

    fn last_sample(&self) -> u64 {
        let filled = self.history_filled.load(Ordering::Relaxed);
        if filled == 0 {
            return 0;
        }
        let write_idx = self.history_idx.load(Ordering::Relaxed);
        let idx = (write_idx + HISTORY_LEN - 1) % HISTORY_LEN;
        self.history[idx].load(Ordering::Relaxed)
    }
}

pub fn spawn_stats_ticker(stats: Arc<RequestStats>) {
    if tokio::runtime::Handle::try_current().is_ok() {
        tokio::spawn(async move {
            let mut tick = interval(TokioDuration::from_secs(1));
            loop {
                tick.tick().await;
                let current = stats.drain_and_sum();
                stats.push_sample(current);
            }
        });
    }
}

#[derive(Serialize, serde::Deserialize)]
pub struct ProxyStatsResponse {
    pub requests_per_second: u64,
    pub avg_rps_10s: f64,
    pub avg_rps_60s: f64,
    pub total_requests: u64,
    pub uptime_seconds: u64,
    pub active_sessions: usize,
}

pub fn build_stats_response(stats: &RequestStats, active_sessions: usize) -> ProxyStatsResponse {
    let last = stats.last_sample();
    let (sum10, n10) = stats.recent_sum(10);
    let (sum60, n60) = stats.recent_sum(HISTORY_LEN);
    let avg10 = if n10 == 0 {
        0.0
    } else {
        sum10 as f64 / n10 as f64
    };
    let avg60 = if n60 == 0 {
        0.0
    } else {
        sum60 as f64 / n60 as f64
    };

    ProxyStatsResponse {
        requests_per_second: last,
        avg_rps_10s: avg10,
        avg_rps_60s: avg60,
        total_requests: stats.total_requests(),
        uptime_seconds: stats.uptime_secs(),
        active_sessions,
    }
}

/// Default path for the local stats control socket — see
/// `spawn_stats_socket`.
pub const STATS_SOCKET_PATH: &str = "/opt/proxyauth/run/stats.sock";

/// Serves `ProxyStatsResponse` as JSON over a Unix domain socket at
/// `socket_path`, for `proxyauth stats` (see `cli::prompt`) to read
/// directly — no HTTPS handshake, no admin token, not even a TCP
/// connection. `RequestStats`/`CounterToken` only ever exist as
/// in-process memory in the running server, so the CLI (a separate,
/// short-lived process each time it runs) has no way to read them
/// except through *some* channel; a Unix socket is the lightest one
/// available; and its own filesystem permissions are the
/// authentication (the socket lives inside `/opt/proxyauth`, `0700`
/// and owned by `run_user` — see `def_config::setup_stats_socket_dir`
/// — so only that user, or root, can even open it), rather than
/// needing the admin token this same data is already gated behind
/// over HTTPS at `/adm/stats`.
///
/// One-shot protocol: a client connects, this writes exactly one JSON
/// object, then closes the connection — no request line needed since
/// this socket only ever serves the one thing.
pub async fn spawn_stats_socket(
    stats: std::sync::Arc<RequestStats>,
    counter: std::sync::Arc<crate::CounterToken>,
    socket_path: &std::path::Path,
    run_user: &str,
    run_group: Option<&str>,
) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    use tokio::net::UnixListener;

    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // A stale socket file from a previous run (e.g. after a crash
    // that skipped normal cleanup) makes bind() fail with "address in
    // use" even though nothing is actually listening — remove it
    // first. Safe: a *live* socket can't be unlinked out from under
    // an accepted connection, only prevents binding a fresh listener
    // at the same path.
    let _ = std::fs::remove_file(socket_path);

    let listener = UnixListener::bind(socket_path)?;

    // Called while still root (see main.rs — this is spawned before
    // the privilege drop, same as the ACME port-80 listener), so the
    // socket starts out root-owned regardless of what `run_user` ends
    // up being. Chown it to match — `proxyauth stats` connects as
    // `run_user` (after its own switch_to_user), and needs write
    // access to the socket to do that.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let owner_spec = format!("{run_user}:{}", run_group.unwrap_or(run_user));
        let _ = std::process::Command::new("chown")
            .args([owner_spec, socket_path.to_string_lossy().to_string()])
            .status();
        let _ = std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600));
    }

    loop {
        let (mut stream, _addr) = listener.accept().await?;
        let stats = stats.clone();
        let counter = counter.clone();
        tokio::spawn(async move {
            let active_sessions = counter.count_active_sessions();
            let resp = build_stats_response(&stats, active_sessions);
            if let Ok(json) = serde_json::to_vec(&resp) {
                let _ = stream.write_all(&json).await;
            }
        });
    }
}
