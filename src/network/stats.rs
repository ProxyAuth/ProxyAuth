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

#[derive(Serialize)]
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
