use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::collections::VecDeque;
use tokio::sync::RwLock;
use tokio::time::{interval, Duration as TokioDuration};
use std::time::Instant;
use serde::Serialize;

pub struct RequestStats {
    counter: AtomicU64,
    total: AtomicU64,
    history: RwLock<VecDeque<u64>>,
    started_at: Instant,
}

impl RequestStats {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            counter: AtomicU64::new(0),
                 total: AtomicU64::new(0),
                 history: RwLock::new(VecDeque::with_capacity(60)),
                 started_at: Instant::now(),
        })
    }

    #[inline]
    pub fn incr(&self) {
        self.counter.fetch_add(1, Ordering::Relaxed);
        self.total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn uptime_secs(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }
}

pub fn spawn_stats_ticker(stats: Arc<RequestStats>) {
    // Only spawn if we're actually inside a Tokio runtime (e.g. not in sync unit tests
    // that build AppState without a runtime context).
    if tokio::runtime::Handle::try_current().is_ok() {
        tokio::spawn(async move {
            let mut tick = interval(TokioDuration::from_secs(1));
            loop {
                tick.tick().await;
                let current = stats.counter.swap(0, Ordering::Relaxed);
                let mut hist = stats.history.write().await;
                if hist.len() >= 60 {
                    hist.pop_front();
                }
                hist.push_back(current);
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

pub async fn build_stats_response(stats: &RequestStats, active_sessions: usize) -> ProxyStatsResponse {
    let hist = stats.history.read().await;
    let last = *hist.back().unwrap_or(&0);
    let n10 = hist.len().min(10);
    let avg10 = if n10 == 0 { 0.0 } else { hist.iter().rev().take(n10).sum::<u64>() as f64 / n10 as f64 };
    let n60 = hist.len();
    let avg60 = if n60 == 0 { 0.0 } else { hist.iter().sum::<u64>() as f64 / n60 as f64 };

    ProxyStatsResponse {
        requests_per_second: last,
        avg_rps_10s: avg10,
        avg_rps_60s: avg60,
        total_requests: stats.total.load(Ordering::Relaxed),
        uptime_seconds: stats.uptime_secs(),
        active_sessions,
    }
}
