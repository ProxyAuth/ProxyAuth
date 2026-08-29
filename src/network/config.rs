use crate::config::config::AppConfig;
use once_cell::sync::OnceCell;

#[derive(Debug)]
pub struct LbTuning {
    pub request_timeout_ms: u64,
    pub pool_max_idle_per_host: usize,
    pub keep_alive_secs: u64,

    pub backend_valid_duration_secs: u64,
    pub cooldown_base_secs: u64,
    pub cooldown_max_secs: u64,
    pub backend_reset_threshold_secs: u64,

    /// Upper bound on a failover backend's response body size, in
    /// bytes, before the load balancer gives up on it rather than
    /// keep buffering. The failover path collects a backend's full
    /// response into memory before deciding whether to forward it or
    /// retry the next backend — see `try_forward_to_backend`'s own
    /// doc comment for why that's needed (a retry can't safely happen
    /// once bytes have already started streaming to the client).
    /// Without a cap, a single misbehaving or malicious backend
    /// returning an unbounded body could grow memory usage without
    /// limit. Reuses the same `max_body_size` already used to cap
    /// *request* bodies — the same "how big is reasonable" judgment
    /// applies symmetrically to responses.
    pub max_response_body_bytes: usize,
}

pub static LB_TUNING: OnceCell<LbTuning> = OnceCell::new();

pub fn init_loadbalancer(cfg: &AppConfig) {
    let _ = LB_TUNING.set(LbTuning {
        request_timeout_ms: cfg.client_timeout,
        pool_max_idle_per_host: cfg.max_idle_per_host as usize,
        keep_alive_secs: cfg.keep_alive,

        backend_valid_duration_secs: 2,
        cooldown_base_secs: 2,
        cooldown_max_secs: 5,
        backend_reset_threshold_secs: 10,

        max_response_body_bytes: cfg.max_body_size,
    });
}
