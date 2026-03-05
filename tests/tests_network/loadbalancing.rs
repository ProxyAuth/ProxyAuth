use proxyauth::config::config::BackendConfig;
use std::time::Instant;
use hyper::Method;
use std::sync::Arc;

#[cfg(test)]
fn reset_lb_state_for_tests() {
    use std::sync::atomic::Ordering;
    use proxyauth::network::loadbalancing::ROUND_ROBIN_COUNTER;
    use proxyauth::network::loadbalancing::LAST_GOOD_BACKEND;
    use proxyauth::network::loadbalancing::BACKEND_COOLDOWN;
    use proxyauth::network::loadbalancing::SWRR_STATE;

    SWRR_STATE.clear();
    BACKEND_COOLDOWN.clear();
    LAST_GOOD_BACKEND.clear();
    ROUND_ROBIN_COUNTER.store(0, Ordering::Relaxed);
}


#[cfg(test)]
mod tests {
    use super::*;
    use hyper::{Body, Request, Response, StatusCode, Server};
    use hyper::service::{make_service_fn, service_fn};
    use std::net::SocketAddr;
    use serial_test::serial;
    use proxyauth::network::loadbalancing::ROUND_ROBIN_COUNTER;
    use proxyauth::network::loadbalancing::LAST_GOOD_BACKEND;
    use proxyauth::network::loadbalancing::BACKEND_COOLDOWN;
    use proxyauth::network::loadbalancing::{get_or_build_client, get_or_build_client_with_proxy};
    use proxyauth::network::loadbalancing::forward_failover;
    use proxyauth::network::loadbalancing::CooldownEntry;
    use proxyauth::network::loadbalancing::ForwardError;
    use proxyauth::network::loadbalancing::{is_in_cooldown, cooldown_base, build_swrr_order, lb};

    use std::sync::atomic::Ordering;

    fn be(url: &str, weight: i32) -> BackendConfig {
        BackendConfig { url: url.to_string(), weight: weight.try_into().unwrap() }
    }


    #[test]
    fn lb_defaults_are_used_when_not_set() {
        let d = lb();
        assert_eq!(d.request_timeout_ms, 2000);
        assert_eq!(d.pool_max_idle_per_host, 1000);
        assert_eq!(d.keep_alive_secs, 30);
        assert_eq!(d.backend_valid_duration_secs, 2);
        assert_eq!(d.cooldown_base_secs, 2);
        assert_eq!(d.cooldown_max_secs, 5);
        assert_eq!(d.backend_reset_threshold_secs, 10);
    }

    #[serial_test::serial]
    #[test]
    fn is_in_cooldown_true_then_false() {
        use super::*;
        reset_lb_state_for_tests();

        let key1 = "backend-1".to_string();

        BACKEND_COOLDOWN.insert(
            key1.clone(),
                                CooldownEntry {
                                    last_failed: Instant::now(),
                                failures: 1,
                                },
        );

        assert!(is_in_cooldown(&key1));

        if let Some(mut entry) = BACKEND_COOLDOWN.get_mut(&key1) {
            let past = Instant::now() - (cooldown_base() + std::time::Duration::from_millis(1));
            entry.value_mut().last_failed = past;
        }

        assert!(!is_in_cooldown(&key1));
    }

    #[serial_test::serial]
    #[test]
    fn swrr_order_prefers_higher_weight_first() {
        // Reset
        reset_lb_state_for_tests();
        ROUND_ROBIN_COUNTER.store(0, Ordering::Relaxed);

        let a = be("A", 3);
        let b = be("B", 1);
        let c = be("C", 1);

        let cands: Vec<&BackendConfig> = vec![&a, &b, &c];

        let order = build_swrr_order(&cands);
        assert!(!order.is_empty());
        assert_eq!(order[0].url, "A");
    }

    #[serial_test::serial]
    #[test]
    fn swrr_rotation_changes_head_when_counter_is_nonzero() {
        // Reset
        reset_lb_state_for_tests();

        let a = be("A", 3);
        let b = be("B", 1);
        let c = be("C", 1);
        let cands: Vec<&BackendConfig> = vec![&a, &b, &c];

        ROUND_ROBIN_COUNTER.store(0, Ordering::Relaxed);
        let o0 = build_swrr_order(&cands);
        assert_eq!(o0[0].url, "A");

        ROUND_ROBIN_COUNTER.store(1, Ordering::Relaxed);
        let o1 = build_swrr_order(&cands);
        assert_ne!(o1[0].url, "A");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn client_pool_returns_same_arc_for_same_backend() {
        let b = "https://example.com";
        let c1 = get_or_build_client(b).await;
        let c2 = get_or_build_client(b).await;
        assert!(Arc::ptr_eq(&c1, &c2), "le pool doit mémoïser par backend");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn proxy_client_pool_returns_same_arc_for_same_tuple() {
        let proxy = "http://127.0.0.1:8888";
        let b = "https://example.com";
        let c1 = get_or_build_client_with_proxy(proxy, b).await;
        let c2 = get_or_build_client_with_proxy(proxy, b).await;
        assert!(Arc::ptr_eq(&c1, &c2), "le pool proxy doit mémoïser par (proxy, backend)");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn forward_failover_with_no_backends_fails_fast() {
        LAST_GOOD_BACKEND.clear();

        let req = Request::builder()
        .method(Method::GET)
        .uri("https://service.local/foo")
        .body(Body::empty())
        .unwrap();

        let backends: Vec<BackendConfig> = vec![]; // aucun backend
        let res = forward_failover(req, &backends, None).await;

        match res {
            Err(ForwardError::AllBackendsFailed) => {}
            other => panic!("attendu AllBackendsFailed, obtenu: {:?}", other),
        }
    }

    async fn spawn_stub(status: StatusCode, body: &'static [u8]) -> SocketAddr {
        let make_svc = make_service_fn(move |_| {
            let body = body.to_vec();
            async move {
                Ok::<_, hyper::Error>(service_fn(move |_req| {
                    let mut resp = Response::new(Body::from(body.clone()));
                    *resp.status_mut() = status;
                    async move { Ok::<_, hyper::Error>(resp) }
                }))
            }
        });

        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let _ = Server::from_tcp(listener).unwrap().serve(make_svc).await;
        });

        addr
    }

    #[tokio::test(flavor = "current_thread")]
    #[serial]
    async fn forward_uses_next_backend_on_error() {
        let a = spawn_stub(StatusCode::INTERNAL_SERVER_ERROR, b"boom").await;
        let b = spawn_stub(StatusCode::OK, b"ok").await;

        let backends = vec![
            be(&format!("http://{}", a), 1),
            be(&format!("http://{}", b), 1),
        ];

        let req = Request::builder()
        .method(Method::GET)
        .uri("/v1/health")
        .body(Body::empty())
        .unwrap();

        let resp = forward_failover(req, &backends, None)
        .await
        .expect("should switch to the second backend");
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn forward_all_backends_failed() {
        let a = spawn_stub(StatusCode::INTERNAL_SERVER_ERROR, b"x").await;
        let b = spawn_stub(StatusCode::INTERNAL_SERVER_ERROR, b"y").await;

        let backends = vec![
            be(&format!("http://{}", a), 1),
            be(&format!("http://{}", b), 1),
        ];

        let req = Request::builder()
        .method(Method::GET)
        .uri("/v1/check")
        .body(Body::empty())
        .unwrap();

        let err = forward_failover(req, &backends, None).await
        .err()
        .expect("expect error when all backends fail");
        assert!(matches!(err, ForwardError::AllBackendsFailed));
    }

}
