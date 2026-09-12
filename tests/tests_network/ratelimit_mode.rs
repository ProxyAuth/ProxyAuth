#[cfg(test)]
mod tests {
    use proxyauth::start_actix::mode_actix_web;

    // `main` computes `1.0 / requests_per_second` for whichever limiter a
    // mode enables, so the mode string has to steer the "both disabled"
    // case (0, 0) away from any branch that would divide by zero. These
    // pin down all four combinations, including that (0, 0) maps to the
    // dedicated GLOBAL_OFF string main's match sends to the no-limiter
    // arm — the regression guard for the startup panic that hit when
    // both limits were 0.

    #[test]
    fn both_disabled_selects_global_off() {
        assert_eq!(mode_actix_web(&0, &0), "RATELIMIT_GLOBAL_OFF");
    }

    #[test]
    fn only_proxy_enabled_disables_auth_limit() {
        assert_eq!(mode_actix_web(&0, &5), "NO_RATELIMIT_AUTH");
    }

    #[test]
    fn only_auth_enabled_disables_proxy_limit() {
        assert_eq!(mode_actix_web(&5, &0), "NO_RATELIMIT_PROXY");
    }

    #[test]
    fn both_enabled_selects_global_on() {
        assert_eq!(mode_actix_web(&5, &5), "RATELIMIT_GLOBAL_ON");
    }

    #[test]
    fn every_combination_is_a_known_mode() {
        // No (auth, proxy) pair may fall through to "NO_CONFIG": each has
        // to resolve to a real mode main knows how to build, otherwise
        // the server would reach the catch-all arm with no limiter where
        // one was configured.
        let known = [
            "NO_RATELIMIT_AUTH",
            "NO_RATELIMIT_PROXY",
            "RATELIMIT_GLOBAL_ON",
            "RATELIMIT_GLOBAL_OFF",
        ];
        for auth in [0u64, 1, 5, 1000] {
            for proxy in [0u64, 1, 5, 1000] {
                let mode = mode_actix_web(&auth, &proxy);
                assert!(
                    known.contains(&mode),
                    "({auth}, {proxy}) produced unexpected mode {mode:?}"
                );
            }
        }
    }
}
