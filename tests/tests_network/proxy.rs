#[cfg(test)]
mod tests {
    use proxyauth::config::config::{AppConfig, RouteRule};
    use proxyauth::network::proxy::{
        find_route_for_redirect_path, init_routes_order, match_route_idx, resolve_tag_csrf_token,
    };

    /// `prefix` is `RouteRule`'s one genuinely required field (no
    /// serde default) — every other field does have one, so a minimal
    /// JSON object naming just the fields these tests actually care
    /// about is enough, no need to spell out all ~30 fields the way a
    /// literal struct construction would require.
    fn rule(prefix: &str, vhost: &[&str]) -> RouteRule {
        let vhost_json = vhost
            .iter()
            .map(|v| format!("\"{v}\""))
            .collect::<Vec<_>>()
            .join(",");
        let json = format!(r#"{{"prefix": "{prefix}", "vhost": [{vhost_json}]}}"#);
        serde_json::from_str(&json)
            .expect("RouteRule must deserialize given just prefix/vhost — every other field has a serde default")
    }

    /// Same idea for `RouteRule`, but adding a `csrf_token` override —
    /// `None` (the JSON key omitted) leaves it unset (inherits the
    /// global default), `Some(b)` sets it explicitly.
    fn rule_with_csrf(prefix: &str, csrf_token: Option<bool>) -> RouteRule {
        let csrf_field = match csrf_token {
            Some(b) => format!(r#","csrf_token": {b}"#),
            None => String::new(),
        };
        let json = format!(r#"{{"prefix": "{prefix}"{csrf_field}}}"#);
        serde_json::from_str(&json).expect("RouteRule must deserialize with just prefix + optional csrf_token")
    }

    /// `token_expiry_seconds`/`secret`/`users` are `AppConfig`'s only
    /// fields without a serde default — everything else, including
    /// `csrf_token` (defaults to `true`), falls back on its own if
    /// omitted from the JSON.
    fn global_config(csrf_token: Option<bool>) -> AppConfig {
        let csrf_field = match csrf_token {
            Some(b) => format!(r#","csrf_token": {b}"#),
            None => String::new(),
        };
        let json = format!(
            r#"{{"token_expiry_seconds": 3600, "secret": "test-secret", "users": []{csrf_field}}}"#
        );
        serde_json::from_str(&json).expect("AppConfig must deserialize with just the 3 required fields + optional csrf_token")
    }

    #[test]
    fn find_route_for_redirect_path_picks_the_matching_vhosts_route() {
        // Reproduces the exact real-world bug this function was
        // extracted to fix: an unrelated vhost's "/" route (here,
        // standing in for something like a "cv" site sharing the same
        // routes.yml) appears BEFORE the actual target vhost's own
        // "/" route — a completely ordinary, realistic ordering, not
        // a contrived edge case.
        let routes = vec![
            rule("/", &["cv.example.com"]),
            rule("/", &["demo.proxyauth.app"]),
            rule("/app", &["demo.proxyauth.app"]),
        ];

        let found = find_route_for_redirect_path("/", Some("demo.proxyauth.app"), &routes);
        assert!(found.is_some());
        assert_eq!(
            found.unwrap().vhost,
            vec!["demo.proxyauth.app".to_string()],
            "must pick demo.proxyauth.app's own route, not cv.example.com's — even though cv's comes first in the list"
        );
    }

    #[test]
    fn find_route_for_redirect_path_never_picks_a_different_vhosts_route() {
        // The inverse check: requesting cv.example.com must never
        // resolve to demo's route either — this isn't just "first
        // vhost-specific match wins", it's genuinely scoped per host.
        let routes = vec![
            rule("/", &["cv.example.com"]),
            rule("/", &["demo.proxyauth.app"]),
        ];

        let found = find_route_for_redirect_path("/", Some("cv.example.com"), &routes);
        assert_eq!(found.unwrap().vhost, vec!["cv.example.com".to_string()]);
    }

    #[test]
    fn find_route_for_redirect_path_falls_back_to_a_catchall() {
        // A route with no `vhost` at all (empty list) is a catch-all —
        // matches any host, same semantics as normal request routing.
        let routes = vec![rule("/", &[])];
        let found = find_route_for_redirect_path("/", Some("anything.example.com"), &routes);
        assert!(found.is_some());
    }

    #[test]
    fn find_route_for_redirect_path_same_prefix_catchall_vs_vhost_specific_is_list_order() {
        // NOT a regression test for the original bug — this documents
        // a separate, narrower, pre-existing characteristic of
        // build_route_order/match_route_idx (the same ordering *every*
        // request uses, not something specific to this function):
        // sorting only considers path-prefix specificity, never vhost
        // specificity. Two routes sharing the *exact same* prefix tie
        // in that sort, and a stable sort then falls back to
        // routes.yml's own listed order — so whichever of the two is
        // listed first in routes.yml wins here, catch-all or not.
        //
        // This is NOT the bug that got fixed: the original report and
        // `find_route_for_redirect_path_picks_the_matching_vhosts_route`
        // above both involve two *vhost-specific* routes (neither an
        // actual catch-all) — vhost_matches correctly skips the
        // non-matching one there regardless of list order, since it's
        // checked before a route is even considered a candidate. This
        // test is narrower: a genuine empty-vhost catch-all specifically
        // competing with a vhost-specific route at the identical prefix
        // is a much rarer configuration, and changing it would mean
        // changing build_route_order itself — core routing logic used
        // by every request, not just this one code path — which is out
        // of scope for the vhost bug this function exists to fix.
        let routes = vec![
            rule("/", &[]), // catch-all, listed first -> wins, by list order
            rule("/", &["demo.proxyauth.app"]),
        ];
        let found = find_route_for_redirect_path("/", Some("demo.proxyauth.app"), &routes);
        assert_eq!(found.unwrap().vhost, Vec::<String>::new());

        // Swap the listing order -> the vhost-specific one wins instead,
        // confirming this really is list-order-dependent, not some
        // fixed "catch-all always wins" rule.
        let routes_swapped = vec![
            rule("/", &["demo.proxyauth.app"]),
            rule("/", &[]),
        ];
        let found_swapped =
            find_route_for_redirect_path("/", Some("demo.proxyauth.app"), &routes_swapped);
        assert_eq!(
            found_swapped.unwrap().vhost,
            vec!["demo.proxyauth.app".to_string()]
        );
    }

    #[test]
    fn find_route_for_redirect_path_none_for_unknown_host_with_no_catchall() {
        let routes = vec![rule("/", &["demo.proxyauth.app"])];
        let found = find_route_for_redirect_path("/", Some("unknown.example.com"), &routes);
        assert!(found.is_none());
    }

    #[test]
    fn find_route_for_redirect_path_respects_path_prefix_too() {
        // Not just a vhost bugfix regression test — confirms the
        // function still does its other, original job correctly:
        // picking the right PATH within a vhost that has more than
        // one route.
        let routes = vec![
            rule("/", &["demo.proxyauth.app"]),
            rule("/app", &["demo.proxyauth.app"]),
        ];
        let found = find_route_for_redirect_path("/app", Some("demo.proxyauth.app"), &routes);
        assert_eq!(found.unwrap().prefix, "/app");
    }

    // ── resolve_tag_csrf_token ──────────────────────────────────────
    //
    // Regression tests for a real reported bug: the tag_proxyauth
    // mechanism's {{ csrf_token }} substitution generated a token
    // unconditionally whenever tag_proxyauth was on, ignoring
    // csrf_token/csrf_enabled entirely — so `csrf_token: false`
    // didn't fully disable CSRF-related behavior the way an operator
    // would reasonably expect. resolve_tag_csrf_token is the fix:
    // None (a token that never gets generated at all) whenever CSRF
    // protection is off for the resolved route/vhost.

    #[test]
    fn resolve_tag_csrf_token_none_when_globally_disabled_and_route_has_no_override() {
        let global = global_config(Some(false));
        let route = rule_with_csrf("/", None);
        assert_eq!(resolve_tag_csrf_token(&route, &global), None);
    }

    #[test]
    fn resolve_tag_csrf_token_some_when_globally_enabled_and_route_has_no_override() {
        let global = global_config(Some(true));
        let route = rule_with_csrf("/", None);
        assert!(resolve_tag_csrf_token(&route, &global).is_some());
    }

    #[test]
    fn resolve_tag_csrf_token_none_when_route_overrides_off_despite_global_on() {
        // The exact reported scenario: csrf protection turned off for
        // this specific route/vhost (via its own csrf_token: false),
        // even though the global default is on. Must NOT generate a
        // token — this is precisely the case the original bug got
        // wrong (a token was generated here regardless).
        let global = global_config(Some(true));
        let route = rule_with_csrf("/", Some(false));
        assert_eq!(
            resolve_tag_csrf_token(&route, &global),
            None,
            "a route/vhost that explicitly disables csrf_token must not get a tag_proxyauth-injected CSRF token, even though the global default is on"
        );
    }

    #[test]
    fn resolve_tag_csrf_token_some_when_route_overrides_on_despite_global_off() {
        // The inverse: a route/vhost can also turn csrf ON
        // independently of a globally-off default — confirms this
        // isn't just "global wins", the route's own resolved value is
        // what's actually checked.
        let global = global_config(Some(false));
        let route = rule_with_csrf("/", Some(true));
        assert!(resolve_tag_csrf_token(&route, &global).is_some());
    }

    // ── URL bypass: a protected prefix stays protected however the
    //    path is disguised ─────────────────────────────────────────────
    //
    // The whole value of a route's `prefix` is that a protected prefix
    // can't be dodged by dressing the path up. These go through the same
    // public `match_route_idx` real request routing uses, so they cover
    // canonicalisation AND route selection together: every disguised
    // spelling of `/app` must resolve to the protected route, never slip
    // to a weaker catch-all, and genuinely different paths must not be
    // caught by `/app`.

    /// `/app` (protected) plus a catch-all `/`. `build_route_order` puts
    /// `/` last, so `/app` and every disguised spelling must resolve to
    /// index 0, and only genuinely different paths fall to index 1.
    fn protected_then_catch_all() -> Vec<RouteRule> {
        let routes = vec![rule("/app", &[]), rule("/", &[])];
        init_routes_order(&routes);
        routes
    }

    #[test]
    fn disguised_paths_resolve_to_the_protected_route() {
        let routes = protected_then_catch_all();
        for path in [
            "/app",
            "/app/",
            "/app/sub",
            "/app/../app",       // dot segments normalise back to /app
            "/app/./sub",
            "//app",             // redundant leading slashes
            "///app///sub",
            "/app%2Fsub",        // percent-encoded slash
            "/app%2f..%2fapp",
            "/app\\sub",         // backslash separator
            "/./app",
        ] {
            assert_eq!(
                match_route_idx(path, None, &routes),
                Some(0),
                "path {path:?} must route to the protected /app route, not the catch-all"
            );
        }
    }

    #[test]
    fn sibling_and_different_paths_do_not_hit_the_protected_route() {
        let routes = protected_then_catch_all();
        for path in [
            "/application", // substring, not a prefix boundary
            "/app-extra",
            "/apps",
            "/other",
            "/APP", // case-sensitive: a different path
        ] {
            assert_eq!(
                match_route_idx(path, None, &routes),
                Some(1),
                "path {path:?} must fall to the catch-all, never silently onto /app"
            );
        }
    }

    #[test]
    fn no_catch_all_means_disguised_paths_still_match_but_outsiders_miss() {
        // Without a catch-all, the disguises still match /app (Some(0)),
        // and a path outside the prefix matches nothing at all rather
        // than leaking onto the protected route.
        let routes = vec![rule("/app", &[])];
        init_routes_order(&routes);

        assert_eq!(match_route_idx("/app/../app", None, &routes), Some(0));
        assert_eq!(match_route_idx("//app//x", None, &routes), Some(0));
        assert_eq!(match_route_idx("/application", None, &routes), None);
        assert_eq!(match_route_idx("/APP", None, &routes), None);
    }

}
