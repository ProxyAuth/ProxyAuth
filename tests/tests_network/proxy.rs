#[cfg(test)]
mod tests {
    use proxyauth::config::config::RouteRule;
    use proxyauth::network::proxy::find_route_for_redirect_path;

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
}
