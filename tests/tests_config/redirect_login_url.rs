//! `redirect_login_url` and the `session_cookie_age` alias in routes.yml:
//! parsing, inheritance from `vhosts:` groups, and startup validation.

#[cfg(test)]
mod tests {
    use proxyauth::config::config::RouteConfig;

    fn expand(yaml: &str) -> RouteConfig {
        serde_yaml::from_str::<RouteConfig>(yaml)
            .expect("routes.yml must parse")
            .expand_vhost_groups()
    }

    fn route<'a>(routes: &'a RouteConfig, prefix: &str) -> &'a proxyauth::config::config::RouteRule {
        routes
            .routes
            .iter()
            .find(|r| r.prefix == prefix)
            .unwrap_or_else(|| panic!("no route {prefix}"))
    }

    #[test]
    fn a_group_value_reaches_every_route() {
        let routes = expand(
            r#"
vhosts:
  - vhost: ["blog.example.com"]
    redirect_login_url: "/login"
    routes:
      - prefix: "/admin"
        target: "http://127.0.0.1:9005"
        required_login: true
      - prefix: "/drafts"
        target: "http://127.0.0.1:9005"
        required_login: true
"#,
        );
        assert_eq!(route(&routes, "/admin").resolved_redirect_login_url(), Some("/login"));
        assert_eq!(route(&routes, "/drafts").resolved_redirect_login_url(), Some("/login"));
    }

    #[test]
    fn a_route_value_overrides_its_group() {
        let routes = expand(
            r#"
vhosts:
  - vhost: ["blog.example.com"]
    redirect_login_url: "/login"
    routes:
      - prefix: "/admin"
        target: "http://127.0.0.1:9005"
        required_login: true
      - prefix: "/partners"
        target: "http://127.0.0.1:9005"
        required_login: true
        redirect_login_url: "https://auth.example.com/login"
"#,
        );
        assert_eq!(route(&routes, "/admin").resolved_redirect_login_url(), Some("/login"));
        assert_eq!(
            route(&routes, "/partners").resolved_redirect_login_url(),
            Some("https://auth.example.com/login")
        );
    }

    #[test]
    fn login_page_url_is_accepted_as_an_alias() {
        let routes = expand(
            r#"
routes:
  - prefix: "/admin"
    target: "http://127.0.0.1:9005"
    required_login: true
    login_page_url: "/signin"
"#,
        );
        assert_eq!(route(&routes, "/admin").resolved_redirect_login_url(), Some("/signin"));
    }

    #[test]
    fn unset_and_blank_values_resolve_to_none() {
        let routes = expand(
            r#"
routes:
  - prefix: "/admin"
    target: "http://127.0.0.1:9005"
    required_login: true
  - prefix: "/blank"
    target: "http://127.0.0.1:9005"
    required_login: true
    redirect_login_url: "   "
"#,
        );
        assert_eq!(route(&routes, "/admin").resolved_redirect_login_url(), None);
        assert_eq!(route(&routes, "/blank").resolved_redirect_login_url(), None);
    }

    #[test]
    fn redirect_login_url_is_independent_of_login_redirect_url() {
        let routes = expand(
            r#"
vhosts:
  - vhost: ["blog.example.com"]
    redirect_login_url: "/login"
    login_redirect_url: "/admin"
    routes:
      - prefix: "/admin"
        target: "http://127.0.0.1:9005"
        required_login: true
"#,
        );
        let admin = route(&routes, "/admin");
        assert_eq!(admin.resolved_redirect_login_url(), Some("/login"));
        assert_eq!(admin.login_redirect_url.as_deref(), Some("/admin"));
    }

    // ── session_cookie_age alias ─────────────────────────────

    #[test]
    fn session_cookie_age_is_an_alias_of_max_age_session_cookie() {
        let routes = expand(
            r#"
vhosts:
  - vhost: ["blog.example.com"]
    session_cookie_age: 1800
    routes:
      - prefix: "/admin"
        target: "http://127.0.0.1:9005"
      - prefix: "/short"
        target: "http://127.0.0.1:9005"
        session_cookie_age: 600
"#,
        );
        assert_eq!(route(&routes, "/admin").max_age_session_cookie, Some(1800));
        assert_eq!(route(&routes, "/short").max_age_session_cookie, Some(600));
    }

    #[test]
    fn max_age_session_cookie_still_works() {
        let routes = expand(
            r#"
vhosts:
  - vhost: ["blog.example.com"]
    max_age_session_cookie: 3600
    routes:
      - prefix: "/admin"
        target: "http://127.0.0.1:9005"
"#,
        );
        assert_eq!(route(&routes, "/admin").max_age_session_cookie, Some(3600));
    }

    // ── validation at startup ────────────────────────────────

    #[test]
    fn same_site_paths_and_absolute_urls_are_accepted() {
        for url in [
            "/login",
            "/login?next=%2Fadmin",
            "https://auth.example.com/login",
            "http://intranet.local/login",
        ] {
            let yaml = format!(
                "routes:\n  - prefix: \"/admin\"\n    target: \"http://127.0.0.1:9005\"\n    redirect_login_url: \"{url}\"\n"
            );
            let routes = expand(&yaml);
            assert_eq!(route(&routes, "/admin").resolved_redirect_login_url(), Some(url));
        }
    }

    fn assert_refused(url: &str) {
        let yaml = format!(
            "routes:\n  - prefix: \"/admin\"\n    target: \"http://127.0.0.1:9005\"\n    redirect_login_url: \"{url}\"\n"
        );
        let result = std::panic::catch_unwind(|| expand(&yaml));
        let err = result.expect_err(&format!("\"{url}\" must be refused at startup"));
        let message = err
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| err.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_default();
        assert!(
            message.contains("redirect_login_url") && message.contains("/admin"),
            "the error must name the setting and the route: {message}"
        );
    }

    #[test]
    fn protocol_relative_urls_are_refused() {
        assert_refused("//evil.example.com/login");
    }

    #[test]
    fn relative_paths_without_a_leading_slash_are_refused() {
        assert_refused("login.html");
    }

    #[test]
    fn other_schemes_are_refused() {
        assert_refused("javascript:alert(1)");
        assert_refused("ftp://example.com/login");
    }

    #[test]
    fn spaces_inside_the_url_are_refused() {
        assert_refused("/log in");
    }
}
