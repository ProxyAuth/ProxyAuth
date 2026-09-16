//! Unit tests for the login-page redirect of `required_login` routes.
//!
//! The rules under test:
//!
//! - a `required_login` route opened without a valid session sends the
//!   visitor to the login page with a `302`;
//! - the login page is `redirect_login_url`, else `logout_redirect_url`
//!   (vhost, then global); with neither, the historical `401` is kept;
//! - API-style requests and non-`GET`/`HEAD` methods keep their `401`;
//! - a page is never redirected to itself;
//! - a signed-in visitor is only forwarded to `login_redirect_url` from
//!   the login page itself, never from other pages.

#[cfg(test)]
mod tests {
    use actix_web::http::{StatusCode, header};
    use actix_web::test::TestRequest;
    use proxyauth::config::config::{AppConfig, RouteRule};
    use proxyauth::network::proxy::{
        is_login_page, login_page_path, login_page_redirect, login_page_redirect_target,
    };

    // ── fixtures ─────────────────────────────────────────────

    fn config(logout_redirect_url: Option<&str>) -> AppConfig {
        serde_json::from_value(serde_json::json!({
            "token_expiry_seconds": 3600,
            "secret": "unit-test-secret-unit-test-secret-unit-test-secret-unit-test",
            "users": [],
            "log": { "type": "disabled" },
            "smtp": null,
            "logout_redirect_url": logout_redirect_url
        }))
        .expect("AppConfig must deserialize from its required fields")
    }

    fn protected(prefix: &str) -> RouteRule {
        serde_json::from_value(serde_json::json!({
            "prefix": prefix,
            "target": "http://127.0.0.1:9",
            "required_login": true
        }))
        .expect("RouteRule must deserialize")
    }

    fn with_login_page(prefix: &str, url: &str) -> RouteRule {
        let mut rule = protected(prefix);
        rule.redirect_login_url = Some(url.to_string());
        rule
    }

    /// What a browser sends when someone opens a page.
    fn navigation(path: &str) -> TestRequest {
        TestRequest::get()
            .uri(path)
            .insert_header(("sec-fetch-mode", "navigate"))
            .insert_header((header::ACCEPT, "text/html,application/xhtml+xml,*/*;q=0.8"))
    }

    // ── which page is the login page ─────────────────────────

    #[test]
    fn redirect_login_url_is_the_first_choice() {
        let cfg = config(Some("/bye"));
        let mut rule = with_login_page("/admin", "/login");
        rule.logout_redirect_url = Some("/signout".into());
        let req = navigation("/admin").to_http_request();
        assert_eq!(login_page_redirect_target(&req, &rule, &cfg), Some("/login"));
    }

    #[test]
    fn falls_back_to_the_vhost_logout_redirect_url() {
        let cfg = config(Some("/global-login"));
        let mut rule = protected("/admin");
        rule.logout_redirect_url = Some("/login".into());
        let req = navigation("/admin").to_http_request();
        assert_eq!(login_page_redirect_target(&req, &rule, &cfg), Some("/login"));
    }

    #[test]
    fn falls_back_to_the_global_logout_redirect_url() {
        let cfg = config(Some("/login"));
        let req = navigation("/admin").to_http_request();
        assert_eq!(
            login_page_redirect_target(&req, &protected("/admin"), &cfg),
            Some("/login")
        );
    }

    #[test]
    fn no_login_page_keeps_the_401() {
        let cfg = config(None);
        let req = navigation("/admin").to_http_request();
        assert_eq!(login_page_redirect_target(&req, &protected("/admin"), &cfg), None);
    }

    #[test]
    fn a_blank_redirect_login_url_counts_as_unset() {
        let cfg = config(None);
        let req = navigation("/admin").to_http_request();
        let rule = with_login_page("/admin", "   ");
        assert_eq!(login_page_redirect_target(&req, &rule, &cfg), None);
    }

    #[test]
    fn absolute_urls_and_query_strings_are_kept() {
        let cfg = config(None);
        let req = navigation("/admin").to_http_request();
        let rule = with_login_page("/admin", "https://auth.example.com/login?next=admin");
        assert_eq!(
            login_page_redirect_target(&req, &rule, &cfg),
            Some("https://auth.example.com/login?next=admin")
        );
    }

    // ── which requests are redirected ────────────────────────

    #[test]
    fn a_browser_navigation_is_redirected() {
        let req = navigation("/admin/stats").to_http_request();
        let rule = with_login_page("/admin", "/login");
        assert_eq!(login_page_redirect_target(&req, &rule, &config(None)), Some("/login"));
    }

    #[test]
    fn plain_curl_and_bare_requests_are_redirected() {
        let rule = with_login_page("/admin", "/login");
        let cfg = config(None);

        let curl = TestRequest::get()
            .uri("/admin")
            .insert_header((header::ACCEPT, "*/*"))
            .insert_header((header::USER_AGENT, "curl/8.5.0"))
            .to_http_request();
        assert_eq!(login_page_redirect_target(&curl, &rule, &cfg), Some("/login"));

        let bare = TestRequest::get().uri("/admin").to_http_request();
        assert_eq!(login_page_redirect_target(&bare, &rule, &cfg), Some("/login"));
    }

    #[test]
    fn head_is_redirected_like_get() {
        let req = TestRequest::default()
            .method(actix_web::http::Method::HEAD)
            .uri("/admin")
            .to_http_request();
        let rule = with_login_page("/admin", "/login");
        assert_eq!(login_page_redirect_target(&req, &rule, &config(None)), Some("/login"));
    }

    #[test]
    fn a_session_cookie_ignored_on_plain_http_still_gets_the_login_page() {
        let req = navigation("/admin")
            .insert_header((header::COOKIE, "theme=dark; session_token=abc"))
            .to_http_request();
        let rule = with_login_page("/admin", "/login");
        assert_eq!(login_page_redirect_target(&req, &rule, &config(None)), Some("/login"));
    }

    // ── which requests keep their 401 ────────────────────────

    #[test]
    fn state_changing_methods_keep_the_401() {
        let rule = with_login_page("/admin", "/login");
        let cfg = config(None);
        for req in [
            TestRequest::post(),
            TestRequest::put(),
            TestRequest::delete(),
            TestRequest::patch(),
        ] {
            let req = req
                .uri("/admin")
                .insert_header((header::ACCEPT, "text/html"))
                .to_http_request();
            assert_eq!(
                login_page_redirect_target(&req, &rule, &cfg),
                None,
                "{} must not be redirected",
                req.method()
            );
        }
    }

    #[test]
    fn an_authorization_header_keeps_the_401() {
        let req = navigation("/admin")
            .insert_header((header::AUTHORIZATION, "Bearer expired-token"))
            .to_http_request();
        let rule = with_login_page("/admin", "/login");
        assert_eq!(login_page_redirect_target(&req, &rule, &config(None)), None);
    }

    #[test]
    fn fetch_and_xhr_keep_the_401() {
        let rule = with_login_page("/admin", "/login");
        let cfg = config(None);

        let fetch = TestRequest::get()
            .uri("/admin/api")
            .insert_header(("sec-fetch-mode", "cors"))
            .insert_header((header::ACCEPT, "*/*"))
            .to_http_request();
        assert_eq!(login_page_redirect_target(&fetch, &rule, &cfg), None);

        let xhr = TestRequest::get()
            .uri("/admin/api")
            .insert_header(("x-requested-with", "XMLHttpRequest"))
            .to_http_request();
        assert_eq!(login_page_redirect_target(&xhr, &rule, &cfg), None);
    }

    #[test]
    fn json_xml_and_event_streams_keep_the_401() {
        let rule = with_login_page("/admin", "/login");
        let cfg = config(None);
        for accept in ["application/json", "application/xml", "text/event-stream"] {
            let req = TestRequest::get()
                .uri("/admin/api")
                .insert_header((header::ACCEPT, accept))
                .to_http_request();
            assert_eq!(
                login_page_redirect_target(&req, &rule, &cfg),
                None,
                "Accept: {accept} must not be redirected"
            );
        }
    }

    #[test]
    fn html_wins_over_json_in_a_browser_accept_header() {
        let req = TestRequest::get()
            .uri("/admin")
            .insert_header((header::ACCEPT, "text/html,application/json;q=0.9"))
            .to_http_request();
        let rule = with_login_page("/admin", "/login");
        assert_eq!(login_page_redirect_target(&req, &rule, &config(None)), Some("/login"));
    }

    // ── loop guard ───────────────────────────────────────────

    #[test]
    fn a_page_is_never_redirected_to_itself() {
        let cfg = config(None);
        let req = navigation("/admin").to_http_request();
        for target in ["/admin", "/admin/", "/admin?from=guard", "/admin#top"] {
            let rule = with_login_page("/admin", target);
            assert_eq!(
                login_page_redirect_target(&req, &rule, &cfg),
                None,
                "{target} points at the page being opened"
            );
        }
    }

    // ── the response ─────────────────────────────────────────

    #[test]
    fn the_redirect_is_a_302_that_is_never_cached() {
        let resp = login_page_redirect("/login", false);
        assert_eq!(resp.status(), StatusCode::FOUND);
        assert_eq!(resp.headers().get(header::LOCATION).unwrap(), "/login");
        let cache = resp.headers().get(header::CACHE_CONTROL).unwrap().to_str().unwrap();
        assert!(cache.contains("no-store"));
        assert!(resp.headers().get(header::SET_COOKIE).is_none());
    }

    #[test]
    fn an_invalid_session_is_cleared_on_the_way() {
        let resp = login_page_redirect("/login", true);
        assert_eq!(resp.status(), StatusCode::FOUND);
        let cookie = resp.headers().get(header::SET_COOKIE).unwrap().to_str().unwrap();
        assert!(cookie.starts_with("session_token=;"));
        assert!(cookie.contains("Max-Age=0"));
        assert!(cookie.contains("Secure") && cookie.contains("HttpOnly"));
    }

    // ── the login page, for signed-in visitors ───────────────

    #[test]
    fn login_page_path_resolution() {
        assert_eq!(login_page_path(None, &config(None)), "/");
        assert_eq!(login_page_path(None, &config(Some("/login"))), "/login");

        let mut rule = protected("/admin");
        rule.logout_redirect_url = Some("/login?x=1".into());
        assert_eq!(login_page_path(Some(&rule), &config(None)), "/login");

        rule.redirect_login_url = Some("https://auth.example.com/sign-in#form".into());
        assert_eq!(login_page_path(Some(&rule), &config(None)), "/sign-in");

        rule.redirect_login_url = Some("https://auth.example.com".into());
        assert_eq!(login_page_path(Some(&rule), &config(None)), "/");
    }

    #[test]
    fn only_the_login_page_counts_as_the_login_page() {
        let mut rule = protected("/admin");
        rule.logout_redirect_url = Some("/login".into());
        let cfg = config(None);

        assert!(is_login_page("/login", Some(&rule), &cfg));
        assert!(is_login_page("/login/", Some(&rule), &cfg));
        assert!(!is_login_page("/", Some(&rule), &cfg), "the public home page is not the login page");
        assert!(!is_login_page("/admin", Some(&rule), &cfg));
        assert!(!is_login_page("/login-help", Some(&rule), &cfg));
    }

    #[test]
    fn the_site_root_is_the_login_page_only_when_nothing_else_is_configured() {
        let cfg = config(None);
        assert!(is_login_page("/", None, &cfg));
        assert!(is_login_page("/", Some(&protected("/")), &cfg));
        assert!(!is_login_page("/", None, &config(Some("/login"))));
    }
}
