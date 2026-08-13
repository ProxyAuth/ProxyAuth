# 🔐 Security Audit — ProxyAuth (beta 1.0.0-beta5)

**Audit date:** August 12–13, 2026 (updated — full re-scan of every remaining module, including the load balancer)
**Scope:** manual review of the Rust source code (`src/`). No `cargo audit` run (not available in the analysis environment) — recommended as a follow-up.
**Overall score:** **5.5 / 10** *(revised down from the initial 7/10 after finding #0 below — a complete, unthrottled 2FA bypass — turned up during this full re-scan)*

The project is generally well designed for a homegrown reverse-proxy authentication system: Argon2 for passwords, authenticated encryption (XChaCha20-Poly1305), HKDF key derivation, CSRF protection with constant-time comparison and a single-use nonce store, strict stripping of `Authorization`/`x-user*` headers before forwarding to the backend, and correct handling of `X-Forwarded-For` **in the main proxy** (only trusted when the peer is explicitly listed in `trust_proxy_forward_for`).

Several concrete vulnerabilities were found, however — including one that undermines the brute-force protection the project advertises, and an inconsistency in how the admin token is compared. Details below, ranked by severity.

> **Note on the hyper 0.14 → 1.x migration:** the request-forwarding path (`network/proxy.rs`) builds outbound requests manually against `hyper::Request::builder()` on top of `hyper_util::client::legacy::Client` — this is exactly the kind of low-level code path a major hyper version bump touches directly. I specifically re-reviewed header/body forwarding with this in mind and found finding **#2** below (hop-by-hop headers forwarded unfiltered, and a duplicated `Connection` header), which is the sort of regression this kind of migration tends to introduce or leave uncovered.

---

## ✅ Summary

| Security feature | Status | Detail |
|---|---|---|
| Argon2 password hashing | ✅ OK | Per-user salt, verification via `PasswordHash`. |
| Token encryption (XChaCha20-Poly1305) | ✅ OK | AEAD, random 24-byte nonce via `OsRng`, no nonce reuse observed. |
| CSRF protection | ✅ OK | Single-use nonce, `blake3::keyed_hash` signature, constant-time comparison (`subtle`). |
| TOTP 2FA | ✅ OK | Supported on both user login and admin flows. |
| Secure RNG (`OsRng`) | ✅ OK | Used for keys, salts, nonces. |
| IP anti-spoofing (main proxy) | ✅ OK | `network::proxy::client_ip` only trusts `X-Forwarded-For` from a trusted peer. |
| IP anti-spoofing (rate limiter) | 🔴 Vulnerable | `network::ratelimit::client_ip` trusts `X-Forwarded-For` with no verification → rate-limit bypass. |
| Admin token comparison | 🟠 Inconsistent | Constant-time on `/adm/stats`, but not on `/adm/revoke` or `/adm/logs`. |
| Resistance to account enumeration | 🔴 Vulnerable | Timing leak on login (`&&` short-circuit before Argon2 runs). |
| Secrets stored in `config.json` | 🟡 Minor | `secret`, `token_admin`, `otpkey` stored in plaintext (acceptable but worth hardening). |
| Header stripping toward backend (auth-related) | ✅ OK | `authorization`, `x-user`, `x-user-roles` are explicitly excluded from client → backend forwarding. |
| Hop-by-hop / framing header stripping | 🔴 Vulnerable | `Content-Length`, `Transfer-Encoding`, `TE`, `Trailer`, `Upgrade`, `Keep-Alive` etc. are forwarded verbatim; `Connection` can end up duplicated on the outbound request. |
| Path traversal (rule matching) | ✅ OK | Path canonicalization (`.`/`..`/`%2e%2e`/`\`) before filter matching. |
| Logging | ✅ OK | No secrets or tokens observed in plaintext in the logs. |

---

## 🟣 Critical finding (full module re-scan)

### 0. `/adm/auth/totp/get` defeats 2FA entirely, and has zero rate limiting
**Files: `src/adm/registry_otp.rs` (`get_otpauth_uri`), `src/main.rs` (route registration)**

This endpoint is meant to let a user provision their authenticator app (returns an `otpauth://` URI + the raw secret). Two separate issues combine into a critical vulnerability:

1. **It returns the existing TOTP secret on every call, not just at first enrollment.** The handler checks `if user.otpkey.is_none() { add_otpkey(...) }` and then, regardless of whether the key already existed, reads it back from `config.json` and returns it in the JSON response:
   ```rust
   if let Some(ref secret) = otpkey {
       let uri = generate_otpauth_uri(&auth.username, "ProxyAuth", &secret, ...);
       return cors_response(HttpResponse::Ok(), &req)
           .json(OtpAuthUriResponse { otpauth_uri: uri, otpkey: otpkey.expect("") });
   }
   ```
   Anyone who can supply a valid `username`/`password` — i.e. the password alone — can retrieve the **already-provisioned** TOTP secret at any time, not just once during enrollment. This collapses two-factor authentication back down to one factor: whoever has the password can always fetch the second factor too, and can then compute valid TOTP codes indefinitely (until an admin manually rotates `otpkey`).
2. **This route carries no rate limiting whatsoever.** Looking at every `mode_actix` branch in `main.rs` (`NO_RATELIMIT_AUTH`, `NO_RATELIMIT_PROXY`, `RATELIMIT_GLOBAL_ON`/`OFF`), the `Governor` rate-limit middleware is only ever attached to `/auth` and to the default proxy service — `/adm/auth/totp/get` is registered inside the `build_app!` macro with **no `.wrap(Governor::new(...))` in any mode**. Combined with point 1, this means an attacker can brute-force a user's password directly against `/adm/auth/totp/get` with **no throttling at all** (bypassing the rate limiting that does protect `/auth`), and the moment the correct password is found, walk away with the TOTP secret in the same response — i.e., a full, unthrottled, single-request 2FA bypass chain.

**Also note (secondary):** same username/password short-circuit timing pattern as finding #6 exists here too (`u.username == auth.username && verify_password(...)`), and the endpoint reads a hardcoded path `/etc/proxyauth/config/config.json` that doesn't match the Docker deployment documented in this project's own README (`./config/config.json:/app/config/config.json`) — meaning in a Docker deployment this endpoint likely panics on every call via `.expect("Failed to reload updated config")` (see finding #1 in "Additional findings" below for why that's worse than it sounds).

**Fix, in order of importance:**
- Never return an already-provisioned OTP secret from an authenticated-by-password-only endpoint. Enrollment should be a one-time flow (show the secret/QR code once, e.g. gated behind an admin action or an already-verified TOTP/session, then mark it consumed), or require re-authentication with the *current* TOTP code to re-view/rotate it.
- Apply the same `Governor` rate limiting used on `/auth` to every `/adm/*` and `/adm/auth/totp/get` route.
- Fix the config path to use the actual configured/running config path instead of a hardcoded `/etc/proxyauth/...` path.

---

## 🔴 High-priority findings

### 1. Rate limiting can be bypassed via a spoofed `X-Forwarded-For` header
**File: `src/network/ratelimit.rs`, function `client_ip`**

Unlike `network::proxy::client_ip`, this function trusts `X-Forwarded-For` / `X-Real-Ip` **without checking whether the caller is a trusted proxy** (`trust_proxy_forward_for`):

```rust
fn client_ip(req: &ServiceRequest) -> Option<IpAddr> {
    if let Some(forwarded) = req.headers().get("x-forwarded-for") {
        // ... accepted as-is, peer not verified
        return Some(ip);
    }
    ...
}
```

**Impact:** an attacker can send a different `X-Forwarded-For` value on every request to obtain a fresh rate-limit key each time, effectively **bypassing brute-force protection on `/auth`** (password and TOTP guessing), even though this project's README presents rate limiting as its main anti-brute-force defense.

**Fix:** reuse the `is_trusted_peer` logic from `network::proxy` (factor it into a shared utility) so forwarding headers are only trusted from peers explicitly listed in `trust_proxy_forward_for`.

### 2. Hop-by-hop headers forwarded unfiltered to the backend (+ duplicated `Connection` header)
**File: `src/network/proxy.rs`, header-forwarding loop (~line 485)**

```rust
for (key, value) in req.headers() {
    let key_str = key.as_str();
    if key_str == "user-agent" { user_agent_fwd = value.to_str().unwrap_or(""); }
    if key_str != "authorization"
        && key_str != "user-agent"
        && key_str != "x-user"
        && key_str != "x-user-roles"
    {
        if let Ok(hv) = hyper::header::HeaderValue::from_bytes(value.as_bytes()) {
            request_builder = request_builder.header(key_str, hv);
        }
    }
}
request_builder = request_builder.header("Connection", "close").header(USER_AGENT, "ProxyAuth");
```

Only the authentication-related headers (`authorization`, `user-agent`, `x-user`, `x-user-roles`) are excluded from forwarding. The classic **hop-by-hop headers** defined by RFC 7230/9110 — `Content-Length`, `Transfer-Encoding`, `TE`, `Trailer`, `Upgrade`, `Keep-Alive`, `Proxy-Connection`, `Proxy-Authenticate`, `Proxy-Authorization` — are **not stripped** and get copied to the outbound request as-is.

Two concrete issues result from this:

- **Duplicated `Connection` header.** `http::request::Builder::header()` *appends* rather than replaces (via `HeaderMap::append`). If the client sends `Connection: keep-alive`, that value is copied in the loop, and the subsequent `.header("Connection", "close")` call adds a **second** `Connection` header rather than overwriting the first. The outbound request to the backend can therefore contain two conflicting `Connection` values (`keep-alive` and `close`) simultaneously — undefined/inconsistent behavior depending on the backend's HTTP parser.
- **Unstripped framing headers.** `Transfer-Encoding`, `TE`, `Trailer`, and `Upgrade` from the original client request are forwarded even though the request is always re-serialized as a fixed body (`Full<Bytes>` for non-GET/HEAD, `Empty` otherwise) via `hyper_util`'s legacy client. This is inconsistent framing metadata riding along with a body that no longer matches it, which is the general shape of the class of bugs that enables HTTP request/response smuggling when multiple HTTP implementations (ProxyAuth's HTTP/1 encoder vs. the backend's parser) disagree on how to interpret ambiguous or duplicated framing headers. The `Connection: close` you already set on every outbound request mitigates the highest-impact keep-alive-based smuggling scenarios (no request pipelining reuse on that connection), but it doesn't address disagreement with the backend's own interpretation of the forwarded `Transfer-Encoding`/`TE`/`Upgrade` headers, nor the general hygiene problem of relaying hop-by-hop metadata across a proxy boundary.

**Fix:** replace the current exclude-list with an explicit strip-list of hop-by-hop headers per RFC 9110 §7.6.1 (`Connection`, and whatever headers `Connection` itself names, plus `Transfer-Encoding`, `TE`, `Trailer`, `Upgrade`, `Keep-Alive`, `Proxy-Connection`, `Proxy-Authenticate`, `Proxy-Authorization`) in addition to the existing `authorization`/`x-user*` exclusions, and set `Connection: close` only once, after the copy loop, without a pre-existing value to conflict with.

### 4. Possible panic (DoS) in the rate-limit key extractor
**File: `src/network/ratelimit.rs`**

```rust
let ip = client_ip(&req).expect("?").to_string();
```

If `peer_addr()` returns `None` and no forwarding header is present, this panics. Should be replaced with a proper `KeyExtractionError` instead of `expect`.

### 5. Unprotected admin token comparison on 2 out of 3 routes
**Files: `src/adm/revoke.rs`, `src/logs.rs`**

```rust
Some(token) if *token == *expected_token => { ... }   // revoke.rs — not constant-time
Some(token) if token == expected_token => { ... }      // logs.rs   — not constant-time
```

`src/adm/stats.rs` correctly uses `subtle::ConstantTimeEq` (`ct_eq`) for the exact same check — the other two routes should be aligned with that pattern. This is the most sensitive secret in the product: compromising it allows arbitrary session revocation and reading of application logs.

### 6. Username enumeration via timing on login
**File: `src/token/auth.rs`**

```rust
.find(|(_, user)| {
    user.username == auth.username && verify_password(&auth.password, &user.password)
})
```

The `&&` short-circuits: `verify_password` (Argon2, expensive) only runs if the username matches. An attacker can therefore distinguish valid from invalid usernames purely by measuring response latency.

**Fix:** always run an Argon2 verification (against a dummy hash when the user doesn't exist) so response time is uniform regardless of username validity.

---

### 7. `panic = "abort"` turns every reachable `.unwrap()`/`.expect()` into a full outage, not just a failed request
**File: `Cargo.toml`**

```toml
[profile.release]
panic = "abort"
```

This is worth calling out on its own because it changes the severity of every other `.unwrap()`/`.expect()` finding in this report (and the many others scattered through the codebase that weren't individually flagged). With `panic = "abort"`, unwinding is disabled at the language level — `catch_unwind` cannot recover from a panic, regardless of what Actix does around request handlers. In the default panic strategy, a panicking request handler typically only kills that one task/connection; with `panic = "abort"`, the **entire process terminates immediately** on any panic, anywhere, including inside a request handler on a hot path. This means bugs that would otherwise be a single dropped request (finding #0's config-reload `.expect()`, finding #4's rate-limit `.expect("?")`, and others found in `token/security.rs`, `token/crypto.rs`, etc.) are, in the actual release build that gets deployed, full-process denial-of-service vectors — a single malformed request or edge-case condition can take the whole proxy down for every user behind it, not just the requester.

**Fix:** either drop `panic = "abort"` from the release profile (accepting the small binary-size/perf cost of unwinding) so a panic in one request doesn't kill the process, or — better — audit and eliminate `.unwrap()`/`.expect()` calls that are reachable from network input, replacing them with proper `Result` handling, and keep `panic = "abort"` only if you're confident no panic can occur on a request path.

### 8. Logout does not revoke the session token server-side
**File: `src/token/logout.rs`, `logout_session`**

`logout_session` only expires the `session_token` cookie client-side (`Expires=<epoch>`); it never calls `revoke::load::revoke_token` (the function the app already exposes via `/adm/revoke`) to invalidate the token itself. If a token was copied/leaked before logout (XSS, log exposure, a shared/borrowed session, a MITM'd connection before HTTPS termination, etc.), it **remains fully valid** until its natural expiry (`token_expiry_seconds`) — "logging out" doesn't actually revoke access for anyone else holding a copy of the token.

**Fix:** on logout, extract the token/session identifier from the request and call `revoke_token` (or the CSRF-protected equivalent) before clearing the cookie, so logout has real security value rather than being purely cosmetic.

### 9. CORS: logout endpoint reflects any Origin with credentials enabled
**File: `src/token/logout.rs`, `logout_session`**

```rust
resp.insert_header((header::ACCESS_CONTROL_ALLOW_CREDENTIALS, "true"));
if let Some(origin) = req.headers().get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
    resp.insert_header((header::ACCESS_CONTROL_ALLOW_ORIGIN, origin));
}
```

Unlike every other CORS-aware handler in the codebase (`registry_otp.rs`, `logout_options`, the `CorsMiddleware`), which all check the incoming `Origin` against `config.cors_origins` before reflecting it, `logout_session` reflects **any** `Origin` header verbatim while also setting `Access-Control-Allow-Credentials: true` — the classic "reflected-origin-with-credentials" CORS anti-pattern. Practical exploitability is currently limited by the session cookie's `SameSite=Strict` attribute (browsers won't attach it to a genuinely cross-site fetch regardless of CORS headers), but this shouldn't be the only thing standing between this endpoint and a credentialed cross-origin read, and it's inconsistent with the origin-allowlist pattern used correctly everywhere else in the project.

**Fix:** reuse the same `cors_origins` allow-list check used elsewhere in the codebase before reflecting `Origin` and setting `Access-Control-Allow-Credentials`.

### 10. Load balancer retries non-idempotent requests across backends on 5xx
**File: `src/network/loadbalancing.rs`**

When a backend returns a 5xx status, `try_forward_to_backend` treats it as a failure and the caller automatically retries the **same request** against the next backend in the SWRR order — for any HTTP method, including `POST`/`PUT`/`DELETE`/`PATCH`. If the first backend actually performed a mutating side effect before failing (e.g., wrote to its own database, then hit a downstream timeout and returned 500), the retry causes the same operation to run again on a second, independent backend — a classic double-execution risk (duplicate writes, double-charging, etc.) for any deployment using `backends` for failover on non-idempotent routes.

**Fix:** only auto-retry idempotent methods (`GET`/`HEAD`, and `PUT`/`DELETE` only if the application guarantees idempotency), or require an idempotency-key mechanism before retrying mutating requests across backends.

### 11. Sticky-backend cache is not scoped per route
**File: `src/network/loadbalancing.rs`, `cache_key`**

```rust
fn cache_key(method: &Method, uri: &Uri, _headers: &hyper::HeaderMap) -> String {
    let host = uri.authority().map(|a| a.as_str()).unwrap_or("default");
    format!("{}|{}", method, host)
}
```

`LAST_GOOD_BACKEND` is keyed only by `(method, target host)`, not by the route's `prefix`/identity, and `try_forward_to_backend` never checks that a cached backend actually belongs to the `backends` list passed in for the *current* call. If two different `routes.yml` rules happen to share the same `target` host (e.g., the same backend server split into multiple path-prefixed rules with different ACLs/`username` restrictions), a successful backend pick made while serving rule A can be silently reused to route traffic for rule B — bypassing rule B's own failover list, weights, and cooldown state. This is a correctness bug with a security-adjacent consequence: route isolation between otherwise-independent rules isn't guaranteed by the load balancer's cache.

**Fix:** include the route's `prefix` (or another unique per-rule identifier) in the cache key, and validate that a cached URL is still a member of the current call's `backends` list before reusing it.

### 12. Same unfiltered hop-by-hop header forwarding in the failover path
**File: `src/network/loadbalancing.rs`, `try_forward_to_backend`**

Same root cause as finding #2 in the main proxy path: this function copies every header except `host` when building each backend attempt, without stripping `Connection`, `Transfer-Encoding`, `TE`, `Trailer`, `Upgrade`, etc. Should be fixed together with finding #2, ideally via one shared header-sanitizing helper used by both `network/proxy.rs` and `network/loadbalancing.rs`.

### 13. Backend responses are fully buffered in memory, on the highest-traffic path
**File: `src/network/loadbalancing.rs`, `try_forward_to_backend`**

```rust
let bytes = body.collect().await.map_err(...)?.to_bytes();
```

Every response routed through the load balancer is read entirely into memory before being returned to the client — no streaming, no size cap. Since this is exactly the code path used for higher-traffic, multi-backend routes, large or numerous concurrent responses (file downloads, large API payloads) can create meaningful memory pressure under load. Not unique to the load balancer (the non-LB path in `network/proxy.rs` buffers similarly), but worth fixing here first given it's the path most likely to see the highest concurrency.

---

## 🟠 Medium-severity findings

### 14. Non-constant-time comparisons (session tokens, TOTP code)
`src/token/security.rs` (`validate_token`) and `src/token/auth.rs` (TOTP check) compare secrets using `!=` rather than a constant-time comparison. Lower practical risk than finding #3, but should be fixed for consistency — `subtle` is already a project dependency.

### 15. `fast = true` mode is less secure
This trade-off is documented in the code itself and disabled by default (`fast: false`) — good default. Worth calling out explicitly in the user-facing docs so nobody enables `fast: true` in production without understanding the implication.

### 16. Cryptographic dependencies pinned to release candidates
`Cargo.toml` pins `sha2`, `chacha20poly1305`, `hkdf`, and `hmac` to `-rc.x` pre-release versions. Recommend moving to stable releases once available, and running `cargo audit` / `cargo deny` regularly in CI.

### 17. Secrets stored in plaintext in `config.json`
`secret`, `token_admin`, and `otpkey` are serialized/deserialized in plaintext. Common architecture choice, not a code bug per se, but worth hardening in production via environment variables, a secrets manager (Vault, SOPS), and restrictive file permissions (`600`) on `config.json`.

---

## 🟢 Positive findings

- Argon2 correctly implemented for password hashing.
- Modern AEAD (XChaCha20-Poly1305), random nonces, no reuse detected.
- Well-designed CSRF protection: single-use nonce, signed, constant-time comparison.
- Solid anti-spoofing handling of `X-Forwarded-For` in the main proxy (should be replicated in the rate limiter, see finding #1).
- Strict stripping of `authorization`/`x-user*` headers before forwarding to the backend — prevents a client from self-assigning identity or roles.
- Robust path canonicalization against encoded path traversal.
- Cookies set with `HttpOnly`, `Secure`, `SameSite=Strict`.
- No plaintext secrets observed in application logs.

---

## Summary table

| # | Severity | Issue | File |
|---|----------|-------|------|
| 0 | 🟣 Critical | Full 2FA bypass: OTP secret re-disclosed on password alone, zero rate limiting | `adm/registry_otp.rs`, `main.rs` |
| 1 | 🔴 High | Rate limit bypass via spoofed `X-Forwarded-For` | `network/ratelimit.rs` |
| 2 | 🔴 High | Hop-by-hop headers unfiltered + duplicated `Connection` header | `network/proxy.rs` |
| 4 | 🔴 High | Possible panic (`expect("?")`) → DoS | `network/ratelimit.rs` |
| 5 | 🔴 High | Non-constant-time admin token comparison | `adm/revoke.rs`, `logs.rs` |
| 6 | 🔴 High | Timing leak → account enumeration on login | `token/auth.rs` |
| 7 | 🔴 High | `panic = "abort"` turns any reachable panic into a full outage | `Cargo.toml` |
| 8 | 🔴 High | Logout doesn't revoke the token server-side | `token/logout.rs` |
| 9 | 🟠 Medium | CORS: logout reflects any Origin with credentials enabled | `token/logout.rs` |
| 10 | 🟠 Medium | Load balancer retries non-idempotent requests on 5xx | `network/loadbalancing.rs` |
| 11 | 🟠 Medium | Sticky-backend cache not scoped per route | `network/loadbalancing.rs` |
| 12 | 🟠 Medium | Hop-by-hop headers unfiltered in failover path | `network/loadbalancing.rs` |
| 13 | 🟡 Low | Backend responses fully buffered in memory | `network/loadbalancing.rs` |
| 14 | 🟠 Medium | Non-constant-time comparisons (session token, TOTP) | `token/security.rs`, `token/auth.rs` |
| 15 | 🟠 Medium | `fast` mode less secure (already disabled by default) | `token/security.rs` |
| 16 | 🟠 Medium | Crypto dependencies pinned to pre-release versions | `Cargo.toml` |
| 17 | 🟡 Low | Plaintext secrets in `config.json` | `config/config.rs` |

---

## Recommendations, in priority order

1. **Fix finding #0 first.** Stop returning an already-provisioned OTP secret from a password-only endpoint, and put `/adm/auth/totp/get` (and every `/adm/*` route) behind the same rate limiting used for `/auth`. As it stands, this is a complete, unthrottled 2FA bypass and the single most urgent item in this report.
2. Fix `network::ratelimit::client_ip` to reuse the `is_trusted_peer` logic from `network::proxy` (finding #1) — undermines the brute-force protection this project advertises.
3. Strip hop-by-hop/framing headers before forwarding to the backend in both `network/proxy.rs` and `network/loadbalancing.rs`, and stop double-setting `Connection` (findings #2, #12) — directly relevant given the recent hyper 0.14 → 1.x migration touched this exact code path; ideally factor this into one shared helper used by both.
4. Align `adm/revoke.rs` and `logs.rs` with the `ct_eq` comparison already used in `adm/stats.rs` (finding #5).
5. Neutralize the login timing leak by always running an Argon2 check, even for non-existent usernames — applies to both `token/auth.rs` and `adm/registry_otp.rs` (finding #6).
6. Make logout actually revoke the token server-side instead of only clearing the cookie (finding #8).
7. Reconsider `panic = "abort"` in the release profile, or audit and remove `.unwrap()`/`.expect()` calls reachable from request handling, given that under this profile any one of them takes down the whole process rather than just the current request (finding #7).
8. Only auto-retry idempotent methods in the load balancer's failover logic, and scope the sticky-backend cache per route (findings #10, #11).

*With these fixes applied, the overall score would comfortably move to 8.5–9/10.*

---

## A note on the hyper 0.14 → 1.x migration

This is exactly the kind of change worth flagging for a follow-up review: hyper 1.x reworked its API around `hyper::Request`/`Response` builders plus the separate `hyper-util` legacy client, and low-level proxies that build requests by hand (as ProxyAuth does in `network/proxy.rs`) are the most likely place for framing/header-handling regressions to slip in — which is exactly where finding #2 was found. It's worth specifically re-testing, after any fix, that:

- a single, correct `Connection` header reaches the backend on every outbound request;
- chunked-encoded client requests are still handled correctly end-to-end (actix decodes them on the way in, but confirm nothing downstream assumes the old hyper 0.14 chunking behavior);
- the connection-pooling behavior of `hyper_util::client::legacy::Client` (`CLIENT_CACHE` / `CLIENT_CACHE_PROXY` in `shared_client.rs`) matches what was expected under 0.14 — pool eviction and idle-timeout semantics changed between major hyper versions and are worth a dedicated load test.
