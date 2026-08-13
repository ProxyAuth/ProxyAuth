# 🔐 AUDIT_AI.md — ProxyAuth Security Audit (beta 1.0.0-beta5)

**Audit date:** August 12–13, 2026 (full manual re-scan of every module, including the load balancer)
**Fix pass:** August 13, 2026
**Scope:** manual review of the Rust source code (`src/`). No `cargo audit` run (not available in the analysis environment) — recommended as a follow-up.
**Overall score:** **5.5 / 10** as first scanned → **≈ 7.5 / 10** after the fixes applied so far (see status tracker below). Full remediation of all open items would bring this to 8.5–9/10.

The project is generally well designed for a homegrown reverse-proxy authentication system: Argon2 for passwords, authenticated encryption (XChaCha20-Poly1305), HKDF key derivation, CSRF protection with constant-time comparison and a single-use nonce store, strict stripping of `Authorization`/`x-user*` headers before forwarding to the backend, and correct handling of `X-Forwarded-For` **in the main proxy** (only trusted when the peer is explicitly listed in `trust_proxy_forward_for`).

Several concrete vulnerabilities were found. Several of the most severe ones have already been fixed as of this pass — see the status tracker immediately below. Full technical detail for every finding (fixed or still open) is kept further down so the reasoning and the exact vulnerable code remain documented for future reference.

> **Note on the hyper 0.14 → 1.x migration:** the request-forwarding path (`network/proxy.rs`) builds outbound requests manually against `hyper::Request::builder()` on top of `hyper_util::client::legacy::Client` — exactly the kind of low-level code path a major hyper version bump touches directly. Re-reviewing header/body forwarding with this in mind is what turned up finding **#2** (hop-by-hop headers forwarded unfiltered, and a duplicated `Connection` header) — the kind of regression this sort of migration tends to introduce or leave uncovered. **Still open.**

---

## 📋 Fix status tracker

| # | Severity | Issue | File(s) | Status |
|---|----------|-------|---------|--------|
| 0 | 🟣 Critical | Full 2FA bypass: OTP secret re-disclosed on password alone, zero rate limiting | `adm/registry_otp.rs`, `main.rs` | ✅ **Fixed** |
| 1 | 🔴 High | Rate limit bypass via spoofed `X-Forwarded-For` | `network/ratelimit.rs` | ✅ **Fixed** |
| 2 | 🔴 High | Hop-by-hop headers unfiltered + duplicated `Connection` header | `network/proxy.rs` | ⬜ Open |
| 4 | 🔴 High | Possible panic (`expect("?")`) → DoS | `network/ratelimit.rs` | ✅ **Fixed** *(fixed as a side effect of #1)* |
| 5 | 🔴 High | Non-constant-time admin token comparison | `adm/revoke.rs`, `logs.rs` | ✅ **Fixed** |
| 6 | 🔴 High | Timing leak → account enumeration on login | `token/auth.rs`, `adm/registry_otp.rs` | ⬜ Open |
| 7 | 🔴 High | `panic = "abort"` turns any reachable panic into a full outage | `Cargo.toml` | ⬜ Open |
| 8 | 🔴 High | Logout doesn't revoke the token server-side | `token/logout.rs` | ⬜ Open |
| 9 | 🟠 Medium | CORS: logout reflects any Origin with credentials enabled | `token/logout.rs` | ⬜ Open |
| 10 | 🟠 Medium | Load balancer retries non-idempotent requests on 5xx | `network/loadbalancing.rs` | ⬜ Open |
| 11 | 🟠 Medium | Sticky-backend cache not scoped per route | `network/loadbalancing.rs` | ⬜ Open |
| 12 | 🟠 Medium | Hop-by-hop headers unfiltered in failover path | `network/loadbalancing.rs` | ⬜ Open |
| 13 | 🟡 Low | Backend responses fully buffered in memory | `network/loadbalancing.rs` | ⬜ Open |
| 14 | 🟠 Medium | Non-constant-time comparisons (session token, TOTP) | `token/security.rs`, `token/auth.rs` | ✅ **Fixed** |
| 15 | 🟠 Medium | `fast` mode less secure (already disabled by default) | `token/security.rs` | ℹ️ No action needed (safe default, doc note only) |
| 16 | 🟠 Medium | Crypto dependencies pinned to pre-release versions | `Cargo.toml` | ⬜ Open |
| 17 | 🟡 Low | Plaintext secrets in `config.json` | `config/config.rs` | ⬜ Open (accepted design trade-off) |

**6 of 17 findings fixed** (including the critical one). The remaining open items are detailed below, still ordered by severity, so they can be picked up one at a time.

---

## ✅ Fixed findings — detail

### 0. `/adm/auth/totp/get` defeated 2FA entirely, and had zero rate limiting — ✅ FIXED
**Files: `src/adm/registry_otp.rs` (`get_otpauth_uri`), `src/main.rs` (route registration)**

This endpoint let a user provision their authenticator app (returns an `otpauth://` URI + the raw secret). Two issues combined into a critical vulnerability:

1. It returned the existing TOTP secret on **every** call, not just at first enrollment — anyone who could supply a valid `username`/`password` (i.e. the password alone) could retrieve the already-provisioned TOTP secret at any time, collapsing 2FA back down to one factor.
2. The route carried **no rate limiting whatsoever** — none of the `Governor`-wrapped modes in `main.rs` covered `/adm/auth/totp/get`, so an attacker could brute-force the password directly against it with no throttling, then walk away with the TOTP secret in the same response.

**Fix applied:**
- `get_otpauth_uri` now returns `409 Conflict` if `user.otpkey` is already set, instead of reading and returning the existing secret. The secret is only ever handed out once, at first enrollment.
- `/adm/auth/totp/get` is now registered behind the same `Governor` rate limiter used for `/auth`, in both rate-limited `mode_actix` branches in `main.rs` (`NO_RATELIMIT_PROXY` and `RATELIMIT_GLOBAL_ON`/`OFF`).
- The two `.expect()` calls used to reload `config.json` after provisioning were replaced with proper `Result` handling (`InternalServerError` instead of a crash) — relevant given finding #7 below.

### 1 & 4. Rate limiting could be bypassed via a spoofed `X-Forwarded-For` header (+ a panic risk) — ✅ FIXED
**File: `src/network/ratelimit.rs`**

`network::ratelimit::client_ip` used to trust `X-Forwarded-For`/`X-Real-Ip` unconditionally, unlike `network::proxy::client_ip` which only trusts them from a peer listed in `trust_proxy_forward_for`. Any client could spoof a fresh IP on every request to dodge rate limiting on `/auth`. The same function also panicked (`.expect("?")`) if `peer_addr()` returned `None`.

**Fix applied:** the local, unsafe `client_ip` in `ratelimit.rs` was removed entirely. The rate-limit key extractor now calls the already-correct `network::proxy::client_ip(req.request(), &app_data.config)`, and returns a proper `KeyExtractionError` instead of panicking when no IP can be determined.

### 5 & 14. Non-constant-time secret comparisons — ✅ FIXED
**Files: `src/adm/stats.rs`, `src/adm/revoke.rs`, `src/logs.rs`, `src/token/security.rs`, `src/token/auth.rs`**

The admin token was compared with plain `==` in `/adm/revoke` and `/adm/logs` (while `/adm/stats` already used `subtle::ConstantTimeEq` correctly), and both the session-token hash (`token/security.rs`) and the TOTP code (`token/auth.rs`) were also compared with `!=` rather than at constant time.

**Fix applied:**
- `is_valid_admin_token` in `adm/stats.rs` (already using `ct_eq`) was made `pub(crate)` and is now reused by `adm/revoke.rs` and `src/logs.rs` instead of each having their own inline `==` check.
- `token/security.rs`: both the `fast` and non-`fast` token-hash comparisons now use `subtle::ConstantTimeEq` instead of `!=`.
- `token/auth.rs`: the TOTP code comparison now uses `subtle::ConstantTimeEq` instead of `!=`.

---

## ⬜ Open findings — detail

### 2 & 12. Hop-by-hop headers forwarded unfiltered to the backend (+ duplicated `Connection` header)
**Files: `src/network/proxy.rs` (header-forwarding loop, ~line 485), `src/network/loadbalancing.rs` (`try_forward_to_backend`)**

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

Only auth-related headers are excluded from forwarding. The classic hop-by-hop headers (RFC 7230/9110) — `Content-Length`, `Transfer-Encoding`, `TE`, `Trailer`, `Upgrade`, `Keep-Alive`, `Proxy-Connection`, `Proxy-Authenticate`, `Proxy-Authorization` — are not stripped and get copied to the outbound request as-is. Two concrete issues:

- **Duplicated `Connection` header**: `http::request::Builder::header()` appends rather than replaces. If the client sends `Connection: keep-alive`, that value is copied in the loop, and the later `.header("Connection", "close")` adds a **second** `Connection` header instead of overwriting it.
- **Unstripped framing headers** riding along with a body that's always re-serialized as fixed-length — the general shape of the bug class that enables HTTP request/response smuggling when two independent HTTP implementations disagree on ambiguous framing.

The exact same root cause exists in `network/loadbalancing.rs`'s `try_forward_to_backend`, which also copies every header except `host`.

**Fix:** replace the exclude-list with an explicit hop-by-hop strip-list per RFC 9110 §7.6.1, ideally factored into one shared helper used by both `network/proxy.rs` and `network/loadbalancing.rs`, and set `Connection: close` only once, after the copy loop.

### 6. Username enumeration via timing on login
**Files: `src/token/auth.rs`, `src/adm/registry_otp.rs`**

```rust
.find(|(_, user)| {
    user.username == auth.username && verify_password(&auth.password, &user.password)
})
```

The `&&` short-circuits: `verify_password` (Argon2, expensive) only runs if the username matches. An attacker can distinguish valid from invalid usernames purely by measuring response latency. The exact same pattern also exists in `adm/registry_otp.rs`'s `get_otpauth_uri`.

**Fix:** always run an Argon2 verification (against a dummy/precomputed hash when the user doesn't exist) so response time is uniform regardless of username validity. Apply in both files.

### 7. `panic = "abort"` turns every reachable `.unwrap()`/`.expect()` into a full outage
**File: `Cargo.toml`**

```toml
[profile.release]
panic = "abort"
```

With unwinding disabled, a panic anywhere — including inside a request handler on a hot path — terminates the **entire process** immediately, not just the current request/task. This amplifies the severity of every `.unwrap()`/`.expect()` reachable from network input throughout the codebase (several were already found and fixed as part of #0 and #1/#4, but others likely remain, e.g. in `token/crypto.rs`, `token/security.rs`).

**Fix:** either drop `panic = "abort"` from the release profile, or audit and eliminate every `.unwrap()`/`.expect()` reachable from a request path, replacing them with explicit `Result` handling.

### 8. Logout does not revoke the session token server-side
**File: `src/token/logout.rs`, `logout_session`**

`logout_session` only expires the `session_token` cookie client-side; it never calls `revoke::load::revoke_token` (already exposed via `/adm/revoke`) to invalidate the token itself. A leaked/copied token remains fully valid until its natural expiry — "logging out" doesn't revoke access for anyone else holding a copy.

**Fix:** on logout, extract the token/session identifier and call `revoke_token` before clearing the cookie.

### 9. CORS: logout endpoint reflects any Origin with credentials enabled
**File: `src/token/logout.rs`, `logout_session`**

```rust
resp.insert_header((header::ACCESS_CONTROL_ALLOW_CREDENTIALS, "true"));
if let Some(origin) = req.headers().get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
    resp.insert_header((header::ACCESS_CONTROL_ALLOW_ORIGIN, origin));
}
```

Unlike every other CORS-aware handler in the codebase, which checks `Origin` against `config.cors_origins` before reflecting it, `logout_session` reflects **any** `Origin` while also setting `Access-Control-Allow-Credentials: true`. Practical exploitability is currently limited by the session cookie's `SameSite=Strict`, but this shouldn't be the only thing standing between this endpoint and a credentialed cross-origin read.

**Fix:** reuse the same `cors_origins` allow-list check used elsewhere before reflecting `Origin`/setting `Allow-Credentials`.

### 10. Load balancer retries non-idempotent requests across backends on 5xx
**File: `src/network/loadbalancing.rs`**

When a backend returns 5xx, the failover logic automatically retries the **same request** against the next backend — for any HTTP method, including `POST`/`PUT`/`DELETE`. If the first backend already performed a mutating side effect before failing, the retry can execute the same operation twice on an independent backend.

**Fix:** only auto-retry idempotent methods (`GET`/`HEAD`), or require an idempotency-key mechanism before retrying mutating requests.

### 11. Sticky-backend cache is not scoped per route
**File: `src/network/loadbalancing.rs`, `cache_key`**

```rust
fn cache_key(method: &Method, uri: &Uri, _headers: &hyper::HeaderMap) -> String {
    let host = uri.authority().map(|a| a.as_str()).unwrap_or("default");
    format!("{}|{}", method, host)
}
```

`LAST_GOOD_BACKEND` is keyed only by `(method, target host)`, not by the route's `prefix`, and a cached backend is never validated against the current call's `backends` list. If two different `routes.yml` rules share the same target host, a backend choice made for one rule can silently leak into another rule's traffic.

**Fix:** include the route `prefix` in the cache key, and validate the cached URL still belongs to the current `backends` list before reuse.

### 13. Backend responses are fully buffered in memory
**File: `src/network/loadbalancing.rs`, `try_forward_to_backend`**

```rust
let bytes = body.collect().await.map_err(...)?.to_bytes();
```

Every load-balanced response is read entirely into memory before being returned — no streaming, no size cap — on what's typically the highest-concurrency code path.

**Fix:** stream the response body to the client instead of buffering it fully, and/or enforce a maximum response size.

### 16. Cryptographic dependencies pinned to release candidates
**File: `Cargo.toml`**

`sha2`, `chacha20poly1305`, `hkdf`, and `hmac` are pinned to `-rc.x` pre-release versions.

**Fix:** move to stable releases once available; run `cargo audit`/`cargo deny` regularly in CI.

### 17. Secrets stored in plaintext in `config.json`
**File: `src/config/config.rs`**

`secret`, `token_admin`, and `otpkey` are serialized/deserialized in plaintext. A common and accepted architecture choice, not a code bug — worth hardening in production via environment variables, a secrets manager, and restrictive file permissions (`600`) on `config.json`.

---

## 🟢 Positive findings (unchanged)

- Argon2 correctly implemented for password hashing.
- Modern AEAD (XChaCha20-Poly1305), random nonces, no reuse detected.
- Well-designed CSRF protection: single-use nonce, signed, constant-time comparison.
- Strict stripping of `authorization`/`x-user*` headers before forwarding to the backend.
- Robust path canonicalization against encoded path traversal.
- Cookies set with `HttpOnly`, `Secure`, `SameSite=Strict`.
- No plaintext secrets observed in application logs.
- Rate limiting and admin-token checks are now consistent across every `/adm/*` route (as of the #0/#1/#5 fixes).

---

## Recommendations, in priority order (remaining work)

1. Strip hop-by-hop/framing headers before forwarding to the backend in both `network/proxy.rs` and `network/loadbalancing.rs`, and stop double-setting `Connection` (findings #2, #12) — most impactful remaining item, and directly tied to the hyper 0.14 → 1.x migration.
2. Neutralize the login timing leak in both `token/auth.rs` and `adm/registry_otp.rs` by always running an Argon2 check (finding #6).
3. Make logout actually revoke the token server-side (finding #8), and fix the CORS origin reflection on the same endpoint (finding #9).
4. Reconsider `panic = "abort"` in the release profile, or finish auditing/removing `.unwrap()`/`.expect()` calls reachable from request handling (finding #7).
5. Only auto-retry idempotent methods in the load balancer's failover logic, and scope the sticky-backend cache per route (findings #10, #11).
6. Lower priority: stream (rather than fully buffer) load-balanced responses (#13), move off RC-pinned crypto dependencies (#16), and harden secret storage in production deployments (#17).

---

## A note on the hyper 0.14 → 1.x migration

Low-level proxies that build requests by hand (as ProxyAuth does in `network/proxy.rs`) are the most likely place for framing/header-handling regressions to slip in after a major hyper version bump — which is exactly where finding #2 was found. Worth specifically re-testing, once that finding is fixed, that:

- a single, correct `Connection` header reaches the backend on every outbound request;
- chunked-encoded client requests are still handled correctly end-to-end;
- the connection-pooling behavior of `hyper_util::client::legacy::Client` (`CLIENT_CACHE`/`CLIENT_CACHE_PROXY` in `shared_client.rs`) matches what was expected under 0.14 — pool eviction and idle-timeout semantics changed between major hyper versions and are worth a dedicated load test.
