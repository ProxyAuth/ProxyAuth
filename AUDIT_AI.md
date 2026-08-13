# 🔐 AUDIT_AI.md — ProxyAuth Security Audit (beta 1.0.0-beta5)

**Initial audit:** August 12–13, 2026 (full manual re-scan of every module, including the load balancer)
**Fix passes:** August 13, 2026
**Verification of fixes:** August 13, 2026 — fixes independently re-verified against a fresh build of the project (`ProxyAuth-beta-1_0_0_1_.zip`)
**Scope:** manual review of the Rust source code (`src/`). No `cargo audit` run (not available in the analysis environment) — recommended as a follow-up.
**Overall score:** **5.5/10** as first scanned → **8.5/10** now that every High-severity finding has been fixed and verified. Closing the remaining Medium/Low items would bring this to 9–9.5/10.

The project is well designed for a homegrown reverse-proxy authentication system: Argon2 for passwords, authenticated encryption (XChaCha20-Poly1305), HKDF key derivation, CSRF protection with constant-time comparison and a single-use nonce store, strict stripping of `Authorization`/`x-user*` headers before forwarding to the backend, and correct handling of `X-Forwarded-For` throughout the request path (now consistently gated behind `trust_proxy_forward_for`, see finding #1). All 8 High-severity findings from the original audit have since been fixed and re-verified line-by-line against the codebase; the remaining open items are all Medium or Low severity.

---

## 📋 Fix status tracker

| # | Severity | Issue | File(s) | Status |
|---|----------|-------|---------|--------|
| 0 | 🟣 Critical | Full 2FA bypass: OTP secret re-disclosed on password alone, zero rate limiting | `adm/registry_otp.rs`, `main.rs` | ✅ **Fixed & verified** |
| 1 | 🔴 High | Rate limit bypass via spoofed `X-Forwarded-For` | `network/ratelimit.rs` | ✅ **Fixed & verified** |
| 2 | 🔴 High | Hop-by-hop headers unfiltered + duplicated `Connection` header | `network/proxy.rs` | ✅ **Fixed & verified** |
| 4 | 🔴 High | Possible panic (`expect("?")`) → DoS | `network/ratelimit.rs` | ✅ **Fixed & verified** *(fixed as a side effect of #1)* |
| 5 | 🔴 High | Non-constant-time admin token comparison | `adm/revoke.rs`, `logs.rs` | ✅ **Fixed & verified** |
| 6 | 🔴 High | Timing leak → account enumeration on login | `token/auth.rs`, `adm/registry_otp.rs` | ✅ **Fixed & verified** |
| 7 | 🔴 High | `panic = "abort"` turns any reachable panic into a full outage | `Cargo.toml` | ✅ **Fixed & verified** |
| 8 | 🔴 High | Logout doesn't revoke the token server-side | `token/logout.rs` | ✅ **Fixed & verified** |
| 9 | 🟠 Medium | CORS: logout reflects any Origin with credentials enabled | `token/logout.rs` | ⬜ Open |
| 10 | 🟠 Medium | Load balancer retries non-idempotent requests on 5xx | `network/loadbalancing.rs` | ⬜ Open |
| 11 | 🟠 Medium | Sticky-backend cache not scoped per route | `network/loadbalancing.rs` | ⬜ Open |
| 12 | 🟠 Medium | Hop-by-hop headers unfiltered in failover path | `network/loadbalancing.rs` | ⬜ Open *(the shared helper from #2, `is_hop_by_hop_header`, already exists and is `pub(crate)` — this is now a small follow-up to reuse it here)* |
| 13 | 🟡 Low | Backend responses fully buffered in memory | `network/loadbalancing.rs` | ⬜ Open |
| 14 | 🟠 Medium | Non-constant-time comparisons (session token, TOTP) | `token/security.rs`, `token/auth.rs` | ✅ **Fixed & verified** |
| 15 | 🟠 Medium | `fast` mode less secure (already disabled by default) | `token/security.rs` | ℹ️ No action needed (safe default, doc note only) |
| 16 | 🟠 Medium | Crypto dependencies pinned to pre-release versions | `Cargo.toml` | ⬜ Open |
| 17 | 🟡 Low | Plaintext secrets in `config.json` | `config/config.rs` | ⬜ Open (accepted design trade-off) |

**All 8 High/Critical findings are fixed and independently re-verified.** 9 findings remain open, all Medium or Low severity, none of them a full compromise on their own.

---

## ✅ Fixed & verified findings — detail

### 0. `/adm/auth/totp/get` defeated 2FA entirely, and had zero rate limiting
**Files: `src/adm/registry_otp.rs` (`get_otpauth_uri`), `src/main.rs` (route registration)**

This endpoint let a user provision their authenticator app (returns an `otpauth://` URI + the raw secret). Two issues combined into a critical vulnerability: (1) it returned the existing TOTP secret on **every** call, not just at first enrollment, so anyone who knew the account password alone could retrieve the second factor at any time; (2) the route carried **no rate limiting** in any `mode_actix` branch in `main.rs`, so an attacker could brute-force the password directly against it with no throttling and walk away with the TOTP secret in the same response.

**Fix (verified in place):** `get_otpauth_uri` now returns `409 Conflict` if `user.otpkey` is already set instead of reading and returning the existing secret — it's handed out once, at first enrollment, and never again. `/adm/auth/totp/get` is now registered behind the same `Governor` rate limiter as `/auth`, in every rate-limited `mode_actix` branch.

### 1 & 4. Rate limiting could be bypassed via a spoofed `X-Forwarded-For` header (+ a panic risk)
**File: `src/network/ratelimit.rs`**

The rate-limit key extractor used its own `client_ip` function that trusted `X-Forwarded-For`/`X-Real-Ip` unconditionally — unlike `network::proxy::client_ip`, which only trusts them from a peer explicitly listed in `trust_proxy_forward_for`. Any client could spoof a fresh rate-limit key on every request. The same function also panicked (`.expect("?")`) if `peer_addr()` returned `None`.

**Fix (verified in place):** the local, unsafe `client_ip` was removed entirely from `ratelimit.rs`; the key extractor now calls `network::proxy::client_ip(req.request(), &app_data.config)` and returns a proper `KeyExtractionError` instead of panicking when no IP can be determined.

### 2 & 12. Hop-by-hop headers forwarded unfiltered to the backend (+ duplicated `Connection` header)
**File: `src/network/proxy.rs`** — fixed. **`src/network/loadbalancing.rs`** — same root cause, still open (see #12 below).

Only auth-related headers (`authorization`, `user-agent`, `x-user`, `x-user-roles`) used to be excluded from forwarding. The classic hop-by-hop headers (RFC 9110 §7.6.1) — `Connection`, `Content-Length`, `Transfer-Encoding`, `TE`, `Trailer`, `Upgrade`, `Keep-Alive`, `Proxy-Connection`, `Proxy-Authenticate`, `Proxy-Authorization` — were copied to the outbound request as-is, and `.header("Connection", "close")` was appending a *second* `Connection` header rather than replacing the client's own value (since `http::request::Builder::header()` appends).

**Fix (verified in place):** a new `pub(crate) fn is_hop_by_hop_header(name: &str) -> bool` in `network/proxy.rs` explicitly lists all ten headers per RFC 9110 §7.6.1, and the forwarding loop now excludes them before copying any header to the outbound request. `Connection: close` is set exactly once, with nothing left to conflict with it.

### 5 & 14. Non-constant-time secret comparisons
**Files: `src/adm/stats.rs`, `src/adm/revoke.rs`, `src/logs.rs`, `src/token/security.rs`, `src/token/auth.rs`**

The admin token was compared with plain `==` in `/adm/revoke` and `/adm/logs` (while `/adm/stats` already used `subtle::ConstantTimeEq` correctly), and both the session-token hash and the TOTP code were also compared with `!=` rather than at constant time.

**Fix (verified in place):** `is_valid_admin_token` in `adm/stats.rs` was made `pub(crate)` and is now reused by `adm/revoke.rs` and `src/logs.rs` instead of each having its own inline `==` check. `token/security.rs`'s token-hash comparison (both `fast` and non-`fast` modes) and `token/auth.rs`'s TOTP code comparison both now use `subtle::ConstantTimeEq`.

### 6. Username enumeration via timing on login
**Files: `src/token/auth.rs`, `src/adm/registry_otp.rs`**

The login check used `user.username == auth.username && verify_password(...)`; the `&&` short-circuits, so the expensive Argon2 verification only ran when the username matched, letting an attacker enumerate valid usernames purely by measuring response latency. The exact same pattern existed in `adm/registry_otp.rs`.

**Fix (verified in place):** a new `dummy_password_hash()` (a real, syntactically valid Argon2id hash with no corresponding account, computed once and cached) and `verify_credentials_constant_time()` in `token/auth.rs` always run a full Argon2 verification — against the real hash if the user matches, against the dummy hash otherwise — so response time no longer depends on whether the username exists. Both the login handler in `token/auth.rs` and `adm/registry_otp.rs`'s `get_otpauth_uri` now call this shared function instead of the old short-circuit pattern.

### 7. `panic = "abort"` turned every reachable `.unwrap()`/`.expect()` into a full outage
**File: `Cargo.toml`**

With `panic = "abort"` set in the release profile, unwinding was disabled at the language level, so any panic anywhere — including inside a request handler — terminated the entire process immediately rather than just failing the current request/task.

**Fix (verified in place):** `panic = "abort"` has been removed from `[profile.release]`. A panic in one request handler no longer takes down every other in-flight connection. (Auditing and removing remaining `.unwrap()`/`.expect()` calls reachable from request handling is still worthwhile as defense in depth, but the worst-case blast radius is now contained.)

### 8. Logout did not revoke the session token server-side
**File: `src/token/logout.rs`, `logout_session`**

`logout_session` used to only expire the `session_token` cookie client-side; it never called `revoke::load::revoke_token`, so a copied/leaked token stayed fully valid until its natural expiry regardless of "logout."

**Fix (verified in place):** `logout_session` now reads the `session_token` cookie, calls `validate_token` to recover its `token_id`, and calls `revoke_token` (the same function used by `/adm/revoke`) to invalidate it server-side before clearing the cookie. This is best-effort: a missing/invalid/already-expired cookie is handled gracefully and logout still proceeds.

---

## ⬜ Open findings — detail (Medium/Low, unchanged since the last full scan)

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

When a backend returns 5xx, the failover logic automatically retries the same request against the next backend — for any HTTP method, including `POST`/`PUT`/`DELETE`. If the first backend already performed a mutating side effect before failing, the retry can execute the same operation twice.

**Fix:** only auto-retry idempotent methods (`GET`/`HEAD`), or require an idempotency-key mechanism before retrying mutating requests.

### 11. Sticky-backend cache is not scoped per route
**File: `src/network/loadbalancing.rs`, `cache_key`**

`LAST_GOOD_BACKEND` is keyed only by `(method, target host)`, not by the route's `prefix`, and a cached backend is never validated against the current call's `backends` list. If two different `routes.yml` rules share the same target host, a backend choice made for one rule can silently leak into another rule's traffic.

**Fix:** include the route `prefix` in the cache key, and validate the cached URL still belongs to the current `backends` list before reuse.

### 12. Same unfiltered hop-by-hop header forwarding in the failover path
**File: `src/network/loadbalancing.rs`, `try_forward_to_backend`**

Same root cause as the now-fixed finding #2: this function still copies every header except `host` when building each backend attempt, without stripping `Connection`, `Transfer-Encoding`, `TE`, `Trailer`, `Upgrade`, etc.

**Fix:** the shared helper already exists (`network::proxy::is_hop_by_hop_header`, `pub(crate)`) — this is now a small, low-risk follow-up: import it into `loadbalancing.rs` and apply the same exclusion in `try_forward_to_backend`'s header-copy loop.

### 13. Backend responses are fully buffered in memory
**File: `src/network/loadbalancing.rs`, `try_forward_to_backend`**

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

## 🟢 Positive findings

- Argon2 correctly implemented for password hashing, now with constant-time-equivalent username enumeration resistance (finding #6).
- Modern AEAD (XChaCha20-Poly1305), random nonces, no reuse detected.
- Well-designed CSRF protection: single-use nonce, signed, constant-time comparison.
- `X-Forwarded-For`/`X-Real-Ip` handling is now consistently gated behind `trust_proxy_forward_for` across both the main proxy path and the rate limiter.
- All admin-token and secret comparisons across `/adm/*` routes and token validation are now constant-time.
- Hop-by-hop header hygiene fixed on the main proxy path, with a reusable helper ready for the load balancer's failover path.
- A panic anywhere in the app no longer takes down the whole process (`panic = "abort"` removed).
- Logout now has real security value — it revokes the token server-side, not just the cookie.
- Strict stripping of `authorization`/`x-user*` headers before forwarding to the backend.
- Robust path canonicalization against encoded path traversal.
- Cookies set with `HttpOnly`, `Secure`, `SameSite=Strict`.
- No plaintext secrets observed in application logs.
- A genuinely dead, unused duplicate `stats.rs` module (`src/stats/stats.rs`, distinct from the actually-wired `src/adm/stats.rs`) was cleanly removed, resolving the `dead_code` warnings that surfaced after the #5/#14 fixes.

---

## Recommendations, in priority order (remaining work — all Medium/Low)

1. Reuse the existing `is_hop_by_hop_header` helper in `network/loadbalancing.rs`'s `try_forward_to_backend` (finding #12) — smallest remaining fix, same pattern as the already-fixed #2.
2. Fix the CORS origin reflection on `token/logout.rs` (finding #9) by reusing the `cors_origins` allow-list check used elsewhere.
3. Only auto-retry idempotent methods in the load balancer's failover logic, and scope the sticky-backend cache per route (findings #10, #11).
4. Lower priority: stream (rather than fully buffer) load-balanced responses (#13), move off RC-pinned crypto dependencies (#16), and harden secret storage in production deployments (#17).

None of the remaining items are a full compromise on their own, and all 8 original High/Critical findings are closed. This is a solid, comfortably-shippable state for a beta.
