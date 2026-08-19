# AUDIT_AI.md - ProxyAuth Security Audit (beta 1.0.0-beta5 -> 1.0.0)

**Initial audit:** August 12-13, 2026 (full manual re-scan of every module, including the load balancer)
**Fix passes:** August 13, 2026
**Verification of fixes:** August 13, 2026 - fixes independently re-verified against a fresh build of the project
**Wiki documentation pass:** August 14, 2026 - five additional findings surfaced while writing the project wiki (documentation work that required re-reading most modules end to end)
**Scope:** manual review of the Rust source code (`src/`). No `cargo audit` run (not available in the analysis environment) - recommended as a follow-up.
**Overall score:** 5.5/10 as first scanned -> 8.5/10 after every High/Critical finding was fixed and verified -> **8/10** after this pass, which added five new Low/Medium findings that don't change the High-severity picture but are worth tracking.

---

## Part 1 - Original security audit (August 12-13)

All 8 High/Critical findings from the original audit are fixed and independently re-verified. The remaining open items from that pass are all Medium or Low severity.

### Fix status tracker

| # | Severity | Issue | File(s) | Status |
|---|----------|-------|---------|--------|
| 0 | Critical | Full 2FA bypass: OTP secret re-disclosed on password alone, zero rate limiting | `adm/registry_otp.rs`, `main.rs` | Fixed & verified |
| 1 | High | Rate limit bypass via spoofed `X-Forwarded-For` | `network/ratelimit.rs` | Fixed & verified |
| 2 | High | Hop-by-hop headers unfiltered + duplicated `Connection` header | `network/proxy.rs` | Fixed & verified |
| 4 | High | Possible panic (`expect("?")`) -> DoS | `network/ratelimit.rs` | Fixed & verified (side effect of #1) |
| 5 | High | Non-constant-time admin token comparison | `adm/revoke.rs`, `logs.rs` | Fixed & verified |
| 6 | High | Timing leak -> account enumeration on login | `token/auth.rs`, `adm/registry_otp.rs` | Fixed & verified |
| 7 | High | `panic = "abort"` turns any reachable panic into a full outage | `Cargo.toml` | Fixed & verified |
| 8 | High | Logout doesn't revoke the token server-side | `token/logout.rs` | Fixed & verified |
| 9 | Medium | CORS: logout reflects any Origin with credentials enabled | `token/logout.rs` | Open |
| 10 | Medium | Load balancer retries non-idempotent requests on 5xx | `network/loadbalancing.rs` | Open |
| 11 | Medium | Sticky-backend cache not scoped per route | `network/loadbalancing.rs` | Open |
| 12 | Medium | Hop-by-hop headers unfiltered in failover path | `network/loadbalancing.rs` | Open (shared helper from #2 already exists, ready to reuse) |
| 13 | Low | Backend responses fully buffered in memory | `network/loadbalancing.rs` | Open |
| 14 | Medium | Non-constant-time comparisons (session token, TOTP) | `token/security.rs`, `token/auth.rs` | Fixed & verified |
| 15 | Medium | `fast` mode less secure (already disabled by default) | `token/security.rs` | No action needed (safe default, doc note only) |
| 16 | Medium | Crypto dependencies pinned to pre-release versions | `Cargo.toml` | Open |
| 17 | Low | Plaintext secrets in `config.json` | `config/config.rs` | Open (accepted design trade-off, mitigated by filesystem permissions - see Security Model in the wiki) |

Full technical detail for every finding in this table (vulnerable code, fix applied or recommended) was documented in earlier passes and carries over unchanged here; this update focuses on what's new.

---

## Part 2 - New findings from the wiki documentation pass (August 14)

Writing the wiki required re-reading nearly every module end to end, including several files that weren't the focus of the original audit's severity-driven scan (install scripts, connection pooling, config validation on load). Five concrete issues surfaced this way - none are High/Critical, but they're real and worth fixing.

### 18. `add_otpkey()` still panics; its sibling `clear_otpkey()` doesn't

**Severity: Low-Medium**
**File: `src/config/config.rs`**

When finding #0 was fixed, `clear_otpkey()` was written with proper `Result`-based error handling - no panics, even on a missing or malformed `config.json`. `add_otpkey()`, its symmetric counterpart (adds an OTP key instead of removing one), was left as it originally was: it still uses `.expect()` on every file read/parse step and panics on failure.

Both functions are reachable from live HTTP routes (`add_otpkey` from `/adm/auth/totp/get`, `clear_otpkey` from `/adm/auth/totp/reset`) - a transiently unreadable or malformed config file during enrollment would panic that request. With `panic = "abort"` removed (finding #7), this is now "only" a failed request rather than a full-process outage, but the inconsistency between two near-identical functions is worth closing.

**Fix:** rewrite `add_otpkey()` to return `Result<bool, String>` following the exact pattern already used in `clear_otpkey()`.

### 19. Client certificate (mTLS) failures degrade silently

**Severity: Medium**
**File: `src/network/shared_client.rs`, `build_hyper_client_cert()`**

If a route's configured client certificate or key (`cert:` in `routes.yml`) is missing, empty, or fails to parse, ProxyAuth does not fail the request or refuse to start - it logs a `tracing::warn!` and silently falls back to a normal connection with no client authentication at all:

```rust
let cert_chain = match load_certs(opts.cert_path.as_ref().unwrap()) {
    Ok(c) if !c.is_empty() => c,
    _ => {
        tracing::warn!("TLS: cert chain vide ou invalide, fallback sans client auth");
        return build_hyper_client_normal(state);
    }
};
```

This is a "fail open" pattern on a security control: if a backend relies on mTLS to authenticate ProxyAuth as a legitimate caller, a broken certificate path silently downgrades that route to no client authentication, with only a log line (easy to miss unless actively monitored) marking the difference. There's no way to distinguish, from ProxyAuth's own external behavior, between "mTLS is working" and "mTLS silently isn't."

**Fix:** consider making this configurable - fail the route (or refuse to start) when a `cert:` block is present but invalid, at least as an opt-in strict mode, rather than only ever falling back silently.

### 20. Route rules can silently block 100% of their own traffic

**Severity: Low (fails closed, not a vulnerability) / operational reliability concern**
**File: `src/config/config.rs` (`default_username`), `src/network/proxy.rs` (`rule.username.contains(&username)`)**

`username` on a `RouteRule` defaults to an empty `Vec` when omitted. A route with `secure: true` but no `username` list checks `rule.username.contains(&username)`, which is always `false` for an empty list - meaning **every** authenticated user is rejected with `403 Forbidden`, silently, for that entire route. There's no validation at config-load time that catches this - `routes.yml` parses successfully, the server starts normally, and the route simply blocks everyone who reaches it.

This fails safe (nobody gets unintended access), so it isn't a security hole - but it's a sharp operational edge: a route that's supposed to allow a set of users but has a typo'd or forgotten `username` field produces no error anywhere, just silent, total denial that looks identical to a misconfigured client or an unrelated bug from the outside.

**Fix:** emit a startup warning (or hard error, depending on how strict you want to be) when a route has `secure: true` and an empty `username` list - this is very unlikely to be intentional, and catching it at startup is far cheaper than debugging it in production.

### 21. Three `AppState` client fields are built at startup and never used

**Severity: Informational / code quality**
**File: `src/main.rs`, `src/config/config.rs` (`AppState`)**

```rust
pub client_normal: Client<HttpsConnector<HttpConnector>, BoxBody>,
#[allow(dead_code)]
pub client_with_cert: Client<HttpsConnector<HttpConnector>, BoxBody>,
#[allow(dead_code)]
pub client_with_proxy: Client<ProxyConnector<HttpsConnector<HttpConnector>>, BoxBody>,
```

These are built once at startup (one of them performs TLS certificate loading) and stored on `AppState`. A project-wide search confirms none of the three are read anywhere - every real request path uses `get_or_build_client()` from `network/shared_client.rs` instead, which builds/caches clients dynamically per route configuration. The `#[allow(dead_code)]` annotations on two of the three confirm this is already known.

**Impact:** none on request handling - purely wasted work at startup (building three HTTP clients, including a TLS setup, for values that are never read). No fix is urgent, but removing these three fields (and their construction in `main.rs`) would be a small, safe cleanup with no behavioral change.

### 22. Stable install script's checksum step references the beta hash

**Severity: Low-Medium (supply-chain integrity hygiene)**
**File: install script served at `https://proxyauth.app/sh/install`**

The stable install script downloads its binary from `.../downloads/latest/proxyauth` but verifies the checksum against `.../downloads/latest-beta/proxyauth/hash` - the source and the integrity check point at two different release channels. The script's own error message on failure (`"Error download beta version from $URL"`) also references "beta," suggesting this is a leftover from when the stable and beta scripts diverged, rather than an intentional shared-hash design.

This doesn't defeat the checksum check outright (a check does run, and a corrupted/tampered stable download would still very likely fail against a mismatched hash rather than silently pass), but it means the verification isn't actually confirming the integrity of the specific artifact it claims to, which undermines the purpose of the step.

**Fix:** point the stable script's hash check at `.../downloads/latest/proxyauth/hash` to match its own download URL, and update the leftover "beta" wording in the error message.

---

## Positive findings (unchanged from prior passes)

- Argon2 correctly implemented for password hashing, now with constant-time-equivalent username enumeration resistance.
- Modern AEAD (XChaCha20-Poly1305), random nonces, no reuse detected.
- Well-designed CSRF protection: single-use nonce, signed, constant-time comparison.
- `X-Forwarded-For`/`X-Real-Ip` handling is consistently gated behind `trust_proxy_forward_for` across both the main proxy path and the rate limiter.
- All admin-token and secret comparisons across `/adm/*` routes and token validation are constant-time.
- A panic anywhere in the app no longer takes down the whole process (`panic = "abort"` removed).
- Logout has real security value - it revokes the token server-side, not just the cookie.
- The two-part token design (config secret + build-time constants) provides genuine, if bounded, defense in depth against a `secret`-only leak, reinforced by `/etc/proxyauth`'s restrictive `750` permissions (see the wiki's Security Model page for the full reasoning).
- Robust path canonicalization against encoded path traversal.
- Cookies set with `HttpOnly`, `Secure`, `SameSite=Strict`.
- No plaintext secrets observed in application logs.
- Comprehensive project wiki now exists, cross-referencing config, security design, and operational behavior in detail - which is itself how findings #18-22 were caught.

---

## Recommendations, in priority order

1. **Finding #19** (silent mTLS fallback) - the most security-relevant of the new findings; a broken client cert should be loud, not a log line.
2. **Finding #20** (silent route lockout) - cheap to fix (a startup-time check), high value for operational sanity.
3. **Finding #18** (`add_otpkey` panic) - small, mechanical fix, same pattern as `clear_otpkey` already sets.
4. **Finding #22** (install script hash mismatch) - a one-line fix in a script served outside this repo's own release process.
5. Carry over Part 1's remaining open items (#9, #10, #11, #12, #13, #16) at their existing priority - reuse the `is_hop_by_hop_header` helper for #12, only auto-retry idempotent methods for #10, scope the sticky cache by route for #11.
6. **Finding #21** (dead client fields) - lowest priority, pure cleanup, no functional impact.

None of the five new findings are High/Critical, and none reopen or weaken any of the eight High/Critical fixes already verified in Part 1. This remains a comfortably shippable state; these are refinements, not red flags.
