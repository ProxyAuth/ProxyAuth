# Security fixes — password-reset race, TLS pinning, SQL identifier guard, static-route logging

Fixes three findings from the security audit (H1, M1, M4) plus a related
logging gap found while verifying the fixes, and removes the dead code
left behind.

## 🔴 H1 — Password-reset token race condition

**Before**: the reset token was validated (read-only) and consumed
(deleted) in two separate calls, with Argon2 password hashing in between —
a real, timed window where two requests carrying the same token could both
pass validation before either one consumed it.

**After**: `reset::db::validate_and_consume_token` checks and deletes the
token inside a **single LMDB read-write transaction**. No window between
"is this valid" and "is this now gone."

- `reset/db.rs` — new `validate_and_consume_token`
- `token/reset_password.rs` — uses it instead of the old
  validate-then-consume-later sequence

> One accepted trade-off: a failure *after* successful validation (e.g. the
> database write itself fails) now costs the token, requiring a fresh
> link. Password-confirmation and minimum-length checks still run
> **before** this call, so a mistyped password never burns a token.

## 🟠 M1 — `reset-otp` accepted any TLS certificate

**Before**: `danger_accept_invalid_certs(true)` on the CLI's loopback
connection to its own admin API — any certificate, from anyone, was
accepted.

**After**: pinned to the server's actual default certificate
(`/etc/proxyauth/certs/cert.pem`) via `tls_certs_only`, tolerating only the
specific hostname mismatch this loopback call always has.

- `cli/prompt.rs` — new `build_loopback_admin_client`

Verified end-to-end against a real TLS server: correct cert connects,
wrong cert is rejected. Falls back to the old behavior (loudly warned) only
if the pinned certificate file can't be read.

## 🟠 M4 — SQL identifiers built via `format!`

**Before**: `load_values_for_user` interpolated `table`/`column` into the
query string with no check — safe today only because every call site
happens to pass a hardcoded value.

**After**: an explicit allow-list is checked before the query is built.

- `databases/db.rs` — `const ALLOWED: &[(&str, &str)]` guard

## 🐛 Bonus fix — static routes weren't logging who made the request

Found while re-verifying the fixes above. `check_static_auth` correctly
enforced `required_login`, but discarded the resolved `(username,
token_id)` instead of publishing it to the access log — `[username]`/
`[tid]` showed `-` for every static route (`static:`/`static_index:`)
regardless of login state, even with `required_login: true` set. Proxied
routes were unaffected; they already did this correctly.

- `network/proxy.rs` — `check_static_auth` now returns the resolved
  identity, caller passes it to `LogContext::set_user`

## 🧹 Cleanup

Removed three functions left unused by the fixes above, instead of
`#[allow(dead_code)]`-suppressing the warnings:

| Function | Why removed |
|---|---|
| `reset::db::validate_token` | superseded by `validate_and_consume_token`; kept around it'd be an easy way to accidentally reintroduce H1 |
| `reset::db::consume_token` | same reason — was the other half of the unsafe pair |
| `config::def_config::ensure_running_as_proxyauth` | doc comment claimed callers that no longer exist; every real call site already migrated to the configurable `ensure_running_as(config.effective_run_user())` |

## Testing

- `validate_and_consume_token`'s atomicity and `load_values_for_user`'s
  allow-list were each tested in isolation (concurrent-access simulation /
  allow-vs-deny cases).
- The TLS pinning fix was tested against a real local HTTPS server with a
  properly-formed self-signed certificate: correct cert → success, wrong
  cert → rejected.
- No behavior changes to already-passing request paths; `cargo build`
  should now be warning-free for these three functions.
