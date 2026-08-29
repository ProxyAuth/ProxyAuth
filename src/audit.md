# ProxyAuth — Security Audit (v2)

**Scope**: full source tree as uploaded, this time including the real
`Cargo.toml` — dependency versions/features are now part of this review,
not a blind spot. This supersedes the first audit: M5 (originally rated
High, revised below)/M1/M4 from that pass
are fixed and verified here; this pass also covers several areas the first
one didn't reach (CORS, cookie attributes, command execution, ACME
challenge handling, Redis, rate-limiter bucketing, LMDB permissions).

**Method**: same as before — manual, category by category, every finding
tied to an actual file/line. Several suspected issues were investigated and
confirmed safe; those are recorded too, since "checked and safe" is
different information from "not checked."

**Summary**: the three issues from the first audit that got fixed are
verified fixed, correctly, in this codebase. This second pass found one
more Low-severity item (CORS header hygiene) and confirmed a broad set of
security-relevant mechanisms — cookie attributes, rate-limiter bucketing,
command execution, ACME challenge handling, LMDB permission inheritance —
are all correctly implemented, not just assumed.

---

## Fixed since the first audit

### ✅ M5 — Password-reset token race (was rated High, revised to Medium — see note)

> **Severity revised from High to Medium.** The race itself is trivial to
> reproduce — anyone can demonstrate it against their own account, no
> victim needed, by firing two concurrent requests with the same
> self-issued token. What keeps this Medium rather than High is the
> precondition for exploiting it *against someone else*: two different
> parties need access to the same still-valid token at roughly the same
> time (a shared/monitored inbox, a leaked token, network interception).
> In most of those same scenarios, an attacker with that level of access
> could usually just use the link first — the race mainly matters when the
> attacker can't quite win outright but can land a request *during* the
> legitimate user's own submission, which is a narrower, more
> attacker-favorable window than "get there first," but still a real
> precondition, not remote-exploitable on its own.

**Then**: `validate_token` (read-only) and `consume_token` (delete) were
separate calls with Argon2 hashing in between — a real, timed race window
where the same token could validate twice.

**Now**: `reset/db.rs::validate_and_consume_token` performs the read and
the delete inside a single LMDB read-write transaction, under the same
mutex every other function in that file already uses. `token/reset_password.rs`
calls this instead of the old two-step sequence; the old `consume_token`
call after the password write was removed (nothing left to consume by
then). Verified: the function's own doc comment correctly documents the
one behavioral trade-off this introduces (a failure *after* successful
validation, e.g. a database write error, now costs the token — acceptable,
since the checks that don't need the token at all, password confirmation
and minimum length, still run earlier and don't burn it on a mistyped
password).

### ✅ M1 — `reset-otp`'s TLS bypass (was: `danger_accept_invalid_certs(true)`)

**Then**: the CLI's loopback connection to its own admin API accepted
*any* certificate whatsoever.

**Now**: `cli/prompt.rs::build_loopback_admin_client` pins the connection
to the server's own default certificate (`/etc/proxyauth/certs/cert.pem`)
via `tls_certs_only([cert])`, combined with `danger_accept_invalid_hostnames`
only for the specific "cert isn't issued for 127.0.0.1" mismatch this
loopback call always has. Falls back to the old behavior, loudly warned,
only if the certificate file itself can't be read.

Verified end-to-end against a real TLS server presenting a properly-formed
end-entity certificate (`CA:FALSE`, matching what any genuine server
certificate — self-signed or CA-issued — actually looks like): the correct
pinned certificate connects successfully, a different certificate is
rejected. This also surfaced a real API difference worth noting for future
reqwest work in this codebase — reqwest 0.13 (the version actually pinned
in `Cargo.toml`) requires `tls_certs_only` specifically when disabling
hostname verification; the older `add_root_certificate` +
`tls_built_in_root_certs(false)` pairing from reqwest 0.12 doesn't exist on
this version.

### ✅ M4 — SQL identifiers via `format!` (was: no compiler-enforced safety net)

**Then**: `load_values_for_user` built `SELECT {column} FROM {table}`
with hardcoded-but-unchecked string interpolation.

**Now**: an explicit allow-list (`const ALLOWED: &[(&str, &str)]`) is
checked before the query is built at all — `("user_allow", "cidr")` and
`("user_roles", "role")` are the only accepted pairs, matching the two real
call sites exactly. Any other combination is refused with a clear error
before touching the database. Tested in isolation: both legitimate pairs
pass, every other combination (including a correct table paired with the
wrong column) is rejected.

---

## Open from the first audit (not addressed by request)

- **M2** — no account lockout; `ratelimit_auth` defaults to disabled
  (`requests_per_second: 0`). Still open.
- **M3** — `/adm/*` routes remain unprotected by rate limiting, by design.
  Explicitly deprioritized — the admin token's own strength (64-char
  BLAKE3-derived hex, constant-time compared) makes this primarily an
  availability concern, not a credential-guessing one.
- **L1** — custom "factor hash" cost function instead of an established KDF.
- **L2** — `generate_random_string`'s timestamp-shift-then-hash construction
  is more complex than its security requires.
- **L3** — no explicit minimum TLS version pinned (relies on rustls
  defaults, which already exclude TLS 1.0/1.1).
- **L4** — constant-time comparison on variable-length input can leak
  *length* via timing (industry-wide `subtle`-style limitation).

---

## New findings, this pass

### 🟡 Low — `Access-Control-Allow-Credentials: true` set unconditionally

**File**: `network/cors.rs`, end of the response-handling closure.

**The issue**: `ACCESS_CONTROL_ALLOW_ORIGIN` is only added when the
request's `Origin` header matches the resolved `cors_origins` allow-list —
correctly implemented, exact match after case/trailing-slash normalization,
no reflection-of-anything-sent behavior. But
`ACCESS_CONTROL_ALLOW_CREDENTIALS: true` is inserted on *every* response,
regardless of whether an origin was present, matched, or even whether this
was a cross-origin request at all.

**Why it's Low, not higher**: browsers require *both* headers, matching the
*specific requesting origin*, before a credentialed cross-origin response
is exposed to the requesting page's JavaScript. Since `ALLOW_ORIGIN` is
correctly gated on the allow-list check, an unauthorized origin still can't
read the response even though `ALLOW_CREDENTIALS` was present — the actual
browser-enforced security boundary holds. This is a hygiene/defense-in-depth
gap (the two headers should be coupled, so a mistake elsewhere in the CORS
logic can't accidentally combine "wrong origin allowed" with "credentials
allowed" — currently that combination can't happen, but the code doesn't
make that structurally impossible, just currently-true).

**Fix**: move the `ACCESS_CONTROL_ALLOW_CREDENTIALS` insert inside the
`if let Some(cors) = cors_origins { if origin matches { ... } }` block,
alongside `ACCESS_CONTROL_ALLOW_ORIGIN` — so the two are set together or
not at all.

---

## Checked this pass and found solid

- **Session cookie attributes**: `Secure`, `HttpOnly`, `SameSite=Strict`
  are genuinely set on every session cookie construction site found
  (`token/auth.rs:681-693`, plus every manual clearing-cookie string in
  `token/logout.rs` and `network/proxy.rs`) — not just claimed, verified
  present in each instance.
- **Command execution**: every `std::process::Command` invocation in the
  codebase (`config/def_config.rs`, `network/stats.rs` — group/user
  creation, chown/chmod during `prepare`) uses `.arg()`/`.args()` with
  hardcoded command names and arguments, never a shell, and never
  interpolates network-facing input. No command-injection surface found.
- **ACME HTTP-01 challenge handling**: `extract_token` rejects empty
  tokens and any path containing an extra `/` before the token is ever
  used, and the token is only ever used as an in-memory/LMDB *lookup key*
  (`acme::challenge::lookup`) — never concatenated into a filesystem path,
  so there's no path-traversal angle even though the input comes straight
  from the request path.
- **Redis-backed token revocation**: `token_id` used in Redis keys
  originates from the server's own encrypted, integrity-checked token
  structure, not raw client input, and all Redis interaction goes through
  the `redis` crate's typed RESP commands (`.set`/`.incr`/`.expire`), not
  string-built commands — no injection surface. Redis itself being a
  trusted-network dependency is an operational assumption, not a code gap.
- **Rate-limiter bucketing**: `network/ratelimit.rs`'s `KeyExtractor`
  already carries an explicit comment and fix for exactly the failure mode
  worth checking for — it used to trust `X-Forwarded-For` unconditionally,
  letting any client manufacture a fresh rate-limit bucket per request and
  defeat brute-force protection entirely. It now reuses the same
  trusted-peer-gated `client_ip` verified in the first audit. An attacker
  without a valid, decryptable token can't manufacture a fresh per-user
  bucket either — extraction cleanly fails and falls through to the
  IP-based key.
- **LMDB store permissions**: `reset/db.rs` and `databases/cache.rs`
  explicitly `chmod 0o700` their own directories. `revoke/db.rs` doesn't
  set permissions itself, but its default path (`/opt/proxyauth/db/`) lives
  under `/opt/proxyauth`, which `prepare`'s `setup_proxyauth_db_directory`
  already `chmod 700`s (owned `proxyauth:proxyauth`) — a 0700 parent
  directory blocks traversal for every other user regardless of the child
  files' own permission bits, so this is protected transitively, not
  missing. `acme/challenge.rs` deliberately does *not* chmod its directory
  (documented reasoning: it's shared between the long-running daemon and
  the short-lived `certbot` subprocess, possibly under different Unix
  users) — an acceptable, intentional exception given the data involved
  (ACME key-authorizations) is meant to be served publicly anyway.

---

## Not covered by this review

- **Dependency vulnerability scan** — `Cargo.toml` is now available, but a
  proper answer needs `cargo audit` against the RustSec database and the
  actual resolved `Cargo.lock`, which wasn't included; version ranges
  alone don't tell you what's actually resolved and installed.
- **Fuzzing/dynamic testing** — still a static read-through, not fuzzing or
  live penetration testing.
- **Deployment/infrastructure hardening** — systemd unit configuration,
  reverse-proxy-in-front-of-ProxyAuth setups, Redis network exposure, and
  similar operational concerns remain outside the source code itself.
