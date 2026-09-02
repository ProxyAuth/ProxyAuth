//! RSA signing key for the OIDC provider — loads the RS256 keypair
//! every `id_token` this instance issues is signed with, and exposes
//! the public half in JWKS format for `/oidc/jwks.json`.
//!
//! # Why RSA/RS256, not ProxyAuth's own token scheme
//!
//! ProxyAuth's own session/bearer tokens (see `token::crypto`) use a
//! bespoke XChaCha20-Poly1305 + BLAKE3 + per-build-constant scheme —
//! deliberately not a standard format, since only ProxyAuth itself
//! ever needs to verify them. An `id_token` is the opposite case by
//! design: external relying parties, using their own, independent
//! standard JWT libraries, need to verify it without knowing anything
//! ProxyAuth-specific. RS256 (or ES256) signed JWTs, verifiable via a
//! published JWKS document, is what every OIDC client library expects
//! — there's no reasonable way to reuse ProxyAuth's own scheme here.
//!
//! # No `rsa` crate — deliberately
//!
//! An earlier version of this module generated its own keypair
//! in-process via the `rsa` crate. That crate carries
//! [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071)
//! (the "Marvin Attack" — an RSA timing side-channel), with no fixed
//! version available. The practical exposure was already narrow —
//! `jsonwebtoken`'s own actual *signing* operation goes through
//! `ring`, not the `rsa` crate at all; `rsa` was only ever used here
//! for one-time key generation and pulling the public modulus/exponent
//! out for JWKS, never in a per-request, attacker-observable path —
//! but "narrow exposure" isn't the same as "no dependency," and a
//! `cargo audit` finding with no available fix is worth actually
//! removing rather than only explaining away.
//!
//! Key generation has moved **out of this binary entirely**. An
//! operator generates the key once, externally, with a standard tool:
//!
//! ```text
//! openssl genrsa -traditional -out /etc/proxyauth/oidc/signing_key.pem 2048
//! chmod 600 /etc/proxyauth/oidc/signing_key.pem
//! chown <run_user> /etc/proxyauth/oidc/signing_key.pem
//! ```
//!
//! This module only ever *reads* that file. Signing itself still goes
//! through `jsonwebtoken::EncodingKey::from_rsa_pem` (→ `ring`,
//! unaffected by the advisory). The one thing that genuinely needed
//! `rsa` before — pulling the modulus/exponent out for JWKS — is now
//! done by [`der`], a small, deliberately narrow DER reader that only
//! knows how to walk a PKCS#1 `RSAPrivateKey` `SEQUENCE` far enough to
//! read those two `INTEGER` fields, verified against real
//! openssl-generated keys (2048-bit and 4096-bit) cross-checked
//! byte-for-byte against `openssl rsa -noout -modulus`'s own report,
//! plus a set of malformed/truncated inputs confirmed to fail cleanly
//! rather than panic.
//!
//! # Key handling
//!
//! Loaded once at startup and cached — **never** regenerated or
//! rewritten by ProxyAuth itself. Every previously-issued `id_token`
//! (and every relying party's cached copy of the old JWKS document)
//! would stop validating the moment the key changed; rotation is a
//! deliberate, external, explicit operation now, same as it always
//! should have been.
//!
//! SECURITY: this key signs every `id_token` this instance issues —
//! anyone who obtains it can forge a token asserting to be *any* user,
//! for *any* relying party that trusts this provider. This is at
//! least as sensitive as the TLS private key at
//! `/etc/proxyauth/certs/key.pem`; ProxyAuth checks it's `0600` at
//! load time and refuses to start with this feature enabled if it
//! isn't, the same bar the TLS key is held to.

use super::der;

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use once_cell::sync::OnceCell;
use serde::Serialize;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

const SIGNING_KEY_PATH: &str = "/etc/proxyauth/oidc/signing_key.pem";

/// One JWK entry, in the exact shape `/oidc/jwks.json` returns it —
/// field names and casing are dictated by RFC 7517, not a style
/// choice.
#[derive(Debug, Clone, Serialize)]
pub struct Jwk {
    pub kty: &'static str, // "RSA"
    #[serde(rename = "use")]
    pub r#use: &'static str,
    pub alg: &'static str, // "RS256"
    pub kid: String,
    pub n: String,
    pub e: String,
}

pub struct OidcSigningKey {
    pub encoding_key: EncodingKey,
    pub decoding_key: DecodingKey,
    pub kid: String,
    jwk: Jwk,
}

impl OidcSigningKey {
    /// Builds a signed JWT header wired to this key's algorithm and
    /// `kid` — every caller constructing an `id_token` should start
    /// from this rather than building a `Header` by hand, so the
    /// `kid` a relying party needs to look up the right JWKS entry is
    /// never accidentally omitted or mismatched.
    ///
    /// Note for anyone locally decoding a token built this way (e.g.
    /// while testing): every `id_token` carries an `aud` claim, and
    /// `jsonwebtoken` treats "claims has `aud`, validation never
    /// configured an expected audience" as a hard failure
    /// (`InvalidAudience`), not a pass-through — a `Validation` used
    /// to verify one of these needs its own `.set_audience(&[...])`
    /// call first. A real external relying party's own OIDC client
    /// library already does this automatically; it only comes up when
    /// something *inside* this codebase needs to decode one, which
    /// isn't a case that currently exists (`/oidc/userinfo` decodes the
    /// separate, `aud`-less `access_token` instead — see
    /// `validation_no_audience`).
    pub fn header(&self) -> Header {
        let mut h = Header::new(Algorithm::RS256);
        h.kid = Some(self.kid.clone());
        h
    }

    /// Builds a `Validation` for tokens that don't carry an `aud`
    /// claim at all — currently just the `access_token` (see
    /// `token::AccessTokenClaims`), which deliberately omits `aud`
    /// since it's only ever verified by ProxyAuth's own `/oidc/userinfo`
    /// endpoint, never an external relying party that would need to
    /// confirm it was the intended audience the way an `id_token`'s
    /// recipient does. `validate_aud` set explicitly to `false` rather
    /// than relying on whatever the library defaults to — verified
    /// directly (not assumed) that a token genuinely carrying no `aud`
    /// claim decodes cleanly with this configuration.
    pub fn validation_no_audience(&self) -> Validation {
        let mut v = Validation::new(Algorithm::RS256);
        v.validate_exp = true;
        v.validate_aud = false;
        v
    }
}

static SIGNING_KEY: OnceCell<OidcSigningKey> = OnceCell::new();

/// Loads the signing key from `SIGNING_KEY_PATH`. Call once at
/// startup, before any OIDC route can be reached — `signing_key()`
/// panics if this hasn't run.
///
/// Returns a clear, actionable `Err` (not a panic) if the key is
/// missing or its permissions are too loose — this is reachable from
/// an operator's own config choice (any vhost declaring `oidc:`), not
/// a programming error, so it deserves a message telling them exactly
/// what to run rather than a stack trace.
pub fn init_signing_key() -> Result<(), String> {
    if !Path::new(SIGNING_KEY_PATH).exists() {
        return Err(format!(
            "OIDC is enabled for at least one vhost, but no signing key was found at \
{SIGNING_KEY_PATH}. Generate one once, externally, before starting ProxyAuth:\n\n\
    openssl genrsa -traditional -out {SIGNING_KEY_PATH} 2048\n\
    chmod 600 {SIGNING_KEY_PATH}\n\n\
This only needs to happen once — every id_token issued after that point is tied \
to this specific key, and it is never regenerated automatically."
        ));
    }

    let meta = fs::metadata(SIGNING_KEY_PATH)
        .map_err(|e| format!("Failed to stat OIDC signing key at {SIGNING_KEY_PATH}: {e}"))?;
    let mode = meta.permissions().mode() & 0o777;
    if mode != 0o600 {
        return Err(format!(
            "OIDC signing key at {SIGNING_KEY_PATH} has permissions {mode:o}, expected 600. \
Refusing to start with a signing key that isn't owner-only-readable — fix with:\n\n    chmod 600 {SIGNING_KEY_PATH}"
        ));
    }

    let pem_str = fs::read_to_string(SIGNING_KEY_PATH)
        .map_err(|e| format!("Failed to read OIDC signing key at {SIGNING_KEY_PATH}: {e}"))?;

    let encoding_key = EncodingKey::from_rsa_pem(pem_str.as_bytes())
        .map_err(|e| format!("Failed to build JWT encoding key from {SIGNING_KEY_PATH}: {e}"))?;

    let pem_doc = pem::parse(&pem_str)
        .map_err(|e| format!("Failed to parse PEM at {SIGNING_KEY_PATH}: {e}"))?;
    let (n, e) = der::extract_rsa_n_e(pem_doc.contents()).ok_or_else(|| {
        format!(
            "Failed to extract modulus/exponent from {SIGNING_KEY_PATH} — is this a \
PKCS#1 RSA private key (\"-----BEGIN RSA PRIVATE KEY-----\")? PKCS#8 \
(\"-----BEGIN PRIVATE KEY-----\") is not currently supported; re-export with \
`openssl rsa -traditional`."
        )
    })?;
    let decoding_key = DecodingKey::from_rsa_raw_components(&n, &e);

    // A single, stable key id for as long as this specific key file is
    // in use — real rotation support (multiple simultaneously-valid
    // keys, an old key kept around just long enough for in-flight
    // tokens to expire) is a deliberate future extension, not
    // implemented by this first pass. Fixed rather than
    // content-derived so relying parties caching the JWKS document by
    // `kid` see a stable identifier across restarts of the same key.
    let kid = "proxyauth-oidc-1".to_string();

    let jwk = Jwk {
        kty: "RSA",
        r#use: "sig",
        alg: "RS256",
        kid: kid.clone(),
        n: b64url(&n),
        e: b64url(&e),
    };

    SIGNING_KEY
        .set(OidcSigningKey {
            encoding_key,
            decoding_key,
            kid,
            jwk,
        })
        .map_err(|_| "OIDC signing key already initialized".to_string())?;

    Ok(())
}

/// Panics if `init_signing_key` hasn't run yet — this is a startup
/// invariant, the same category of "must be initialized before use"
/// as the rest of ProxyAuth's `OnceCell`/`static`-backed subsystems
/// (e.g. `revoke::db::LMDB_ENV`), not a per-request condition a
/// caller is expected to handle.
pub fn signing_key() -> &'static OidcSigningKey {
    SIGNING_KEY
        .get()
        .expect("init_signing_key() must run before signing_key() is called")
}

/// The JWKS document body for `/oidc/jwks.json` — currently always exactly
/// one key. Structured as a `Vec` from the start (rather than a
/// single `Jwk`) so real key rotation later — publishing both the
/// current and a recently-retired key simultaneously while in-flight
/// tokens signed with the old one are still valid — is an additive
/// change here, not a breaking one.
pub fn jwks_document() -> serde_json::Value {
    serde_json::json!({ "keys": [signing_key().jwk] })
}

/// Base64url, no padding — the encoding RFC 7517 requires for a JWK's
/// `n`/`e` fields.
fn b64url(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}
