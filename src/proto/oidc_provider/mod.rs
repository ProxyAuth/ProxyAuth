//! ProxyAuth acting as a genuine OpenID Connect provider (OP) — a
//! vhost with `oidc:` configured (see [`config::OidcProviderConfig`])
//! lets the backend sitting behind it act as a standard OIDC relying
//! party, receiving a real, independently-verifiable `id_token`
//! rather than relying on ProxyAuth's own header injection or session
//! cookie.
//!
//! This is the opposite direction from an `oidc_client` module (not
//! yet built): here, ProxyAuth *issues* identity to other
//! applications; an OIDC client integration would instead let
//! ProxyAuth *consume* identity from an external provider (Google,
//! Keycloak, ...) as an alternative way for a human to log in to
//! ProxyAuth itself. Both are meant to coexist with ProxyAuth's
//! existing username/password(+TOTP) system, not replace it — see
//! each module's own doc comment for the details specific to that
//! direction.
//!
//! # Why a standard JWT/RSA scheme here, unlike the rest of ProxyAuth
//!
//! ProxyAuth's own session/bearer tokens (`token::crypto`) use a
//! bespoke encryption scheme precisely because only ProxyAuth itself
//! ever needs to verify them. An `id_token` is the opposite case by
//! design — external relying parties, using independent, standard JWT
//! libraries, need to verify it without knowing anything
//! ProxyAuth-specific. See [`jwt`] for the RS256/JWKS implementation
//! this requires.
//!
//! # Submodules
//! - [`config`] — the `oidc:` block itself (`OidcProviderConfig`).
//! - [`jwt`] — the RS256 signing key: generation, on-disk persistence,
//!   and the JWKS document served at `/oidc/jwks.json`.
//! - [`discovery`] — `/.well-known/openid-configuration` and
//!   `/oidc/jwks.json`, the two read-only endpoints.
//! - [`authcode`] — the LMDB-backed, atomically single-use
//!   authorization code store bridging `/oidc/authorize` and `/oidc/token`.
//! - [`authorize`] — `GET /authorize`, where the browser lands to
//!   authenticate and get redirected back to the relying party with a
//!   code.
//! - [`token`] — `POST /token`, where the relying party exchanges
//!   that code (server-to-server) for a signed `id_token`.
//! - [`userinfo`] — `GET /userinfo`, where the relying party presents
//!   the `access_token` to get claims about the authenticated user.
//! - [`logout`] — `GET /end-session`, RP-Initiated Logout.

pub mod authcode;
pub mod authorize;
pub mod config;
mod der;
pub mod discovery;
pub mod jwt;
pub mod logout;
pub mod token;
pub mod userinfo;
