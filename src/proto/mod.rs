//! External network communication protocols — anything ProxyAuth
//! speaks *outward*, to a system that isn't the backend it's
//! proxying to and isn't a database/cache it's reading from. Each
//! protocol gets its own submodule here.
//!
//! Currently:
//! - [`blakegate`] — pushes ProxyAuth's live in-memory configuration
//!   to external WebSocket endpoints, near real-time.
//! - [`oidc_provider`] — ProxyAuth acting as a genuine OpenID Connect
//!   provider for a vhost's own backend.
//!
//! Planned/expected to land here over time: an `oidc_client` module
//! (the opposite direction — ProxyAuth as an OIDC *relying party*,
//! letting a human log in to ProxyAuth itself via an external
//! provider), and other external integration protocols as they come
//! up. Grouping them under one `proto` module (rather than scattering
//! each at the crate root the way `blakegate` briefly was) keeps
//! "protocol ProxyAuth speaks to the outside world" visually and
//! structurally distinct from ProxyAuth's own core concerns
//! (`config`, `network`, `token`, ...).

pub mod blakegate;
pub mod oidc_provider;
