//! External network communication protocols — anything ProxyAuth
//! speaks *outward*, to a system that isn't the backend it's
//! proxying to and isn't a database/cache it's reading from. Each
//! protocol gets its own submodule here.
//!
//! Currently:
//! - [`blakegate`] — pushes ProxyAuth's live in-memory configuration
//!   to external WebSocket endpoints, near real-time.
//!
//! Planned/expected to land here over time: OIDC, and other external
//! integration protocols as they come up. Grouping them under one
//! `proto` module (rather than scattering each at the crate root the
//! way `blakegate` briefly was) keeps "protocol ProxyAuth speaks to
//! the outside world" visually and structurally distinct from
//! ProxyAuth's own core concerns (`config`, `network`, `token`, ...).

pub mod blakegate;
