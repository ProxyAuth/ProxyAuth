// Copyright 2025 Vladimir Souchet
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

pub mod acme;
pub mod adm;
pub mod build;
pub mod cli;
pub mod config;
pub mod databases;
pub mod keystore;
pub mod network;
pub mod proto;
pub mod reset;
pub mod revoke;
pub mod smtp;
pub mod start_actix;
pub mod stats;
pub mod token;

/// Mirrors `main.rs`'s own `VERSION`/`ID` consts — needed here too
/// since `network::proxy` (used for `{{ proxyauth_version }}`/
/// `{{ proxyauth_id }}` tag substitution) is compiled as part of both
/// the library and binary crate roots; `crate::VERSION` needs to
/// resolve in both, and a binary crate's own root consts aren't
/// visible from code also compiled into the library.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const ID: &str = env!("id");

pub use config::config::{AppConfig, AppState, RouteConfig};
pub use network::proxy::global_proxy;
pub use stats::tokencount::CounterToken;
pub use token::auth::auth;
