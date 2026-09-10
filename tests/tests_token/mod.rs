mod auth;
mod build_info;
mod crypto;
mod csrf;
mod security;

/// Initialises the process-wide token vault for this test binary.
///
/// `main.rs` does this at startup; a test binary has no startup, so
/// without it the first call that mints or checks a token panics.
///
/// The secret here is arbitrary. Both issuing and verifying go through
/// the vault now, not through `config.secret`, so a test's own config may
/// carry a different secret without anything failing — only consistency
/// *within* the vault matters, and there is exactly one per process.
#[ctor::ctor]
fn init_token_vault() {
    let config = proxyauth::AppConfig {
        secret: "test-vault-secret".into(),
        timezone: "UTC".into(),
        token_expiry_seconds: 3600,
        ..Default::default()
    };

    if let Err(e) = proxyauth::token::vault::init(&config) {
        panic!("test setup: cannot initialise the token vault: {e}");
    }
}
