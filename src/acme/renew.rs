//! Runs one certificate renewal for one vhost against a real ACME
//! server (Let's Encrypt by default — see `AcmeConfig.directory_url`),
//! using the HTTP-01 challenge.
//!
//! Built against `instant-acme` 0.7's actual API (verified against its
//! own published example, not written from memory) — this module
//! itself has no way to exercise a real ACME exchange in isolation the
//! way the rest of this codebase's tests do (no fake in-process ACME
//! server stands in for Let's Encrypt the way a fake TCP listener
//! stands in for a database). Test this against
//! `AcmeConfig.directory_url` pointed at Let's Encrypt's **staging**
//! environment before ever pointing it at production — staging has no
//! meaningful rate limits and issues certificates that exercise the
//! exact same code path, just from a CA nothing trusts by default.
//!
//! Does **not** trigger a TLS hot-reload itself after writing the new
//! certificate — nothing needs to. The existing per-vhost certificate
//! file watcher (`tls::watch_cert_key`, spawned once at startup for
//! every `vhost_cert` in `routes.yml`) is a real filesystem event
//! watcher already watching these exact paths; it picks up the new
//! files and swaps them into the live TLS resolver on its own, the
//! same way it already does for a certificate replaced by hand.

use crate::acme::challenge;
use crate::config::acme::AcmeConfig;
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount,
    NewOrder, OrderStatus, RetryPolicy,
};
use rcgen::{CertificateParams, DistinguishedName, KeyPair};
use std::path::Path;
use tracing::info;

/// One renewal attempt for `vhost`, issuing a certificate that covers
/// exactly that hostname. Writes the new certificate chain and private
/// key to `cert_path`/`key_path` on success. On any failure, nothing
/// is written — whatever certificate was already at those paths is
/// untouched and keeps being served, exactly as required ("le
/// certificat actuellement valide doit rester utilisé").
///
/// The in-RAM HTTP-01 challenge response is always cleaned up before
/// this returns, success or failure — via a guard, not a
/// success-path-only call, so a `?`-propagated error partway through
/// can't leave a stale challenge response behind.
pub async fn renew_certificate(
    names: &[String],
    cert_path: &Path,
    key_path: &Path,
    acme_cfg: &AcmeConfig,
) -> Result<(), String> {
    if names.is_empty() {
        return Err("renew_certificate called with no DNS names".to_string());
    }
    let account = load_or_create_account(acme_cfg).await?;

    // Used only for messages. Every name goes on one order and one
    // CSR, so failures concern the whole set rather than any single
    // name.
    let vhost = names.join(", ");

    // One identifier per name — the ACME server then issues one
    // authorization per name, all of which must validate before the
    // single multi-SAN certificate is issued. Note this means a name
    // that doesn't resolve to this server fails the *whole* order: a
    // group listing `www.` needs that DNS record to exist.
    let identifiers: Vec<Identifier> =
    names.iter().map(|n| Identifier::Dns(n.clone())).collect();
    let mut order = account
    .new_order(&NewOrder::new(&identifiers))
    .await
    .map_err(|e| format!("failed to create ACME order for {vhost}: {e}"))?;

    let state = order.state();
    if state.status == OrderStatus::Invalid {
        return Err(format!("ACME order for {vhost} was immediately invalid"));
    }

    // Guards the published challenge response: dropped (running its
    // cleanup) on every exit path below, `?`/early-return included —
    // not just the success path.
    let mut cleanup = ChallengeCleanupGuard {
        names: names.to_vec(),
        tokens: Vec::new(),
    };

    let mut authorizations = order.authorizations();
    while let Some(result) = authorizations.next().await {
        let mut authz = result
        .map_err(|e| format!("failed to fetch an authorization for {vhost}: {e}"))?;

        match authz.status {
            AuthorizationStatus::Valid => continue,
            AuthorizationStatus::Pending => {}
            other => {
                return Err(format!(
                    "authorization for {vhost} in unexpected state {other:?}"
                ));
            }
        }

        let mut challenge = authz
        .challenge(ChallengeType::Http01)
        .ok_or_else(|| format!("no HTTP-01 challenge offered for {vhost}"))?;

        let key_auth = challenge.key_authorization();
        // ChallengeHandle derefs to Challenge, so .token is the real
        // ACME challenge token (not .identifier(), which is the
        // domain name being validated — a mistake worth flagging
        // since both looked plausible here).
        let token = challenge.token.clone();
        // Published under every name in the set rather than under the
        // one this authorization is for. The key authorization is
        // bound to the token, not to the hostname, so a token that
        // answers on any name in the group is still correct — and this
        // avoids depending on the exact shape of instant-acme's
        // per-authorization identifier accessor. Tokens are unique per
        // authorization, so the entries never collide.
        for name in names {
            challenge::publish(name, &token, key_auth.as_str())
            .map_err(|e| format!("failed to publish HTTP-01 challenge for {name}: {e}"))?;
        }
        cleanup.tokens.push(token);

        challenge
        .set_ready()
        .await
        .map_err(|e| format!("failed to mark challenge ready for {vhost}: {e}"))?;
    }

    // Built-in exponential backoff while Let's Encrypt validates the
    // challenge, replacing what used to be a hand-rolled retry loop —
    // instant-acme 0.8 added this itself.
    let status = order
    .poll_ready(&RetryPolicy::default())
    .await
    .map_err(|e| format!("failed waiting for order to become ready for {vhost}: {e}"))?;
    if status != OrderStatus::Ready {
        let reason = describe_failure(&mut order).await;
        return Err(format!(
            "order for {vhost} ended in state {status:?}, expected Ready — {reason}"
        ));
    }

    // Every name becomes a SAN on this one certificate — the whole
    // point of the grouping. `CertificateParams::new` puts the first
    // entry in the CN too, so `routes.yml` order decides the primary
    // name.
    let mut params = CertificateParams::new(names.to_vec())
    .map_err(|e| format!("failed to build certificate params for {vhost}: {e}"))?;
    params.distinguished_name = DistinguishedName::new();
    let private_key =
    KeyPair::generate().map_err(|e| format!("failed to generate key pair for {vhost}: {e}"))?;
    let csr = params
    .serialize_request(&private_key)
    .map_err(|e| format!("failed to build CSR for {vhost}: {e}"))?;

    // finalize_csr (bring your own CSR/key), not the newer finalize()
    // (which generates its own key internally) — keeps a fresh,
    // locally-generated key per renewal under our own control, same
    // as before.
    order
    .finalize_csr(csr.der())
    .await
    .map_err(|e| format!("failed to finalize order for {vhost}: {e}"))?;

    let cert_chain_pem = order
    .poll_certificate(&RetryPolicy::default())
    .await
    .map_err(|e| format!("failed to fetch certificate for {vhost}: {e}"))?;

    // Write the new cert/key to disk only once both are ready to go —
    // never leave a half-written pair for the file watcher to trip
    // over mid-write (see write_atomically's own doc comment for how
    // "atomically" is done here).
    write_atomically(cert_path, cert_chain_pem.as_bytes())
    .map_err(|e| format!("failed to write {}: {e}", cert_path.display()))?;
    write_atomically(key_path, private_key.serialize_pem().as_bytes())
    .map_err(|e| format!("failed to write {}: {e}", key_path.display()))?;

    info!(
        "ACME: renewed certificate for {vhost} -> {} / {}",
        cert_path.display(),
          key_path.display()
    );

    Ok(())
}

/// Re-fetches every authorization on `order` and collects any error
/// Let's Encrypt attached to a failed challenge — called once
/// `poll_ready` reports the order didn't reach `Ready`, so the
/// resulting error message says *why* the challenge failed (a DNS
/// problem, a connection refused, an unexpected response body, etc.)
/// instead of just "ended in state Invalid", which on its own gives no
/// hint about what to actually go fix.
async fn describe_failure(order: &mut instant_acme::Order) -> String {
    let mut reasons = Vec::new();
    let mut authorizations = order.authorizations();
    while let Some(result) = authorizations.next().await {
        let Ok(mut authz) = result else { continue };
        // Only HTTP-01 is ever requested by this code (see the main
        // renewal flow above) — checking for other challenge types'
        // errors here wouldn't reflect anything this code actually
        // attempted, so there's no need to loop over ChallengeType
        // variants (which also wouldn't work directly: each call to
        // `.challenge()` ties its returned handle to the same
        // borrowed lifetime as `authz` itself, so calling it more than
        // once per authorization doesn't borrow-check cleanly anyway).
        if let Some(reason) = authz
            .challenge(instant_acme::ChallengeType::Http01)
            .and_then(|c| c.error.as_ref().map(|p| p.to_string()))
            {
                reasons.push(reason);
            }
    }

    if reasons.is_empty() {
        "Let's Encrypt gave no further detail — check that the domain is publicly resolvable and reachable on port 80 from outside your network.".to_string()
    } else {
        reasons.join("; ")
    }
}

/// Loads the persisted ACME account from
/// `AcmeConfig.account_credentials_path`, or registers a new one and
/// persists it there if none exists yet. Reusing one account across
/// every renewal (rather than creating a fresh one each time) matters
/// beyond tidiness — excessive account creation is itself something
/// Let's Encrypt rate-limits.
/// Wraps the raw ACME account credentials together with the
/// `directory_url` they were registered against — staging and
/// production are two entirely separate ACME servers, each with their
/// own account database, so a credential set from one is meaningless
/// (and silently *wrong*, not merely rejected) against the other.
/// Without tracking this, switching `directory_url` from staging to
/// production would keep reusing the staging account indefinitely —
/// every order still submitted to staging via that account's own
/// server-assigned URL, regardless of what `directory_url` now says —
/// with nothing to indicate why the resulting certificate still says
/// `(STAGING)` in its issuer, which is exactly what happened here
/// before this was tracked.
#[derive(serde::Serialize, serde::Deserialize)]
struct StoredAccount {
    directory_url: String,
    credentials: AccountCredentials,
}

async fn load_or_create_account(acme_cfg: &AcmeConfig) -> Result<Account, String> {
    let path = Path::new(&acme_cfg.account_credentials_path);

    if let Ok(existing) = std::fs::read(path) {
        // Only reused when it matches the *currently configured*
        // directory_url. A parse failure here also falls through to
        // creating a fresh account below — deliberately, rather than
        // propagating the error — covering both a corrupted file and
        // (mainly) the pre-existing on-disk format from before this
        // wrapper existed, which was just the bare credentials with no
        // directory_url recorded at all; there's no way to know what
        // environment *that* one was for, so the safest thing is to
        // treat it the same as a mismatch and register cleanly against
        // whatever's configured now.
        if let Ok(stored) = serde_json::from_slice::<StoredAccount>(&existing) {
            if stored.directory_url == acme_cfg.directory_url {
                return Account::builder()
                .map_err(|e| format!("failed to build ACME account client: {e}"))?
                .from_credentials(stored.credentials)
                .await
                .map_err(|e| format!("failed to restore ACME account: {e}"));
            }
            info!(
                "ACME: stored account was registered against {} but {} is now configured — registering a new account instead of reusing an account from a different ACME environment",
                stored.directory_url, acme_cfg.directory_url
            );
        }
    }

    let contact: Vec<String> = acme_cfg
    .contact_email
    .as_ref()
    .map(|e| vec![format!("mailto:{e}")])
    .unwrap_or_default();
    let contact_refs: Vec<&str> = contact.iter().map(String::as_str).collect();

    let (account, credentials) = Account::builder()
    .map_err(|e| format!("failed to build ACME account client: {e}"))?
    .create(
        &NewAccount {
            contact: &contact_refs,
            terms_of_service_agreed: true,
            only_return_existing: false,
        },
        acme_cfg.directory_url.clone(),
            None,
    )
    .await
    .map_err(|e| format!("failed to register ACME account: {e}"))?;

    let stored = StoredAccount {
        directory_url: acme_cfg.directory_url.clone(),
        credentials,
    };
    let serialized = serde_json::to_vec_pretty(&stored)
    .map_err(|e| format!("failed to serialize new ACME account credentials: {e}"))?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
        .map_err(|e| format!("failed to create {}: {e}", parent.display()))?;
    }
    write_atomically(path, &serialized)
    .map_err(|e| format!("failed to persist ACME account credentials: {e}"))?;

    // 0600 — this is effectively a bearer credential for the ACME
    // account (whoever holds it can request certificates under it).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }

    info!(
        "ACME: registered a new account against {}, credentials saved to {}",
        acme_cfg.directory_url,
        path.display()
    );

    Ok(account)
}

/// Writes `contents` to `path` via a temp file + rename in the same
/// directory, rather than truncating the destination in place — so
/// `tls::watch_cert_key`'s filesystem watcher (and anything else that
/// might read the file mid-write) only ever observes either the
/// complete old content or the complete new content, never a
/// partially-written file.
fn write_atomically(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(dir)?;
    let tmp_path = dir.join(format!(
        ".{}.tmp",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("acme")
    ));
    std::fs::write(&tmp_path, contents)?;
    std::fs::rename(&tmp_path, path)
}

/// Ensures the published HTTP-01 challenge response for `(vhost,
/// token)` is always removed, on every exit path — including an early
/// `?` return partway through `renew_certificate` — not just the
/// success path. `token` starts `None` (nothing published yet) and is
/// filled in the moment something actually gets published; the `Drop`
/// impl is a no-op until then.
struct ChallengeCleanupGuard {
    names: Vec<String>,
    /// One token per authorization — a multi-name order has several,
    /// and every one of them must be cleaned up. This was a single
    /// `Option<String>` that each loop iteration overwrote, so on a
    /// multi-name order only the last token was ever removed and the
    /// earlier challenge responses stayed published indefinitely.
    tokens: Vec<String>,
}

impl Drop for ChallengeCleanupGuard {
    fn drop(&mut self) {
        for token in &self.tokens {
            for name in &self.names {
                challenge::remove(name, token);
            }
        }
    }
}
