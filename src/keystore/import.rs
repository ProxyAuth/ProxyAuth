use crate::config::config::load_config;
use openpgp::{
    Cert, KeyID, Result,
    crypto::{KeyPair, Password, SessionKey},
    packet::{PKESK, SKESK},
    parse::Parse,
    parse::stream::{DecryptionHelper, DecryptorBuilder, MessageStructure, VerificationHelper},
    policy::{Policy, StandardPolicy},
    types::SymmetricAlgorithm,
};
use sequoia_openpgp as openpgp;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Default location of config.json, used to load the passphrase that
/// protects the secret key material in key.asc.
const DEFAULT_CONFIG_PATH: &str = "/etc/proxyauth/config/config.json";

/// Resolves the config.json path to use: the PROXYAUTH_CONFIG_PATH
/// environment variable if set (mainly useful for tests, so they can
/// point at a temporary config without requiring access to
/// /etc/proxyauth), otherwise DEFAULT_CONFIG_PATH.
fn resolve_config_path() -> String {
    std::env::var("PROXYAUTH_CONFIG_PATH").unwrap_or_else(|_| DEFAULT_CONFIG_PATH.to_string())
}

/// Reads `key.asc` and `data.pgp` from `import_dir` (or the default
/// `/etc/proxyauth/import` directory), decrypts the payload using the
/// certificate's secret key, and returns the decrypted text.
///
/// The passphrase protecting the secret key material in `key.asc` is
/// loaded from the path returned by `resolve_config_path()`.
pub fn decrypt_keystore(import_dir_opt: Option<&Path>) -> Result<Option<String>> {
    let import_dir: PathBuf = match import_dir_opt {
        Some(p) => p.to_path_buf(),
        None => PathBuf::from("/etc/proxyauth/import"),
    };

    let key_path = import_dir.join("key.asc");
    let data_path = import_dir.join("data.pgp");

    if !key_path.exists() || !data_path.exists() {
        return Ok(None);
    }

    // The AppConfig secret is used as the passphrase that decrypts
    // the secret key material stored in key.asc.
    let app_config = load_config(&resolve_config_path());
    let password = Password::from(app_config.secret.as_str());

    let cert = Cert::from_reader(BufReader::new(File::open(&key_path)?))?;
    let mut file = File::open(&data_path)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;

    let policy = &StandardPolicy::new();
    let helper = Helper::new(policy, vec![cert.clone()], password)?;

    let mut decryptor = DecryptorBuilder::from_bytes(&data)?.with_policy(policy, None, helper)?;

    let mut output = Vec::new();
    std::io::copy(&mut decryptor, &mut output)?;

    let text = String::from_utf8(output)?;
    Ok(Some(text))
}

/// Helper implementing the decryption/verification callbacks required
/// by sequoia's streaming decryptor. Holds a keypair per key ID so
/// PKESK packets can be matched to the right secret key.
struct Helper<'a> {
    keys: HashMap<KeyID, (Arc<Cert>, KeyPair)>,
    #[allow(dead_code)]
    policy: &'a dyn Policy,
}

impl<'a> Helper<'a> {
    /// Builds the helper, unlocking every transport-encryption capable
    /// secret key found in `certs` using `password`.
    ///
    /// Keys that are already unencrypted are used as-is; keys that are
    /// password-protected are decrypted with `password` before being
    /// turned into a usable keypair. Keys with no secret material at
    /// all are skipped.
    pub fn new(policy: &'a dyn Policy, certs: Vec<Cert>, password: Password) -> Result<Self> {
        let mut keys = HashMap::new();
        for cert in certs {
            let cert = Arc::new(cert);
            for ka in cert
                .keys()
                .with_policy(policy, None)
                .supported()
                .for_transport_encryption()
            {
                // Cert only ever exposes PublicParts keys, so we
                // explicitly opt in to treating this as a secret key.
                let secret_key = match ka.key().clone().parts_into_secret() {
                    Ok(k) => k,
                    Err(_) => continue, // no secret material for this key, skip it
                };

                let pair = if secret_key.has_unencrypted_secret() {
                    secret_key.into_keypair()
                } else {
                    secret_key
                        .decrypt_secret(&password)
                        .and_then(|k| k.into_keypair())
                };

                if let Ok(pair) = pair {
                    keys.insert(ka.key().keyid(), (cert.clone(), pair));
                }
            }
        }
        Ok(Self { keys, policy })
    }
}

impl<'a> DecryptionHelper for Helper<'a> {
    fn decrypt(
        &mut self,
        pkesks: &[PKESK],
        _skesks: &[SKESK],
        sym_algo: Option<SymmetricAlgorithm>,
        decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &SessionKey) -> bool,
    ) -> Result<Option<Cert>> {
        let mut recipient: Option<Cert> = None;

        for pkesk in pkesks {
            if let Some((cert, pair)) = self.keys.get_mut(&KeyID::from(pkesk.recipient())) {
                let mut keypair = pair.clone();

                if let Some((algo, session_key)) = pkesk.decrypt(&mut keypair, sym_algo) {
                    if decrypt(algo, &session_key) {
                        recipient = Some(cert.as_ref().clone());
                        break;
                    }
                }
            }
        }

        Ok(recipient)
    }
}

impl<'a> VerificationHelper for Helper<'a> {
    fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> Result<Vec<Cert>> {
        Ok(Vec::new())
    }

    fn check(&mut self, _structure: MessageStructure) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::Mutex;
    use std::{fs, io::Write};

    // Serializes tests that mutate PROXYAUTH_CONFIG_PATH, since env
    // vars are process-global and cargo test runs tests concurrently.
    static CONFIG_ENV_LOCK: Mutex<()> = Mutex::new(());

    fn mk_tmpdir(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("proxyauth-import-{}-{}", std::process::id(), tag));
        if p.exists() {
            let _ = fs::remove_dir_all(&p);
        }
        fs::create_dir_all(&p).expect("create tmpdir");
        p
    }

    // Helper to write a minimal config.json with a fixed secret,
    // used as the passphrase in these tests.
    fn mk_test_config(dir: &Path) -> PathBuf {
        let config_path = dir.join("config.json");
        let config_json = r#"{
        "token_expiry_seconds": 3600,
        "secret": "test-secret-passphrase",
        "users": [],
        "log": {}
    }"#;
        fs::write(&config_path, config_json).expect("write test config");
        config_path
    }

    // --- key-dependent cases -------------------------------

    #[test]
    fn returns_none_if_directory_missing() {
        let mut dir = std::env::temp_dir();
        dir.push(format!("proxyauth-import-missing-{}", std::process::id()));

        let got = decrypt_keystore(Some(&dir)).expect("should not error");
        assert!(got.is_none());
    }

    #[test]
    fn returns_none_if_one_of_files_is_missing() {
        let d1 = mk_tmpdir("only-key");
        fs::write(d1.join("key.asc"), b"not a real key").unwrap();
        let got1 = decrypt_keystore(Some(&d1)).expect("should not error");
        assert!(got1.is_none());

        let d2 = mk_tmpdir("only-data");
        fs::write(d2.join("data.pgp"), b"not pgp data").unwrap();
        let got2 = decrypt_keystore(Some(&d2)).expect("should not error");
        assert!(got2.is_none());
    }

    #[test]
    fn returns_error_with_invalid_files() {
        // Both key.asc and data.pgp exist here, so decrypt_keystore
        // will reach the config-loading code path. Point it at a
        // temp config instead of /etc/proxyauth/config/config.json.
        let _guard = CONFIG_ENV_LOCK.lock().unwrap();
        let cfg_dir = mk_tmpdir("cfg-for-invalid");
        let config_path = mk_test_config(&cfg_dir);
        unsafe {
            std::env::set_var("PROXYAUTH_CONFIG_PATH", config_path.to_str().unwrap());
        }

        let d = mk_tmpdir("invalid-both");
        fs::write(d.join("key.asc"), b"--- invalid openpgp key ---").unwrap();
        fs::write(d.join("data.pgp"), b"--- invalid pgp ciphertext ---").unwrap();

        let res = decrypt_keystore(Some(&d));
        unsafe {
            std::env::remove_var("PROXYAUTH_CONFIG_PATH");
        }
        assert!(res.is_err(), "Expected error when both files are invalid");
    }

    // --- default path (None) -----------------

    #[test]
    fn passing_none_uses_default_path_and_returns_none_when_missing() {
        // NOTE: this assumes /etc/proxyauth/import does not exist in
        // the test environment. Adjust or skip if that assumption
        // doesn't hold on CI.
        let res = decrypt_keystore(None);
        if let Ok(got) = res {
            assert!(got.is_none());
        }
    }

    // --- empty cert cases ----------------

    #[test]
    fn helper_new_with_empty_certs_yields_empty_keymap() {
        let policy = StandardPolicy::new();
        let password = Password::from("unused-password");
        let h =
            Helper::new(&policy, vec![], password).expect("helper construction should not fail");

        let mut h2 = h;
        let pkesks: &[PKESK] = &[];
        let skesks: &[SKESK] = &[];
        let mut called = false;
        let mut dec = |algo: Option<SymmetricAlgorithm>, _sk: &SessionKey| {
            called = true;
            algo.is_some()
        };
        let out = DecryptionHelper::decrypt(&mut h2, pkesks, skesks, None, &mut dec)
            .expect("decrypt with empty pkesks should not fail");
        assert!(out.is_none(), "no recipient should be found");
        assert!(
            !called,
            "decrypt closure must not be called with empty pkesks"
        );
    }

    #[test]
    fn verification_helper_get_certs_returns_empty() {
        let policy = StandardPolicy::new();
        let password = Password::from("unused-password");
        let mut h =
            Helper::new(&policy, vec![], password).expect("helper construction should not fail");
        let got = VerificationHelper::get_certs(&mut h, &[]).expect("get_certs should not fail");
        assert!(got.is_empty());
    }

    #[test]
    fn tries_to_parse_when_both_files_exist() {
        // Both key.asc and data.pgp exist here, so decrypt_keystore
        // will reach the config-loading code path.
        let _guard = CONFIG_ENV_LOCK.lock().unwrap();
        let cfg_dir = mk_tmpdir("cfg-for-parse-attempt");
        let config_path = mk_test_config(&cfg_dir);
        unsafe {
            std::env::set_var("PROXYAUTH_CONFIG_PATH", config_path.to_str().unwrap());
        }

        let d = mk_tmpdir("exists-both-but-invalid");
        {
            let mut f = File::create(d.join("key.asc")).unwrap();
            f.write_all(b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n...")
                .unwrap();
        }
        {
            let mut f = File::create(d.join("data.pgp")).unwrap();
            f.write_all(b"\x99\x01\x02\x03notreallypgp").unwrap();
        }

        let res = decrypt_keystore(Some(&d));
        unsafe {
            std::env::remove_var("PROXYAUTH_CONFIG_PATH");
        }
        assert!(res.is_err(), "Parsing should fail with bogus contents");
    }
}
