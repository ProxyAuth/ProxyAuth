use base64::{Engine as _, engine::general_purpose};

use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};

use hkdf::Hkdf;
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::Sha256;

/// Key length for the password-based helpers below.
const KEY_LEN: usize = 32;

/// Format tag for `encrypt_base64` output. Distinct from any token tag:
/// these two formats must never be mistaken for one another.
pub const TAG_V1_PW: u8 = 0xE1;

/// HKDF context string for the password-based helpers. Domain-separated
/// from anything else so the same password can never yield the same key
/// in two different places.
const HKDF_INFO_PW: &[u8] = b"encrypt_base64.password.v1";

// Token key derivation, sealing, the BLAKE3 signature and the optional
// obfuscation pass all moved to the `zerocrypt` crate — see
// `crate::token::vault`. What is left here is the standalone
// password-based helper pair below, which is unrelated to session
// tokens and has no equivalent in the library.

#[allow(dead_code)]
pub fn encrypt_base64(message: &str, password: &str) -> String {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);

    let hk = Hkdf::<Sha256>::new(Some(&salt), password.as_bytes());
    let mut key_bytes = [0u8; KEY_LEN];
    hk.expand(HKDF_INFO_PW, &mut key_bytes)
        .expect("HKDF expand");

    let key = Key::try_from(&key_bytes[..]).expect("invalid key");
    let cipher = XChaCha20Poly1305::new(&key);

    let mut nonce_bytes = [0u8; 24];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::try_from(&nonce_bytes[..]).unwrap();

    let ct = cipher.encrypt(&nonce, message.as_bytes()).expect("encrypt");

    let mut out = Vec::with_capacity(1 + 16 + 24 + ct.len());
    out.push(TAG_V1_PW);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);

    general_purpose::STANDARD.encode(out)
}

#[allow(dead_code)]
pub fn decrypt_base64(encoded: &str, password: &str) -> String {
    let data = general_purpose::STANDARD
        .decode(encoded.as_bytes())
        .expect("Invalid base64");

    if data.len() < 1 + 16 + 24 || data[0] != TAG_V1_PW {
        panic!("Invalid ciphertext format");
    }

    let salt = &data[1..17];
    let nonce = XNonce::try_from(&data[17..41]).expect("bad nonce");
    let ct = &data[41..];

    let hk = Hkdf::<Sha256>::new(Some(salt), password.as_bytes());
    let mut key_bytes = [0u8; KEY_LEN];
    hk.expand(HKDF_INFO_PW, &mut key_bytes)
        .expect("HKDF expand");

    let key = Key::try_from(&key_bytes[..]).expect("invalid key");
    let cipher = XChaCha20Poly1305::new(&key);

    let pt = cipher
        .decrypt(&nonce, ct)
        .expect("decryption/authentication failed");

    String::from_utf8(pt).expect("Invalid UTF-8")
}
