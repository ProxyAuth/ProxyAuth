//! What is left of ProxyAuth's own token crypto.
//!
//! Key derivation, sealing, the signature, the obfuscation pass and the
//! keystream all moved to the `zerocrypt` crate and are tested there —
//! including the cases this file used to cover (determinism of the
//! keystream, the shape of `process_string`'s output, the chunking, a
//! round trip through the AEAD, rejection of a bad tag or a wrong key).
//! Re-testing them here would only duplicate that suite.
//!
//! What remains in this module is the password-based helper pair, which
//! has nothing to do with session tokens and no equivalent in the
//! library.

use proxyauth::token::crypto::decrypt_base64;
use proxyauth::token::crypto::encrypt_base64;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_base64_decrypt_base64_roundtrip() {
        let msg = "some message with unicode: éàü 🙂";
        let enc = encrypt_base64(msg, "correct horse battery staple");
        assert_eq!(decrypt_base64(&enc, "correct horse battery staple"), msg);
    }

    #[test]
    fn ciphertexts_are_not_deterministic() {
        // A fresh salt and nonce each time: encrypting the same message
        // twice must not produce the same string, or an observer could
        // tell that two stored values are equal without decrypting them.
        let a = encrypt_base64("same message", "same password");
        let b = encrypt_base64("same message", "same password");
        assert_ne!(a, b);
    }

    #[test]
    fn output_is_base64() {
        let enc = encrypt_base64("hello", "password");
        assert!(
            enc.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='),
            "unexpected characters in {enc}"
        );
    }

    #[test]
    #[should_panic]
    fn decrypt_base64_panics_on_wrong_password() {
        let enc = encrypt_base64("secret", "right password");
        let _ = decrypt_base64(&enc, "wrong password");
    }

    #[test]
    #[should_panic]
    fn decrypt_base64_panics_on_garbage() {
        let _ = decrypt_base64("not base64 at all!!", "password");
    }
}
