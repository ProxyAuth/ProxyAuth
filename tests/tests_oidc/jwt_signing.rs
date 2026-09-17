//! The build can actually sign an `id_token`.
//!
//! `jsonwebtoken` 11 resolves its crypto provider lazily and panics when
//! the crate was compiled without one. This test performs a real RS256
//! signing and verification so a build without a working provider fails
//! during the test suite instead of at runtime.
//!
//! The RSA key is generated only for this test using OpenSSL. Nothing from
//! the application is modified and no additional `rsa`/`rand` dependency
//! is required.

#[cfg(test)]
mod tests {
    use jsonwebtoken::{
        decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation,
    };
    use openssl::rsa::Rsa;
    use std::collections::BTreeMap;

    #[test]
    fn this_build_can_sign_and_verify_rs256() {
        // Generate a throwaway RSA key exclusively for this test.
        //
        // Using OpenSSL here avoids introducing another `rand`/`rand_core`
        // dependency into the test suite. The application already has
        // OpenSSL available.
        let rsa = Rsa::generate(2048).expect("generate RSA test key");

        let private_der = rsa
        .private_key_to_der()
        .expect("encode RSA private key as DER");

        let public_der = rsa
        .public_key_to_der()
        .expect("encode RSA public key as DER");

        let encoding_key =
        EncodingKey::from_rsa_der(&private_der);

        let mut claims = BTreeMap::new();
        claims.insert("sub", "alice");
        claims.insert("iss", "https://oidc.example.com");

        let header = Header::new(Algorithm::RS256);

        let token = encode(&header, &claims, &encoding_key)
        .expect("signing an id_token");

        assert_eq!(
            token.matches('.').count(),
                   2,
                   "a JWT must contain three parts"
        );

        let decoding_key =
        DecodingKey::from_rsa_der(&public_der);

        let mut validation = Validation::new(Algorithm::RS256);

        // The test claims intentionally don't contain `exp`.
        validation.validate_exp = false;

        // We are testing the cryptographic signing/verification itself,
        // not the presence of the standard JWT claims.
        validation.required_spec_claims.clear();

        let decoded =
        decode::<BTreeMap<String, String>>(
            &token,
            &decoding_key,
            &validation,
        )
        .expect("the RS256 signature verifies");

        assert_eq!(
            decoded.claims.get("sub"),
                   Some(&"alice".to_string())
        );

        assert_eq!(
            decoded.claims.get("iss"),
                   Some(&"https://oidc.example.com".to_string())
        );
    }
}
