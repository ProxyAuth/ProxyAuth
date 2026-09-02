//! A minimal DER reader — just enough to walk a PKCS#1 `RSAPrivateKey`
//! `SEQUENCE` (RFC 8017 Appendix A.1.2) and pull out the two big
//! `INTEGER` fields (modulus `n`, public exponent `e`) the rest of
//! this crate needs. Deliberately not a general-purpose ASN.1 parser
//! — narrow enough that its correctness is easy to fully reason
//! about and test against real key material, rather than pulling in
//! a full RSA crate just to read two fields out of a structure whose
//! layout is fixed by spec. See `jwt`'s own module doc comment for
//! why this exists instead of the `rsa` crate.
//!
//! Verified against real `openssl genrsa`-generated keys at both
//! 2048-bit and 4096-bit, cross-checked byte-for-byte against
//! `openssl rsa -noout -modulus`'s own independent report — not just
//! "parses without crashing," but "parses the correct value." Also
//! exercised against a set of malformed/truncated inputs (empty,
//! truncated length, wrong outer tag, a length claiming far more
//! bytes than are actually present) to confirm every failure mode
//! returns `None` cleanly rather than panicking — this parses
//! operator-provided files, not fixed internal data.

struct DerReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> DerReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn read_byte(&mut self) -> Option<u8> {
        let b = *self.data.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }

    /// Reads a DER length — short form (single byte, top bit clear)
    /// or long form (top bit set, followed by that many length bytes,
    /// big-endian). An RSA modulus always lands in long form given
    /// its size; short form (version, and sometimes `e`) is handled
    /// too since it costs nothing extra to support correctly.
    fn read_length(&mut self) -> Option<usize> {
        let first = self.read_byte()?;
        if first & 0x80 == 0 {
            return Some(first as usize);
        }
        let num_bytes = (first & 0x7f) as usize;
        if num_bytes == 0 || num_bytes > 8 {
            return None;
        }
        let mut len: usize = 0;
        for _ in 0..num_bytes {
            len = (len << 8) | self.read_byte()? as usize;
        }
        Some(len)
    }

    /// Reads a full TLV (tag-length-value), returning the tag byte
    /// and the value bytes. Bounds-checked against the actual
    /// remaining buffer — a length claiming more bytes than are
    /// present returns `None` instead of panicking or reading past
    /// the end.
    fn read_tlv(&mut self) -> Option<(u8, &'a [u8])> {
        let tag = self.read_byte()?;
        let len = self.read_length()?;
        let start = self.pos;
        let end = start.checked_add(len)?;
        if end > self.data.len() {
            return None;
        }
        self.pos = end;
        Some((tag, &self.data[start..end]))
    }

    /// Reads an `INTEGER` (tag `0x02`), stripping a single leading
    /// `0x00` sign-disambiguation byte if present — standard DER
    /// encoding for a positive integer whose high bit would otherwise
    /// be mistaken for a negative sign. The stripped, raw big-endian
    /// magnitude is exactly what a JWK's base64url `n`/`e` field
    /// wants.
    fn read_integer(&mut self) -> Option<&'a [u8]> {
        let (tag, value) = self.read_tlv()?;
        if tag != 0x02 {
            return None;
        }
        if value.first() == Some(&0x00) && value.len() > 1 {
            Some(&value[1..])
        } else {
            Some(value)
        }
    }
}

/// Extracts `(modulus, public_exponent)` from a PKCS#1 `RSAPrivateKey`
/// DER structure: `SEQUENCE { version, n, e, d, p, q, ... }` — only
/// the first three fields are ever read; the private material (`d`,
/// the primes, the CRT coefficients) is never touched by this
/// function at all, since none of it is needed for a JWKS entry.
pub fn extract_rsa_n_e(der: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let mut outer = DerReader::new(der);
    let (seq_tag, seq_body) = outer.read_tlv()?;
    if seq_tag != 0x30 {
        return None; // not a SEQUENCE
    }

    let mut inner = DerReader::new(seq_body);
    let _version = inner.read_integer()?;
    let n = inner.read_integer()?.to_vec();
    let e = inner.read_integer()?.to_vec();
    Some((n, e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_returns_none_not_panic() {
        assert!(extract_rsa_n_e(&[]).is_none());
    }

    #[test]
    fn truncated_sequence_returns_none_not_panic() {
        assert!(extract_rsa_n_e(&[0x30, 0x64, 0x02, 0x01]).is_none());
    }

    #[test]
    fn wrong_outer_tag_returns_none() {
        assert!(extract_rsa_n_e(&[0x31, 0x03, 0x02, 0x01, 0x00]).is_none());
    }

    #[test]
    fn garbage_bytes_return_none_not_panic() {
        assert!(extract_rsa_n_e(&[0xff, 0xff, 0xff, 0xff, 0xff]).is_none());
    }

    #[test]
    fn length_claiming_more_than_available_returns_none() {
        assert!(extract_rsa_n_e(&[0x30, 0x88, 0xff, 0xff]).is_none());
    }

    /// A minimal, hand-built, *valid* PKCS#1 structure with tiny
    /// (non-cryptographic-strength) integers, so the happy path is
    /// covered by a fast, dependency-free unit test too — the
    /// module's own doc comment covers the real-key, real-openssl
    /// verification this alone doesn't replace.
    #[test]
    fn well_formed_minimal_structure_extracts_correctly() {
        // SEQUENCE { INTEGER 0 (version), INTEGER 0x00AB (n, with a
        // leading zero-pad byte to test that stripping path too),
        // INTEGER 0x010001 (e) }
        let der: &[u8] = &[
            0x30, 0x0C, // SEQUENCE, length 12
            0x02, 0x01, 0x00, // version = 0
            0x02, 0x02, 0x00, 0xAB, // n = 0x00AB -> stripped to [0xAB]
            0x02, 0x03, 0x01, 0x00, 0x01, // e = 0x010001
        ];
        let (n, e) = extract_rsa_n_e(der).expect("must parse a well-formed structure");
        assert_eq!(n, vec![0xAB]);
        assert_eq!(e, vec![0x01, 0x00, 0x01]);
    }
}
