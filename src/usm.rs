//! SNMPv3 USM (User-based Security Model) crypto primitives.
//!
//! - Auth: HMAC-SHA-{1,224,256,384,512} per RFC 7860. HMAC-MD5 is rejected
//!   at CLI parse time and never reaches this module.
//! - Priv: AES-{128,192,256}-CFB per RFC 3826 + Cisco extensions. DES-CBC
//!   and 3DES-CBC are rejected at CLI parse time.
//! - Password localization: RFC 3414 §A.2 extended for SHA-2 per RFC 7860 §3.4.

// cipher 0.5 (used by aes 0.9 / cfb-mode 0.9) made `encrypt`/`decrypt`
// inherent methods on `cfb_mode::Encryptor`/`Decryptor` rather than trait
// methods on `AsyncStreamCipher`, so only `KeyIvInit` is needed for the
// constructor. hmac 0.13 split `new_from_slice` off the `Mac` trait onto
// `KeyInit`; the `Mac` trait is still used for `update` and `finalize`.
use aes::cipher::KeyIvInit;
use hmac::{Hmac, KeyInit, Mac};
use sha1::{Digest as _, Sha1};
use sha2::{Sha224, Sha256, Sha384, Sha512};

use crate::engine::EngineId;
use crate::error::Error;

/// USM auth protocols. HMAC-MD5 is intentionally absent (rejected at parse time).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthProtocol {
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

impl AuthProtocol {
    /// Length of the underlying digest, in bytes. Doubles as the localized-key length.
    pub fn digest_len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha224 => 28,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    /// RFC 7860 §4.2.2 truncated authParameters lengths (in bytes).
    pub fn auth_param_len(self) -> usize {
        match self {
            Self::Sha1 => 12,
            Self::Sha224 => 16,
            Self::Sha256 => 24,
            Self::Sha384 => 32,
            Self::Sha512 => 48,
        }
    }
}

impl std::str::FromStr for AuthProtocol {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Net-SNMP accepts these names case-insensitively. Normalize first;
        // the deprecation hint for MD5 must trigger regardless of input case.
        match s.to_ascii_uppercase().as_str() {
            "SHA" | "SHA-1" | "SHA1" => Ok(Self::Sha1),
            "SHA-224" | "SHA224" => Ok(Self::Sha224),
            "SHA-256" | "SHA256" => Ok(Self::Sha256),
            "SHA-384" | "SHA384" => Ok(Self::Sha384),
            "SHA-512" | "SHA512" => Ok(Self::Sha512),
            "MD5" | "HMAC-MD5" => Err(Error::Usage(
                "HMAC-MD5 (RFC 3414 default) is not supported by this build; \
                 use SHA, SHA-224, SHA-256, SHA-384, or SHA-512 (RFC 7860)."
                    .into(),
            )),
            _ => Err(Error::Usage(format!(
                "unknown auth protocol '{s}'; supported: SHA, SHA-224, SHA-256, SHA-384, SHA-512"
            ))),
        }
    }
}

/// USM priv protocols. DES-CBC and 3DES-CBC are intentionally absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivProtocol {
    Aes128,
    Aes192,
    Aes256,
}

impl PrivProtocol {
    pub fn key_len(self) -> usize {
        match self {
            Self::Aes128 => 16,
            Self::Aes192 => 24,
            Self::Aes256 => 32,
        }
    }
}

impl std::fmt::Display for AuthProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Sha1 => "SHA-1",
            Self::Sha224 => "SHA-224",
            Self::Sha256 => "SHA-256",
            Self::Sha384 => "SHA-384",
            Self::Sha512 => "SHA-512",
        })
    }
}

impl std::fmt::Display for PrivProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Aes128 => "AES-128",
            Self::Aes192 => "AES-192",
            Self::Aes256 => "AES-256",
        })
    }
}

impl std::str::FromStr for PrivProtocol {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Net-SNMP accepts these names case-insensitively. The deprecation
        // hints for DES/3DES must trigger regardless of input case.
        match s.to_ascii_uppercase().as_str() {
            "AES" | "AES-128" | "AES128" => Ok(Self::Aes128),
            "AES-192" | "AES192" => Ok(Self::Aes192),
            "AES-256" | "AES256" => Ok(Self::Aes256),
            "DES" | "DES-CBC" => Err(Error::Usage(
                "DES-CBC (RFC 3414 default) is not supported by this build; \
                 use AES, AES-192, or AES-256."
                    .into(),
            )),
            "3DES" | "3DES-CBC" | "TDES" => Err(Error::Usage(
                "3DES-CBC is not supported by this build; use AES-256.".into(),
            )),
            _ => Err(Error::Usage(format!(
                "unknown priv protocol '{s}'; supported: AES, AES-192, AES-256"
            ))),
        }
    }
}

/// RFC 3414 §11.2 mandates USM passwords be at least 8 octets.
pub const MIN_USM_PASSWORD_LEN: usize = 8;

/// Localize a password to a key per RFC 3414 §A.2 (extended for the SHA-2
/// family per RFC 7860 §3.4).
///
/// Returns a `Usage` error if the password is shorter than 8 octets — RFC
/// 3414 §11.2 mandates that floor and Net-SNMP enforces it. Empty / 1-char
/// passwords would otherwise produce a deterministic, attacker-known
/// localized key derived purely from the engine-ID.
///
/// Algorithm:
///   1. Form a 1 MiB byte string by repeating the password.
///   2. Hash the 1 MiB string. Result = "intermediate digest" (length =
///      `proto.digest_len()`).
///   3. Localize: hash(digest || engine_id || digest). Result = the
///      localized key. Length matches `proto.digest_len()`.
pub fn password_to_key(
    password: &str,
    engine_id: &EngineId,
    proto: AuthProtocol,
) -> Result<Vec<u8>, Error> {
    if password.len() < MIN_USM_PASSWORD_LEN {
        return Err(Error::Usage(format!(
            "USM password must be at least {MIN_USM_PASSWORD_LEN} characters (RFC 3414 §11.2); got {}",
            password.len()
        )));
    }
    let intermediate = password_intermediate_digest(password, proto);
    let mut localizer = Vec::with_capacity(intermediate.len() * 2 + engine_id.len());
    localizer.extend_from_slice(&intermediate);
    localizer.extend_from_slice(engine_id.as_bytes());
    localizer.extend_from_slice(&intermediate);
    Ok(hash(&localizer, proto))
}

/// Derive a priv key from a priv password, then truncate to the AES variant's
/// required key length. The auth protocol's hash function is used for the KDF
/// (per RFC 3826 §3.1.2.1).
///
/// Returns a `Usage` error if the auth protocol's digest is shorter than the
/// requested AES key length — Cisco's key-extension algorithm for that case
/// is intentionally not implemented in this version.
pub fn priv_key_from_password(
    password: &str,
    engine_id: &EngineId,
    auth_proto: AuthProtocol,
    priv_proto: PrivProtocol,
) -> Result<Vec<u8>, Error> {
    let key = password_to_key(password, engine_id, auth_proto)?;
    let need = priv_proto.key_len();
    if key.len() < need {
        return Err(Error::Usage(format!(
            "auth protocol {auth_proto} produces a {}-byte localized key, but priv protocol \
             {priv_proto} requires {need} bytes. Use SHA-224 or higher with AES-192, or \
             SHA-256 or higher with AES-256.",
            key.len(),
        )));
    }
    Ok(key[..need].to_vec())
}

/// Compute the truncated HMAC tag for the SNMPv3 `authenticationParameters`
/// field per RFC 7860 §4.2.2. The caller supplies the entire serialized
/// message with `authenticationParameters` set to a placeholder of the
/// expected length; the returned tag replaces that placeholder.
///
/// RFC 7860 expects `auth_key` to be exactly `proto.digest_len()` bytes long
/// (the localized-key length). HMAC mathematically accepts any key length,
/// but a wrong-sized key produces a syntactically valid but semantically
/// wrong tag — caught here with an `assert_eq!` rather than allowed to
/// silently drift past testing.
pub fn auth_sign(message: &[u8], auth_key: &[u8], proto: AuthProtocol) -> Vec<u8> {
    assert_eq!(
        auth_key.len(),
        proto.digest_len(),
        "auth_key must be exactly {} bytes for {} (got {})",
        proto.digest_len(),
        proto,
        auth_key.len()
    );
    let full = match proto {
        AuthProtocol::Sha1 => {
            let mut mac = <Hmac<Sha1> as KeyInit>::new_from_slice(auth_key)
                .expect("HMAC accepts any key length");
            mac.update(message);
            mac.finalize().into_bytes().to_vec()
        }
        AuthProtocol::Sha224 => {
            let mut mac = <Hmac<Sha224> as KeyInit>::new_from_slice(auth_key)
                .expect("HMAC accepts any key length");
            mac.update(message);
            mac.finalize().into_bytes().to_vec()
        }
        AuthProtocol::Sha256 => {
            let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(auth_key)
                .expect("HMAC accepts any key length");
            mac.update(message);
            mac.finalize().into_bytes().to_vec()
        }
        AuthProtocol::Sha384 => {
            let mut mac = <Hmac<Sha384> as KeyInit>::new_from_slice(auth_key)
                .expect("HMAC accepts any key length");
            mac.update(message);
            mac.finalize().into_bytes().to_vec()
        }
        AuthProtocol::Sha512 => {
            let mut mac = <Hmac<Sha512> as KeyInit>::new_from_slice(auth_key)
                .expect("HMAC accepts any key length");
            mac.update(message);
            mac.finalize().into_bytes().to_vec()
        }
    };
    full[..proto.auth_param_len()].to_vec()
}

/// Encrypt the scopedPDU per RFC 3826. The 16-byte AES-CFB-128 IV is
/// constructed as `engineBoots(4 BE) || engineTime(4 BE) || salt(8 BE)`.
///
/// `priv_key` must be at least `proto.key_len()` bytes long. The function
/// asserts this up-front rather than letting an under-length slice produce
/// an opaque slice-OOB panic later.
pub fn priv_encrypt(
    plaintext: &[u8],
    priv_key: &[u8],
    engine_boots: u32,
    engine_time: u32,
    salt: u64,
    proto: PrivProtocol,
) -> Vec<u8> {
    assert!(
        priv_key.len() >= proto.key_len(),
        "priv_key is {} bytes, but {} requires {}",
        priv_key.len(),
        proto,
        proto.key_len()
    );
    let iv = make_aes_iv(engine_boots, engine_time, salt);
    let key = &priv_key[..proto.key_len()];
    let mut buf = plaintext.to_vec();
    match proto {
        PrivProtocol::Aes128 => {
            cfb_mode::Encryptor::<aes::Aes128>::new_from_slices(key, &iv)
                .expect("AES-128 key length validated by caller")
                .encrypt(&mut buf);
        }
        PrivProtocol::Aes192 => {
            cfb_mode::Encryptor::<aes::Aes192>::new_from_slices(key, &iv)
                .expect("AES-192 key length validated by caller")
                .encrypt(&mut buf);
        }
        PrivProtocol::Aes256 => {
            cfb_mode::Encryptor::<aes::Aes256>::new_from_slices(key, &iv)
                .expect("AES-256 key length validated by caller")
                .encrypt(&mut buf);
        }
    }
    buf
}

/// Generate a fresh 8-byte salt (the `privacyParameters` field) per
/// outbound message. RFC 3826 requires uniqueness within `(engineBoots,
/// engineTime)`; randomness over that window is sufficient.
pub fn fresh_salt() -> u64 {
    rand::random()
}

// ---- internals ----

fn make_aes_iv(engine_boots: u32, engine_time: u32, salt: u64) -> [u8; 16] {
    let mut iv = [0u8; 16];
    iv[0..4].copy_from_slice(&engine_boots.to_be_bytes());
    iv[4..8].copy_from_slice(&engine_time.to_be_bytes());
    iv[8..16].copy_from_slice(&salt.to_be_bytes());
    iv
}

fn password_intermediate_digest(password: &str, proto: AuthProtocol) -> Vec<u8> {
    const TARGET: usize = 1024 * 1024;
    let pw = password.as_bytes();
    if pw.is_empty() {
        return hash(&[], proto);
    }
    match proto {
        AuthProtocol::Sha1 => incremental_digest::<Sha1>(pw, TARGET),
        AuthProtocol::Sha224 => incremental_digest::<Sha224>(pw, TARGET),
        AuthProtocol::Sha256 => incremental_digest::<Sha256>(pw, TARGET),
        AuthProtocol::Sha384 => incremental_digest::<Sha384>(pw, TARGET),
        AuthProtocol::Sha512 => incremental_digest::<Sha512>(pw, TARGET),
    }
}

fn incremental_digest<D: sha1::Digest + Default>(pw: &[u8], target: usize) -> Vec<u8> {
    let mut hasher = D::new();
    let mut written = 0;
    while written < target {
        let take = (target - written).min(pw.len());
        hasher.update(&pw[..take]);
        written += take;
    }
    hasher.finalize().to_vec()
}

fn hash(input: &[u8], proto: AuthProtocol) -> Vec<u8> {
    match proto {
        AuthProtocol::Sha1 => Sha1::digest(input).to_vec(),
        AuthProtocol::Sha224 => Sha224::digest(input).to_vec(),
        AuthProtocol::Sha256 => Sha256::digest(input).to_vec(),
        AuthProtocol::Sha384 => Sha384::digest(input).to_vec(),
        AuthProtocol::Sha512 => Sha512::digest(input).to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: parse a hex string into bytes. Whitespace tolerated.
    fn hex(s: &str) -> Vec<u8> {
        let cleaned: String = s.chars().filter(|c| !c.is_ascii_whitespace()).collect();
        let mut out = Vec::with_capacity(cleaned.len() / 2);
        for chunk in cleaned.as_bytes().chunks_exact(2) {
            let hi = char::from(chunk[0]).to_digit(16).unwrap() as u8;
            let lo = char::from(chunk[1]).to_digit(16).unwrap() as u8;
            out.push((hi << 4) | lo);
        }
        out
    }

    fn rfc3414_engine_id() -> EngineId {
        // RFC 3414 §A.3 test-vector engine-ID: 12 zero-padded bytes ending in 0x02.
        // Constructed via parse_user_input so no PEN-prefix is applied.
        EngineId::parse_user_input("000000000000000000000002").unwrap()
    }

    // ---------- Auth-protocol parsing ----------

    #[test]
    fn auth_proto_parse_accepts_sha_aliases() {
        use std::str::FromStr;
        assert_eq!(AuthProtocol::from_str("SHA").unwrap(), AuthProtocol::Sha1);
        assert_eq!(AuthProtocol::from_str("SHA-1").unwrap(), AuthProtocol::Sha1);
        assert_eq!(
            AuthProtocol::from_str("SHA-256").unwrap(),
            AuthProtocol::Sha256
        );
        assert_eq!(
            AuthProtocol::from_str("SHA512").unwrap(),
            AuthProtocol::Sha512
        );
    }

    #[test]
    fn auth_proto_parse_is_case_insensitive() {
        use std::str::FromStr;
        assert_eq!(AuthProtocol::from_str("sha").unwrap(), AuthProtocol::Sha1);
        assert_eq!(
            AuthProtocol::from_str("Sha-256").unwrap(),
            AuthProtocol::Sha256
        );
        assert_eq!(
            AuthProtocol::from_str("sha512").unwrap(),
            AuthProtocol::Sha512
        );
    }

    #[test]
    fn auth_proto_parse_rejects_md5_with_deprecation_hint() {
        use std::str::FromStr;
        // Both upper- and lower-case variants must trigger the targeted hint,
        // not the generic "unknown auth protocol" arm.
        for input in ["MD5", "md5", "Md5", "HMAC-MD5", "hmac-md5"] {
            let err = AuthProtocol::from_str(input).unwrap_err();
            match err {
                Error::Usage(msg) => {
                    assert!(msg.contains("HMAC-MD5"), "input={input} msg={msg}");
                    assert!(msg.contains("not supported"), "input={input} msg={msg}");
                    assert!(msg.contains("SHA"), "input={input} msg={msg}");
                }
                other => panic!("expected Usage for {input}, got {other:?}"),
            }
        }
    }

    // ---------- Priv-protocol parsing ----------

    #[test]
    fn priv_proto_parse_accepts_aes_aliases() {
        use std::str::FromStr;
        assert_eq!(PrivProtocol::from_str("AES").unwrap(), PrivProtocol::Aes128);
        assert_eq!(
            PrivProtocol::from_str("AES-128").unwrap(),
            PrivProtocol::Aes128
        );
        assert_eq!(
            PrivProtocol::from_str("AES-256").unwrap(),
            PrivProtocol::Aes256
        );
    }

    #[test]
    fn priv_proto_parse_is_case_insensitive() {
        use std::str::FromStr;
        assert_eq!(PrivProtocol::from_str("aes").unwrap(), PrivProtocol::Aes128);
        assert_eq!(
            PrivProtocol::from_str("Aes-256").unwrap(),
            PrivProtocol::Aes256
        );
    }

    #[test]
    fn priv_proto_parse_rejects_des() {
        use std::str::FromStr;
        for input in ["DES", "des", "Des", "DES-CBC", "des-cbc"] {
            let err = PrivProtocol::from_str(input).unwrap_err();
            match err {
                Error::Usage(msg) => {
                    assert!(msg.contains("DES-CBC"), "input={input} msg={msg}");
                    assert!(msg.contains("AES"), "input={input} msg={msg}");
                }
                other => panic!("expected Usage for {input}, got {other:?}"),
            }
        }
    }

    #[test]
    fn priv_proto_parse_rejects_3des() {
        use std::str::FromStr;
        for input in ["3DES", "3des", "3DES-CBC", "tdes", "TDES"] {
            let err = PrivProtocol::from_str(input).unwrap_err();
            match err {
                Error::Usage(msg) => assert!(msg.contains("3DES-CBC"), "input={input} msg={msg}"),
                other => panic!("expected Usage for {input}, got {other:?}"),
            }
        }
    }

    // ---------- Password-to-key (RFC 3414 §A.3) ----------

    /// RFC 3414 §A.3 — the canonical SHA-1 localized-key vector.
    #[test]
    fn password_to_key_sha1_rfc3414_a3() {
        let key = password_to_key("maplesyrup", &rfc3414_engine_id(), AuthProtocol::Sha1).unwrap();
        let expected = hex("6695febc 9288e362 82235fc7 151f1284 97b38f3f");
        assert_eq!(key, expected, "RFC 3414 §A.3 SHA-1 vector mismatch");
    }

    #[test]
    fn password_to_key_lengths_match_digest() {
        // Length-only sanity for the SHA-2 family. Exact-byte vectors for
        // SHA-256 / SHA-512 come from RFC 7860; transcribed in dedicated
        // tests if we ever need exact-match coverage beyond SHA-1.
        let eid = rfc3414_engine_id();
        for proto in [
            AuthProtocol::Sha224,
            AuthProtocol::Sha256,
            AuthProtocol::Sha384,
            AuthProtocol::Sha512,
        ] {
            let key = password_to_key("maplesyrup", &eid, proto).unwrap();
            assert_eq!(
                key.len(),
                proto.digest_len(),
                "key length mismatch for {proto:?}"
            );
        }
    }

    #[test]
    fn password_to_key_rejects_short_passwords() {
        // RFC 3414 §11.2 mandates ≥8 octets; empty / 1-char silently bypassed
        // would otherwise produce a deterministic engine-ID-derived key.
        for short in ["", "a", "1234567"] {
            let err =
                password_to_key(short, &rfc3414_engine_id(), AuthProtocol::Sha256).unwrap_err();
            match err {
                Error::Usage(msg) => {
                    assert!(msg.contains("at least 8"), "short={short:?} msg={msg}");
                    assert!(msg.contains("RFC 3414"), "short={short:?} msg={msg}");
                }
                other => panic!("expected Usage, got {other:?}"),
            }
        }
        // 8 chars is at the floor and SHALL be accepted.
        assert!(password_to_key("12345678", &rfc3414_engine_id(), AuthProtocol::Sha256).is_ok());
    }

    // ---------- Priv-key derivation ----------

    #[test]
    fn priv_key_from_password_sha256_aes128() {
        let eid = rfc3414_engine_id();
        let priv_key =
            priv_key_from_password("privpass", &eid, AuthProtocol::Sha256, PrivProtocol::Aes128)
                .unwrap();
        assert_eq!(priv_key.len(), 16);
    }

    #[test]
    fn priv_key_from_password_sha1_aes192_rejected() {
        let eid = rfc3414_engine_id();
        // SHA-1 → 20-byte digest; AES-192 needs 24. Reject with hint.
        // Password is ≥8 chars so we test the priv-length path, not the
        // password-length path.
        let err =
            priv_key_from_password("passw0rd", &eid, AuthProtocol::Sha1, PrivProtocol::Aes192)
                .unwrap_err();
        match err {
            Error::Usage(msg) => {
                // Display impls produce hyphenated names ("SHA-1", "AES-192"),
                // matching the user's CLI input rather than Rust enum variant
                // Debug format ("Sha1", "Aes192").
                assert!(msg.contains("SHA-1"), "msg: {msg}");
                assert!(msg.contains("AES-192"), "msg: {msg}");
            }
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn priv_key_from_password_sha1_aes256_rejected() {
        let eid = rfc3414_engine_id();
        let err =
            priv_key_from_password("passw0rd", &eid, AuthProtocol::Sha1, PrivProtocol::Aes256)
                .unwrap_err();
        assert!(matches!(err, Error::Usage(_)));
    }

    #[test]
    fn priv_key_from_password_rejects_short_password_first() {
        // Password length floor takes precedence over the auth/priv mismatch.
        let eid = rfc3414_engine_id();
        let err = priv_key_from_password("p", &eid, AuthProtocol::Sha1, PrivProtocol::Aes256)
            .unwrap_err();
        match err {
            Error::Usage(msg) => assert!(msg.contains("at least 8"), "msg: {msg}"),
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn auth_protocol_display() {
        assert_eq!(AuthProtocol::Sha1.to_string(), "SHA-1");
        assert_eq!(AuthProtocol::Sha256.to_string(), "SHA-256");
        assert_eq!(AuthProtocol::Sha512.to_string(), "SHA-512");
    }

    #[test]
    fn priv_protocol_display() {
        assert_eq!(PrivProtocol::Aes128.to_string(), "AES-128");
        assert_eq!(PrivProtocol::Aes192.to_string(), "AES-192");
        assert_eq!(PrivProtocol::Aes256.to_string(), "AES-256");
    }

    #[test]
    #[should_panic(expected = "auth_key must be exactly 32 bytes")]
    fn auth_sign_panics_on_wrong_key_length() {
        // RFC 7860 expects the localized-key length; a wrong-sized key would
        // produce a syntactically valid but semantically wrong tag. The
        // assert catches programmer error before that drift can ship.
        auth_sign(b"x", &[0u8; 16], AuthProtocol::Sha256);
    }

    #[test]
    #[should_panic(expected = "priv_key is 8 bytes")]
    fn priv_encrypt_panics_on_under_length_key() {
        // Defensive: the slice-OOB panic is replaced by an assert with a
        // legible message naming the contract.
        priv_encrypt(b"plain", &[0u8; 8], 1, 1, 0, PrivProtocol::Aes128);
    }

    // ---------- HMAC (RFC 4231 Test Case 1) ----------

    /// RFC 4231 TC1 specifies a 20-byte all-`0x0b` key. Our `auth_sign` asserts
    /// `auth_key.len() == proto.digest_len()` (per RFC 7860's USM contract).
    /// HMAC-internal zero-padding of any key shorter than the hash's block
    /// size means appending zeros to bring the 20-byte test key up to
    /// `digest_len` produces the same tag as the bare 20-byte key — both
    /// expand to the same `K'` after the spec's pad-to-block-size step.
    fn rfc4231_tc1_key_padded(proto: AuthProtocol) -> Vec<u8> {
        let mut key = vec![0x0bu8; 20];
        key.resize(proto.digest_len(), 0x00);
        key
    }

    #[test]
    fn hmac_sha256_rfc4231_tc1() {
        let key = rfc4231_tc1_key_padded(AuthProtocol::Sha256);
        let msg = b"Hi There";
        let tag = auth_sign(msg, &key, AuthProtocol::Sha256);
        // Full HMAC-SHA-256 tag (32 bytes) per RFC 4231 §4.2:
        //   b0344c61 d8db3853 5ca8afce af0bf12b 881dc200 c9833da7 26e9376c 2e32cff7
        // Truncated to 24 bytes for SNMPv3 authParameters per RFC 7860.
        let full = hex("b0344c61 d8db3853 5ca8afce af0bf12b 881dc200 c9833da7 26e9376c 2e32cff7");
        assert_eq!(tag.len(), 24);
        assert_eq!(tag, &full[..24]);
    }

    #[test]
    fn hmac_sha512_rfc4231_tc1() {
        let key = rfc4231_tc1_key_padded(AuthProtocol::Sha512);
        let msg = b"Hi There";
        let tag = auth_sign(msg, &key, AuthProtocol::Sha512);
        // Full HMAC-SHA-512 tag (64 bytes) per RFC 4231 §4.2; truncated to 48.
        let full = hex(
            "87aa7cde a5ef619d 4ff0b424 1a1d6cb0 2379f4e2 ce4ec278 7ad0b305 45e17cde
             daa833b7 d6b8a702 038b274e aea3f4e4 be9d914e eb61f170 2e696c20 3a126854",
        );
        assert_eq!(tag.len(), 48);
        assert_eq!(tag, &full[..48]);
    }

    #[test]
    fn hmac_sha1_truncates_to_12_bytes() {
        // SHA-1 digest_len is 20 — key is exactly that.
        let tag = auth_sign(b"x", &[0u8; 20], AuthProtocol::Sha1);
        assert_eq!(tag.len(), 12);
    }

    // ---------- AES-CFB encryption ----------

    #[test]
    fn priv_encrypt_round_trip_aes128() {
        let key = [0x42u8; 16];
        let plaintext = b"the scoped PDU bytes go here".to_vec();
        let ct = priv_encrypt(
            &plaintext,
            &key,
            1,
            100,
            0xDEADBEEF_CAFEBABE,
            PrivProtocol::Aes128,
        );
        assert_eq!(ct.len(), plaintext.len(), "CFB preserves length");
        assert_ne!(ct, plaintext, "ciphertext should differ from plaintext");

        // Decrypt and verify.
        let iv = make_aes_iv(1, 100, 0xDEADBEEF_CAFEBABE);
        let mut buf = ct.clone();
        cfb_mode::Decryptor::<aes::Aes128>::new_from_slices(&key, &iv)
            .unwrap()
            .decrypt(&mut buf);
        assert_eq!(buf, plaintext);
    }

    #[test]
    fn priv_encrypt_round_trip_aes256() {
        let key = [0x77u8; 32];
        let plaintext = b"another scoped PDU".to_vec();
        let ct = priv_encrypt(
            &plaintext,
            &key,
            7,
            9999,
            0xFFFFEEEE_DDDDCCCC,
            PrivProtocol::Aes256,
        );
        assert_eq!(ct.len(), plaintext.len());
        let iv = make_aes_iv(7, 9999, 0xFFFFEEEE_DDDDCCCC);
        let mut buf = ct.clone();
        cfb_mode::Decryptor::<aes::Aes256>::new_from_slices(&key, &iv)
            .unwrap()
            .decrypt(&mut buf);
        assert_eq!(buf, plaintext);
    }

    #[test]
    fn priv_encrypt_iv_construction() {
        // engineBoots = 1, engineTime = 0x10203040, salt = 0xAABBCCDD_EEFF0011.
        let iv = make_aes_iv(1, 0x10203040, 0xAABBCCDD_EEFF0011);
        assert_eq!(
            iv,
            [
                0x00, 0x00, 0x00, 0x01, // engineBoots
                0x10, 0x20, 0x30, 0x40, // engineTime
                0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, // salt
            ]
        );
    }

    #[test]
    fn fresh_salt_varies() {
        // Astronomically unlikely to collide twice in a row.
        let a = fresh_salt();
        let b = fresh_salt();
        assert_ne!(a, b);
    }
}
