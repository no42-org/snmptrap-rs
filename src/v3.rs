//! SNMPv3 message wrapper per RFC 3412 + RFC 3414 + RFC 3826.
//!
//! Builds an SNMPv3 message that wraps a v2-style trap PDU, applies USM
//! security parameters (engine-ID, boots, time, user, optional auth/priv),
//! and emits the BER-encoded wire bytes ready for UDP send.
//!
//! Build flow:
//!   1. Construct the inner v2-Trap PDU from the input varbinds.
//!   2. Wrap in `ScopedPdu` (contextEngineID + contextName + PDU).
//!   3. If priv: encrypt the encoded scopedPDU with AES-CFB; wrap as
//!      `ScopedPduData::EncryptedPdu`. Else: `ScopedPduData::CleartextPdu`.
//!   4. Build `USMSecurityParameters` with a placeholder of `auth_param_len`
//!      zero bytes for `authenticationParameters`.
//!   5. Encode the full v3 `Message`. Compute HMAC over those bytes.
//!   6. Re-encode with the HMAC tag in `authenticationParameters`. The
//!      OCTET STRING length is unchanged so the resulting bytes differ from
//!      the placeholder version only at the tag positions — receiver's
//!      "replace authParams with zeros and recompute" gives the same input
//!      we hashed, and HMAC verifies.
//!
//! The reportable bit in `msgFlags` is set on outbound traps to mirror
//! Net-SNMP's `snmptrap -v 3` behavior (RFC 3412 §6.4 makes it SHOULD-zero
//! for unconfirmed PDUs but receivers tolerate either; matching Net-SNMP
//! eliminates needless interop variation).

use rasn::types::{Integer, OctetString};
use rasn_snmp::{v2 as snmp_v2, v3 as snmp_v3};

use crate::engine::EngineId;
use crate::error::Error;
use crate::pdu::{SNMP_TRAP_OID_OID, SYS_UPTIME_OID, V2cTrap, make_v2_varbind};
use crate::usm::{self, AuthProtocol, PrivProtocol};
use crate::varbind::VarBindValue;

const SECURITY_MODEL_USM: u32 = 3;
const MSG_VERSION_V3: u32 = 3;
const MSG_MAX_SIZE: u32 = 65507;

const FLAG_AUTH: u8 = 0b001;
const FLAG_PRIV: u8 = 0b010;
const FLAG_REPORTABLE: u8 = 0b100;

#[derive(Debug, Clone)]
pub struct V3TrapMessage {
    /// Authoritative engine-ID — identifies the sending engine in the USM
    /// security parameters (and, by default, in the inner scopedPDU's
    /// `contextEngineID`).
    pub authoritative_engine_id: EngineId,
    /// Context engine-ID — defaults to the authoritative engine-ID; can
    /// differ if the user passes `-e` with a value distinct from `-E`.
    pub context_engine_id: EngineId,
    pub context_name: Vec<u8>,
    pub user_name: Vec<u8>,
    pub engine_boots: u32,
    pub engine_time: u32,
    pub msg_id: i32,
    pub security: V3Security,
    /// Inner trap PDU contents. The `community` field of `V2cTrap` is
    /// ignored for v3 (USM replaces community-string auth).
    pub trap: V2cTrap,
}

#[derive(Debug, Clone)]
pub enum V3Security {
    NoAuthNoPriv,
    AuthNoPriv {
        proto: AuthProtocol,
        auth_key: Vec<u8>,
    },
    AuthPriv {
        auth_proto: AuthProtocol,
        auth_key: Vec<u8>,
        priv_proto: PrivProtocol,
        priv_key: Vec<u8>,
        salt: u64,
    },
}

impl V3Security {
    fn flag_byte(&self) -> u8 {
        let base = FLAG_REPORTABLE;
        match self {
            Self::NoAuthNoPriv => base,
            Self::AuthNoPriv { .. } => base | FLAG_AUTH,
            Self::AuthPriv { .. } => base | FLAG_AUTH | FLAG_PRIV,
        }
    }

    fn auth(&self) -> Option<(AuthProtocol, &[u8])> {
        match self {
            Self::NoAuthNoPriv => None,
            Self::AuthNoPriv { proto, auth_key } => Some((*proto, auth_key.as_slice())),
            Self::AuthPriv {
                auth_proto,
                auth_key,
                ..
            } => Some((*auth_proto, auth_key.as_slice())),
        }
    }
}

pub fn build_v3_trap_message(m: &V3TrapMessage) -> Result<Vec<u8>, Error> {
    let scoped_pdu = build_scoped_pdu(m)?;

    // Encrypt the scopedPDU when priv is in effect, otherwise leave plaintext.
    // The privacyParameters field is the salt as 8 BE bytes — the same 8
    // bytes used as the second half of the AES-CFB IV in `usm::priv_encrypt`.
    let (scoped_data, priv_params_bytes) = match &m.security {
        V3Security::AuthPriv {
            priv_proto,
            priv_key,
            salt,
            ..
        } => {
            let plaintext = encode(&scoped_pdu)?;
            let ct = usm::priv_encrypt(
                &plaintext,
                priv_key,
                m.engine_boots,
                m.engine_time,
                *salt,
                *priv_proto,
            );
            (
                snmp_v3::ScopedPduData::EncryptedPdu(OctetString::from(ct)),
                salt.to_be_bytes().to_vec(),
            )
        }
        _ => (snmp_v3::ScopedPduData::CleartextPdu(scoped_pdu), Vec::new()),
    };

    let auth_param_len = match &m.security {
        V3Security::NoAuthNoPriv => 0,
        V3Security::AuthNoPriv { proto, .. } => proto.auth_param_len(),
        V3Security::AuthPriv { auth_proto, .. } => auth_proto.auth_param_len(),
    };

    let usm_params_placeholder =
        build_usm_params(m, vec![0u8; auth_param_len], priv_params_bytes.clone());
    let security_params_bytes = encode(&usm_params_placeholder)?;

    let header = snmp_v3::HeaderData {
        message_id: Integer::from(m.msg_id),
        max_size: Integer::from(MSG_MAX_SIZE),
        flags: OctetString::from(vec![m.security.flag_byte()]),
        security_model: Integer::from(SECURITY_MODEL_USM),
    };
    let message_placeholder = snmp_v3::Message {
        version: Integer::from(MSG_VERSION_V3),
        global_data: header.clone(),
        security_parameters: OctetString::from(security_params_bytes),
        scoped_data: scoped_data.clone(),
    };
    let bytes_with_placeholder = encode(&message_placeholder)?;

    let Some((proto, key)) = m.security.auth() else {
        // noAuthNoPriv: nothing to splice; placeholder bytes ARE the wire bytes.
        return Ok(bytes_with_placeholder);
    };

    // Compute HMAC over the placeholder-version bytes, then re-encode with
    // the tag in the authParams slot. Receiver does the inverse: extracts the
    // tag, replaces with zeros, recomputes HMAC — gets the same input we
    // hashed, so the tags compare equal.
    let tag = usm::auth_sign(&bytes_with_placeholder, key, proto);
    // Always-on assertion: the splice scheme is correct only if the tag
    // length equals the zero-filled placeholder length. If this ever drifted
    // (e.g. a future protocol mis-set its `auth_param_len()`), every byte
    // after the authParams OctetString length descriptor would shift,
    // putting the HMAC over the wrong window — receivers would silently
    // reject every emitted trap.
    assert_eq!(
        tag.len(),
        auth_param_len,
        "auth_sign tag length must match the placeholder length"
    );

    let usm_params_signed = build_usm_params(m, tag, priv_params_bytes);
    let security_params_signed = encode(&usm_params_signed)?;
    let message_signed = snmp_v3::Message {
        version: Integer::from(MSG_VERSION_V3),
        global_data: header,
        security_parameters: OctetString::from(security_params_signed),
        scoped_data,
    };
    let bytes_signed = encode(&message_signed)?;

    debug_assert_eq!(
        bytes_signed.len(),
        bytes_with_placeholder.len(),
        "BER re-encoding with same-length authParams must preserve message length"
    );

    Ok(bytes_signed)
}

fn build_scoped_pdu(m: &V3TrapMessage) -> Result<snmp_v3::ScopedPdu, Error> {
    let mut bindings = Vec::with_capacity(2 + m.trap.varbinds.len());
    bindings.push(make_v2_varbind(
        SYS_UPTIME_OID,
        VarBindValue::TimeTicks(m.trap.uptime_centiseconds),
    )?);
    bindings.push(make_v2_varbind(
        SNMP_TRAP_OID_OID,
        VarBindValue::ObjectId(m.trap.trap_oid.clone()),
    )?);
    for (oid, v) in &m.trap.varbinds {
        bindings.push(make_v2_varbind(oid, v.clone())?);
    }

    let pdu = snmp_v2::Pdu {
        request_id: m.trap.request_id,
        error_status: snmp_v2::Pdu::ERROR_STATUS_NO_ERROR,
        error_index: 0,
        variable_bindings: bindings,
    };
    let trap = snmp_v2::Trap(pdu);
    Ok(snmp_v3::ScopedPdu {
        engine_id: OctetString::from(m.context_engine_id.as_bytes().to_vec()),
        name: OctetString::from(m.context_name.clone()),
        data: snmp_v2::Pdus::Trap(trap),
    })
}

fn build_usm_params(
    m: &V3TrapMessage,
    auth_params: Vec<u8>,
    priv_params: Vec<u8>,
) -> snmp_v3::USMSecurityParameters {
    snmp_v3::USMSecurityParameters {
        authoritative_engine_id: OctetString::from(m.authoritative_engine_id.as_bytes().to_vec()),
        authoritative_engine_boots: Integer::from(m.engine_boots),
        authoritative_engine_time: Integer::from(m.engine_time),
        user_name: OctetString::from(m.user_name.clone()),
        authentication_parameters: OctetString::from(auth_params),
        privacy_parameters: OctetString::from(priv_params),
    }
}

fn encode<T: rasn::Encode>(value: &T) -> Result<Vec<u8>, Error> {
    rasn::ber::encode(value).map_err(|e| Error::Encode(e.to_string()))
}

/// Generate a fresh msgID per RFC 3412 §6.2 — random in [1, i32::MAX].
pub fn fresh_msg_id() -> i32 {
    use rand::RngExt;
    let mut rng = rand::rng();
    rng.random_range(1..=i32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pdu::fresh_request_id;
    use rasn::ber;

    fn fixture_engine_id_v3() -> EngineId {
        // Sender's authoritative engine-ID. Use parse_user_input to avoid
        // depending on host MAC / hostname in tests.
        EngineId::parse_user_input("80001f88010203040506").unwrap()
    }

    fn fixture_trap() -> V2cTrap {
        V2cTrap {
            community: Vec::new(), // unused under v3
            request_id: fresh_request_id(),
            uptime_centiseconds: 12345,
            trap_oid: vec![1, 3, 6, 1, 6, 3, 1, 1, 5, 1],
            varbinds: vec![(
                vec![1, 3, 6, 1, 4, 1, 8072, 2, 3, 2, 1],
                VarBindValue::Integer(42),
            )],
        }
    }

    fn fixture_no_auth() -> V3TrapMessage {
        let eid = fixture_engine_id_v3();
        V3TrapMessage {
            authoritative_engine_id: eid.clone(),
            context_engine_id: eid,
            context_name: Vec::new(),
            user_name: b"testuser".to_vec(),
            engine_boots: 1,
            engine_time: 100,
            msg_id: 0xCAFEBABE_u32 as i32 & 0x7FFF_FFFF,
            security: V3Security::NoAuthNoPriv,
            trap: fixture_trap(),
        }
    }

    fn decode_message(bytes: &[u8]) -> snmp_v3::Message {
        ber::decode(bytes).expect("v3 message decodes")
    }

    fn decode_usm_params(msg: &snmp_v3::Message) -> snmp_v3::USMSecurityParameters {
        ber::decode(&msg.security_parameters).expect("USM params decode")
    }

    #[test]
    fn no_auth_no_priv_round_trip() {
        let m = fixture_no_auth();
        let bytes = build_v3_trap_message(&m).unwrap();

        let msg = decode_message(&bytes);
        assert_eq!(msg.version, Integer::from(MSG_VERSION_V3));
        assert_eq!(
            msg.global_data.security_model,
            Integer::from(SECURITY_MODEL_USM)
        );
        assert_eq!(msg.global_data.flags.as_ref(), &[FLAG_REPORTABLE]);

        let usm = decode_usm_params(&msg);
        assert_eq!(
            usm.authoritative_engine_id.to_vec(),
            m.authoritative_engine_id.as_bytes().to_vec()
        );
        assert_eq!(usm.user_name.to_vec(), b"testuser".to_vec());
        assert!(usm.authentication_parameters.is_empty());
        assert!(usm.privacy_parameters.is_empty());

        match msg.scoped_data {
            snmp_v3::ScopedPduData::CleartextPdu(scoped) => {
                assert_eq!(
                    scoped.engine_id.to_vec(),
                    m.authoritative_engine_id.as_bytes().to_vec()
                );
                match scoped.data {
                    snmp_v2::Pdus::Trap(trap) => {
                        let bindings = &trap.0.variable_bindings;
                        assert_eq!(bindings.len(), 3);
                        assert_eq!(bindings[0].name.to_vec(), SYS_UPTIME_OID.to_vec());
                        assert_eq!(bindings[1].name.to_vec(), SNMP_TRAP_OID_OID.to_vec());
                    }
                    other => panic!("expected Trap PDU, got {other:?}"),
                }
            }
            other => panic!("expected CleartextPdu, got {other:?}"),
        }
    }

    #[test]
    fn auth_no_priv_sha256_hmac_verifies() {
        let mut m = fixture_no_auth();
        let auth_key = vec![0xAAu8; AuthProtocol::Sha256.digest_len()];
        m.security = V3Security::AuthNoPriv {
            proto: AuthProtocol::Sha256,
            auth_key: auth_key.clone(),
        };

        let bytes = build_v3_trap_message(&m).unwrap();
        let msg = decode_message(&bytes);

        // Flags: reportable | auth.
        assert_eq!(
            msg.global_data.flags.as_ref(),
            &[FLAG_REPORTABLE | FLAG_AUTH]
        );

        let usm = decode_usm_params(&msg);
        let received_tag = usm.authentication_parameters.to_vec();
        assert_eq!(received_tag.len(), AuthProtocol::Sha256.auth_param_len());

        // Recompute HMAC the way a receiver would: zero the authParams in the
        // wire bytes, re-encode, and compare. We can't easily zero in place
        // without parsing — so reconstruct the message struct, replace
        // authentication_parameters with zeros, encode, then HMAC.
        let zero_tag = vec![0u8; AuthProtocol::Sha256.auth_param_len()];
        let usm_zeroed = snmp_v3::USMSecurityParameters {
            authentication_parameters: OctetString::from(zero_tag),
            ..usm.clone()
        };
        let usm_zeroed_bytes = ber::encode(&usm_zeroed).unwrap();
        let msg_zeroed = snmp_v3::Message {
            security_parameters: OctetString::from(usm_zeroed_bytes),
            ..msg.clone()
        };
        let zeroed_message_bytes = ber::encode(&msg_zeroed).unwrap();
        let recomputed = usm::auth_sign(&zeroed_message_bytes, &auth_key, AuthProtocol::Sha256);

        assert_eq!(recomputed, received_tag, "HMAC tag must verify");
    }

    #[test]
    fn auth_priv_sha256_aes128_round_trip() {
        let mut m = fixture_no_auth();
        let auth_key = vec![0x11u8; AuthProtocol::Sha256.digest_len()];
        let priv_key = vec![0x22u8; PrivProtocol::Aes128.key_len()];
        let salt = 0xDEADBEEF_CAFEBABE_u64;
        m.security = V3Security::AuthPriv {
            auth_proto: AuthProtocol::Sha256,
            auth_key,
            priv_proto: PrivProtocol::Aes128,
            priv_key: priv_key.clone(),
            salt,
        };

        let bytes = build_v3_trap_message(&m).unwrap();
        let msg = decode_message(&bytes);

        assert_eq!(
            msg.global_data.flags.as_ref(),
            &[FLAG_REPORTABLE | FLAG_AUTH | FLAG_PRIV]
        );

        let usm = decode_usm_params(&msg);
        // privacyParameters carries the salt (8 BE bytes).
        assert_eq!(usm.privacy_parameters.to_vec(), salt.to_be_bytes().to_vec());

        // msgData is encrypted; decrypt and re-decode to inspect.
        let encrypted = match &msg.scoped_data {
            snmp_v3::ScopedPduData::EncryptedPdu(bytes) => bytes.to_vec(),
            other => panic!("expected EncryptedPdu, got {other:?}"),
        };
        // Re-derive the salt from privacyParameters: BE u64. It must match
        // the salt we used.
        let recovered_salt = {
            let pp = usm.privacy_parameters.to_vec();
            assert_eq!(pp.len(), 8);
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&pp);
            u64::from_be_bytes(buf)
        };
        assert_eq!(recovered_salt, salt);

        // Decrypt: AES-CFB is symmetric — encrypt with same key/IV inverts.
        // Build the IV the same way priv_encrypt did.
        let mut iv = [0u8; 16];
        iv[0..4].copy_from_slice(&m.engine_boots.to_be_bytes());
        iv[4..8].copy_from_slice(&m.engine_time.to_be_bytes());
        iv[8..16].copy_from_slice(&salt.to_be_bytes());

        use aes::cipher::{AsyncStreamCipher, KeyIvInit};
        let mut buf = encrypted;
        cfb_mode::Decryptor::<aes::Aes128>::new_from_slices(&priv_key, &iv)
            .unwrap()
            .decrypt(&mut buf);

        let scoped: snmp_v3::ScopedPdu = ber::decode(&buf).expect("scopedPDU decodes");
        assert_eq!(
            scoped.engine_id.to_vec(),
            m.context_engine_id.as_bytes().to_vec()
        );
        match scoped.data {
            snmp_v2::Pdus::Trap(trap) => {
                let bindings = &trap.0.variable_bindings;
                assert_eq!(bindings.len(), 3);
                assert_eq!(bindings[0].name.to_vec(), SYS_UPTIME_OID.to_vec());
                assert_eq!(bindings[1].name.to_vec(), SNMP_TRAP_OID_OID.to_vec());
            }
            other => panic!("expected Trap PDU, got {other:?}"),
        }
    }

    #[test]
    fn auth_priv_with_src_addr_engine_id_coherence() {
        // Drive the actual cascade — `engine::resolve(None, Some(X))` must
        // pick format-1 (IPv4), not fall through to MAC/hostname. If the
        // cascade ordering ever regresses, this test must fail.
        let src_addr: std::net::Ipv4Addr = "198.51.100.42".parse().unwrap();
        let derived = crate::engine::resolve(None, Some(src_addr));
        assert_eq!(
            derived.as_bytes(),
            &[0x80, 0x00, 0xF0, 0x45, 0x01, 0xC6, 0x33, 0x64, 0x2A],
            "engine::resolve cascade must return format-1 (IPv4) when -E is unset and --src-addr is set"
        );

        let mut m = fixture_no_auth();
        m.authoritative_engine_id = derived.clone();
        m.context_engine_id = derived.clone();
        m.security = V3Security::AuthPriv {
            auth_proto: AuthProtocol::Sha256,
            auth_key: vec![0x33u8; AuthProtocol::Sha256.digest_len()],
            priv_proto: PrivProtocol::Aes128,
            priv_key: vec![0x44u8; PrivProtocol::Aes128.key_len()],
            salt: 0,
        };

        let bytes = build_v3_trap_message(&m).unwrap();
        let msg = decode_message(&bytes);
        let usm = decode_usm_params(&msg);

        // 9-byte IPv4-format engine-ID: 80 00 F0 45 01 C6 33 64 2A
        assert_eq!(
            usm.authoritative_engine_id.to_vec(),
            vec![0x80, 0x00, 0xF0, 0x45, 0x01, 0xC6, 0x33, 0x64, 0x2A]
        );
    }

    #[test]
    fn flag_byte_encoding() {
        assert_eq!(V3Security::NoAuthNoPriv.flag_byte(), 0b100);
        assert_eq!(
            V3Security::AuthNoPriv {
                proto: AuthProtocol::Sha256,
                auth_key: vec![0u8; 32],
            }
            .flag_byte(),
            0b101
        );
        assert_eq!(
            V3Security::AuthPriv {
                auth_proto: AuthProtocol::Sha256,
                auth_key: vec![0u8; 32],
                priv_proto: PrivProtocol::Aes128,
                priv_key: vec![0u8; 16],
                salt: 0,
            }
            .flag_byte(),
            0b111
        );
    }

    #[test]
    fn fresh_msg_id_is_positive() {
        for _ in 0..32 {
            let id = fresh_msg_id();
            assert!(id > 0);
        }
    }
}
