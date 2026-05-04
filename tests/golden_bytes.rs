//! Compare PDUs we emit against captures of Net-SNMP `snmptrap` output.
//!
//! The fixtures in `tests/fixtures/` are real UDP payloads captured during the
//! development of this crate (see proposal task 5.4). The captures fix every
//! input that affects the encoding except `request-id` (set by Net-SNMP at
//! random for v2c). For v1 there is no `request-id` field, so byte-equality
//! is exact.

use rasn::ber;
use rasn::types::Integer;
use rasn_smi::v1 as smi_v1;
use rasn_snmp::{v1 as snmp_v1, v2 as snmp_v2, v2c as snmp_v2c};
use snmptrap_rs::pdu::{V1Trap, V2cTrap, build_v1_trap, build_v2c_trap};
use snmptrap_rs::varbind::VarBindValue;
use std::net::Ipv4Addr;

fn load_fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/tests/fixtures/{}", env!("CARGO_MANIFEST_DIR"), name);
    let raw = std::fs::read_to_string(&path).expect("fixture file");
    let trimmed = raw.trim();
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(trimmed)
        .expect("base64 decode")
}

#[test]
fn v2c_trap_matches_netsnmp_capture_structurally() {
    let captured = load_fixture("netsnmp_v2c_trap.b64");

    // Decode the captured Net-SNMP message.
    let netsnmp: snmp_v2c::Message<snmp_v2::Trap> =
        ber::decode(&captured).expect("decode netsnmp v2c");

    let netsnmp_pdu = &netsnmp.data.0;

    // Build our equivalent using the same request-id (otherwise the bytes
    // would differ in just that field).
    let ours = V2cTrap {
        community: b"public".to_vec(),
        request_id: netsnmp_pdu.request_id,
        uptime_centiseconds: 12345,
        trap_oid: vec![1, 3, 6, 1, 6, 3, 1, 1, 5, 1],
        varbinds: vec![(
            vec![1, 3, 6, 1, 4, 1, 8072, 2, 3, 2, 1],
            VarBindValue::Integer(42),
        )],
    };
    let our_bytes = build_v2c_trap(&ours).expect("encode v2c");

    assert_eq!(
        our_bytes,
        captured,
        "byte-level mismatch:\n  ours    = {}\n  netsnmp = {}",
        hex::encode(&our_bytes),
        hex::encode(&captured),
    );
}

#[test]
fn v1_trap_matches_netsnmp_capture_byte_for_byte() {
    let captured = load_fixture("netsnmp_v1_trap.b64");

    // Sanity-check that the capture decodes cleanly via rasn.
    let _: snmp_v1::Message<snmp_v1::Trap> = ber::decode(&captured).expect("decode netsnmp v1");

    let ours = V1Trap {
        community: b"public".to_vec(),
        enterprise: vec![1, 3, 6, 1, 4, 1, 8072, 2, 3, 0, 1],
        agent_addr: Ipv4Addr::new(10, 0, 0, 1),
        generic: 6,
        specific: 17,
        uptime_centiseconds: 99999,
        varbinds: vec![(
            vec![1, 3, 6, 1, 4, 1, 8072, 2, 3, 2, 1],
            VarBindValue::Integer(7),
        )],
    };
    let our_bytes = build_v1_trap(&ours).expect("encode v1");

    assert_eq!(
        our_bytes,
        captured,
        "byte-level mismatch:\n  ours    = {}\n  netsnmp = {}",
        hex::encode(&our_bytes),
        hex::encode(&captured),
    );
}

#[test]
fn v1_trap_matches_via_decoded_fields() {
    // Decode capture and assert on individual fields (in addition to byte
    // equality) so that any future deviation is reported in human-readable terms.
    let captured = load_fixture("netsnmp_v1_trap.b64");
    let msg: snmp_v1::Message<snmp_v1::Trap> = ber::decode(&captured).unwrap();
    let trap = &msg.data;

    assert_eq!(msg.community.to_vec(), b"public".to_vec());
    assert_eq!(trap.generic_trap, Integer::from(6));
    assert_eq!(trap.specific_trap, Integer::from(17));
    assert_eq!(trap.time_stamp.0, 99999);
    match &trap.agent_addr {
        smi_v1::NetworkAddress::Internet(ip) => {
            assert_eq!(ip.0.as_ref(), &[10, 0, 0, 1]);
        }
    }
    assert_eq!(trap.variable_bindings.len(), 1);
}
