use std::net::Ipv4Addr;

use rasn::types::{Integer, ObjectIdentifier, OctetString};
use rasn_smi::{v1 as smi_v1, v2 as smi_v2};
use rasn_snmp::{v1 as snmp_v1, v2 as snmp_v2, v2c as snmp_v2c};

use crate::error::Error;
use crate::varbind::VarBindValue;

/// `1.3.6.1.2.1.1.3.0` — sysUpTime.0
pub const SYS_UPTIME_OID: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 3, 0];
/// `1.3.6.1.6.3.1.1.4.1.0` — snmpTrapOID.0
pub const SNMP_TRAP_OID_OID: &[u32] = &[1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0];
/// `1.3.6.1.4.1.3.1.1` — Net-SNMP's default v1 enterprise OID.
pub const DEFAULT_V1_ENTERPRISE_OID: &[u32] = &[1, 3, 6, 1, 4, 1, 3, 1, 1];

#[derive(Debug, Clone)]
pub struct V2cTrap {
    pub community: Vec<u8>,
    pub request_id: i32,
    pub uptime_centiseconds: u32,
    pub trap_oid: Vec<u32>,
    pub varbinds: Vec<(Vec<u32>, VarBindValue)>,
}

#[derive(Debug, Clone)]
pub struct V1Trap {
    pub community: Vec<u8>,
    pub enterprise: Vec<u32>,
    pub agent_addr: Ipv4Addr,
    pub generic: i32,
    pub specific: i32,
    pub uptime_centiseconds: u32,
    pub varbinds: Vec<(Vec<u32>, VarBindValue)>,
}

pub fn build_v2c_trap(t: &V2cTrap) -> Result<Vec<u8>, Error> {
    let mut bindings: Vec<snmp_v2::VarBind> = Vec::with_capacity(2 + t.varbinds.len());

    bindings.push(make_v2_varbind(
        SYS_UPTIME_OID,
        VarBindValue::TimeTicks(t.uptime_centiseconds),
    )?);
    bindings.push(make_v2_varbind(
        SNMP_TRAP_OID_OID,
        VarBindValue::ObjectId(t.trap_oid.clone()),
    )?);
    for (oid, v) in &t.varbinds {
        bindings.push(make_v2_varbind(oid, v.clone())?);
    }

    let pdu = snmp_v2::Pdu {
        request_id: t.request_id,
        error_status: snmp_v2::Pdu::ERROR_STATUS_NO_ERROR,
        error_index: 0,
        variable_bindings: bindings,
    };
    let trap = snmp_v2::Trap(pdu);
    let message = snmp_v2c::Message::<snmp_v2::Trap> {
        version: Integer::from(snmp_v2c::Message::<snmp_v2::Trap>::VERSION),
        community: OctetString::from(t.community.clone()),
        data: trap,
    };
    rasn::ber::encode(&message).map_err(|e| Error::Encode(e.to_string()))
}

pub fn build_v1_trap(t: &V1Trap) -> Result<Vec<u8>, Error> {
    let mut bindings: Vec<snmp_v1::VarBind> = Vec::with_capacity(t.varbinds.len());
    for (oid, v) in &t.varbinds {
        bindings.push(make_v1_varbind(oid, v.clone())?);
    }
    let agent = smi_v1::IpAddress(rasn::types::FixedOctetString::from(t.agent_addr.octets()));
    let trap = snmp_v1::Trap {
        enterprise: oid_from_slice(&t.enterprise),
        agent_addr: smi_v1::NetworkAddress::Internet(agent),
        generic_trap: Integer::from(t.generic),
        specific_trap: Integer::from(t.specific),
        time_stamp: smi_v1::TimeTicks(t.uptime_centiseconds),
        variable_bindings: bindings,
    };
    let message = snmp_v1::Message::<snmp_v1::Trap> {
        version: Integer::from(snmp_v1::Message::<snmp_v1::Trap>::VERSION_1),
        community: OctetString::from(t.community.clone()),
        data: trap,
    };
    rasn::ber::encode(&message).map_err(|e| Error::Encode(e.to_string()))
}

fn make_v2_varbind(oid: &[u32], v: VarBindValue) -> Result<snmp_v2::VarBind, Error> {
    let value = match v {
        VarBindValue::Integer(i) => snmp_v2::VarBindValue::Value(smi_v2::ObjectSyntax::Simple(
            smi_v2::SimpleSyntax::Integer(Integer::from(i)),
        )),
        VarBindValue::Unsigned32(u) => {
            snmp_v2::VarBindValue::Value(smi_v2::ObjectSyntax::ApplicationWide(
                smi_v2::ApplicationSyntax::Unsigned(smi_v1::Gauge(u)),
            ))
        }
        VarBindValue::TimeTicks(t) => {
            snmp_v2::VarBindValue::Value(smi_v2::ObjectSyntax::ApplicationWide(
                smi_v2::ApplicationSyntax::Ticks(smi_v1::TimeTicks(t)),
            ))
        }
        VarBindValue::IpAddress(ip) => {
            let bytes: rasn::types::FixedOctetString<4> =
                rasn::types::FixedOctetString::from(ip.octets());
            snmp_v2::VarBindValue::Value(smi_v2::ObjectSyntax::ApplicationWide(
                smi_v2::ApplicationSyntax::Address(smi_v1::IpAddress(bytes)),
            ))
        }
        VarBindValue::ObjectId(arcs) => snmp_v2::VarBindValue::Value(smi_v2::ObjectSyntax::Simple(
            smi_v2::SimpleSyntax::ObjectId(oid_from_slice(&arcs)),
        )),
        VarBindValue::OctetString(bytes) => snmp_v2::VarBindValue::Value(
            smi_v2::ObjectSyntax::Simple(smi_v2::SimpleSyntax::String(OctetString::from(bytes))),
        ),
        VarBindValue::Null => snmp_v2::VarBindValue::Unspecified,
        VarBindValue::Bits(bytes) => snmp_v2::VarBindValue::Value(smi_v2::ObjectSyntax::Simple(
            smi_v2::SimpleSyntax::String(OctetString::from(bytes)),
        )),
        VarBindValue::Counter64(n) => {
            snmp_v2::VarBindValue::Value(smi_v2::ObjectSyntax::ApplicationWide(
                smi_v2::ApplicationSyntax::BigCounter(smi_v2::Counter64(n)),
            ))
        }
    };
    Ok(snmp_v2::VarBind {
        name: oid_from_slice(oid),
        value,
    })
}

fn make_v1_varbind(oid: &[u32], v: VarBindValue) -> Result<snmp_v1::VarBind, Error> {
    let value = match v {
        VarBindValue::Integer(i) => {
            smi_v1::ObjectSyntax::Simple(smi_v1::SimpleSyntax::Number(Integer::from(i)))
        }
        VarBindValue::Unsigned32(u) => smi_v1::ObjectSyntax::ApplicationWide(
            smi_v1::ApplicationSyntax::Gauge(smi_v1::Gauge(u)),
        ),
        VarBindValue::TimeTicks(t) => smi_v1::ObjectSyntax::ApplicationWide(
            smi_v1::ApplicationSyntax::Ticks(smi_v1::TimeTicks(t)),
        ),
        VarBindValue::IpAddress(ip) => {
            let bytes: rasn::types::FixedOctetString<4> =
                rasn::types::FixedOctetString::from(ip.octets());
            smi_v1::ObjectSyntax::ApplicationWide(smi_v1::ApplicationSyntax::Address(
                smi_v1::NetworkAddress::Internet(smi_v1::IpAddress(bytes)),
            ))
        }
        VarBindValue::ObjectId(arcs) => {
            smi_v1::ObjectSyntax::Simple(smi_v1::SimpleSyntax::Object(oid_from_slice(&arcs)))
        }
        VarBindValue::OctetString(bytes) => {
            smi_v1::ObjectSyntax::Simple(smi_v1::SimpleSyntax::String(OctetString::from(bytes)))
        }
        VarBindValue::Null => smi_v1::ObjectSyntax::Simple(smi_v1::SimpleSyntax::Empty),
        VarBindValue::Bits(bytes) => {
            smi_v1::ObjectSyntax::Simple(smi_v1::SimpleSyntax::String(OctetString::from(bytes)))
        }
        VarBindValue::Counter64(_) => {
            return Err(Error::Encode(
                "Counter64 (type 'U') is not representable in SNMPv1; use -v 2c instead".into(),
            ));
        }
    };
    Ok(snmp_v1::VarBind {
        name: oid_from_slice(oid),
        value,
    })
}

fn oid_from_slice(arcs: &[u32]) -> ObjectIdentifier {
    ObjectIdentifier::new_unchecked(arcs.to_vec().into())
}

/// Generate a request-id suitable for an SNMPv2c trap. RFC 3416 leaves the
/// choice up to the sender; using a randomized 31-bit value avoids any clash
/// with peer-side caches and stays positive.
pub fn fresh_request_id() -> i32 {
    use rand::Rng;
    let mut rng = rand::rng();
    rng.random_range(1..=i32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rasn::ber;

    #[test]
    fn v2c_trap_roundtrips() {
        let t = V2cTrap {
            community: b"public".to_vec(),
            request_id: 1414684022,
            uptime_centiseconds: 12345,
            trap_oid: vec![1, 3, 6, 1, 6, 3, 1, 1, 5, 1],
            varbinds: vec![(
                vec![1, 3, 6, 1, 4, 1, 8072, 2, 3, 2, 1],
                VarBindValue::Integer(42),
            )],
        };
        let bytes = build_v2c_trap(&t).expect("encode v2c");

        let decoded: snmp_v2c::Message<snmp_v2::Trap> = ber::decode(&bytes).expect("decode v2c");
        assert_eq!(decoded.community.to_vec(), b"public".to_vec());
        let pdu = &decoded.data.0;
        assert_eq!(pdu.request_id, 1414684022);
        assert_eq!(pdu.error_status, 0);
        assert_eq!(pdu.error_index, 0);
        assert_eq!(pdu.variable_bindings.len(), 3);

        // first varbind must be sysUpTime.0
        let sysuptime_oid = pdu.variable_bindings[0].name.to_vec();
        assert_eq!(sysuptime_oid, SYS_UPTIME_OID.to_vec());

        // second must be snmpTrapOID.0
        let trapoid_oid = pdu.variable_bindings[1].name.to_vec();
        assert_eq!(trapoid_oid, SNMP_TRAP_OID_OID.to_vec());
    }

    #[test]
    fn v1_trap_roundtrips() {
        let t = V1Trap {
            community: b"public".to_vec(),
            enterprise: vec![1, 3, 6, 1, 4, 1, 3, 1, 1],
            agent_addr: Ipv4Addr::new(10, 0, 0, 1),
            generic: 6,
            specific: 17,
            uptime_centiseconds: 99999,
            varbinds: vec![(
                vec![1, 3, 6, 1, 4, 1, 8072, 2, 3, 2, 1],
                VarBindValue::Integer(7),
            )],
        };
        let bytes = build_v1_trap(&t).expect("encode v1");

        let decoded: snmp_v1::Message<snmp_v1::Trap> = ber::decode(&bytes).expect("decode v1");
        assert_eq!(decoded.community.to_vec(), b"public".to_vec());
        let trap = &decoded.data;
        assert_eq!(trap.generic_trap, Integer::from(6));
        assert_eq!(trap.specific_trap, Integer::from(17));
        assert_eq!(trap.time_stamp.0, 99999);
        match &trap.agent_addr {
            smi_v1::NetworkAddress::Internet(ip) => {
                assert_eq!(ip.0.as_ref(), &[10, 0, 0, 1]);
            }
        }
    }

    #[test]
    fn counter64_in_v1_rejected() {
        let t = V1Trap {
            community: b"public".to_vec(),
            enterprise: vec![1, 3, 6, 1, 4, 1, 3, 1, 1],
            agent_addr: Ipv4Addr::new(10, 0, 0, 1),
            generic: 6,
            specific: 1,
            uptime_centiseconds: 0,
            varbinds: vec![(
                vec![1, 3, 6, 1, 4, 1, 8072, 2, 3, 2, 1],
                VarBindValue::Counter64(42),
            )],
        };
        let err = build_v1_trap(&t).unwrap_err();
        match err {
            Error::Encode(msg) => assert!(msg.contains("Counter64"), "got {msg}"),
            other => panic!("expected Encode, got {other:?}"),
        }
    }
}
