use std::net::Ipv4Addr;
use std::time::Duration;

pub mod cli;
pub mod debug;
pub mod engine;
pub mod error;
pub mod helpers;
pub mod pdu;
pub mod transport;
pub mod usm;
pub mod varbind;

pub use error::Error;

use crate::cli::{Cli, SnmpVersion};
use crate::pdu::{
    DEFAULT_V1_ENTERPRISE_OID, SNMP_TRAP_OID_OID, SYS_UPTIME_OID, V1Trap, V2cTrap, build_v1_trap,
    build_v2c_trap, fresh_request_id,
};
use crate::varbind::{VarBindValue, parse_oid, parse_typed_value};

pub fn run() -> Result<(), Error> {
    let cli = Cli::parse_argv()?;
    let dst = cli.resolve_agent()?;
    let timeout = Duration::from_secs(cli.timeout.into());
    let payload = build_payload(&cli, dst)?;

    if cli.debug_print_pdu {
        let mut stderr = std::io::stderr().lock();
        let _ = debug::print_pre_send_dump(
            &mut stderr,
            cli.version,
            dst,
            cli.src_addr_v4(),
            cli.src_port,
            &payload,
        );
    }

    match cli.src_addr_v4() {
        Some(src) => {
            transport::raw::send_spoofed(dst, src, cli.src_port, timeout, cli.retries, &payload)
        }
        None => transport::unprivileged::send(dst, cli.src_port, timeout, cli.retries, &payload),
    }
}

fn build_payload(cli: &Cli, dst: std::net::SocketAddrV4) -> Result<Vec<u8>, Error> {
    match cli.version {
        SnmpVersion::V1 => build_v1_payload(cli, dst),
        SnmpVersion::V2c => build_v2c_payload(cli),
    }
}

fn build_v2c_payload(cli: &Cli) -> Result<Vec<u8>, Error> {
    let args = &cli.trap_args;
    if args.len() < 2 {
        return Err(Error::Usage(
            "v2c trap requires at minimum: <UPTIME> <TRAP-OID> [OID TYPE VALUE]...".into(),
        ));
    }

    let uptime = parse_uptime_or_default(&args[0])?;
    let trap_oid = parse_oid(&args[1]).map_err(Error::Usage)?;
    let varbinds = parse_trailing_varbinds(&args[2..])?;
    // The v2c trap PDU auto-prepends sysUpTime.0 and snmpTrapOID.0 from
    // the dedicated `<UPTIME>` and `<TRAP-OID>` positionals; passing them
    // again as trailing varbinds creates a duplicate that some receivers
    // reject and others log as an oddity. Reject up-front with a hint.
    for (oid, _) in &varbinds {
        if oid.as_slice() == SYS_UPTIME_OID {
            return Err(Error::Usage(
                "sysUpTime.0 (1.3.6.1.2.1.1.3.0) is auto-prepended; do not pass it as a trailing varbind. \
                 Use the <UPTIME> positional (or '' to substitute host uptime)."
                    .into(),
            ));
        }
        if oid.as_slice() == SNMP_TRAP_OID_OID {
            return Err(Error::Usage(
                "snmpTrapOID.0 (1.3.6.1.6.3.1.1.4.1.0) is auto-prepended; do not pass it as a trailing varbind. \
                 Use the <TRAP-OID> positional."
                    .into(),
            ));
        }
    }

    let trap = V2cTrap {
        community: cli.community.as_bytes().to_vec(),
        request_id: fresh_request_id(),
        uptime_centiseconds: uptime,
        trap_oid,
        varbinds,
    };
    build_v2c_trap(&trap)
}

fn build_v1_payload(cli: &Cli, dst: std::net::SocketAddrV4) -> Result<Vec<u8>, Error> {
    let args = &cli.trap_args;
    if args.len() < 5 {
        return Err(Error::Usage(
            "v1 trap requires: <ENTERPRISE-OID> <AGENT-ADDR> <GENERIC> <SPECIFIC> <UPTIME> [OID TYPE VALUE]...".into(),
        ));
    }

    let enterprise = if args[0].is_empty() {
        DEFAULT_V1_ENTERPRISE_OID.to_vec()
    } else {
        parse_oid(&args[0]).map_err(Error::Usage)?
    };

    let agent_addr = resolve_v1_agent_addr(&args[1], cli.src_addr_v4(), dst)?;

    let generic: i32 = args[2].parse().map_err(|e: std::num::ParseIntError| {
        Error::Usage(format!("invalid generic-trap '{}': {}", args[2], e))
    })?;
    if !(0..=6).contains(&generic) {
        return Err(Error::Usage(format!(
            "generic-trap must be 0..=6, got {generic}"
        )));
    }
    let specific: i32 = args[3].parse().map_err(|e: std::num::ParseIntError| {
        Error::Usage(format!("invalid specific-trap '{}': {}", args[3], e))
    })?;
    if specific < 0 {
        return Err(Error::Usage(format!(
            "specific-trap must be non-negative (RFC 1157), got {specific}"
        )));
    }

    let uptime = parse_uptime_or_default(&args[4])?;
    let varbinds = parse_trailing_varbinds(&args[5..])?;

    let trap = V1Trap {
        community: cli.community.as_bytes().to_vec(),
        enterprise,
        agent_addr,
        generic,
        specific,
        uptime_centiseconds: uptime,
        varbinds,
    };
    build_v1_trap(&trap)
}

pub(crate) fn resolve_v1_agent_addr(
    positional: &str,
    src_addr_flag: Option<Ipv4Addr>,
    dst: std::net::SocketAddrV4,
) -> Result<Ipv4Addr, Error> {
    if !positional.is_empty() {
        return positional.parse::<Ipv4Addr>().map_err(|_| {
            Error::Usage(format!(
                "v1 agent-addr positional must be a dotted-quad IPv4 (or empty), got '{positional}'"
            ))
        });
    }
    if let Some(src) = src_addr_flag {
        return Ok(src);
    }
    helpers::egress_ipv4_for(dst).map_err(Error::from)
}

fn parse_uptime_or_default(s: &str) -> Result<u32, Error> {
    if s.is_empty() {
        return helpers::host_uptime_centiseconds().map_err(Error::from);
    }
    s.parse::<u32>()
        .map_err(|e: std::num::ParseIntError| Error::Usage(format!("invalid uptime '{s}': {e}")))
}

fn parse_trailing_varbinds(rest: &[String]) -> Result<Vec<(Vec<u32>, VarBindValue)>, Error> {
    if !rest.len().is_multiple_of(3) {
        return Err(Error::Usage(format!(
            "trailing var-binds must come in OID TYPE VALUE triplets; got {} extra args",
            rest.len()
        )));
    }
    let mut out = Vec::with_capacity(rest.len() / 3);
    for triplet in rest.chunks(3) {
        let oid = parse_oid(&triplet[0]).map_err(Error::Usage)?;
        let mut chars = triplet[1].chars();
        let letter = chars.next().ok_or_else(|| {
            Error::Usage(format!("type letter for OID '{}' is empty", triplet[0]))
        })?;
        if chars.next().is_some() {
            return Err(Error::Usage(format!(
                "type letter for OID '{}' must be a single character, got '{}'",
                triplet[0], triplet[1]
            )));
        }
        let value = parse_typed_value(letter, &triplet[2]).map_err(|e| match e {
            varbind::ParseError::UnknownLetter { letter } => Error::Usage(format!(
                "unknown type letter '{}' after OID '{}'",
                letter, triplet[0]
            )),
            varbind::ParseError::BadValue { letter, detail } => Error::Usage(format!(
                "bad value for type '{}' (OID '{}'): {}",
                letter, triplet[0], detail
            )),
        })?;
        out.push((oid, value));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddrV4;

    fn dst() -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 162)
    }

    #[test]
    fn v1_agent_addr_explicit_overrides() {
        let r = resolve_v1_agent_addr("203.0.113.5", Some(Ipv4Addr::new(198, 51, 100, 42)), dst())
            .unwrap();
        assert_eq!(r, Ipv4Addr::new(203, 0, 113, 5));
    }

    #[test]
    fn v1_agent_addr_empty_inherits_src_addr() {
        let r = resolve_v1_agent_addr("", Some(Ipv4Addr::new(198, 51, 100, 42)), dst()).unwrap();
        assert_eq!(r, Ipv4Addr::new(198, 51, 100, 42));
    }

    #[test]
    fn v1_agent_addr_empty_with_no_src_addr_falls_back_to_egress() {
        // For loopback dest, egress is loopback.
        let r = resolve_v1_agent_addr("", None, dst()).unwrap();
        assert!(r.is_loopback(), "got {r}");
    }

    fn make_cli_v2c(trailing: &[&str]) -> Cli {
        let mut argv = vec![
            "snmptrap-rs",
            "-v",
            "2c",
            "-c",
            "public",
            "127.0.0.1",
            "12345",
            "1.3.6.1.6.3.1.1.5.1",
        ];
        argv.extend_from_slice(trailing);
        Cli::parse_from_iter(argv).unwrap()
    }

    #[test]
    fn v2c_rejects_user_passed_sys_uptime_in_trailing_varbinds() {
        let cli = make_cli_v2c(&["1.3.6.1.2.1.1.3.0", "t", "1000"]);
        let err = build_v2c_payload(&cli).unwrap_err();
        match err {
            Error::Usage(msg) => assert!(
                msg.contains("sysUpTime.0") && msg.contains("auto-prepended"),
                "got {msg}"
            ),
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn v2c_rejects_user_passed_snmp_trap_oid_in_trailing_varbinds() {
        let cli = make_cli_v2c(&["1.3.6.1.6.3.1.1.4.1.0", "o", "1.3.6.1.6.3.1.1.5.2"]);
        let err = build_v2c_payload(&cli).unwrap_err();
        match err {
            Error::Usage(msg) => assert!(
                msg.contains("snmpTrapOID.0") && msg.contains("auto-prepended"),
                "got {msg}"
            ),
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn v2c_accepts_unrelated_trailing_varbinds() {
        let cli = make_cli_v2c(&["1.3.6.1.4.1.8072.2.3.2.1", "i", "42"]);
        let bytes = build_v2c_payload(&cli).expect("should encode");
        assert!(!bytes.is_empty());
    }
}
