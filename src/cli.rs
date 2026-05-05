use std::net::{IpAddr, Ipv4Addr, SocketAddrV4, ToSocketAddrs};

use clap::Parser;

use crate::error::Error;

const DEFAULT_TRAP_PORT: u16 = 162;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnmpVersion {
    V1,
    V2c,
}

impl std::str::FromStr for SnmpVersion {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "1" => Ok(Self::V1),
            "2c" => Ok(Self::V2c),
            other => Err(Error::Usage(format!(
                "unsupported SNMP version '{other}'; only '1' and '2c' are supported in this build"
            ))),
        }
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "snmptrap-rs",
    version,
    about = "Send SNMP traps; optional L3 source-IP spoofing via raw IPv4 socket",
    disable_help_subcommand = true,
    disable_version_flag = true
)]
pub struct Cli {
    /// Print the binary version and exit.
    #[arg(long = "binary-version", action = clap::ArgAction::Version)]
    pub binary_version: (),

    /// SNMP version: 1 or 2c.
    #[arg(
        short = 'v',
        long = "snmp-version",
        value_name = "VERSION",
        required = true
    )]
    pub version: SnmpVersion,

    /// Community string.
    #[arg(short = 'c', long = "community", value_name = "COMMUNITY")]
    pub community: String,

    /// Retry count for transport-level resends. Default 0 for traps.
    #[arg(
        short = 'r',
        long = "retries",
        value_name = "RETRIES",
        default_value_t = 0
    )]
    pub retries: u8,

    /// Accepted for Net-SNMP CLI compatibility. Trap PDUs are unconfirmed
    /// (no peer ack), so this value has no effect on traps; reserved for
    /// future inform-PDU support.
    #[arg(
        short = 't',
        long = "timeout",
        value_name = "SECONDS",
        default_value_t = 1
    )]
    pub timeout: u32,

    /// Spoofed L3 source IPv4 address. Trap PDUs only; combining --src-addr
    /// with inform-PDU emission is permanently unsupported by design (the
    /// receiver's Response would route to the spoofed address, not this
    /// host). Requires CAP_NET_RAW (Linux) or root (macOS).
    #[arg(long = "src-addr", value_name = "IPv4")]
    pub src_addr: Option<String>,

    /// Pin the UDP source port. Default ephemeral.
    #[arg(long = "src-port", value_name = "PORT")]
    pub src_port: Option<u16>,

    /// Hex+ASCII dump of the encoded SNMP message to stderr immediately before send.
    #[arg(long = "debug-print-pdu", default_value_t = false)]
    pub debug_print_pdu: bool,

    /// AGENT — destination, accepted as host, host:port, or udp:host:port.
    #[arg(value_name = "AGENT", required = true)]
    pub agent: String,

    /// Trap-shape positional arguments, version-dependent. See README.
    #[arg(value_name = "TRAP-ARGS", trailing_var_arg = true)]
    pub trap_args: Vec<String>,
}

impl Cli {
    /// Parse from CLI argv (used by main); errors as `Error::Usage`.
    pub fn parse_argv() -> Result<Self, Error> {
        match <Self as Parser>::try_parse() {
            Ok(cli) => cli.validate(),
            Err(e) => match e.kind() {
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion => {
                    let _ = e.print();
                    std::process::exit(0);
                }
                _ => Err(Error::Usage(e.to_string())),
            },
        }
    }

    /// Parse from an explicit argv slice; used by tests.
    pub fn parse_from_iter<I, T>(iter: I) -> Result<Self, Error>
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        match <Self as Parser>::try_parse_from(iter) {
            Ok(cli) => cli.validate(),
            Err(e) => Err(Error::Usage(e.to_string())),
        }
    }

    fn validate(self) -> Result<Self, Error> {
        if self.community.is_empty() {
            return Err(Error::Usage(
                "community string (-c) must be non-empty for SNMPv1 and SNMPv2c".into(),
            ));
        }
        if self.timeout == 0 {
            return Err(Error::Usage("--timeout must be > 0 (in seconds)".into()));
        }
        if matches!(self.src_port, Some(0)) {
            return Err(Error::Usage(
                "--src-port 0 is not allowed; on UDP it means 'kernel-selected ephemeral'. Omit the flag to get an ephemeral port.".into(),
            ));
        }
        if let Some(s) = self.src_addr.as_deref() {
            match s.parse::<IpAddr>() {
                Ok(IpAddr::V4(_)) => {}
                Ok(IpAddr::V6(_)) => {
                    return Err(Error::Usage(
                        "--src-addr accepts IPv4 only; IPv6 source spoofing is not supported"
                            .into(),
                    ));
                }
                Err(_) => {
                    return Err(Error::Usage(format!(
                        "--src-addr must be a valid IPv4 literal, got '{s}'"
                    )));
                }
            }
        }
        Ok(self)
    }

    /// Resolve `agent` to an IPv4 SocketAddr. Accepts `host`, `host:port`, `udp:host:port`.
    pub fn resolve_agent(&self) -> Result<SocketAddrV4, Error> {
        resolve_agent_string(&self.agent)
    }

    pub fn src_addr_v4(&self) -> Option<Ipv4Addr> {
        self.src_addr
            .as_deref()
            .and_then(|s| s.parse::<Ipv4Addr>().ok())
    }
}

pub(crate) fn resolve_agent_string(agent: &str) -> Result<SocketAddrV4, Error> {
    let stripped = agent.strip_prefix("udp:").unwrap_or(agent);

    if stripped.starts_with('[') || stripped.matches(':').count() >= 2 {
        return Err(Error::Usage(format!(
            "AGENT '{agent}' looks like IPv6; only IPv4 destinations are supported"
        )));
    }

    let (host, port) = match stripped.rsplit_once(':') {
        Some((h, p)) if !h.is_empty() && !h.contains(':') => {
            let port: u16 = p
                .parse()
                .map_err(|_| Error::Usage(format!("invalid port in AGENT: {agent}")))?;
            (h, port)
        }
        _ => (stripped, DEFAULT_TRAP_PORT),
    };

    let mut addrs = (host, port)
        .to_socket_addrs()
        .map_err(|e| Error::Usage(format!("could not resolve AGENT '{agent}': {e}")))?;
    let v4 = addrs.find_map(|sa| match sa {
        std::net::SocketAddr::V4(v4) => Some(v4),
        _ => None,
    });
    v4.ok_or_else(|| {
        Error::Usage(format!(
            "AGENT '{agent}' did not resolve to any IPv4 address"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(args: &[&str]) -> Result<Cli, Error> {
        let mut full = vec!["snmptrap-rs"];
        full.extend_from_slice(args);
        Cli::parse_from_iter(full)
    }

    #[test]
    fn minimal_v2c_invocation_accepted() {
        let cli = p(&[
            "-v",
            "2c",
            "-c",
            "public",
            "127.0.0.1",
            "",
            "1.3.6.1.6.3.1.1.5.1",
        ])
        .unwrap();
        assert_eq!(cli.version, SnmpVersion::V2c);
        assert_eq!(cli.community, "public");
        assert_eq!(cli.agent, "127.0.0.1");
    }

    #[test]
    fn minimal_v1_invocation_accepted() {
        let cli = p(&["-v", "1", "-c", "public", "127.0.0.1", "", "", "6", "0", ""]).unwrap();
        assert_eq!(cli.version, SnmpVersion::V1);
        assert_eq!(cli.trap_args.len(), 5);
    }

    #[test]
    fn missing_version_rejected() {
        let err = p(&["-c", "public", "127.0.0.1"]).unwrap_err();
        match err {
            Error::Usage(msg) => {
                assert!(
                    msg.contains("--snmp-version")
                        || msg.contains("-v")
                        || msg.contains("required"),
                    "unexpected message: {msg}"
                );
            }
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn unknown_flag_rejected() {
        let err = p(&[
            "-v",
            "2c",
            "-c",
            "public",
            "--not-a-flag",
            "127.0.0.1",
            "",
            "1.3.6.1.6.3.1.1.5.1",
        ])
        .unwrap_err();
        match err {
            Error::Usage(msg) => assert!(msg.contains("not-a-flag"), "msg: {msg}"),
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn ipv6_in_src_addr_rejected() {
        let err = p(&[
            "-v",
            "2c",
            "-c",
            "public",
            "--src-addr",
            "2001:db8::1",
            "127.0.0.1",
            "",
            "1.3.6.1.6.3.1.1.5.1",
        ])
        .unwrap_err();
        match err {
            Error::Usage(msg) => {
                assert!(
                    msg.contains("IPv6") || msg.contains("IPv4 only"),
                    "msg: {msg}"
                );
            }
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn empty_community_rejected() {
        let err = p(&["-v", "2c", "-c", "", "127.0.0.1", "", "1.3.6.1.6.3.1.1.5.1"]).unwrap_err();
        match err {
            Error::Usage(msg) => assert!(msg.contains("community"), "msg: {msg}"),
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn agent_resolution_accepts_host_only() {
        let sa = resolve_agent_string("127.0.0.1").unwrap();
        assert_eq!(sa.ip(), &Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(sa.port(), 162);
    }

    #[test]
    fn agent_resolution_accepts_host_port() {
        let sa = resolve_agent_string("127.0.0.1:1620").unwrap();
        assert_eq!(sa.port(), 1620);
    }

    #[test]
    fn agent_resolution_accepts_udp_prefix() {
        let sa = resolve_agent_string("udp:127.0.0.1:1620").unwrap();
        assert_eq!(sa.ip(), &Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(sa.port(), 1620);
    }

    #[test]
    fn ipv4_in_src_addr_accepted() {
        let cli = p(&[
            "-v",
            "2c",
            "-c",
            "public",
            "--src-addr",
            "198.51.100.42",
            "127.0.0.1",
            "",
            "1.3.6.1.6.3.1.1.5.1",
        ])
        .unwrap();
        assert_eq!(cli.src_addr_v4(), Some(Ipv4Addr::new(198, 51, 100, 42)));
    }

    #[test]
    fn invalid_src_addr_rejected() {
        let err = p(&[
            "-v",
            "2c",
            "-c",
            "public",
            "--src-addr",
            "not-an-ip",
            "127.0.0.1",
            "",
            "1.3.6.1.6.3.1.1.5.1",
        ])
        .unwrap_err();
        match err {
            Error::Usage(msg) => assert!(msg.contains("--src-addr"), "msg: {msg}"),
            other => panic!("expected Usage, got {other:?}"),
        }
    }
}
