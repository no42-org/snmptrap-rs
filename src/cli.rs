use std::net::{IpAddr, Ipv4Addr, SocketAddrV4, ToSocketAddrs};

use clap::Parser;

use crate::error::Error;
use crate::usm::{AuthProtocol, MIN_USM_PASSWORD_LEN, PrivProtocol};

const DEFAULT_TRAP_PORT: u16 = 162;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnmpVersion {
    V1,
    V2c,
    V3,
}

impl std::str::FromStr for SnmpVersion {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "1" => Ok(Self::V1),
            "2c" => Ok(Self::V2c),
            "3" => Ok(Self::V3),
            other => Err(Error::Usage(format!(
                "unsupported SNMP version '{other}'; supported: 1, 2c, 3"
            ))),
        }
    }
}

/// SNMPv3 USM security level. Net-SNMP names accepted case-insensitively.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLevel {
    NoAuthNoPriv,
    AuthNoPriv,
    AuthPriv,
}

impl std::str::FromStr for SecurityLevel {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "noauthnopriv" => Ok(Self::NoAuthNoPriv),
            "authnopriv" => Ok(Self::AuthNoPriv),
            "authpriv" => Ok(Self::AuthPriv),
            _ => Err(Error::Usage(format!(
                "unknown security level '{s}'; supported: noAuthNoPriv, authNoPriv, authPriv"
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

    /// SNMP version: 1, 2c, or 3.
    #[arg(
        short = 'v',
        long = "snmp-version",
        value_name = "VERSION",
        required = true
    )]
    pub version: SnmpVersion,

    /// Community string. Required for SNMPv1/v2c; silently ignored under v3
    /// (USM replaces community-string auth).
    #[arg(
        short = 'c',
        long = "community",
        value_name = "COMMUNITY",
        default_value = ""
    )]
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

    // ---------- SNMPv3 USM flags (Net-SNMP -3* family) ----------
    //
    // All optional in clap; conditional requirements (e.g. -u under -v 3)
    // are enforced post-parse in `validate()`. Accepting v3 flags under
    // -v 1 / -v 2c is also rejected post-parse.
    /// SNMPv3 security level: noAuthNoPriv, authNoPriv, or authPriv.
    /// Defaults to noAuthNoPriv when -v 3 and -l is omitted (matches Net-SNMP).
    #[arg(short = 'l', long = "security-level", value_name = "LEVEL")]
    pub security_level: Option<SecurityLevel>,

    /// SNMPv3 USM user name. Required when -v 3.
    #[arg(short = 'u', long = "user", value_name = "USER")]
    pub user_name: Option<String>,

    /// SNMPv3 auth protocol: SHA, SHA-224, SHA-256, SHA-384, or SHA-512.
    /// HMAC-MD5 is rejected at parse time (RFC 7860 modern-only).
    /// Required when -l is authNoPriv or authPriv.
    #[arg(short = 'a', long = "auth-protocol", value_name = "AUTH-PROTO")]
    pub auth_protocol: Option<AuthProtocol>,

    /// SNMPv3 auth password (≥8 chars per RFC 3414 §11.2). Required when -a
    /// is set. WARNING: passed via argv — visible in process listings and
    /// shell history. Use a dedicated test/sandbox account, not production.
    #[arg(short = 'A', long = "auth-password", value_name = "AUTH-PASS")]
    pub auth_password: Option<String>,

    /// SNMPv3 priv protocol: AES, AES-192, or AES-256. DES-CBC and 3DES-CBC
    /// are rejected at parse time. Required when -l is authPriv.
    #[arg(short = 'x', long = "priv-protocol", value_name = "PRIV-PROTO")]
    pub priv_protocol: Option<PrivProtocol>,

    /// SNMPv3 priv password (≥8 chars). Required when -x is set. Same argv
    /// caveat as -A.
    #[arg(short = 'X', long = "priv-password", value_name = "PRIV-PASS")]
    pub priv_password: Option<String>,

    /// SNMPv3 context engine ID (hex, with or without `0x` prefix; `:` /
    /// whitespace separators allowed). Defaults to the authoritative
    /// engine ID.
    #[arg(short = 'e', long = "context-engine-id", value_name = "ENGINE-ID")]
    pub context_engine_id: Option<String>,

    /// SNMPv3 authoritative engine ID (hex, same format as -e). Defaults
    /// per the engine-ID resolve cascade: `--src-addr` IPv4 → host MAC →
    /// hostname.
    #[arg(
        short = 'E',
        long = "authoritative-engine-id",
        value_name = "ENGINE-ID"
    )]
    pub authoritative_engine_id: Option<String>,

    /// SNMPv3 context name. Defaults to empty.
    #[arg(short = 'n', long = "context-name", value_name = "CONTEXT")]
    pub context_name: Option<String>,

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

    fn validate(mut self) -> Result<Self, Error> {
        // v1/v2c require a non-empty community. Under v3, community is
        // silently ignored — RFC 3414 USM replaces it.
        if self.version != SnmpVersion::V3 && self.community.is_empty() {
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

        // v3 flag scoping: any -3* / -l / -u / -e / -E / -n / -a / -A / -x / -X
        // set under -v 1 or -v 2c is a usage error.
        self.validate_v3_flag_scope()?;

        if self.version == SnmpVersion::V3 {
            // Default -l to noAuthNoPriv if omitted (matches Net-SNMP).
            if self.security_level.is_none() {
                self.security_level = Some(SecurityLevel::NoAuthNoPriv);
            }
            self.validate_v3_required()?;
        }

        Ok(self)
    }

    /// Reject any v3-specific flag set when the version is v1 or v2c.
    fn validate_v3_flag_scope(&self) -> Result<(), Error> {
        if self.version == SnmpVersion::V3 {
            return Ok(());
        }
        let v_label = match self.version {
            SnmpVersion::V1 => "-v 1",
            SnmpVersion::V2c => "-v 2c",
            SnmpVersion::V3 => unreachable!(),
        };
        let pairs: &[(&str, bool)] = &[
            ("-l/--security-level", self.security_level.is_some()),
            ("-u/--user", self.user_name.is_some()),
            ("-a/--auth-protocol", self.auth_protocol.is_some()),
            ("-A/--auth-password", self.auth_password.is_some()),
            ("-x/--priv-protocol", self.priv_protocol.is_some()),
            ("-X/--priv-password", self.priv_password.is_some()),
            ("-e/--context-engine-id", self.context_engine_id.is_some()),
            (
                "-E/--authoritative-engine-id",
                self.authoritative_engine_id.is_some(),
            ),
            ("-n/--context-name", self.context_name.is_some()),
        ];
        for (flag, present) in pairs {
            if *present {
                return Err(Error::Usage(format!(
                    "{flag} is an SNMPv3 flag and is not valid with {v_label}"
                )));
            }
        }
        Ok(())
    }

    /// Enforce conditional requirements once `-v 3` is selected.
    fn validate_v3_required(&self) -> Result<(), Error> {
        let level = self.security_level.expect("defaulted in validate()");

        if self.user_name.as_deref().is_none_or(str::is_empty) {
            return Err(Error::Usage(
                "-u <USER> is required with -v 3 (USM identifies the sender by user name)".into(),
            ));
        }

        match level {
            SecurityLevel::NoAuthNoPriv => {
                // Auth/priv flags are not required, but if provided are pointless;
                // accept silently rather than reject (matches Net-SNMP leniency).
            }
            SecurityLevel::AuthNoPriv => {
                require_some(&self.auth_protocol, "-a", "authNoPriv")?;
                require_password(&self.auth_password, "-A", "authNoPriv")?;
            }
            SecurityLevel::AuthPriv => {
                require_some(&self.auth_protocol, "-a", "authPriv")?;
                require_password(&self.auth_password, "-A", "authPriv")?;
                require_some(&self.priv_protocol, "-x", "authPriv")?;
                require_password(&self.priv_password, "-X", "authPriv")?;
            }
        }
        Ok(())
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

fn require_some<T>(value: &Option<T>, flag: &str, level: &str) -> Result<(), Error> {
    if value.is_none() {
        Err(Error::Usage(format!("{flag} is required with -l {level}")))
    } else {
        Ok(())
    }
}

fn require_password(value: &Option<String>, flag: &str, level: &str) -> Result<(), Error> {
    // Enforce the RFC 3414 §11.2 ≥8-char floor at the CLI layer so the user
    // sees the error close to what they typed, instead of failing far inside
    // build_v3_payload's `password_to_key` call. The doc-comments on -A/-X
    // already cite this requirement.
    match value.as_deref() {
        None => Err(Error::Usage(format!("{flag} is required with -l {level}"))),
        Some("") => Err(Error::Usage(format!("{flag} must be a non-empty password"))),
        Some(s) if s.len() < MIN_USM_PASSWORD_LEN => Err(Error::Usage(format!(
            "{flag} must be at least {MIN_USM_PASSWORD_LEN} characters (RFC 3414 §11.2); got {}",
            s.len()
        ))),
        Some(_) => Ok(()),
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

    // ---------- SNMPv3 CLI parsing + validation ----------

    #[test]
    fn v3_minimal_no_auth_no_priv_accepted() {
        let cli = p(&[
            "-v",
            "3",
            "-u",
            "testuser",
            "127.0.0.1",
            "",
            "1.3.6.1.6.3.1.1.5.1",
        ])
        .unwrap();
        assert_eq!(cli.version, SnmpVersion::V3);
        assert_eq!(cli.user_name.as_deref(), Some("testuser"));
        // -l defaults to noAuthNoPriv when -v 3 and -l omitted (Net-SNMP-compat).
        assert_eq!(cli.security_level, Some(SecurityLevel::NoAuthNoPriv));
    }

    #[test]
    fn v3_security_level_is_case_insensitive() {
        let cli = p(&[
            "-v",
            "3",
            "-u",
            "u",
            "-l",
            "AuthPriv",
            "-a",
            "SHA-256",
            "-A",
            "passw0rd",
            "-x",
            "AES",
            "-X",
            "passw0rd",
            "127.0.0.1",
            "",
            "1.3.6.1.6.3.1.1.5.1",
        ])
        .unwrap();
        assert_eq!(cli.security_level, Some(SecurityLevel::AuthPriv));
    }

    #[test]
    fn v3_user_required() {
        let err = p(&["-v", "3", "127.0.0.1", "", "1.3.6.1.6.3.1.1.5.1"]).unwrap_err();
        match err {
            Error::Usage(msg) => {
                assert!(msg.contains("-u") && msg.contains("required"), "msg: {msg}")
            }
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn v3_authnopriv_requires_a_and_uppercase_a() {
        let err = p(&[
            "-v",
            "3",
            "-u",
            "u",
            "-l",
            "authNoPriv",
            "127.0.0.1",
            "",
            "1.3.6.1.6.3.1.1.5.1",
        ])
        .unwrap_err();
        match err {
            Error::Usage(msg) => assert!(msg.contains("-a"), "msg: {msg}"),
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn v3_authpriv_requires_x_and_uppercase_x() {
        let err = p(&[
            "-v",
            "3",
            "-u",
            "u",
            "-l",
            "authPriv",
            "-a",
            "SHA-256",
            "-A",
            "passw0rd",
            "127.0.0.1",
            "",
            "1.3.6.1.6.3.1.1.5.1",
        ])
        .unwrap_err();
        match err {
            Error::Usage(msg) => assert!(msg.contains("-x"), "msg: {msg}"),
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn v3_md5_rejected_at_parse() {
        let err = p(&[
            "-v",
            "3",
            "-u",
            "u",
            "-l",
            "authNoPriv",
            "-a",
            "MD5",
            "-A",
            "passw0rd",
            "127.0.0.1",
            "",
            "1.3.6.1.6.3.1.1.5.1",
        ])
        .unwrap_err();
        match err {
            Error::Usage(msg) => assert!(msg.contains("HMAC-MD5"), "msg: {msg}"),
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn v3_des_rejected_at_parse() {
        let err = p(&[
            "-v",
            "3",
            "-u",
            "u",
            "-l",
            "authPriv",
            "-a",
            "SHA-256",
            "-A",
            "passw0rd",
            "-x",
            "DES",
            "-X",
            "passw0rd",
            "127.0.0.1",
            "",
            "1.3.6.1.6.3.1.1.5.1",
        ])
        .unwrap_err();
        match err {
            Error::Usage(msg) => assert!(msg.contains("DES-CBC"), "msg: {msg}"),
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn v3_flag_rejected_under_v2c() {
        let err = p(&[
            "-v",
            "2c",
            "-c",
            "public",
            "-u",
            "testuser",
            "127.0.0.1",
            "",
            "1.3.6.1.6.3.1.1.5.1",
        ])
        .unwrap_err();
        match err {
            Error::Usage(msg) => {
                assert!(msg.contains("-u") && msg.contains("-v 2c"), "msg: {msg}");
            }
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn v3_silently_ignores_community() {
        // -c is permitted under v3 (Net-SNMP behavior); validate doesn't reject.
        let cli = p(&[
            "-v",
            "3",
            "-c",
            "ignored-by-v3",
            "-u",
            "testuser",
            "127.0.0.1",
            "",
            "1.3.6.1.6.3.1.1.5.1",
        ])
        .unwrap();
        assert_eq!(cli.community, "ignored-by-v3");
    }

    #[test]
    fn v3_short_auth_password_rejected_at_cli() {
        // < 8 chars must be rejected at the CLI layer — not deferred to
        // password_to_key. Surface the error close to user input.
        let err = p(&[
            "-v",
            "3",
            "-u",
            "u",
            "-l",
            "authNoPriv",
            "-a",
            "SHA-256",
            "-A",
            "short",
            "127.0.0.1",
            "",
            "1.3.6.1.6.3.1.1.5.1",
        ])
        .unwrap_err();
        match err {
            Error::Usage(msg) => {
                assert!(msg.contains("at least 8"), "msg: {msg}");
                assert!(msg.contains("RFC 3414"), "msg: {msg}");
                assert!(msg.contains("-A"), "msg: {msg}");
            }
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn v3_short_priv_password_rejected_at_cli() {
        let err = p(&[
            "-v",
            "3",
            "-u",
            "u",
            "-l",
            "authPriv",
            "-a",
            "SHA-256",
            "-A",
            "auth-passw0rd",
            "-x",
            "AES",
            "-X",
            "tiny",
            "127.0.0.1",
            "",
            "1.3.6.1.6.3.1.1.5.1",
        ])
        .unwrap_err();
        match err {
            Error::Usage(msg) => {
                assert!(msg.contains("at least 8"), "msg: {msg}");
                assert!(msg.contains("-X"), "msg: {msg}");
            }
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    #[test]
    fn v3_authpriv_full_inputs_parse() {
        let cli = p(&[
            "-v",
            "3",
            "-u",
            "alice",
            "-l",
            "authPriv",
            "-a",
            "SHA-256",
            "-A",
            "auth-passw0rd",
            "-x",
            "AES-128",
            "-X",
            "priv-passw0rd",
            "-E",
            "80001f88010203040506",
            "-n",
            "ctx",
            "127.0.0.1",
            "",
            "1.3.6.1.6.3.1.1.5.1",
        ])
        .unwrap();
        assert_eq!(cli.user_name.as_deref(), Some("alice"));
        assert_eq!(cli.security_level, Some(SecurityLevel::AuthPriv));
        assert_eq!(cli.auth_protocol, Some(AuthProtocol::Sha256));
        assert_eq!(cli.priv_protocol, Some(PrivProtocol::Aes128));
        assert_eq!(
            cli.authoritative_engine_id.as_deref(),
            Some("80001f88010203040506")
        );
        assert_eq!(cli.context_name.as_deref(), Some("ctx"));
    }
}
