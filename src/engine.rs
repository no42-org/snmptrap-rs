//! SNMPv3 engine-ID handling per RFC 3411 §5.
//!
//! The first four octets carry IANA Private Enterprise Number 61509
//! (assigned to no42.org), with the high bit of octet 0 set per the RFC.
//! Octet 4 is a format selector; octets 5..N are format-specific.
//!
//! Default-resolution cascade (design.md D3):
//!     1. `-E ENGINE-ID` user override → use verbatim.
//!     2. `--src-addr X` → RFC 3411 format 1 (IPv4), payload = X big-endian.
//!     3. host primary-interface MAC → format 3 (MAC).
//!     4. fallback → format 4 (text), payload = hostname truncated to fit.

use std::net::Ipv4Addr;

/// IANA Private Enterprise Number 61509, assigned to no42.org.
pub const PEN_NO42_ORG: u32 = 61509;

const FORMAT_IPV4: u8 = 1;
const FORMAT_MAC: u8 = 3;
const FORMAT_TEXT: u8 = 4;
const FORMAT_OCTETS: u8 = 5;

/// RFC 3411 §5: engine-ID is between 5 and 32 octets total. Octets 5..N are at most 27.
const MIN_ENGINE_ID: usize = 5;
const MAX_ENGINE_ID: usize = 32;
const MAX_PAYLOAD: usize = MAX_ENGINE_ID - 5;

/// Linux network-interface name prefixes that don't carry a stable host MAC —
/// docker bridges resynthesize per daemon restart, bonded slaves get the
/// bond's MAC after enslavement, tunnels and WireGuard use synthetic MACs,
/// container CNI plugins create ephemeral `veth*` pairs, etc. Skipping these
/// in `host_mac()` keeps engine-ID stable on developer workstations.
#[cfg(target_os = "linux")]
const VIRTUAL_INTERFACE_PREFIXES: &[&str] = &[
    "docker", "br-", "bond", "virbr", "veth", "tun", "tap", "wg", "cni", "kube", "flannel",
    "cilium", "ovs", "dummy", "vboxnet", "vmnet",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineId(Vec<u8>);

impl EngineId {
    /// RFC 3411 §5 format 1 (IPv4). 9 octets total.
    pub fn from_ipv4(addr: Ipv4Addr) -> Self {
        let mut buf = Vec::with_capacity(9);
        Self::push_pen_prefix(&mut buf);
        buf.push(FORMAT_IPV4);
        buf.extend_from_slice(&addr.octets());
        Self(buf)
    }

    /// RFC 3411 §5 format 3 (MAC). 11 octets total.
    pub fn from_mac(mac: [u8; 6]) -> Self {
        let mut buf = Vec::with_capacity(11);
        Self::push_pen_prefix(&mut buf);
        buf.push(FORMAT_MAC);
        buf.extend_from_slice(&mac);
        Self(buf)
    }

    /// RFC 3411 §5 format 4 (text). Truncates the payload to fit MAX_ENGINE_ID.
    pub fn from_text(text: &str) -> Self {
        let bytes = text.as_bytes();
        let take = bytes.len().min(MAX_PAYLOAD);
        let mut buf = Vec::with_capacity(5 + take);
        Self::push_pen_prefix(&mut buf);
        buf.push(FORMAT_TEXT);
        buf.extend_from_slice(&bytes[..take]);
        Self(buf)
    }

    /// RFC 3411 §5 format 5 (admin-defined octets). Truncates to fit.
    pub fn from_octets(octets: &[u8]) -> Self {
        let take = octets.len().min(MAX_PAYLOAD);
        let mut buf = Vec::with_capacity(5 + take);
        Self::push_pen_prefix(&mut buf);
        buf.push(FORMAT_OCTETS);
        buf.extend_from_slice(&octets[..take]);
        Self(buf)
    }

    /// Parse a user-supplied engine-ID from CLI input.
    ///
    /// Accepts:
    /// - hex digits with or without `0x`/`0X` prefix
    /// - `:` or ASCII-whitespace separators
    ///
    /// Stored verbatim (no PEN-prefix re-application — the user is in charge).
    pub fn parse_user_input(s: &str) -> Result<Self, EngineIdParseError> {
        let trimmed = s.trim();
        let body = trimmed
            .strip_prefix("0x")
            .or_else(|| trimmed.strip_prefix("0X"))
            .unwrap_or(trimmed);
        let cleaned: String = body
            .chars()
            .filter(|c| !c.is_ascii_whitespace() && *c != ':')
            .collect();

        if cleaned.is_empty() {
            return Err(EngineIdParseError::Empty);
        }
        // Cheap up-front length check — avoids an O(n) parse on hostile-but-bounded
        // argv input. Real bound is checked again post-decode below.
        if cleaned.len() > MAX_ENGINE_ID * 2 {
            return Err(EngineIdParseError::TooLong {
                got: cleaned.len() / 2,
                max: MAX_ENGINE_ID,
            });
        }
        if !cleaned.len().is_multiple_of(2) {
            return Err(EngineIdParseError::OddLength { got: cleaned.len() });
        }

        let mut bytes = Vec::with_capacity(cleaned.len() / 2);
        let cleaned_bytes = cleaned.as_bytes();
        for chunk in cleaned_bytes.chunks_exact(2) {
            let hi = decode_hex_nibble(chunk[0])?;
            let lo = decode_hex_nibble(chunk[1])?;
            bytes.push((hi << 4) | lo);
        }

        if bytes.len() < MIN_ENGINE_ID {
            return Err(EngineIdParseError::TooShort {
                got: bytes.len(),
                min: MIN_ENGINE_ID,
            });
        }
        if bytes.len() > MAX_ENGINE_ID {
            return Err(EngineIdParseError::TooLong {
                got: bytes.len(),
                max: MAX_ENGINE_ID,
            });
        }

        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Push the four-octet PEN prefix with the high bit set on octet 0.
    /// For PEN 61509 (0x0000F045), produces `[0x80, 0x00, 0xF0, 0x45]`.
    fn push_pen_prefix(buf: &mut Vec<u8>) {
        let pen_bytes = PEN_NO42_ORG.to_be_bytes();
        buf.push(pen_bytes[0] | 0x80);
        buf.push(pen_bytes[1]);
        buf.push(pen_bytes[2]);
        buf.push(pen_bytes[3]);
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EngineIdParseError {
    #[error("engine-ID is empty")]
    Empty,
    #[error("engine-ID is {got} octets long, RFC 3411 §5 requires at least {min}")]
    TooShort { got: usize, min: usize },
    #[error("engine-ID hex string has odd length ({got} chars)")]
    OddLength { got: usize },
    #[error("engine-ID contains non-hex character '{ch}'")]
    BadHex { ch: char },
    #[error("engine-ID is {got} octets long, max is {max}")]
    TooLong { got: usize, max: usize },
}

fn decode_hex_nibble(b: u8) -> Result<u8, EngineIdParseError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        other => Err(EngineIdParseError::BadHex { ch: other as char }),
    }
}

/// Read the primary network interface's MAC address.
///
/// **Linux**: walks `/sys/class/net/*/address`, picks the first non-loopback,
/// non-zero MAC. Pure file I/O — no syscalls, no extra deps.
///
/// **macOS**: not yet implemented; returns `None`. The resolve cascade then
/// falls through to the text/hostname format. Production macOS users who care
/// about engine-ID stability can pass `-E` directly. Linking against
/// `getifaddrs()` for full macOS MAC discovery is a follow-up.
pub fn host_mac() -> Option<[u8; 6]> {
    #[cfg(target_os = "linux")]
    {
        host_mac_linux()
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

#[cfg(target_os = "linux")]
fn host_mac_linux() -> Option<[u8; 6]> {
    let entries = std::fs::read_dir("/sys/class/net").ok()?;
    let mut candidates: Vec<String> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|name| name != "lo" && !is_virtual_interface(name))
        .collect();
    // Two-tier ordering: physical-looking prefixes (`en*`, `eth*`, `wl*`)
    // first, alphabetical within each tier. This keeps engine-ID stable on
    // hosts where docker/virbr/etc. have been filtered already, but still
    // works on hosts with non-conventional names by falling through to the
    // alphabetic tail.
    candidates.sort_by(|a, b| {
        let pa = is_physical_prefix(a);
        let pb = is_physical_prefix(b);
        pb.cmp(&pa).then_with(|| a.cmp(b))
    });

    for name in candidates {
        let path = format!("/sys/class/net/{name}/address");
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Some(mac) = parse_mac_text(text.trim()) else {
            continue;
        };
        if mac == [0u8; 6] {
            continue;
        }
        return Some(mac);
    }
    None
}

#[cfg(target_os = "linux")]
fn is_virtual_interface(name: &str) -> bool {
    VIRTUAL_INTERFACE_PREFIXES
        .iter()
        .any(|p| name.starts_with(p))
}

#[cfg(target_os = "linux")]
fn is_physical_prefix(name: &str) -> bool {
    name.starts_with("en") || name.starts_with("eth") || name.starts_with("wl")
}

#[cfg(target_os = "linux")]
fn parse_mac_text(s: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut out = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        if p.len() != 2 {
            return None;
        }
        let bytes = p.as_bytes();
        let hi = decode_hex_nibble(bytes[0]).ok()?;
        let lo = decode_hex_nibble(bytes[1]).ok()?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

/// Resolve the authoritative engine-ID per the design D3 cascade.
///
/// Inputs are pre-parsed CLI values, so this function has no dependency on
/// the `cli` module — caller does the parsing.
pub fn resolve(user_authoritative: Option<&EngineId>, src_addr_v4: Option<Ipv4Addr>) -> EngineId {
    if let Some(eid) = user_authoritative {
        return eid.clone();
    }
    if let Some(addr) = src_addr_v4 {
        return EngineId::from_ipv4(addr);
    }
    if let Some(mac) = host_mac() {
        return EngineId::from_mac(mac);
    }
    let hostname = host_name().unwrap_or_else(|| "snmptrap-rs".to_string());
    EngineId::from_text(&hostname)
}

/// Best-effort hostname read. Returns `None` if the syscall fails or the
/// hostname is empty / not valid UTF-8.
fn host_name() -> Option<String> {
    let mut buf = vec![0u8; 256];
    // SAFETY: gethostname writes at most `buf.len()` bytes (including NUL) into
    // the buffer, returns 0 on success, -1 on error. We pass a buffer we own.
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
    if rc != 0 {
        return None;
    }
    let nul = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    let s = std::str::from_utf8(&buf[..nul]).ok()?;
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pen_prefix_bytes() {
        let mut buf = Vec::new();
        EngineId::push_pen_prefix(&mut buf);
        // PEN 61509 = 0x0000F045; high bit on octet 0 → 0x80 0x00 0xF0 0x45.
        assert_eq!(buf, vec![0x80, 0x00, 0xF0, 0x45]);
    }

    #[test]
    fn from_ipv4_layout() {
        let eid = EngineId::from_ipv4("198.51.100.42".parse().unwrap());
        assert_eq!(
            eid.as_bytes(),
            &[0x80, 0x00, 0xF0, 0x45, 0x01, 0xC6, 0x33, 0x64, 0x2A]
        );
        assert_eq!(eid.len(), 9);
    }

    #[test]
    fn from_mac_layout() {
        let eid = EngineId::from_mac([0xDE, 0xAD, 0xBE, 0xEF, 0x12, 0x34]);
        assert_eq!(
            eid.as_bytes(),
            &[
                0x80, 0x00, 0xF0, 0x45, 0x03, 0xDE, 0xAD, 0xBE, 0xEF, 0x12, 0x34
            ]
        );
        assert_eq!(eid.len(), 11);
    }

    #[test]
    fn from_text_layout() {
        let eid = EngineId::from_text("host42");
        assert_eq!(
            eid.as_bytes(),
            &[
                0x80, 0x00, 0xF0, 0x45, 0x04, b'h', b'o', b's', b't', b'4', b'2'
            ]
        );
    }

    #[test]
    fn from_text_truncates_to_max_payload() {
        let long = "a".repeat(MAX_PAYLOAD + 10);
        let eid = EngineId::from_text(&long);
        assert_eq!(eid.len(), 5 + MAX_PAYLOAD); // == MAX_ENGINE_ID
    }

    #[test]
    fn from_octets_layout() {
        let eid = EngineId::from_octets(&[0x01, 0x02, 0x03]);
        assert_eq!(
            eid.as_bytes(),
            &[0x80, 0x00, 0xF0, 0x45, 0x05, 0x01, 0x02, 0x03]
        );
    }

    #[test]
    fn parse_user_input_plain_hex() {
        let eid = EngineId::parse_user_input("80001f88010203").unwrap();
        assert_eq!(eid.as_bytes(), &[0x80, 0x00, 0x1F, 0x88, 0x01, 0x02, 0x03]);
    }

    #[test]
    fn parse_user_input_with_0x_prefix() {
        let eid = EngineId::parse_user_input("0x80001f88010203").unwrap();
        assert_eq!(eid.as_bytes(), &[0x80, 0x00, 0x1F, 0x88, 0x01, 0x02, 0x03]);
    }

    #[test]
    fn parse_user_input_with_uppercase_0x_prefix() {
        let eid = EngineId::parse_user_input("0X80001F8842").unwrap();
        assert_eq!(eid.as_bytes(), &[0x80, 0x00, 0x1F, 0x88, 0x42]);
    }

    #[test]
    fn parse_user_input_with_colon_separators() {
        let eid = EngineId::parse_user_input("80:00:1f:88:01:02").unwrap();
        assert_eq!(eid.as_bytes(), &[0x80, 0x00, 0x1F, 0x88, 0x01, 0x02]);
    }

    #[test]
    fn parse_user_input_with_whitespace() {
        let eid = EngineId::parse_user_input("80 00 1f 88 42").unwrap();
        assert_eq!(eid.as_bytes(), &[0x80, 0x00, 0x1F, 0x88, 0x42]);
    }

    #[test]
    fn parse_user_input_rejects_empty() {
        assert!(matches!(
            EngineId::parse_user_input(""),
            Err(EngineIdParseError::Empty)
        ));
        assert!(matches!(
            EngineId::parse_user_input("   "),
            Err(EngineIdParseError::Empty)
        ));
    }

    #[test]
    fn parse_user_input_rejects_odd_length() {
        assert!(matches!(
            EngineId::parse_user_input("abc"),
            Err(EngineIdParseError::OddLength { got: 3 })
        ));
    }

    #[test]
    fn parse_user_input_rejects_garbage() {
        assert!(matches!(
            EngineId::parse_user_input("zzzz"),
            Err(EngineIdParseError::BadHex { .. })
        ));
    }

    #[test]
    fn parse_user_input_rejects_too_long() {
        let s: String = (0..50).map(|_| "ab").collect(); // 100 hex → 50 bytes
        assert!(matches!(
            EngineId::parse_user_input(&s),
            Err(EngineIdParseError::TooLong { got: 50, max: 32 })
        ));
    }

    #[test]
    fn parse_user_input_rejects_too_short() {
        // RFC 3411 §5: snmpEngineID is 5..32 octets. 4 bytes is wire-invalid.
        assert!(matches!(
            EngineId::parse_user_input("01020304"),
            Err(EngineIdParseError::TooShort { got: 4, min: 5 })
        ));
    }

    #[test]
    fn parse_user_input_min_length_accepted() {
        // 5 bytes is the RFC 3411 minimum and should round-trip.
        let eid = EngineId::parse_user_input("0102030405").unwrap();
        assert_eq!(eid.as_bytes(), &[0x01, 0x02, 0x03, 0x04, 0x05]);
    }

    #[test]
    fn parse_user_input_rejects_pre_decode_when_overlong() {
        // A hostile-but-legal input that tries to allocate 5 KB before the
        // post-decode length check fires. Pre-decode bound rejects fast.
        let s: String = (0..MAX_ENGINE_ID + 10).map(|_| "ab").collect();
        let err = EngineId::parse_user_input(&s).unwrap_err();
        assert!(matches!(err, EngineIdParseError::TooLong { .. }));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn is_virtual_interface_matches_known_prefixes() {
        for name in [
            "docker0",
            "br-abc123",
            "bond0",
            "virbr0",
            "veth123abc",
            "tun0",
            "tap0",
            "wg0",
            "cni0",
            "kube-bridge",
            "flannel.1",
            "cilium_host",
            "ovs-system",
            "dummy0",
            "vboxnet0",
            "vmnet8",
        ] {
            assert!(is_virtual_interface(name), "expected virtual: {name}");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn is_virtual_interface_does_not_match_physical() {
        for name in ["eth0", "en0", "enp0s3", "ens33", "wlan0", "wlp2s0"] {
            assert!(!is_virtual_interface(name), "expected physical: {name}");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn is_physical_prefix_matches() {
        assert!(is_physical_prefix("eth0"));
        assert!(is_physical_prefix("en0"));
        assert!(is_physical_prefix("enp0s3"));
        assert!(is_physical_prefix("wlan0"));
        assert!(is_physical_prefix("wlp2s0"));
        assert!(!is_physical_prefix("docker0"));
        assert!(!is_physical_prefix("bond0"));
    }

    #[test]
    fn resolve_user_override_wins_over_src_addr() {
        let user = EngineId::parse_user_input("80001fa050000102").unwrap();
        let resolved = resolve(Some(&user), Some("10.0.0.1".parse().unwrap()));
        assert_eq!(resolved, user);
    }

    #[test]
    fn resolve_src_addr_produces_format_1() {
        let resolved = resolve(None, Some("198.51.100.42".parse().unwrap()));
        assert_eq!(resolved.as_bytes()[4], FORMAT_IPV4);
        assert_eq!(&resolved.as_bytes()[5..], &[0xC6, 0x33, 0x64, 0x2A]);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_mac_text_basic() {
        assert_eq!(
            parse_mac_text("de:ad:be:ef:12:34"),
            Some([0xDE, 0xAD, 0xBE, 0xEF, 0x12, 0x34])
        );
        assert_eq!(parse_mac_text("00:00:00:00:00:00"), Some([0u8; 6]));
        assert_eq!(parse_mac_text("not-a-mac"), None);
        assert_eq!(parse_mac_text("de:ad:be:ef:12"), None); // too few segments
    }
}
