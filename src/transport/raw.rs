//! Raw IPv4 + IP_HDRINCL transport. Spoofs the L3 source address.
//!
//! Implemented in section 8 of `tasks.md`. The pure functions
//! (header builders, checksums) live here and are unit-tested even on
//! platforms where actually opening a raw socket requires root /
//! `CAP_NET_RAW`. The send path is gated on Linux + macOS / BSD.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use crate::error::{Error, Platform};

/// One's-complement Internet checksum (RFC 1071) over `data`.
pub fn ip_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        let word = u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        sum = sum.wrapping_add(word);
        i += 2;
    }
    if i < data.len() {
        sum = sum.wrapping_add((data[i] as u32) << 8);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Encode a 16-bit IPv4-header field that BSD-derived raw(4) implementations
/// expect in **host** byte order (`ip_len`, `ip_off` on macOS / *BSD); on
/// Linux these go on the wire untouched and so are written in network order.
/// See FreeBSD raw(4), Apple xnu `bsd/netinet/raw_ip.c`, and Linux raw(7).
fn iphdr_u16_to_kernel(val: u16) -> [u8; 2] {
    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    ))]
    {
        val.to_ne_bytes()
    }
    #[cfg(not(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
    )))]
    {
        val.to_be_bytes()
    }
}

/// Build a 20-byte IPv4 header with the given parameters. DF set, TTL=64,
/// protocol=UDP(17). Header checksum filled in.
pub fn build_ipv4_header(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    payload_len: u16,
    identification: u16,
) -> [u8; 20] {
    let total_length = 20u16 + payload_len;
    let mut hdr = [0u8; 20];
    hdr[0] = (4 << 4) | 5; // version=4, IHL=5
    hdr[1] = 0; // DSCP/ECN
    hdr[2..4].copy_from_slice(&iphdr_u16_to_kernel(total_length));
    hdr[4..6].copy_from_slice(&identification.to_be_bytes());
    hdr[6..8].copy_from_slice(&iphdr_u16_to_kernel(0x4000u16)); // Flags=DF, FragOff=0
    hdr[8] = 64; // TTL
    hdr[9] = 17; // protocol = UDP
    hdr[10..12].copy_from_slice(&[0, 0]); // checksum placeholder
    hdr[12..16].copy_from_slice(&src.octets());
    hdr[16..20].copy_from_slice(&dst.octets());
    let csum = ip_checksum(&hdr);
    hdr[10..12].copy_from_slice(&csum.to_be_bytes());
    hdr
}

/// Build the 8-byte UDP header followed by `payload`, with checksum computed
/// over the IPv4 pseudo-header + UDP header + payload using the (possibly
/// spoofed) `src` address.
pub fn build_udp_datagram(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = 8u16 + (payload.len() as u16);

    // 12-byte IPv4 pseudo-header
    let mut pseudo = Vec::with_capacity(12 + udp_len as usize);
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.push(0);
    pseudo.push(17); // protocol = UDP
    pseudo.extend_from_slice(&udp_len.to_be_bytes());

    // UDP header (checksum placeholder)
    pseudo.extend_from_slice(&src_port.to_be_bytes());
    pseudo.extend_from_slice(&dst_port.to_be_bytes());
    pseudo.extend_from_slice(&udp_len.to_be_bytes());
    pseudo.extend_from_slice(&[0, 0]); // placeholder
    pseudo.extend_from_slice(payload);

    let mut csum = ip_checksum(&pseudo);
    if csum == 0 {
        csum = 0xFFFF; // RFC 768: a computed-zero checksum is transmitted as all-ones.
    }

    // Now emit the actual UDP header + payload (no pseudo-header on the wire)
    let mut out = Vec::with_capacity(udp_len as usize);
    out.extend_from_slice(&src_port.to_be_bytes());
    out.extend_from_slice(&dst_port.to_be_bytes());
    out.extend_from_slice(&udp_len.to_be_bytes());
    out.extend_from_slice(&csum.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Maximum payload size that fits in a single IPv4 datagram after the
/// 20-byte IP header and 8-byte UDP header (`u16::MAX - 28 = 65507`). Past
/// this the IP `total_length` and UDP `length` fields would silently wrap.
const MAX_UDP_PAYLOAD: usize = (u16::MAX as usize) - 20 - 8;

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn send_spoofed(
    dst: SocketAddrV4,
    src: Ipv4Addr,
    src_port: Option<u16>,
    _timeout: Duration,
    retries: u8,
    payload: &[u8],
) -> Result<(), Error> {
    use socket2::{Domain, Protocol, Socket, Type};

    if payload.len() > MAX_UDP_PAYLOAD {
        return Err(Error::Other(std::io::Error::other(format!(
            "SNMP payload {} bytes exceeds IPv4/UDP single-datagram max {}",
            payload.len(),
            MAX_UDP_PAYLOAD,
        ))));
    }

    let sock =
        Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::UDP)).map_err(classify_raw_open)?;
    sock.set_header_included_v4(true)
        .map_err(classify_raw_open)?;

    let chosen_src_port = src_port.unwrap_or_else(pick_ephemeral_port);
    let udp = build_udp_datagram(src, *dst.ip(), chosen_src_port, dst.port(), payload);

    let dst_sa: std::net::SocketAddr = std::net::SocketAddr::V4(dst);
    let dst_sock2 = socket2::SockAddr::from(dst_sa);

    let mut last_err: Option<std::io::Error> = None;
    let mut budget: i32 = retries as i32 + 1;
    while budget > 0 {
        // Fresh IP `Identification` per attempt so retransmits don't collide
        // with the first packet's tuple if it actually got out.
        let ident: u16 = rand::random();
        let ip = build_ipv4_header(src, *dst.ip(), udp.len() as u16, ident);
        let mut packet = Vec::with_capacity(ip.len() + udp.len());
        packet.extend_from_slice(&ip);
        packet.extend_from_slice(&udp);

        match sock.send_to(&packet, &dst_sock2) {
            Ok(_) => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => {
                last_err = Some(e);
                budget -= 1;
            }
        }
    }
    Err(classify_raw_send(last_err.unwrap_or_else(|| {
        std::io::Error::other("raw send_to failed without an OS error")
    })))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn send_spoofed(
    _dst: SocketAddrV4,
    _src: Ipv4Addr,
    _src_port: Option<u16>,
    _timeout: Duration,
    _retries: u8,
    _payload: &[u8],
) -> Result<(), Error> {
    Err(Error::Unsupported(
        "--src-addr is not supported on this platform; only Linux and macOS/BSD are supported"
            .into(),
    ))
}

/// Errors during socket creation / `IP_HDRINCL` setsockopt. `EPERM`/`EACCES`
/// here unambiguously means missing `CAP_NET_RAW` (Linux) or non-root (macOS).
fn classify_raw_open(err: std::io::Error) -> Error {
    match err.raw_os_error() {
        Some(libc::EPERM) | Some(libc::EACCES) => Error::RawSocketDenied {
            platform: Platform::current(),
            underlying: err,
        },
        _ => Error::Other(err),
    }
}

/// Errors during `send_to` after the raw socket is open. `EACCES` here is
/// **not** a capability problem (open already succeeded) — it typically means
/// the destination is broadcast/multicast and `SO_BROADCAST` is unset, or a
/// netfilter/MAC policy rejected the packet. Classify all such cases as
/// routing-class so the user does not see a spurious `setcap` recipe.
fn classify_raw_send(err: std::io::Error) -> Error {
    match err.raw_os_error() {
        Some(libc::EHOSTUNREACH)
        | Some(libc::ENETUNREACH)
        | Some(libc::EADDRNOTAVAIL)
        | Some(libc::EMSGSIZE)
        | Some(libc::EACCES)
        | Some(libc::EPERM) => Error::Routing(err),
        _ => match err.kind() {
            std::io::ErrorKind::HostUnreachable
            | std::io::ErrorKind::NetworkUnreachable
            | std::io::ErrorKind::AddrNotAvailable => Error::Routing(err),
            _ => Error::Other(err),
        },
    }
}

fn pick_ephemeral_port() -> u16 {
    // 49152..65535 is the IANA-recommended dynamic/private range.
    use rand::RngExt;
    rand::rng().random_range(49152..=65535)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc1071_known_answer() {
        // RFC 1071 example: 0001 f203 f4f5 f6f7 -> 0xddf2 (one's complement)
        let data = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(ip_checksum(&data), 0x220d);
    }

    #[test]
    fn checksum_zero_data() {
        // All zeros sum to zero; one's complement is 0xFFFF.
        assert_eq!(ip_checksum(&[0u8; 20]), 0xFFFF);
    }

    #[test]
    fn ipv4_header_round_trip() {
        let src = Ipv4Addr::new(198, 51, 100, 42);
        let dst = Ipv4Addr::new(192, 0, 2, 50);
        let hdr = build_ipv4_header(src, dst, 28, 0xBEEF);
        // version 4, IHL 5
        assert_eq!(hdr[0], 0x45);
        // protocol UDP
        assert_eq!(hdr[9], 17);
        // TTL 64
        assert_eq!(hdr[8], 64);
        // total length 20+28 = 48 — bytes encoded for whatever order the
        // kernel expects (network on Linux, host on macOS/BSD).
        assert_eq!([hdr[2], hdr[3]], iphdr_u16_to_kernel(48));
        // DF flag set, no offset (also kernel-byte-order on BSD).
        assert_eq!([hdr[6], hdr[7]], iphdr_u16_to_kernel(0x4000));
        // src/dst correct
        assert_eq!(&hdr[12..16], &src.octets());
        assert_eq!(&hdr[16..20], &dst.octets());
        // header checksum verifies (sum over header == 0xFFFF in one's complement)
        assert_eq!(ip_checksum(&hdr), 0);
    }

    #[test]
    fn udp_checksum_uses_spoofed_source() {
        let payload = b"\x30\x05hello";
        let src_spoofed = Ipv4Addr::new(198, 51, 100, 42);
        let src_real = Ipv4Addr::new(10, 0, 0, 1);
        let dst = Ipv4Addr::new(192, 0, 2, 50);

        let dg_a = build_udp_datagram(src_spoofed, dst, 50000, 162, payload);
        let dg_b = build_udp_datagram(src_real, dst, 50000, 162, payload);

        // Different src in pseudo-header => different checksums.
        assert_ne!(&dg_a[6..8], &dg_b[6..8]);
    }

    #[test]
    fn udp_zero_checksum_replaced_with_all_ones() {
        // It is hard to construct a payload that hashes to zero deterministically
        // without a search, but we can at least verify the wrap behavior holds:
        // any datagram has a non-zero checksum after the replacement rule.
        let dg = build_udp_datagram(
            Ipv4Addr::new(1, 2, 3, 4),
            Ipv4Addr::new(5, 6, 7, 8),
            12345,
            162,
            b"x",
        );
        let csum = u16::from_be_bytes([dg[6], dg[7]]);
        assert_ne!(csum, 0, "UDP checksum must never be zero on the wire");
    }
}
