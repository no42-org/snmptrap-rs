use std::io::{self, Write};
use std::net::{Ipv4Addr, SocketAddrV4};

use crate::cli::SnmpVersion;

/// Write a structured pre-send debug header + xxd-style hex dump of `payload`
/// to `out` (typically `io::stderr()`). Community is redacted in the header
/// but the `payload` bytes are dumped verbatim.
///
/// `src` is `None` when the kernel will pick the source IP (no `--src-addr`).
/// `src_port` is `None` when the kernel will pick an ephemeral port. The
/// header renders these as the spec-mandated placeholders `<kernel-selected>`
/// and `<ephemeral>` so the debug output reflects what is actually known
/// at print time, not a probed prediction.
pub fn print_pre_send_dump<W: Write>(
    out: &mut W,
    version: SnmpVersion,
    dst: SocketAddrV4,
    src: Option<Ipv4Addr>,
    src_port: Option<u16>,
    payload: &[u8],
) -> io::Result<()> {
    let v = match version {
        SnmpVersion::V1 => "1",
        SnmpVersion::V2c => "2c",
    };
    let src_display: String = match src {
        Some(ip) => ip.to_string(),
        None => "<kernel-selected>".into(),
    };
    let src_port_display: String = match src_port {
        Some(p) => p.to_string(),
        None => "<ephemeral>".into(),
    };
    writeln!(
        out,
        "[debug] snmp_version={} dst={} src={} src_port={} community=*** payload_bytes={}",
        v,
        dst,
        src_display,
        src_port_display,
        payload.len()
    )?;
    write_hex_dump(out, payload)
}

fn write_hex_dump<W: Write>(out: &mut W, data: &[u8]) -> io::Result<()> {
    for (offset, chunk) in data.chunks(16).enumerate() {
        write!(out, "{:08x}: ", offset * 16)?;
        for (i, b) in chunk.iter().enumerate() {
            if i == 8 {
                write!(out, " ")?;
            }
            write!(out, "{b:02x} ")?;
        }
        // pad to align ASCII column
        let pad = 16 - chunk.len();
        for i in 0..pad {
            if chunk.len() + i == 8 {
                write!(out, " ")?;
            }
            write!(out, "   ")?;
        }
        write!(out, " ")?;
        for b in chunk {
            let c = if b.is_ascii_graphic() || *b == b' ' {
                *b as char
            } else {
                '.'
            };
            write!(out, "{c}")?;
        }
        writeln!(out)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_redacts_community_and_names_fields() {
        let mut buf = Vec::new();
        let dst = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 50), 162);
        let src = Ipv4Addr::new(198, 51, 100, 42);
        let payload = b"\x30\x05hello";
        print_pre_send_dump(
            &mut buf,
            SnmpVersion::V2c,
            dst,
            Some(src),
            Some(49152),
            payload,
        )
        .unwrap();
        let text = String::from_utf8(buf).unwrap();
        assert!(text.contains("snmp_version=2c"), "{}", text);
        assert!(text.contains("dst=192.0.2.50:162"), "{}", text);
        assert!(text.contains("src=198.51.100.42"), "{}", text);
        assert!(text.contains("community=***"), "{}", text);
        assert!(text.contains("payload_bytes=7"), "{}", text);
        // hexdump body present
        assert!(text.contains("30 05"), "{}", text);
        // ASCII column shows "hello"
        assert!(text.contains("hello"), "{}", text);
    }

    #[test]
    fn header_uses_placeholders_when_src_unset() {
        let mut buf = Vec::new();
        let dst = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 50), 162);
        print_pre_send_dump(&mut buf, SnmpVersion::V2c, dst, None, None, b"x").unwrap();
        let text = String::from_utf8(buf).unwrap();
        assert!(text.contains("src=<kernel-selected>"), "{}", text);
        assert!(text.contains("src_port=<ephemeral>"), "{}", text);
    }

    #[test]
    fn hex_dump_format_matches_xxd_basics() {
        let mut buf = Vec::new();
        write_hex_dump(&mut buf, &[0u8; 16]).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.starts_with("00000000: "));
        assert!(s.contains("00 00 00 00"));
    }
}
