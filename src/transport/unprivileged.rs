use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::time::Duration;

use crate::error::Error;

/// Send `payload` to `dst` over an ordinary UDP socket. No raw socket, no
/// elevated capability. The kernel selects the source IPv4 by routing.
pub fn send(
    dst: SocketAddrV4,
    src_port: Option<u16>,
    _timeout: Duration,
    retries: u8,
    payload: &[u8],
) -> Result<(), Error> {
    let chosen_port = src_port.unwrap_or(0);
    let bind: SocketAddr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, chosen_port).into();
    let sock = UdpSocket::bind(bind).map_err(|e| classify_bind_io(e, src_port))?;

    let mut last_err: Option<std::io::Error> = None;
    let mut budget: i32 = retries as i32 + 1;
    while budget > 0 {
        match sock.send_to(payload, SocketAddr::V4(dst)) {
            Ok(_) => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => {
                last_err = Some(e);
                budget -= 1;
            }
        }
    }
    Err(map_send_io(last_err.unwrap_or_else(|| {
        std::io::Error::other("send_to failed without an OS error")
    })))
}

/// Classify a `bind(2)` failure on the unprivileged UDP socket. The
/// `src_port` argument is the user's `--src-port` choice (or `None` for
/// kernel-ephemeral) — used to render an actionable message that names
/// which port hit the problem.
fn classify_bind_io(err: std::io::Error, src_port: Option<u16>) -> Error {
    let port_ctx = match src_port {
        Some(p) => format!("--src-port {p}"),
        None => "kernel-ephemeral source port".to_string(),
    };
    match err.raw_os_error() {
        // EACCES on bind for a privileged port (<1024) means the user asked
        // for a port that needs CAP_NET_BIND_SERVICE or root. Surface this
        // as Usage rather than a generic Other so the message is actionable.
        Some(libc::EACCES) if matches!(src_port, Some(p) if p < 1024) => Error::Usage(format!(
            "{port_ctx} requires root or CAP_NET_BIND_SERVICE (port < 1024); bind failed: {err}"
        )),
        Some(libc::EADDRINUSE) => Error::Usage(format!(
            "{port_ctx} is already in use by another process; bind failed: {err}"
        )),
        _ => Error::Other(err),
    }
}

fn map_send_io(err: std::io::Error) -> Error {
    match err.kind() {
        std::io::ErrorKind::HostUnreachable
        | std::io::ErrorKind::NetworkUnreachable
        | std::io::ErrorKind::AddrNotAvailable => Error::Routing(err),
        _ => Error::Other(err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;
    use std::sync::mpsc;
    use std::thread;

    /// Bind a real UdpSocket to receive a trap, then send to it. Ensures the
    /// payload arrives byte-identical and the receiver sees a loopback source.
    #[test]
    fn unprivileged_send_round_trip_loopback() {
        let listener = UdpSocket::bind("127.0.0.1:0").unwrap();
        let listener_addr = match listener.local_addr().unwrap() {
            SocketAddr::V4(v4) => v4,
            _ => unreachable!(),
        };
        listener
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();

        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let mut buf = [0u8; 4096];
            let (n, from) = listener.recv_from(&mut buf).unwrap();
            tx.send((buf[..n].to_vec(), from)).unwrap();
        });

        let payload = b"\x30\x05hello"; // arbitrary bytes
        send(listener_addr, None, Duration::from_secs(1), 0, payload).expect("send");

        let (received, from) = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(received, payload);
        match from {
            SocketAddr::V4(v4) => assert!(v4.ip().is_loopback(), "got {}", v4.ip()),
            _ => panic!("expected v4 source"),
        }
    }
}
