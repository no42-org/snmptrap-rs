use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::time::Duration;

use crate::error::Error;

/// Send `payload` to `dst` over an ordinary UDP socket. No raw socket, no
/// elevated capability. The kernel selects the source IPv4 by routing.
pub fn send(
    dst: SocketAddrV4,
    src_port: Option<u16>,
    timeout: Duration,
    retries: u8,
    payload: &[u8],
) -> Result<(), Error> {
    let bind: SocketAddr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, src_port.unwrap_or(0)).into();
    let sock = UdpSocket::bind(bind).map_err(map_send_io)?;
    sock.set_write_timeout(Some(timeout)).map_err(map_send_io)?;

    let mut last_err: Option<std::io::Error> = None;
    for _ in 0..=retries {
        match sock.send_to(payload, SocketAddr::V4(dst)) {
            Ok(_) => return Ok(()),
            Err(e) => last_err = Some(e),
        }
    }
    Err(map_send_io(last_err.unwrap_or_else(|| {
        std::io::Error::other("send_to failed without an OS error")
    })))
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
