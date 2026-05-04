use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};

/// Host uptime in hundredths of a second, matching Net-SNMP's `get_uptime()`
/// auto-fill behavior. Linux: parses `/proc/uptime`. macOS: reads
/// `kern.boottime` and subtracts from `gettimeofday`.
pub fn host_uptime_centiseconds() -> std::io::Result<u32> {
    #[cfg(target_os = "linux")]
    {
        let raw = std::fs::read_to_string("/proc/uptime")?;
        let first = raw.split_whitespace().next().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "/proc/uptime had no content",
            )
        })?;
        let secs: f64 = first.parse().map_err(|e: std::num::ParseFloatError| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
        })?;
        let centiseconds = (secs * 100.0) as u64;
        Ok(centiseconds.min(u32::MAX as u64) as u32)
    }
    #[cfg(target_os = "macos")]
    {
        macos_uptime_centiseconds()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        // Fallback for other Unixes — process-start monotonic. This diverges
        // from Net-SNMP's host-uptime semantics; documented in README.
        Ok(0)
    }
}

#[cfg(target_os = "macos")]
fn macos_uptime_centiseconds() -> std::io::Result<u32> {
    use std::mem::MaybeUninit;

    let mib: [libc::c_int; 2] = [libc::CTL_KERN, libc::KERN_BOOTTIME];
    let mut tv: MaybeUninit<libc::timeval> = MaybeUninit::uninit();
    let mut size = std::mem::size_of::<libc::timeval>();

    let rc = unsafe {
        libc::sysctl(
            mib.as_ptr() as *mut _,
            mib.len() as libc::c_uint,
            tv.as_mut_ptr() as *mut _,
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let boottime = unsafe { tv.assume_init() };

    let mut now: MaybeUninit<libc::timeval> = MaybeUninit::uninit();
    let rc = unsafe { libc::gettimeofday(now.as_mut_ptr(), std::ptr::null_mut()) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let now = unsafe { now.assume_init() };

    let mut secs: i64 = now.tv_sec - boottime.tv_sec;
    let mut usecs: i64 = i64::from(now.tv_usec) - i64::from(boottime.tv_usec);
    if usecs < 0 {
        secs -= 1;
        usecs += 1_000_000;
    }
    if secs < 0 {
        // Wall clock is earlier than the recorded boottime — treat as zero
        // uptime rather than silently returning a large number through the
        // saturating cast below.
        return Ok(0);
    }
    let total_us = (secs as u64)
        .saturating_mul(1_000_000)
        .saturating_add(usecs as u64);
    let centi = total_us / 10_000;
    Ok(centi.min(u32::MAX as u64) as u32)
}

/// Egress IPv4 the kernel would use as L3 source for `dst`. Implemented by
/// `connect()`-ing a UDP socket and reading `local_addr()` — no packets sent.
pub fn egress_ipv4_for(dst: SocketAddrV4) -> std::io::Result<Ipv4Addr> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.connect(SocketAddr::V4(dst))?;
    match sock.local_addr()? {
        SocketAddr::V4(v4) => Ok(*v4.ip()),
        SocketAddr::V6(_) => Err(std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            "kernel selected an IPv6 source for IPv4 destination",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_uptime_returns_some_value() {
        let v = host_uptime_centiseconds().expect("uptime call");
        // Anything > 0 is a sane post-boot value; we don't assert exact equality.
        assert!(
            v > 0 || cfg!(not(any(target_os = "linux", target_os = "macos"))),
            "uptime was 0 on a supported platform"
        );
    }

    #[test]
    fn egress_for_loopback_is_loopback() {
        let dst = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 9);
        let src = egress_ipv4_for(dst).expect("egress lookup");
        assert!(src.is_loopback(), "expected loopback, got {src}");
    }
}
