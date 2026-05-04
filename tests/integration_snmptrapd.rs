//! End-to-end integration tests against a real `snmptrapd` running in Docker.
//!
//! These are gated behind `#[ignore]` so the default `cargo test` run stays
//! fast and offline. Run them with:
//!
//!   make integration-test
//!
//! which is `cargo test --features integration -- --ignored`.
//!
//! Requirements:
//!   - Docker / Docker Compose v2 available on PATH
//!   - Port 31620/udp free on the host
//!
//! The compose file at the repository root brings up `snmptrapd` listening
//! on UDP/162 inside the container, mapped to host UDP/31620, logging to
//! `tests/docker/log/trap.log`.

#![cfg(feature = "integration")]

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const HOST_PORT: u16 = 31620;
const LOG_PATH: &str = "tests/docker/log/trap.log";

fn compose_up() {
    // Wipe prior log
    let _ = std::fs::remove_file(LOG_PATH);
    std::fs::create_dir_all("tests/docker/log").unwrap();
    Command::new("docker")
        .args(["compose", "up", "-d"])
        .status()
        .expect("docker compose up");
    // Wait briefly for snmptrapd to bind.
    std::thread::sleep(Duration::from_millis(1500));
}

fn compose_down() {
    let _ = Command::new("docker")
        .args(["compose", "down"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

fn wait_for_log_line(needle: &str, timeout: Duration) -> Option<String> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(content) = std::fs::read_to_string(LOG_PATH) {
            if let Some(line) = content.lines().find(|l| l.contains(needle)) {
                return Some(line.to_string());
            }
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    None
}

fn run_binary(args: &[&str]) {
    let bin = env!("CARGO_BIN_EXE_snmptrap-rs");
    let status = Command::new(bin)
        .args(args)
        .status()
        .expect("run snmptrap-rs");
    assert!(status.success(), "binary exited non-zero on: {:?}", args);
}

#[test]
#[ignore = "requires docker"]
fn v2c_trap_arrives_at_snmptrapd() {
    compose_up();
    let result = std::panic::catch_unwind(|| {
        let host_arg = format!("127.0.0.1:{}", HOST_PORT);
        run_binary(&[
            "-v",
            "2c",
            "-c",
            "public",
            &host_arg,
            "12345",
            "1.3.6.1.6.3.1.1.5.1",
        ]);
        let line =
            wait_for_log_line("v=2c", Duration::from_secs(5)).expect("v2c trap not seen in log");
        assert!(line.contains("trap_oid="));
    });
    compose_down();
    if let Err(e) = result {
        std::panic::resume_unwind(e);
    }
}

#[test]
#[ignore = "requires docker"]
fn v1_trap_arrives_with_explicit_agent_addr() {
    compose_up();
    let result = std::panic::catch_unwind(|| {
        let host_arg = format!("127.0.0.1:{}", HOST_PORT);
        run_binary(&[
            "-v",
            "1",
            "-c",
            "public",
            &host_arg,
            "1.3.6.1.4.1.8072.2.3.0.1",
            "10.0.0.1",
            "6",
            "17",
            "99999",
        ]);
        let line =
            wait_for_log_line("v=1", Duration::from_secs(5)).expect("v1 trap not seen in log");
        // src might be 127.0.0.1 (the container saw it); enterprise must match
        assert!(
            line.contains("enterprise="),
            "expected enterprise field: {}",
            line
        );
    });
    compose_down();
    if let Err(e) = result {
        std::panic::resume_unwind(e);
    }
}

#[test]
#[ignore = "requires docker AND CAP_NET_RAW or root"]
fn spoofed_src_addr_appears_at_receiver() {
    compose_up();
    let result = std::panic::catch_unwind(|| {
        let host_arg = format!("127.0.0.1:{}", HOST_PORT);
        run_binary(&[
            "-v",
            "2c",
            "-c",
            "public",
            "--src-addr",
            "198.51.100.42",
            &host_arg,
            "12345",
            "1.3.6.1.6.3.1.1.5.1",
        ]);
        let line = wait_for_log_line("198.51.100.42", Duration::from_secs(5))
            .expect("spoofed source not seen in log");
        assert!(line.contains("src=198.51.100.42"), "got: {}", line);
    });
    compose_down();
    if let Err(e) = result {
        std::panic::resume_unwind(e);
    }
}
