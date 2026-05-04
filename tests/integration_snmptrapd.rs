//! End-to-end integration tests against a real `snmptrapd` running in Docker.
//!
//! These are gated behind `#[ignore]` so the default `cargo test` run stays
//! fast and offline. Run them with:
//!
//!   make integration-test
//!
//! which is `cargo test --features integration -- --ignored --test-threads=1`.
//! Serialization is required because all tests share one compose project,
//! one host port, and one log file.
//!
//! Requirements:
//!   - Docker / Docker Compose v2 available on PATH
//!   - `SNMPTRAP_RS_HOST_PORT` (default 31620) free on the host
//!
//! The compose file at the repository root brings up `snmptrapd` listening
//! on UDP/162 inside the container, mapped to `${SNMPTRAP_RS_HOST_PORT}` on
//! the host, logging to `tests/docker/log/trap.log`.

#![cfg(feature = "integration")]

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const DEFAULT_HOST_PORT: u16 = 31620;

fn host_port() -> u16 {
    std::env::var("SNMPTRAP_RS_HOST_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_HOST_PORT)
}

fn host_arg() -> String {
    format!("127.0.0.1:{}", host_port())
}

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn log_path() -> PathBuf {
    manifest_dir().join("tests/docker/log/trap.log")
}

/// `docker compose ...` rooted at the workspace dir, with the host-port env
/// var propagated so compose.yml's `${SNMPTRAP_RS_HOST_PORT:-31620}` resolves
/// consistently across the test process and the spawned container.
fn docker_compose() -> Command {
    let mut c = Command::new("docker");
    c.args(["compose"]);
    c.current_dir(manifest_dir());
    c.env("SNMPTRAP_RS_HOST_PORT", host_port().to_string());
    c
}

/// RAII wrapper that brings the compose stack up on construction and tears
/// it down on drop — including on test panic. Defensively wipes any stale
/// state before bringing the stack up.
struct ComposeGuard;

impl ComposeGuard {
    fn up() -> Self {
        // Defensive teardown of any orphan from a previous crashed run.
        let _ = docker_compose()
            .args(["down", "--remove-orphans", "-v"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        // Wipe the log file so each run starts from a clean baseline.
        let path = log_path();
        let _ = std::fs::remove_file(&path);
        std::fs::create_dir_all(path.parent().unwrap()).expect("create log dir");

        // Bring the stack up; capture output so we can surface the real
        // failure rather than a misleading "trap not seen in log" later.
        let out = docker_compose()
            .args(["up", "-d"])
            .output()
            .expect("docker compose up");
        if !out.status.success() {
            let logs = docker_compose().args(["logs"]).output().ok();
            panic!(
                "docker compose up failed: status={:?}\nstderr: {}\nlogs:\n{}",
                out.status,
                String::from_utf8_lossy(&out.stderr),
                logs.as_ref()
                    .map(|l| String::from_utf8_lossy(&l.stdout).into_owned())
                    .unwrap_or_default(),
            );
        }

        wait_for_ready(Duration::from_secs(20));
        ComposeGuard
    }
}

impl Drop for ComposeGuard {
    fn drop(&mut self) {
        match docker_compose()
            .args(["down", "--remove-orphans", "-v"])
            .output()
        {
            Ok(o) if !o.status.success() => {
                eprintln!(
                    "compose down failed: status={:?} stderr={}",
                    o.status,
                    String::from_utf8_lossy(&o.stderr)
                );
            }
            Err(e) => eprintln!("compose down errored: {e}"),
            _ => {}
        }
    }
}

/// Poll `docker compose ps` until it reports the container in `running`
/// state. A short additional sleep gives snmptrapd time to bind UDP/162.
fn wait_for_ready(timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(out) = docker_compose()
            .args(["ps", "--status=running", "-q", "snmptrapd"])
            .output()
            && !out.stdout.is_empty()
        {
            std::thread::sleep(Duration::from_millis(500));
            return;
        }
        if Instant::now() > deadline {
            let logs = docker_compose().args(["logs"]).output().ok();
            panic!(
                "snmptrapd did not become ready within {:?}\nlogs:\n{}",
                timeout,
                logs.as_ref()
                    .map(|l| String::from_utf8_lossy(&l.stdout).into_owned())
                    .unwrap_or_default(),
            );
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Current size of the trap log, used as a baseline so subsequent
/// `wait_for_log_line` calls only consider lines appended after the test's
/// own send (no stale-line false positives).
fn current_log_size() -> u64 {
    std::fs::metadata(log_path()).map(|m| m.len()).unwrap_or(0)
}

fn wait_for_log_line<F>(baseline: u64, predicate: F, timeout: Duration) -> Option<String>
where
    F: Fn(&str) -> bool,
{
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(content) = std::fs::read_to_string(log_path()) {
            let new_text = if (content.len() as u64) > baseline {
                &content[baseline as usize..]
            } else {
                ""
            };
            if let Some(line) = new_text.lines().find(|l| predicate(l)) {
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
        .current_dir(manifest_dir())
        .status()
        .expect("run snmptrap-rs");
    assert!(status.success(), "binary exited non-zero on: {args:?}");
}

/// Best-effort detection that the current process can open a raw IPv4
/// socket. Used to skip spoofing tests cleanly on hosts without
/// `CAP_NET_RAW` / root, instead of failing with a misleading error.
fn has_raw_privileges() -> bool {
    socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::RAW,
        Some(socket2::Protocol::UDP),
    )
    .is_ok()
}

#[test]
#[ignore = "requires docker"]
fn v2c_trap_arrives_at_snmptrapd() {
    let _guard = ComposeGuard::up();
    let baseline = current_log_size();
    run_binary(&[
        "-v",
        "2c",
        "-c",
        "public",
        &host_arg(),
        "12345",
        "1.3.6.1.6.3.1.1.5.1",
    ]);
    let line = wait_for_log_line(baseline, |l| l.contains("v=2c"), Duration::from_secs(5))
        .expect("v2c trap not seen in log");
    assert!(line.contains("community=public"), "got: {line}");
    // Unprivileged path: kernel selects loopback as egress for 127.0.0.1.
    assert!(
        line.contains("src=127.0.0.1"),
        "expected loopback egress src, got: {line}"
    );
    // The trap-OID must reach snmptrapd intact — anchor on the literal value
    // we fired (with or without leading dot, depending on snmptrapd render).
    assert!(
        line.contains("1.3.6.1.6.3.1.1.5.1"),
        "expected trap-OID in line, got: {line}"
    );
}

#[test]
#[ignore = "requires docker"]
fn v2c_default_uptime_does_not_crash_or_panic() {
    let _guard = ComposeGuard::up();
    let baseline = current_log_size();
    // Empty UPTIME → binary substitutes host_uptime_centiseconds. We do not
    // assert on the rendered uptime value (snmptrapd's varbind rendering
    // depends on MIB resolution and may not include a numeric suffix); we
    // assert only that the path produces a packet snmptrapd accepts.
    run_binary(&[
        "-v",
        "2c",
        "-c",
        "public",
        &host_arg(),
        "",
        "1.3.6.1.6.3.1.1.5.1",
    ]);
    let line = wait_for_log_line(baseline, |l| l.contains("v=2c"), Duration::from_secs(5))
        .expect("v2c trap with default uptime not seen in log");
    assert!(line.contains("community=public"), "got: {line}");
    assert!(line.contains("1.3.6.1.6.3.1.1.5.1"), "got: {line}");
}

#[test]
#[ignore = "requires docker"]
fn v1_trap_arrives_with_explicit_agent_addr() {
    let _guard = ComposeGuard::up();
    let baseline = current_log_size();
    run_binary(&[
        "-v",
        "1",
        "-c",
        "public",
        &host_arg(),
        "1.3.6.1.4.1.8072.2.3.0.1",
        "10.0.0.1",
        "6",
        "17",
        "99999",
    ]);
    let line = wait_for_log_line(baseline, |l| l.contains("v=1"), Duration::from_secs(5))
        .expect("v1 trap not seen in log");
    assert!(line.contains("community=public"), "got: {line}");
    assert!(
        line.contains("enterprise=") && line.contains("1.3.6.1.4.1.8072.2.3.0.1"),
        "got: {line}"
    );
    assert!(line.contains("agent_addr=10.0.0.1"), "got: {line}");
    assert!(line.contains("generic=6"), "got: {line}");
    assert!(line.contains("specific=17"), "got: {line}");
    assert!(line.contains("uptime=99999"), "got: {line}");
}

#[test]
#[ignore = "requires docker AND CAP_NET_RAW or root"]
fn spoofed_v2c_src_addr_appears_at_receiver() {
    if !has_raw_privileges() {
        eprintln!("skipping: requires CAP_NET_RAW (Linux) or root");
        return;
    }
    let _guard = ComposeGuard::up();
    let baseline = current_log_size();
    run_binary(&[
        "-v",
        "2c",
        "-c",
        "public",
        "--src-addr",
        "198.51.100.42",
        &host_arg(),
        "12345",
        "1.3.6.1.6.3.1.1.5.1",
    ]);
    let line = wait_for_log_line(
        baseline,
        |l| l.contains("198.51.100.42"),
        Duration::from_secs(5),
    )
    .expect("spoofed source not seen in log");
    assert!(line.contains("src=198.51.100.42"), "got: {line}");
}

#[test]
#[ignore = "requires docker AND CAP_NET_RAW or root"]
fn spoofed_v1_src_addr_appears_in_l3_and_pdu() {
    if !has_raw_privileges() {
        eprintln!("skipping: requires CAP_NET_RAW (Linux) or root");
        return;
    }
    let _guard = ComposeGuard::up();
    let baseline = current_log_size();
    // Empty <AGENT-ADDR> + --src-addr X => in-PDU agent-addr inherits X.
    // This pins design D6 / source-ip-spoofing spec scenario
    // "Empty agent-addr inherits --src-addr".
    run_binary(&[
        "-v",
        "1",
        "-c",
        "public",
        "--src-addr",
        "198.51.100.42",
        &host_arg(),
        "1.3.6.1.4.1.8072.2.3.0.1",
        "",
        "6",
        "17",
        "99999",
    ]);
    let line = wait_for_log_line(baseline, |l| l.contains("v=1"), Duration::from_secs(5))
        .expect("v1 spoofed trap not seen in log");
    assert!(
        line.contains("src=198.51.100.42"),
        "L3 source mismatch: {line}"
    );
    assert!(
        line.contains("agent_addr=198.51.100.42"),
        "in-PDU agent-addr should inherit --src-addr: {line}"
    );
}
