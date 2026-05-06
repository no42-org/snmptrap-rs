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
    // snmptrapd's `%P` renders as `<TYPE>, SNMP v<VERSION>, community <C>` —
    // anchor on the community string itself, not the whole field prefix.
    assert!(
        line.contains("public"),
        "expected community 'public': {line}"
    );
    // Note: we deliberately do NOT assert on `src=` here. Linux loopback NAT
    // through a docker bridge can rewrite the source to 0.0.0.0 for traffic
    // originating on `127.0.0.1`, and no daemon flag makes that go away
    // cleanly. The test verifies trap *arrival*, not source preservation
    // — that's what the spoofed_* tests are for.
    // Trap-OID must reach snmptrapd intact. With `-On` snmptrapd renders
    // OIDs numerically; without it, MIB resolution turns `1.3.6.1.6.3.1.1.5.1`
    // into `coldStart`. Match either form so the test isn't brittle to the
    // image's MIB-resolution config.
    assert!(
        line.contains("1.3.6.1.6.3.1.1.5.1") || line.contains("coldStart"),
        "expected trap-OID (numeric or symbolic) in line: {line}"
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
    assert!(
        line.contains("public"),
        "expected community 'public': {line}"
    );
    assert!(
        line.contains("1.3.6.1.6.3.1.1.5.1") || line.contains("coldStart"),
        "expected trap-OID in line: {line}"
    );
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
    assert!(
        line.contains("public"),
        "expected community 'public': {line}"
    );
    // Enterprise OID may render numeric (with `-On`) or symbolic depending
    // on the receiver's MIB-resolution config — accept either.
    assert!(
        line.contains("1.3.6.1.4.1.8072.2.3.0.1")
            || line.contains("netSnmpExampleHeartbeatNotification"),
        "expected enterprise OID in line: {line}"
    );
    assert!(line.contains("agent_addr=10.0.0.1"), "got: {line}");
    assert!(line.contains("generic=6"), "got: {line}");
    // snmptrapd's `%q` renders the specific-trap with a leading dot
    // (`specific=.17`) on some versions. Match either form.
    assert!(
        line.contains("specific=17") || line.contains("specific=.17"),
        "expected specific=17: {line}"
    );
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
    // Wait for any v2c line, not specifically one matching the spoofed
    // source — that lets us distinguish "trap arrived but source got
    // stripped by the bridge NAT" from "trap never arrived".
    let line = wait_for_log_line(baseline, |l| l.contains("v=2c"), Duration::from_secs(5))
        .expect("v2c trap not seen in log");
    if line.contains("src=0.0.0.0") {
        // Linux loopback NAT through docker-bridge rewrites the L3 source
        // for traffic originating on `127.0.0.1`. snmptrapd's `%a` for v2c
        // is the L3 source, so on a docker-bridge CI runner we cannot
        // observe the spoofed source from inside the container. The
        // spoofing IS happening at the kernel level — it's just not
        // observable through this receive path. The v1 spoofed test
        // covers spoofing-end-to-end via the in-PDU agent-addr field.
        eprintln!(
            "skipping L3-source assertion: docker-bridge NAT stripped UDP src to 0.0.0.0\n\
             (kernel still emitted the spoofed source; receive-side observation requires \
             tcpdump or `network_mode: host`)"
        );
        return;
    }
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

// ─────────────────────────────────────────────────────────────────────────
// Privilege-failure diagnostics (archived tasks.md §9.5 / §9.6)
//
// These tests verify that `--src-addr` failures map to the correct error
// class and produce the right user-facing message — the `setcap` recipe
// for capability denials, plain routing-class messages for everything else.
// They don't require the snmptrapd container (no trap is expected to
// arrive); they test exit code + stderr only.
// ─────────────────────────────────────────────────────────────────────────

#[test]
#[ignore = "requires Linux"]
fn eperm_emits_setcap_remediation_on_linux() {
    // Task 9.5: when `--src-addr` is used without CAP_NET_RAW, the binary
    // SHALL exit non-zero with a stderr message naming the
    // `setcap cap_net_raw+ep` remediation.
    //
    // We can't easily drop caps from inside the test process (the CI lane
    // grants the test binary CAP_NET_RAW). But `cp` doesn't preserve file
    // capabilities by default, so a freshly-cp'd copy of `snmptrap-rs` is
    // cap-less — exec'ing it produces a child without CAP_NET_RAW even
    // when the parent test process has the cap.
    if !cfg!(target_os = "linux") {
        eprintln!("skipping: setcap remediation message is Linux-specific");
        return;
    }

    let src = std::path::Path::new(env!("CARGO_BIN_EXE_snmptrap-rs"));
    let tmp_dir = std::env::temp_dir().join(format!("snmptrap-rs-eperm-{}", std::process::id()));
    std::fs::create_dir_all(&tmp_dir).expect("create temp dir");
    let dst = tmp_dir.join("snmptrap-rs");
    std::fs::copy(src, &dst).expect("copy production binary");

    let output = std::process::Command::new(&dst)
        .args([
            "-v",
            "2c",
            "-c",
            "public",
            "--src-addr",
            "198.51.100.42",
            "127.0.0.1:31620",
            "12345",
            "1.3.6.1.6.3.1.1.5.1",
        ])
        .output()
        .expect("run no-caps binary");

    let _ = std::fs::remove_dir_all(&tmp_dir);

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "expected non-zero exit when --src-addr is used without CAP_NET_RAW;\nstatus: {:?}\nstderr:\n{stderr}",
        output.status,
    );
    assert!(
        stderr.contains("setcap cap_net_raw+ep"),
        "expected `setcap cap_net_raw+ep` remediation in stderr, got:\n{stderr}",
    );
    // The structured error should also include the underlying I/O error,
    // which on Linux contains the strerror text for EPERM/EACCES.
    assert!(
        stderr.contains("Operation not permitted") || stderr.contains("Permission denied"),
        "expected EPERM/EACCES strerror in stderr, got:\n{stderr}",
    );
}

// ─────────────────────────────────────────────────────────────────────────
// SNMPv3 — end-to-end via snmptrapd USM
//
// These tests exercise the full v3 emission path (engine-ID + KDF +
// HMAC-then-splice + AES-CFB) against a real Net-SNMP receiver. If any
// piece of the wire format diverges, snmptrapd silently drops the message
// — no log line appears — and `wait_for_log_line` times out. So the
// presence of the user name in the log IS the wire-format-correctness
// check end-to-end.
//
// All three tests use the same fixed authoritative engine-ID
// `0x8000f045050102030405` (10 bytes total):
//   octets 0..3  80 00 F0 45  — IANA PEN 61509 (no42.org), high bit set
//                                on octet 0 per RFC 3411 §5
//   octet  4     05           — format 5 (admin-defined octets)
//   octets 5..9  01 02 03 04 05  — 5 admin payload bytes
// snmptrapd.conf has matching `createUser -e <same-engine-id>` entries
// so its key localization agrees with ours. Auth/priv passwords are
// pinned to "authpassword1234" / "privpassword1234" (both 16 chars,
// satisfying the RFC 3414 §11.2 ≥8-char floor).
//
// Predicates below grep for `SNMP v3` AND `user <name>,` (with the
// trailing comma from snmptrapd's `%P` expansion). The `SNMP v3` token
// asserts that what arrived was actually v3 — without it, a regression
// downgrading v3 emission to v2c could slip through (format2 fires for
// both versions and emits the literal `v=2c` token regardless). The
// trailing comma anchors past the user-name end so `user testAuth,`
// cannot accidentally match a `user testNoAuth, …` log line from a
// neighbouring test.
// ─────────────────────────────────────────────────────────────────────────

const V3_TEST_ENGINE_ID_HEX: &str = "0x8000f045050102030405";

#[test]
#[ignore = "requires docker"]
fn v3_noauthnopriv_trap_arrives_at_snmptrapd() {
    let _guard = ComposeGuard::up();
    let baseline = current_log_size();
    run_binary(&[
        "-v",
        "3",
        "-u",
        "testNoAuth",
        "-l",
        "noAuthNoPriv",
        "-E",
        V3_TEST_ENGINE_ID_HEX,
        &host_arg(),
        "12345",
        "1.3.6.1.6.3.1.1.5.1",
    ]);
    // %P for v3 expands to "TRAP2, SNMP v3, user testNoAuth, ..." — assert
    // both `SNMP v3` (proves the wire was v3, not just format2 firing for
    // v2c) and `user testNoAuth,` (with trailing comma so `user testAuth,`
    // can't false-match a `testNoAuth` line).
    let line = wait_for_log_line(
        baseline,
        |l| l.contains("SNMP v3") && l.contains("user testNoAuth,"),
        Duration::from_secs(5),
    )
    .expect("v3 noAuthNoPriv trap not seen in log");
    assert!(
        line.contains("1.3.6.1.6.3.1.1.5.1") || line.contains("coldStart"),
        "expected trap-OID (numeric or symbolic) in line: {line}"
    );
}

#[test]
#[ignore = "requires docker"]
fn v3_authnopriv_sha256_trap_arrives_at_snmptrapd() {
    let _guard = ComposeGuard::up();
    let baseline = current_log_size();
    run_binary(&[
        "-v",
        "3",
        "-u",
        "testAuth",
        "-l",
        "authNoPriv",
        "-a",
        "SHA-256",
        "-A",
        "authpassword1234",
        "-E",
        V3_TEST_ENGINE_ID_HEX,
        &host_arg(),
        "12345",
        "1.3.6.1.6.3.1.1.5.1",
    ]);
    // If our HMAC-SHA-256 over the message bytes differs from snmptrapd's
    // recompute (different key derivation, wrong placeholder zero-fill,
    // off-by-one truncation, etc.), snmptrapd silently drops and the wait
    // times out — that's the wire-format check.
    // Anchor on the trailing `,` so `user testAuth,` cannot substring-match
    // a `testNoAuth` line, and on `SNMP v3` so a regression downgrading to
    // v2c can't slip through.
    let line = wait_for_log_line(
        baseline,
        |l| l.contains("SNMP v3") && l.contains("user testAuth,"),
        Duration::from_secs(5),
    )
    .expect(
        "v3 authNoPriv trap not seen — HMAC may have failed verification \
         (SHA-256 KDF, message bytes, or auth-param truncation mismatch)",
    );
    assert!(
        line.contains("1.3.6.1.6.3.1.1.5.1") || line.contains("coldStart"),
        "expected trap-OID in line: {line}"
    );
}

#[test]
#[ignore = "requires docker"]
fn v3_authpriv_sha256_aes128_trap_arrives_at_snmptrapd() {
    let _guard = ComposeGuard::up();
    let baseline = current_log_size();
    run_binary(&[
        "-v",
        "3",
        "-u",
        "testPriv",
        "-l",
        "authPriv",
        "-a",
        "SHA-256",
        "-A",
        "authpassword1234",
        "-x",
        "AES",
        "-X",
        "privpassword1234",
        "-E",
        V3_TEST_ENGINE_ID_HEX,
        &host_arg(),
        "12345",
        "1.3.6.1.6.3.1.1.5.1",
    ]);
    // Both AES-CFB-128 decryption and HMAC-SHA-256 verification must
    // succeed for snmptrapd to log. AES IV layout (engineBoots(4) ||
    // engineTime(4) || salt(8)), priv-key derivation (SHA-256 KDF
    // truncated to 16 bytes), and the HMAC splice must all agree with
    // snmptrapd's interpretation of RFC 3826 + RFC 7860.
    let line = wait_for_log_line(
        baseline,
        |l| l.contains("SNMP v3") && l.contains("user testPriv,"),
        Duration::from_secs(5),
    )
    .expect(
        "v3 authPriv trap not seen — AES decrypt or HMAC may have failed \
         (priv-key derivation, IV layout, or salt encoding mismatch)",
    );
    assert!(
        line.contains("1.3.6.1.6.3.1.1.5.1") || line.contains("coldStart"),
        "expected trap-OID in line: {line}"
    );
}

#[test]
#[ignore = "requires Linux AND CAP_NET_RAW AND `ip route add unreachable 192.0.2.0/24`"]
fn routing_failure_does_not_blame_capabilities_linux() {
    // Task 9.6: when `--src-addr` is used WITH CAP_NET_RAW and the
    // destination is unroutable, the binary SHALL classify the failure as
    // Routing and SHALL NOT print the setcap recipe (which would be
    // misleading since the process already has the capability).
    //
    // Requires the host to have a `unreachable` route covering the
    // destination IP (TEST-NET-1, RFC 5737) so the kernel sendto returns
    // ENETUNREACH. Without that route, the default route happily forwards
    // and we cannot observe the routing-vs-capability discrimination — so
    // we detect the success case and skip cleanly.
    if !cfg!(target_os = "linux") {
        eprintln!("skipping: routing classification messages are platform-specific");
        return;
    }
    if !has_raw_privileges() {
        eprintln!("skipping: requires CAP_NET_RAW (Linux) or root");
        return;
    }

    let bin = env!("CARGO_BIN_EXE_snmptrap-rs");
    let output = std::process::Command::new(bin)
        .args([
            "-v",
            "2c",
            "-c",
            "public",
            "--src-addr",
            "198.51.100.42",
            "192.0.2.50",
            "12345",
            "1.3.6.1.6.3.1.1.5.1",
        ])
        .output()
        .expect("run snmptrap-rs");

    if output.status.success() {
        eprintln!(
            "skipping: send to 192.0.2.50 succeeded — \
             `ip route add unreachable 192.0.2.0/24` not configured on this host \
             (the test is observable only when the kernel returns a routing error \
             from sendto)"
        );
        return;
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("setcap cap_net_raw+ep"),
        "stderr must NOT contain the setcap remediation for a routing failure \
         (capability errors and routing errors must be classified distinctly), \
         got:\n{stderr}",
    );
    // The error should name the routing condition.
    assert!(
        stderr.contains("send failed")
            || stderr.contains("unreachable")
            || stderr.contains("Network is unreachable"),
        "expected routing-class error message in stderr, got:\n{stderr}",
    );
}
