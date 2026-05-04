//! Anti-regression tests for the binary's CLI surface, focused specifically
//! on the `--help` / `--binary-version` exit-0-to-stdout contract that was
//! once broken by wrapping every `clap::Error` as `Error::Usage` (exit 2 to
//! stderr). Other CLI scenarios remain covered by unit tests in `src/cli.rs`.

use std::process::Command;

#[test]
fn help_exits_zero_to_stdout() {
    let bin = env!("CARGO_BIN_EXE_snmptrap-rs");
    let out = Command::new(bin)
        .arg("--help")
        .output()
        .expect("run --help");
    assert!(out.status.success(), "exit status: {:?}", out.status);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stdout.contains("snmptrap-rs"),
        "stdout missing program name: {stdout}"
    );
    assert!(
        stdout.contains("--snmp-version"),
        "stdout missing --snmp-version flag: {stdout}"
    );
    assert!(
        stderr.is_empty(),
        "--help should not write to stderr, got: {stderr}"
    );
}

#[test]
fn binary_version_exits_zero_to_stdout() {
    let bin = env!("CARGO_BIN_EXE_snmptrap-rs");
    let out = Command::new(bin)
        .arg("--binary-version")
        .output()
        .expect("run --binary-version");
    assert!(out.status.success(), "exit status: {:?}", out.status);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("snmptrap-rs"),
        "stdout missing program name: {stdout}"
    );
}
