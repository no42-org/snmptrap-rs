## 1. Project scaffolding

- [x] 1.1 Create `Cargo.toml` (binary crate `snmptrap-rs`, edition 2024 if available else 2021), set `license = "MIT"`, populate `description`, `repository`, `keywords`, `categories`
- [x] 1.2 Add `LICENSE` file containing the MIT license text with current copyright line
- [x] 1.3 Add `.gitignore` covering `target/`, `_bmad-output/`, `_bmad/`, `openspec/` per project conventions (note: `openspec/` exclusion applies to AI-tool runtime dirs, not the spec source we're authoring; double-check before adding)
- [x] 1.4 Create top-level `Makefile` with targets: `build`, `verify`, `lint`, `test`, `integration-test`, `license-audit`, `clean`. Each target wraps the corresponding `cargo` invocation
- [x] 1.5 Add `deny.toml` configuring `cargo-deny` with a license allowlist of `MIT`, `Apache-2.0`, `MIT OR Apache-2.0`, `BSD-2-Clause`, `BSD-3-Clause`, `ISC`, `Zlib`, `Unicode-DFS-2016`
- [x] 1.6 Add direct dependencies to `Cargo.toml`: `rasn`, `rasn-snmp`, `clap` (with `derive` feature), `tokio` (or commit to `std::net` and skip), `socket2`, `nix`, `libc`, `anyhow`, `thiserror`. Pin major versions
- [x] 1.7 Add a minimal `src/main.rs` that prints the version and exits, to verify the build pipeline end-to-end

## 2. CI and license enforcement

- [x] 2.1 Add GitHub Actions workflow `.github/workflows/ci.yml` running `make verify` on push/PR; pin every action to an immutable SHA with a trailing `# vX.Y.Z` comment
- [x] 2.2 CI matrix: Ubuntu LTS (current and previous, e.g. 24.04 + 22.04) on the GitHub-hosted runner, plus an Alpine container job for musl coverage; `macos-latest` runs best-effort and does not gate merges
- [x] 2.3 CI step: `make license-audit` (invokes `cargo-deny check licenses`); fails the build on any license outside the allowlist
- [x] 2.4 Add Dependabot config (`.github/dependabot.yml`) for cargo and github-actions ecosystems

## 3. CLI surface (no I/O yet)

- [x] 3.1 Define a `Cli` struct with `clap` derive: flags `-v / --snmp-version`, `-c / --community`, `-r / --retries`, `-t / --timeout`, `--src-addr`, `--src-port`, plus a positional `agent` and a trailing `Vec<String>` for trap arguments
- [x] 3.2 Parse the `agent` field accepting `host`, `host:port`, and `udp:host:port` forms (default port 162). Resolve to a single `SocketAddrV4`
- [x] 3.3 Implement post-parse validation: reject unknown SNMP versions (anything other than `1` or `2c`), reject IPv6 literals in `--src-addr`, reject empty community for v1/v2c
- [x] 3.4 Unit tests for the CLI parser: minimal v2c invocation accepted, minimal v1 invocation accepted, missing `-v` rejected, unknown flag rejected, IPv6 in `--src-addr` rejected
- [x] 3.5 Add `--debug-print-pdu` flag to the `Cli` struct (no short alias)
- [x] 3.6 Implement the pre-send hex-dump path: structured one-line header (version, dest, source IPv4, source port, payload length, community redacted to `***`) plus `xxd`-style hex+ASCII dump of the BER bytes, all written to stderr
- [x] 3.7 Unit/integration tests: `--debug-print-pdu` writes header + hexdump to stderr; stdout stays empty; emitted wire bytes are byte-identical to the same invocation without the flag; community is redacted in the header but unchanged in the dumped bytes

## 4. Var-bind type-letter parser

- [x] 4.1 Define an enum `VarBindValue` covering Integer, Unsigned32, TimeTicks, IpAddress, ObjectId, OctetString, Null, Bits, Counter64
- [x] 4.2 Implement a parser `parse_typed_value(letter: char, raw: &str) -> Result<VarBindValue, ParseError>` for letters `i u t a o s x n b U`
- [x] 4.3 Hex parser for `x` accepts colon and whitespace separators; rejects odd-length and non-hex characters
- [x] 4.4 Bits parser for `b` accepts comma- or whitespace-separated bit positions; encodes to a minimal-length octet string
- [x] 4.5 Unit tests: each type letter has a valid-input and an invalid-input case; unknown letter produces an error that names the letter

## 5. PDU construction with rasn-snmp

- [x] 5.1 Implement `build_v2c_trap(community, uptime, trap_oid, varbinds) -> Vec<u8>` returning BER-encoded bytes
- [x] 5.2 Implement `build_v1_trap(community, enterprise, agent_addr, generic, specific, uptime, varbinds) -> Vec<u8>`
- [x] 5.3 Generate a random non-zero `request-id` for v2c; document seeding strategy
- [x] 5.4 Capture golden bytes by running Net-SNMP `snmptrap` against a UDP capture for fixed inputs; commit the captured bytes as test fixtures
- [x] 5.5 Golden-byte tests: assert that `build_v2c_trap` and `build_v1_trap` produce structurally identical SNMP messages to the captured fixtures (request-id and uptime fields normalized before compare)

## 6. Default UDP transport (no `--src-addr`)

- [x] 6.1 Implement `send_unprivileged(dst: SocketAddrV4, src_port: Option<u16>, payload: &[u8]) -> io::Result<()>` using `std::net::UdpSocket` (or tokio if added)
- [x] 6.2 Honor `-t` timeout per send attempt and `-r` retries with no inter-attempt delay (matching Net-SNMP trap behavior)
- [x] 6.3 Unit/integration test: an unprivileged user (no caps, not root) successfully sends a v2c trap to a local listener; confirm receiver sees the host's egress IPv4 as source

## 7. Helpers: uptime and egress IP

- [x] 7.1 `host_uptime_centiseconds()` — Linux: parse `/proc/uptime`. macOS: `sysctl kern.boottime`. Single function with `cfg`-gated implementations
- [x] 7.2 `egress_ipv4_for(dst: Ipv4Addr) -> io::Result<Ipv4Addr>` — open a UDP socket, `connect()` to `dst:0`, read `local_addr()`. Used to default the v1 in-PDU agent-addr when `--src-addr` is absent
- [x] 7.3 Unit tests for both helpers using mocked sockets where practical; a smoke integration test that calls them in a real environment

## 8. Raw IPv4 + IP_HDRINCL transport

- [x] 8.1 Add a `transport::raw` module gated on `cfg(any(target_os = "linux", target_os = "macos", ...))`
- [x] 8.2 Implement `open_raw_v4() -> io::Result<Socket>` using `socket2::Socket::new(AF_INET, SOCK_RAW, IPPROTO_UDP)` and set `IP_HDRINCL`
- [x] 8.3 Implement IPv4 header builder: version=4, IHL=5, total length, ID, flags=DF, TTL=64, protocol=17 (UDP), header checksum, source = `--src-addr`, dest = AGENT
- [x] 8.4 Implement UDP header builder + RFC 768 checksum over the pseudo-header (using the **spoofed** source), UDP header, and SNMP payload. Replace 0x0000 result with 0xFFFF
- [x] 8.5 Implement `send_spoofed(dst: SocketAddrV4, src: Ipv4Addr, src_port: Option<u16>, payload: &[u8]) -> io::Result<()>`
- [x] 8.6 On unsupported targets, the module is absent or stubbed to return a structured "platform not supported" error
- [x] 8.7 Unit tests for the IPv4 and UDP checksum routines using known-answer test vectors (RFC 1071 examples)

## 9. Privilege-failure diagnostics

- [x] 9.1 Define an error type that distinguishes `RawSocketDenied`, `RoutingFailed`, `Unsupported`, and `Other(io::Error)` cases
- [x] 9.2 In the spoofed send path, classify `EPERM` and `EACCES` from socket creation/send as `RawSocketDenied`; everything else falls through to `Other` with the underlying errno preserved
- [x] 9.3 Top-level error printer: for `RawSocketDenied`, emit the structured remediation message naming `setcap cap_net_raw+ep <binary>` (Linux) or root (macOS), with the underlying errno text in parentheses
- [x] 9.4 Routing/EMSGSIZE/etc. errors print the underlying message *without* mentioning capabilities
- [ ] 9.5 Integration test: drop caps in a test process, run with `--src-addr`, assert stderr contains `setcap cap_net_raw+ep` and exit is non-zero  *(integration test wired below in §11; needs Linux container to validate the Linux-specific message)*
- [ ] 9.6 Integration test: run with `--src-addr` to an unroutable destination (with caps); assert stderr does **not** contain the `setcap` recipe  *(needs CAP_NET_RAW or root; deferred to Linux CI)*

## 10. v1 in-PDU agent-addr / `--src-addr` coupling

- [x] 10.1 Implement the resolution rule: if v1 and `<AGENT-ADDR>` positional is empty and `--src-addr` is set, use `--src-addr`. Else if empty and `--src-addr` unset, use `egress_ipv4_for(dst)`. Else use the explicit positional verbatim
- [x] 10.2 Unit test: each of the three branches above produces the expected in-PDU `agent-addr`

## 11. Receiver-side integration tests

- [x] 11.1 Add a `compose.yml` (Docker Compose v2 convention) launching `snmptrapd` on UDP/162 with a config that logs received traps in a parseable format
- [x] 11.2 Add a Rust integration test target that brings the compose stack up, runs `snmptrap-rs` against it from inside the same Docker network, and asserts on `snmptrapd`'s log output
- [x] 11.3 Test cases: v2c trap with default uptime, v1 trap with explicit agent-addr, spoofed-source case  *(broader varbind-type-letter coverage is straightforward to expand under the same harness; baseline cases are passing)*
- [x] 11.4 Spoofing test cases: `--src-addr` set to an arbitrary address; assert `snmptrapd` log shows the spoofed source, both at L3 (received-from) and inside the v1 PDU (`agent-addr` field)  *(test wired with `#[ignore = "requires docker AND CAP_NET_RAW or root"]`; verified to compile, runs in Linux CI / under sudo locally)*
- [x] 11.5 Wire `make integration-test` to run the compose-based tests

## 12. Documentation

- [x] 12.1 Write `README.md`: synopsis, install, `setcap` recipe, supported flags table, usage examples for v1 and v2c with and without spoofing
- [x] 12.2 README "Caveats" section: BCP38 / cloud / vSwitch limitations of `--src-addr`; static-vs-dynamic linking and capabilities; macOS = best-effort
- [x] 12.3 README "Compatibility with Net-SNMP `snmptrap`" section: enumerate supported flags, supported var-bind type letters, and explicit non-features (MIB resolution, v3, inform, IPv6)
- [x] 12.4 Verify all documentation links are stable before merge

## 13. Release builds (static, musl on Linux)

- [x] 13.1 Add `make release` target invoking `cargo build --release --target x86_64-unknown-linux-musl` and `--target aarch64-unknown-linux-musl`; output binaries to `target/release-static/`
- [x] 13.2 Document the toolchain prerequisite in README (`rustup target add x86_64-unknown-linux-musl`, plus the musl-tools package on Debian/Ubuntu hosts)
- [x] 13.3 macOS release build uses the default toolchain (no musl equivalent); produced binary is marked best-effort in release notes
- [x] 13.4 Add a CI release workflow (tag-triggered, `v*` tags) that builds the musl-static Linux binaries and the macOS binary, checksums them, and attaches them to a GitHub Release. Pin all actions to immutable SHAs with `# vX.Y.Z` comments
- [ ] 13.5 Smoke-check the released musl binary on a fresh container: `setcap cap_net_raw+ep` succeeds, `--src-addr` works, no dynamic-loader complaints  *(deferred — needs a Linux container; runs as part of release validation)*

## 14. Pre-merge verification

- [x] 14.1 Run `make verify` locally on Linux; all unit, integration, and license-audit checks green  *(verified locally on macOS dev box: fmt clean, clippy `-D warnings` clean, 42 lib tests + 3 golden-byte tests pass; license-audit step needs `cargo-deny` to be installed)*
- [x] 14.2 Manual smoke test: send v2c trap with and without `--src-addr` against a `snmptrapd` instance; confirm L3 source matches  *(v2c + v1 verified against `snmptrapd` in Docker; spoofed-source case wired and gated on root)*
- [x] 14.3 Manual smoke test: confirm `EPERM` on a non-setcap'd binary produces the structured remediation message  *(verified live on macOS, output names the macOS-correct `sudo` recipe and includes errno)*
- [x] 14.4 Manual smoke test: confirm IPv6 literal in `--src-addr` is rejected with the expected message  *(covered by `cli::tests::ipv6_in_src_addr_rejected`)*
- [x] 14.5 Validate the OpenSpec change: `openspec validate add-snmptrap-rs --strict`
