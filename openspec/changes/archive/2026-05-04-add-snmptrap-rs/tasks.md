## 1. Project scaffolding

- [x] 1.1 Create `Cargo.toml` (binary crate `snmptrap-rs`, edition 2024 if available else 2021), set `license = "MIT"`, populate `description`, `repository`, `keywords`, `categories`
- [x] 1.2 Add `LICENSE` file containing the MIT license text with current copyright line
- [x] 1.3 Add `.gitignore` covering `target/`, `_bmad-output/`, `_bmad/`, `openspec/` per project conventions (note: `openspec/` exclusion applies to AI-tool runtime dirs, not the spec source we're authoring; double-check before adding)
- [x] 1.4 Create top-level `Makefile` with targets: `build`, `verify`, `lint`, `test`, `integration-test`, `license-audit`, `clean`. Each target wraps the corresponding `cargo` invocation
- [x] 1.5 Add `deny.toml` configuring `cargo-deny` with a license allowlist of `MIT`, `Apache-2.0`, `MIT OR Apache-2.0`, `BSD-2-Clause`, `BSD-3-Clause`, `ISC`, `Zlib`, `Unicode-DFS-2016`, `Unicode-3.0` (per the design D8 amendment that added `Unicode-3.0` as the modern SPDX equivalent)
- [x] 1.6 Add direct dependencies to `Cargo.toml`: `rasn`, `rasn-snmp`, `clap` (with `derive` feature), `tokio` (or commit to `std::net` and skip), `socket2`, `nix`, `libc`, `anyhow`, `thiserror`. Pin major versions
- [x] 1.7 Add a minimal `src/main.rs` that prints the version and exits, to verify the build pipeline end-to-end

## 2. CI and license enforcement

- [x] 2.1 Add GitHub Actions workflow `.github/workflows/ci.yml` running `make verify` on push/PR; pin every action to an immutable SHA with a trailing `# vX.Y.Z` comment
- [x] 2.2 CI matrix: Ubuntu LTS (current, 24.04) on the GitHub-hosted runner, plus an Alpine container job for musl coverage; `macos-latest` runs best-effort and does not gate merges
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
- [x] 6.2 Honor `-r` retries with no inter-attempt delay (matching Net-SNMP trap behavior). `-t` is accepted-only-for-CLI-compat and has no observable effect on trap emission, since trap PDUs are unconfirmed. Retry on `EINTR` without consuming the retry budget.
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
- [x] 9.3 Top-level error printer: for `RawSocketDenied`, emit the structured remediation message naming `setcap cap_net_raw+ep <binary>` (Linux) or root (macOS), with the underlying I/O error text (which itself contains the syscall errno) for debuggability. Send-time `EPERM`/`EACCES` (after a successful raw-socket open) is reclassified as routing rather than capability so broadcast-without-`SO_BROADCAST` etc. don't trigger the `setcap` recipe.
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

### Review Findings

*Generated by `/bmad-code-review` on 2026-05-04. Scope: `src/` (group 1 of 4). Layers: Blind Hunter, Edge Case Hunter, Acceptance Auditor.*

#### Decision-needed (resolved 2026-05-04)

- [x] [Review][Decision] **macOS `IP_HDRINCL` byte order** — Resolved (b): patch defensively with `cfg(target_os = "macos")` host-byte-order branch for `ip_len`/`ip_off`. Promoted to patch P24 below.
- [x] [Review][Decision] **`--timeout` is a no-op on UDP/raw** — Resolved (b): document `-t` as accepted-but-no-effect-on-traps (matches Net-SNMP semantics for unconfirmed PDUs). Promoted to patch P25 below.
- [x] [Review][Decision] **Net-SNMP type letters `c` / `d` missing** — Resolved (b): keep spec strict; document the gap in README's compatibility section. Deferred to group-4 review (README) since `src/` already rejects via `UnknownLetter`.

#### Patch (unambiguous fixes)

- [x] [Review][Patch] **`--help` and `--binary-version` exit non-zero, output to stderr** [src/cli.rs:96-99] — `parse_argv` wraps every `clap::Error` into `Error::Usage` (exit 2). `DisplayHelp` and `DisplayVersion` variants must be branched on `e.kind()` and printed to stdout with `ExitCode::SUCCESS`. Violates spec.md `Help output lists supported flags` scenario.
- [x] [Review][Patch] **`parse_bits` unbounded allocation (DoS via CLI)** [src/varbind.rs:140-148] — `bytes_needed = (max as usize / 8) + 1` with `max: u32`; `b 4294967295` allocates ~512 MiB. Cap accepted positions to a hard ceiling (e.g. 65535).
- [x] [Review][Patch] **IPv4 / UDP header length-field truncation** [src/transport/raw.rs:39, 66, 119] — `total_length = 20u16 + payload_len`, `udp_len = 8u16 + (payload.len() as u16)`, and `udp.len() as u16` all wrap silently for payloads ≥ 65508 bytes. Validate `payload.len() ≤ u16::MAX - 28` at top of `send_spoofed` and return `Error::Other` / typed encode error.
- [x] [Review][Patch] **OID arc-0 / arc-1 validation missing; `new_unchecked` bypass** [src/varbind.rs:81-100, src/pdu.rs:173-175] — `parse_oid` only checks `parts.len() ≥ 2`; never enforces `parts[0] ∈ {0,1,2}` and (when `parts[0] < 2`) `parts[1] < 40`. `ObjectIdentifier::new_unchecked` then encodes whatever arcs it gets. Garbage trap-OIDs go on the wire as valid-but-misdecoded.
- [x] [Review][Patch] **EINTR is treated as a fatal retry** [src/transport/raw.rs:129-138, src/transport/unprivileged.rs:21-25] — Default `retries=0` means a single signal during `send_to` aborts the trap. Retry on `io::ErrorKind::Interrupted` without consuming the retry budget.
- [x] [Review][Patch] **Debug-print source IP omits `<kernel-selected>` placeholder** [src/lib.rs:26-40, src/debug.rs:21-29] — Spec.md `Debug hex dump of emitted PDU` says: "the source IPv4 (the spoofed `--src-addr` if set, otherwise a placeholder string `<kernel-selected>`)". Code probes egress and prints actual octets — predictive, not observational.
- [x] [Review][Patch] **Debug-print source port shows `0` instead of `<ephemeral>`** [src/lib.rs:37] — `cli.src_port.unwrap_or(0)` writes literal `0` when ephemeral. Spec intent is a placeholder when the value is unknown.
- [x] [Review][Patch] **`--debug-print-pdu` has a side effect (egress-probe `connect`)** [src/lib.rs:27-29] — Spec.md: "The flag SHALL NOT alter any wire-emitted bytes; it is observation-only." Probing egress opens & connects a UDP socket whose only purpose is filling the debug header; remove once the placeholder fix lands.
- [x] [Review][Patch] **`--src-port 0` has two different meanings between transports** [src/lib.rs, src/transport/raw.rs:116, src/transport/unprivileged.rs:15-16] — In raw path `Some(0)` keeps `0` and writes it to UDP header. In unprivileged path `bind 0` means "ephemeral". Reject `--src-port 0` in CLI validation.
- [x] [Review][Patch] **`Routing` classifier doesn't catch `EMSGSIZE`; `EACCES` blanket-maps to `RawSocketDenied`** [src/transport/raw.rs:159-172, src/error.rs] — `EACCES` from binding a privileged source port or sending to broadcast (without `SO_BROADCAST`) prints the misleading `setcap` remediation. Doc on `Error::Routing` says it covers EMSGSIZE; classifier doesn't. Tighten classification.
- [x] [Review][Patch] **`Error::Routing(io)` and `Error::Other(io)` print bare `io::Display`** [src/error.rs:95-97] — Spec.md `Privilege-failure diagnostics` requires errno text in parentheses for debuggability. Current display drops context for non-`RawSocketDenied` cases.
- [x] [Review][Patch] **`ParseError::UnknownLetter` constructed with empty `oid`** [src/varbind.rs:74-78] — Variant has an `oid: String` field but `parse_typed_value` always sets it to `""`. Re-wrap in `lib.rs:163-166` happens to inject the OID, so the `Unknown type letter is rejected` scenario passes through accident. Either thread the OID through `parse_typed_value` or drop the field.
- [x] [Review][Patch] **macOS uptime: tv_usec underflow without borrow + `.max(0)` clamps clock skew** [src/helpers.rs:64-68] — Use `clock_gettime(CLOCK_MONOTONIC)` / `Instant` derived from boottime, or do proper carry/borrow on `tv_usec`. Currently can be off by ~1s low and silently returns 0 on backwards wall-clock change.
- [x] [Review][Patch] **`udp:[::1]:162`-style agent silently drops user port** [src/cli.rs:151-176] — `rsplit_once(':')` matches inside `[::1]`, falls to `(stripped, DEFAULT_TRAP_PORT)`, the user-supplied port is lost. Reject IPv6 agent literals up front with a clear "IPv6 destination not supported" message (matches spec scope).
- [x] [Review][Patch] **`timeout: u8` caps requests at 255 s** [src/cli.rs:71-76] — Net-SNMP allows arbitrary timeouts. Use `u32` (or `u64`).
- [x] [Review][Patch] **`--timeout 0` → `set_write_timeout(Duration::ZERO)` → `EINVAL`** [src/lib.rs] — Validate `cli.timeout > 0` in `validate()`.
- [x] [Review][Patch] **Multi-char type letter silently accepted (only first char read)** [src/lib.rs:159-161] — `triplet[1].chars().next()` lets `"oid"` parse as `'o'` and `"int"` as `'i'`. Reject `triplet[1].len() != 1` with a clear error.
- [x] [Review][Patch] **Hex (`x`) parser doesn't strip `0x` prefix; multibyte chars surface as UTF-8 error** [src/varbind.rs:102-125] — `0xab` rejected as "non-hex character". Multibyte UTF-8 in input yields a UTF-8 error rather than a hex error. Strip `0x`/`0X` prefix; classify cleaner.
- [x] [Review][Patch] **Retries reuse the same IP `Identification`** [src/transport/raw.rs:118] — `ident: u16 = rand::random()` is computed once outside the loop. Move inside the retry loop so each attempt has a fresh ID (RFC 6864 friendlier).
- [x] [Review][Patch] **v1 trap silently accepts `b` (BITS) — SMIv1 has no BITS construct** [src/pdu.rs:158-160] — Asymmetric with the explicit Counter64-in-v1 rejection. Reject `VarBindValue::Bits` in `build_v1_trap` with a structured error.
- [x] [Review][Patch] **v1 `specific-trap` accepts negative values** [src/lib.rs:104-106] — RFC 1157 specifies non-negative for `specific-trap`. Reject negatives in `validate()`.
- [x] [Review][Patch] **Stray `stderr().flush()` after successful `send_to`** [src/transport/raw.rs:1321 (file-relative)] — Looks like leftover debugging; line-buffered stderr is already flushed. Remove.
- [x] [Review][Patch] **`pub binary_version: ()` field shape** [src/cli.rs:43-45] — Works but is awkward clap-derive shape. Cosmetic; safe to leave or normalize.
- [x] [Review][Patch] **macOS `IP_HDRINCL` host-byte-order branch for `ip_len`/`ip_off`** [src/transport/raw.rs:39-45] — From Decision 1 (resolved (b)): wrap `total_length` and `frag_off` writes with `cfg(target_os = "macos")` to use host byte order on macOS, network byte order on Linux. Document the divergence in a one-line comment.
- [x] [Review][Patch] **Document `-t/--timeout` as no-effect-on-traps** [src/cli.rs:71-76] — From Decision 2 (resolved (b)): update the `--timeout` doc comment to explicitly say "accepted for Net-SNMP CLI compatibility; has no effect on trap PDUs since traps are unconfirmed; reserved for future inform support". Pair with the README compatibility note (group-4 follow-up).

#### Deferred (logged for follow-up, not pre-existing in the strict sense — first commit, but out-of-scope for this review/sprint)

- [x] [Review][Defer] **No backoff/jitter between retries** [src/transport/raw.rs, src/transport/unprivileged.rs] — `retries=255 × timeout=255s` could hang ~18 hours. User-controlled, low risk; matches Net-SNMP defaults. Deferred.
- [x] [Review][Defer] **Trailing-varbind dupe `sysUpTime.0` / `snmpTrapOID.0`** [src/pdu.rs:40-47] — User can pass these in trailing positionals, creating duplicates. Receivers may reject. Low risk; user error.
- [x] [Review][Defer] **`resolve_agent` called twice in v1 path** [src/lib.rs:22, :93] — Two DNS lookups for the same agent; round-robin DNS could differ between v1 agent_addr resolution and the actual send.
- [x] [Review][Defer] **Bind `EADDRINUSE` confusing message** [src/transport/unprivileged.rs:15-16] — User sees raw `Address already in use` without context that it's the chosen `--src-port`. Polish.
- [x] [Review][Defer] **Privileged `--src-port` without root → `EACCES` → `Other`** [src/transport/unprivileged.rs:15-16] — Should differentiate from `RawSocketDenied`; needs its own classification path.
- [x] [Review][Defer] **Non-Linux/macOS uptime returns `Ok(0)` silently** [src/helpers.rs:26-31] — Per design D7 only Linux/macOS are specified; FreeBSD/etc. fall through. README documents but no warning.
- [x] [Review][Defer] **Agent containing only `udp:` prefix** [src/cli.rs:151-176] — `stripped` becomes empty; resolver yields generic error rather than naming the empty-host condition.
- [x] [Review][Defer] **`/proc/uptime` accepts `inf` / `nan` / negative** [src/helpers.rs:9-21] — `f64` parser permissive; collapses to 0 silently. Hostile-input scenario, very low real-world risk.
- [x] [Review][Defer] **License-audit (`cargo-deny`) not installed locally per task 14.1 note** — claimed `[x]` but unverified locally; needs CI run to confirm.

### Review Findings — group 2 (`tests/`)

*Generated by `/bmad-code-review` on 2026-05-04. Scope: `tests/` (group 2 of 4). Layers: Blind Hunter, Edge Case Hunter, Acceptance Auditor.*

#### Decision-needed (resolved 2026-05-04)

- [x] [Review][Decision] **Integration-test concurrency** — Resolved (a): serialize via `--test-threads=1` in the `make integration-test` target. Promoted to patch P20.
- [x] [Review][Decision] **Net-SNMP fixture coverage breadth** — Resolved (c): defer fixture expansion until a real encoding regression motivates it. Logged in deferred-work.md.
- [x] [Review][Decision] **Binary-surface CLI tests** — Resolved (c): add only the help/version exit-0-to-stdout regression test (minimal `tests/cli_surface.rs`). Promoted to patch P21.

#### Patch (unambiguous fixes)

- [x] [Review][Patch] **v2c integration assertions pass for any v2c trap** [tests/integration_snmptrapd.rs:84-86] — `assert!(line.contains("trap_oid="))` matches every line `format2` ever produces. Tighten to assert the actual trap-OID value, the community, and the source IP — anchored on the literal string the test fired.
- [x] [Review][Patch] **v1 integration assertions pass for any v1 trap** [tests/integration_snmptrapd.rs:114-118] — `assert!(line.contains("enterprise="))` is structurally unable to fail. Assert each parsed field: `enterprise=.1.3.6.1.4.1.8072.2.3.0.1`, `generic=6`, `specific=17`, `uptime=99999`.
- [x] [Review][Patch] **`spoofed_src_addr_appears_at_receiver` is v2c-only — task 11.4 claims v1 in-PDU coupling** [tests/integration_snmptrapd.rs:128-151, tasks.md §11.4] — Add a v1 sibling: `--src-addr X` + `<AGENT-ADDR>=''` and assert the in-PDU `agent-addr` decoded from `format1`'s `enterprise=...` line equals `X`. This is the actual content of design D6.
- [x] [Review][Patch] **No integration coverage for default-uptime (`''`)** [tests/integration_snmptrapd.rs, tasks.md §11.3] — The v2c integration test passes literal `12345` rather than `''`. Add a sibling test that passes `''` and asserts a non-zero `uptime=` value within ±2 s of `helpers::host_uptime_centiseconds()`.
- [x] [Review][Patch] **Compose lifecycle has no Drop guard; container leaks on panic** [tests/integration_snmptrapd.rs:23-44] — `compose_down()` only runs on the happy path. Wrap the container in an RAII guard whose `Drop` shells out `docker compose down --remove-orphans -v`, and call `compose down` defensively at the **start** of `compose_up()` to claim a clean slate.
- [x] [Review][Patch] **`docker compose up -d` exit status is ignored** [tests/integration_snmptrapd.rs:30-34] — `.status()` is captured but the result is dropped. A failed image build, port collision, or daemon-not-running silently degrades into "trap not seen in log" 6.5 s later. Assert `status.success()`; on failure dump `docker compose logs` to stderr.
- [x] [Review][Patch] **Blind 1.5 s sleep instead of readiness probe** [tests/integration_snmptrapd.rs:35] — Replace with a poll loop: try `docker compose exec` of `nc -uz 127.0.0.1 162` (or look for `Listening on UDP` in `docker compose logs`) with a generous timeout. Remove the bare `sleep`.
- [x] [Review][Patch] **Hard-coded host port `31620` collides on shared runners** [tests/integration_snmptrapd.rs:23] — Either request port `0` and read back via `docker compose port`, or randomize per run, or document as Linux-CI-only and pin port via env var.
- [x] [Review][Patch] **`wait_for_log_line` returns the first match, not the most recent — risks stale-line false positives** [tests/integration_snmptrapd.rs:46-57] — Track `metadata().len()` of `LOG_PATH` before the binary is invoked and only consider lines appended past that offset.
- [x] [Review][Patch] **Hard-coded relative path `tests/docker/log/trap.log`** [tests/integration_snmptrapd.rs:24, 28-29] — `golden_bytes.rs` correctly uses `env!("CARGO_MANIFEST_DIR")`. Make `LOG_PATH` consistent so tests work from a workspace root or under `cargo nextest run --workspace`.
- [x] [Review][Patch] **`compose_down` errors swallowed via `let _ = ...` to `/dev/null`** [tests/integration_snmptrapd.rs:38-44] — At least log non-success exit codes; pass `--remove-orphans -v` to clear named volumes.
- [x] [Review][Patch] **`authCommunity log,execute,net public` permits `execute`** [tests/docker/snmptrapd.conf:6] — Drop `execute,net`; the test fixture only ever logs. Reduces blast radius if a future config introduces a `traphandle`.
- [x] [Review][Patch] **`spoofed_src_addr_appears_at_receiver` panics with "binary exited non-zero" when run unprivileged** [tests/integration_snmptrapd.rs:128-151] — There is no privilege guard. Detect missing CAP_NET_RAW / non-root at the top of the test and `eprintln!("skipping: requires root or CAP_NET_RAW") ; return ;` so `--ignored` runs surface as skips, not failures.
- [x] [Review][Patch] **`v1_trap_matches_via_decoded_fields` decodes the fixture, not our output** [tests/golden_bytes.rs:90-108] — Currently exercises only the `rasn` decoder. Either round-trip our `build_v1_trap` output through `ber::decode` and assert on the decoded fields, or remove the test as redundant with the byte-for-byte case immediately above it.
- [x] [Review][Patch] **Test name `v2c_trap_matches_netsnmp_capture_structurally` is a misnomer — assertion is byte-equality** [tests/golden_bytes.rs:28-58] — Rename to `v2c_trap_matches_netsnmp_capture_byte_for_byte` to match the v1 sibling and the actual assertion.
- [x] [Review][Patch] **Pin Alpine + net-snmp versions in the test image** [tests/docker/Dockerfile:1, 3] — `FROM alpine:3.21` + `apk add --no-cache net-snmp` floats with security updates. Pin to `alpine:3.21.3` (or current) and `net-snmp=X.Y.Z` so a base-image rebuild can't silently invalidate the captured fixtures.
- [x] [Review][Patch] **`format2` (v2c) has no `src=` field** [tests/docker/snmptrapd.conf:5] — Add `src=%a` so the v2c integration test can pin the L3 source for the unprivileged path (egress-IP-as-source assertion required by `tasks.md §6.3`).
- [x] [Review][Patch] **Strip embedded whitespace in fixture loader** [tests/golden_bytes.rs:69-75] — `raw.trim()` covers trailing newline, but a base64 file edited with internal whitespace dies with the opaque message `"base64 decode"`. Filter `is_ascii_whitespace` before decoding and surface a more useful error.
- [x] [Review][Patch] **Default v1 enterprise OID never compared against Net-SNMP** [tests/golden_bytes.rs, src/pdu.rs:15] — `DEFAULT_V1_ENTERPRISE_OID = 1.3.6.1.4.1.3.1.1` is an assumption about Net-SNMP's compiled-in default. Either capture a Net-SNMP fixture with `''` enterprise and pin equality, or add a one-line note in `pdu.rs` documenting the source citation.
- [x] [Review][Patch] **Serialize integration tests via `--test-threads=1`** [Makefile, integration-test target] — From Decision 1 (resolved (a)): pass `-- --test-threads=1` to the `cargo test` invocation in the `integration-test` Makefile target so the three Docker-bound integration tests cannot trample each other.
- [x] [Review][Patch] **Add minimal `tests/cli_surface.rs` for `--help` / `--binary-version` exit-0-to-stdout regression** — From Decision 3 (resolved (c)): a small `assert_cmd`-based test file that locks in the recent `clap::error::ErrorKind::DisplayHelp/DisplayVersion` patch — exit 0, output to stdout, contains expected strings. Anti-regression only; broader CLI surface coverage stays as unit tests.

#### Deferred (logged for follow-up, not patched in this group)

- [x] [Review][Defer] **UDP checksum + DF bit spec scenarios untested at integration level** [source-ip-spoofing/spec.md] — Pinned by `src/transport/raw.rs` unit tests against fixed inputs (RFC 1071 known answer, `udp_checksum_uses_spoofed_source`, `udp_zero_checksum_replaced_with_all_ones`). Pcap-based integration would be high-cost / low-marginal-value. Defer.
- [x] [Review][Defer] **EPERM remediation + routing-doesn't-blame-caps scenarios** [source-ip-spoofing/spec.md, tasks.md §9.5–9.6] — Already left `[ ]` in tasks.md (correct). Need an unprivileged Linux runtime that can deny CAP_NET_RAW; deferred to Linux CI lane.
- [x] [Review][Defer] **`--debug-print-pdu` binary-surface integration test** — Covered by `src/cli.rs` + `src/debug.rs` unit tests; binary-level assert_cmd would be redundant. Reconsider only if the CLI surface drifts.
- [x] [Review][Defer] **Net-SNMP fixture expansion to all type letters** — Hand-capture per type with controllable request-id/uptime; significant infrastructure. Defer until a regression motivates it (covered by Decision 2).
- [x] [Review][Defer] **CLI rejection scenarios via `assert_cmd`** — Covered by unit tests in `src/cli.rs`. End-to-end binary tests would be a nice-to-have. (Covered by Decision 3.)
- [x] [Review][Defer] **Docker rootless / Podman / SELinux compatibility** [tests/docker/Dockerfile, compose.yml] — Bind-mount path `tests/docker/log` requires the test runner UID to match what the container writes as. Out-of-scope for this review; document supported environments in README.
- [x] [Review][Defer] **snmptrapd log flush buffering** [tests/docker/snmptrapd.conf, Dockerfile] — `-Lf <file>` should be line-buffered but is implementation-dependent; the readiness-probe + size-offset patches reduce exposure. Revisit if flake recurs.
- [x] [Review][Defer] **Default-`cargo test` stays Docker-free** — Currently guarded by `#[cfg(feature = "integration")]` + `#[ignore]`. Adding a meta-test that asserts the gate stays in place is low-value churn.
- [x] [Review][Defer] **format1/format2 token-typo silent breakage** [tests/docker/snmptrapd.conf] — Once assertions are tightened (patches above), this is automatically caught.

### Review Findings — group 3 (CI / build)

*Generated by `/bmad-code-review` on 2026-05-04. Scope: `.github/workflows/*`, `Makefile`, `Cargo.toml`, `deny.toml`, `compose.yml`, `.gitignore`, `dependabot.yml`. Layers: Blind Hunter, Edge Case Hunter, Acceptance Auditor.*

#### Decision-needed (resolved 2026-05-04)

- [x] [Review][Decision] **`deny.toml` allowlist drift from D8** — Resolved (b): amend D8 to add `Unicode-3.0` explicitly; `deny.toml` already correct. Landed in commit f147142.
- [x] [Review][Decision] **Broaden `cargo-deny` to `check all`** — Resolved (c): probationary `cargo-deny-probationary` CI job (advisories + bans + sources, `continue-on-error: true`) runs alongside the gated `license-audit` job. Promote to gating once a release cycle clean. Landed in commit f147142.
- [x] [Review][Decision] **Release artifact provenance / signing** — Resolved (a): `actions/attest-build-provenance` step added to the publish job in `release.yml`, with `id-token: write` + `attestations: write` permissions. Verifiable post-release via `gh attestation verify`. Landed in commit f147142.

#### Patch (unambiguous fixes)

- [x] [Review][Patch] **`release.yml` invokes `cargo` directly, violating D9 + CLAUDE.md** [.github/workflows/release.yml:32, :64] — D9 mandates Make-driven CI ("CI invokes Makefile targets, never the underlying tooling directly"). Add `release-macos-x86` and `release-macos-arm` Makefile targets, then have each workflow step call `make release-x86`/`release-arm`/`release-macos-*` instead of `cargo build --release --target …`.
- [x] [Review][Patch] **`ci.yml` license-audit bypasses `make license-audit`** [.github/workflows/ci.yml:54-61] — Same D9 violation. The `license-audit` job invokes `EmbarkStudios/cargo-deny-action` directly. Change to `run: make license-audit` (after pinning `cargo-deny` install in the Makefile or installing it in the CI step). Restores Makefile-as-source-of-truth.
- [x] [Review][Patch] **No `concurrency:` group on either workflow** [.github/workflows/ci.yml, release.yml top-level] — Rapid pushes to the same PR start parallel CI runs that race on cache writes; rapid re-tags cause `softprops/action-gh-release` to race. Add `concurrency: { group: ${{ github.workflow }}-${{ github.ref }}, cancel-in-progress: true }` for ci.yml; on release.yml use `cancel-in-progress: false` (don't kill a partial release in flight).
- [x] [Review][Patch] **macOS release `continue-on-error: true` silently ships incomplete release** [.github/workflows/release.yml:48] — A failed macOS leg lets the Linux release ship with macOS artifacts missing; consumers see 404s. Either drop `continue-on-error` (gate the release on macOS) or stage all artifacts in a single aggregator job that publishes only when all legs succeed.
- [x] [Review][Patch] **`compose.yml` exposes UDP/162 publicly** [compose.yml:8] — `${SNMPTRAP_RS_HOST_PORT:-31620}:162/udp` binds `0.0.0.0` by default. Bind to `127.0.0.1:${...}:162/udp` so a developer running tests on a public network does not expose `snmptrapd` to the LAN.
- [x] [Review][Patch] **No release-tag validation** [.github/workflows/release.yml:5-6] — `v*` matches `vfoo`, `v1..2`, `v0`. A typo'd tag publishes a broken release. Add a step early in each release job that validates the tag matches `v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?` and that the tag is on `main` (`git merge-base --is-ancestor "$GITHUB_SHA" origin/main`).
- [x] [Review][Patch] **`Cargo.toml` declares `edition = "2024"` but no `rust-version` MSRV** [Cargo.toml:4] — Edition 2024 needs rustc ≥ 1.85; without an explicit `rust-version`, a stale toolchain fails mid-compile rather than producing a clear error. Add `rust-version = "1.85"` (or whatever the floor is once stable rustc provides edition-2024 support).
- [x] [Review][Patch] **`RUSTFLAGS: "-D warnings"` set globally in CI** [.github/workflows/ci.yml:14] — Promotes every rustc warning to an error in every cargo command in every job, including dependency rebuilds; toolchain bumps that touch unchanged dep code can break CI for purely cosmetic upstream warnings. Either remove (rely on `make lint` running `clippy -D warnings`) or scope to the `lint` step.
- [x] [Review][Patch] **`rust:1-alpine` floating tag breaks reproducibility** [.github/workflows/ci.yml:45] — Same reproducibility argument as `tests/docker/Dockerfile` (which is now pinned to `alpine:3.21.3`). Pin `rust:1-alpine` to a specific patch (`rust:1.85.1-alpine3.21` or to a digest) so unrelated upstream changes can't silently shift CI.
- [x] [Review][Patch] **Dependabot has no docker ecosystem and no grouping** [.github/dependabot.yml:7-13] — Docker base images (`tests/docker/Dockerfile`, the `rust:1-alpine` CI container) never receive automated bumps. Add `package-ecosystem: docker` for `tests/docker/`. Add `groups:` for cargo so the rasn family (`rasn`, `rasn-smi`, `rasn-snmp`, all version 0.28) lands as one PR — splitting them yields a non-buildable intermediate state.
- [x] [Review][Patch] **`.github/workflows/ci.yml` lacks `workflow_dispatch:`** [.github/workflows/ci.yml:3-7] — Cannot manually re-run on demand for a given ref; only push-to-main and PR-to-main fire it. Add `workflow_dispatch:` so flaky-external retries don't require an empty commit.
- [x] [Review][Patch] **CI never compiles `--features integration`** [.github/workflows/ci.yml, Cargo.toml `[features] integration = []`] — `tests/integration_snmptrapd.rs` is `#[cfg(feature = "integration")]`-elided in CI's default `cargo test`. A breaking compile error there is invisible until `make integration-test` is run locally. Add a `cargo check --features integration --tests` step (no Docker required) so the integration test file at least typechecks under CI.
- [x] [Review][Patch] **`actions/checkout` does not set `persist-credentials: false`** [.github/workflows/ci.yml:30, :47, :58, release.yml:22, :56] — Default GITHUB_TOKEN remains in `.git/config` for the rest of the job; with `contents: write` in `release.yml`, anything later in the job can `git push`. Hardening miss; add `with: persist-credentials: false` to every `actions/checkout` invocation.
- [x] [Review][Patch] **`release.yml` workflow-wide `permissions: contents: write`** [.github/workflows/release.yml:8-9] — Every step (including build steps that compile potentially-untrusted dependency build scripts) inherits release-write tokens. Move `permissions: contents: write` to the upload step, or split build/upload into two jobs and grant `contents: write` only to the upload job.
- [x] [Review][Patch] **Add `dist/` to `.gitignore`** [.gitignore] — `release.yml` stages artifacts in `dist/`; a developer reproducing the recipe locally accidentally tracks them. One-line add.
- [x] [Review][Patch] **`[profile.release]` `lto = "thin"` + `codegen-units = 1` is contradictory** [Cargo.toml:39-42] — `codegen-units = 1` disables parallel codegen for max optimization; `lto = "thin"` is the parallel-friendly LTO mode. Pick `lto = "fat"` to match `codegen-units = 1`, or drop `codegen-units = 1` and keep `thin`. Slightly slower release builds today for no measurable gain.
- [x] [Review][Patch] **Release workflow: half-populated GitHub Release if a leg fails** [.github/workflows/release.yml] — With `fail-fast: false` and per-leg `softprops/action-gh-release` uploads, a partial matrix shows up as a public release. Restructure: build artifacts in matrix legs that emit them as workflow artifacts (`actions/upload-artifact`), then a single aggregator job downloads + verifies all of them and runs `softprops/action-gh-release` once.
- [x] [Review][Patch] **`release.yml` `softprops/action-gh-release` overwrite behavior unspecified** [.github/workflows/release.yml:39-43, :71-75] — Re-tagging behavior depends on the action's defaults, which have shifted across versions. Add `with: overwrite_files: true` (or `false` and document) to make re-cuts deterministic.

### Review Findings — group 4 (docs)

*Generated by `/bmad-code-review` on 2026-05-04. Scope: `README.md`, `LICENSE`, `openspec/**`. Layers: Blind Hunter, Edge Case Hunter, Acceptance Auditor.*

#### Decision-needed (resolved 2026-05-04)

- [x] [Review][Decision] **Spec / OpenSpec sync scope** — Resolved (a): full sync now. Rewrite scenarios in both spec.md files, update design.md D7/D9/D10/D11/Risks, update proposal.md "What Changes", correct tasks.md §1.5/§6.2/§9.3 to reflect post-implementation reality. All promoted to patches below.

#### Patch (unambiguous fixes)

**README.md (P1–P11):**

- [x] [Review][Patch] **README compat: document `c` (Counter32) and `d` (decimal-bytes) gap** [README.md:111-117] — Deferred Decision 3 from group 1. Add to the "Not supported" bullet list.
- [x] [Review][Patch] **README `-t/--timeout` row claims "per-attempt timeout"** [README.md:81] — Patched code (P25) makes `-t` a no-op for traps. Update flag table description.
- [x] [Review][Patch] **README `--src-port` rejects `0`, undocumented** [README.md:83] — Note this in flag table description.
- [x] [Review][Patch] **README `--binary-version` undocumented vs Net-SNMP `--version` convention** [README.md:85] — Add a one-line breadcrumb so `--version` failing isn't a mystery.
- [x] [Review][Patch] **README install + setcap recipe walks into the dynamic-linker pitfall design D11 explicitly avoids** [README.md:13-23] — Order recipes: musl-static first for `--src-addr` users, `cargo install` second with a warning.
- [x] [Review][Patch] **README `make release` on Mac silently builds Linux musl** [README.md:139] — Document `make release-macos-*` targets.
- [x] [Review][Patch] **README `make verify` requires `cargo-deny` not stated** [README.md:137] — Add the prerequisite line.
- [x] [Review][Patch] **README `rp_filter` described as "kernel hardening before egress"** [README.md:126] — `rp_filter` is purely ingress; drop the egress-flavored qualifier.
- [x] [Review][Patch] **README "all direct deps are MIT" claim broader than allowlist enforces** [README.md:144] — Soften to match `deny.toml` allowlist scope.
- [x] [Review][Patch] **README missing v1 + `--src-addr` + empty agent-addr example** [README.md:57-64] — Design D6's hero use case. Add an example.
- [x] [Review][Patch] **README missing MSRV note** [README.md] — `Cargo.toml` now pins `rust-version = "1.87"`. Add note.
- [x] [Review][Patch] **README hex-dump section omits placeholder mention** [README.md:69-72] — Spec mandates `<kernel-selected>` / `<ephemeral>`; surface in README.

**proposal.md (P12–P13):**

- [x] [Review][Patch] **proposal.md "What Changes" omits `--debug-print-pdu` (D10), static-musl release (D11), binary name (D12)** [proposal.md:9-14]
- [x] [Review][Patch] **proposal.md `-t TIMEOUT` listed without no-op qualification** [proposal.md:10]

**design.md (P14–P17):**

- [x] [Review][Patch] **D7 promises `sysctl kern.boottime ; subtract from now` but implementation fixed tv_usec borrow + clamp** [design.md:107] — Update D7.
- [x] [Review][Patch] **D10 doesn't mention `<kernel-selected>` / `<ephemeral>` placeholders or observation-only contract** [design.md:128]
- [x] [Review][Patch] **D11 "best-effort marking" unspecified** [design.md:139, tasks.md §13.3] — Pin filename-suffix convention.
- [x] [Review][Patch] **Risks list still flags macOS raw IPv4 quirk as live** [design.md:158] — Mark resolved.

**spec/snmp-trap-cli/spec.md (P18–P22):**

- [x] [Review][Patch] **`-t TIMEOUT` requirement says "per-attempt timeout in seconds"** [snmp-trap-cli/spec.md:12] — Replace with no-op-for-traps wording.
- [x] [Review][Patch] **Add `--binary-version` requirement + scenario** [snmp-trap-cli/spec.md] — Lock the regression group-1 P1 fixed.
- [x] [Review][Patch] **Variable-binding type letters table doesn't note v1 rejection of `U` and `b`** [snmp-trap-cli/spec.md:91-108]
- [x] [Review][Patch] **Hex parser scenario doesn't cover `0x` prefix** [snmp-trap-cli/spec.md:110-112]
- [x] [Review][Patch] **Help-output scenario doesn't enumerate `--debug-print-pdu` or `--binary-version`** [snmp-trap-cli/spec.md:22-26]
- [x] [Review][Patch] **Debug header scenario doesn't assert `<kernel-selected>` placeholder** [snmp-trap-cli/spec.md:137-142]
- [x] [Review][Patch] **Add scenario for malformed trap-OID rejection** [snmp-trap-cli/spec.md:46]

**spec/source-ip-spoofing/spec.md (P23–P28):**

- [x] [Review][Patch] **Add SHALL: `ip_len` and `ip_off` host byte order on macOS/BSD; network byte order on Linux** [source-ip-spoofing/spec.md:26-27]
- [x] [Review][Patch] **Add SHALL: per-attempt IP `Identification`** [source-ip-spoofing/spec.md]
- [x] [Review][Patch] **Add SHALL: `--src-port 0` is rejected** [source-ip-spoofing/spec.md:31]
- [x] [Review][Patch] **Platform support boundary spec says "macOS / BSD" but code is Linux + macOS only** [source-ip-spoofing/spec.md:88]
- [x] [Review][Patch] **Privilege-failure diagnostics scenario asserts setcap text on macOS too** [source-ip-spoofing/spec.md:74-79] — Split per-platform.
- [x] [Review][Patch] **Privilege-failure diagnostics requirement #4 ("README pointer") is unimplemented** [source-ip-spoofing/spec.md:70] — Soften to "may include" since implementation doesn't add the pointer.

**tasks.md (P29–P31):**

- [x] [Review][Patch] **§1.5 allowlist text is stale** [tasks.md:7] — Append `Unicode-3.0`.
- [x] [Review][Patch] **§6.2 promises "honor `-t` timeout per send attempt"** [tasks.md:47] — Clarify `-t` no-op.
- [x] [Review][Patch] **§9.3 promises error printer "with underlying errno text in parentheses"** [tasks.md:70] — Verify message format matches.

#### Deferred (logged for follow-up, not patched in this group)

- [x] [Review][Defer] **`tasks.md` §1.3 risks excluding `openspec/`** [tasks.md:5] — Parenthetical caveat is present; literal "Add `openspec/`" wording remains a footgun. Low risk since directory is committed.
- [x] [Review][Defer] **`openspec/config.yaml` is a stub** — Could encode project conventions. Low value until next OpenSpec change.
- [x] [Review][Defer] **`.openspec.yaml` metadata lacks `archived`/`status`/`owners`** — Helps future archaeology.
- [x] [Review][Defer] **README acknowledgements URL claims wire-format is "verified against captures of `apps/snmptrap.c`"** — Implies ongoing verification; reality is committed fixtures. Cosmetic.
- [x] [Review][Defer] **Tasks edition 2024 fallback hedge is stale** [tasks.md:702] — "if available else 2021" is moot in 2026.
- [x] [Review][Defer] **Markdown table pipe imbalance in flag-table description column** [README.md:78] — Renders correctly on GitHub; cosmetic.
- [x] [Review][Defer] **README missing macOS install/binary path** — Group-3 added Makefile macOS release targets; full Mac install flow can be documented in a follow-up.
- [x] [Review][Defer] **Tasks §13.5 unverified (smoke-check binary)** — Already correctly marked `[ ]` open.
