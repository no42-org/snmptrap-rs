## Context

`snmptrap` from the Net-SNMP project (`apps/snmptrap.c`, ~390 lines) emits SNMPv1, SNMPv2c, and SNMPv3 traps and informs over UDP. Most of its real logic lives in `libnetsnmp`: argument parsing (`snmp_parse_args`), PDU construction (`snmp_pdu_create`, `snmp_add_var`), transport selection (`netsnmp_transport_open_client`), and crypto for v3 (USM). The L3 source IP of the emitted datagram is always the host's egress IP for the destination — set by the kernel during `connect(2)` / `sendto(2)` on the unprivileged UDP socket the library opens.

When developers and operators stress-test trap receivers (OpenNMS, custom handlers, correlation engines), they routinely need to simulate traps from many different "source devices." Today this is done by configuring the host or upstream to rewrite or alias source IPs — e.g. `iptables -t nat -A POSTROUTING -j SNAT`, `nft add rule ip nat …`, per-IP loopback aliases (`ip addr add 10.0.0.5/32 dev lo`), or network namespaces. These approaches modify host or firewall state, scale poorly across many fake sources, and are awkward to drive from CI or one-shot scripts.

A small, single-binary Rust port that reproduces the working subset of `snmptrap`'s CLI **plus** an opt-in `--src-addr` flag that forges the L3 source inside the process — without touching firewall rules, interface aliases, or namespaces — fills that gap. This change scopes the port to v1 + v2c trap PDUs, IPv4-only, with v3 / inform / IPv6 deferred to follow-up work.

## Goals / Non-Goals

**Goals:**

- Reproduce the parts of Net-SNMP `snmptrap` that scripts actually use: SNMPv1 trap, SNMPv2c trap, common flags (`-v`, `-c`, `-r`, `-t`), the type-letter var-bind grammar, and matching positional argument shapes.
- Provide `--src-addr <IPv4>` that forges the L3 source by building IPv4 + UDP + SNMP in user space and emitting via a raw IPv4 socket with `IP_HDRINCL`.
- Keep the default (no `--src-addr`) code path **fully unprivileged** — same privilege profile as `snmptrap`.
- When `--src-addr` is used and `CAP_NET_RAW` is missing, fail with an actionable stderr message that names the precise remediation, not a raw `EPERM`.
- Ship under the **MIT License**, with all dependencies in the permissive (`MIT` / `MIT OR Apache-2.0`) family. CI enforces this.
- First-class on Linux; best-effort on macOS/BSD; clearly unsupported elsewhere for the spoofing path.

**Non-Goals:**

- SNMPv3 (USM auth/priv, engine-ID discovery, `-3*` flag family). Deferred — significant separate engineering effort.
- Inform PDUs (v2c or v3). Deferred — spoofed source plus inform requires raw RX (BPF / AF_PACKET) to capture the ack on a foreign IP.
- IPv6 source spoofing. Deferred — `IPV6_HDRINCL` semantics differ across kernels and ancillary-data patterns are needed.
- MIB resolution (`-m`, `-M`). Numeric OIDs only. libnetsnmp's MIB parser is a tarpit; out of scope.
- Alternate transports — TCP, DTLS, TLS, Unix domain. UDP/IPv4 only.
- Windows. The unprivileged path *may* work via `std::net`, but the `--src-addr` path requires Npcap-class drivers and is excluded.
- `snmpinform` dual-naming (argv[0]-based dispatch). Excluded because inform is itself out of scope.
- A library/crate API. The deliverable is a CLI binary; if a `lib.rs` falls out, it is incidental and unstable.

## Decisions

### D1: Reproduce a subset of `snmptrap`'s CLI rather than build a fresh CLI

**Choice:** flag letters and positional argument order match Net-SNMP for the supported subset. `--src-addr` and `--src-port` are new long flags that don't collide with anything in `snmp_parse_args`.

**Alternatives considered:**

- *Drop-in compatibility (full).* Reimplements MIB parsing, all transport prefixes, all type letters including libnetsnmp non-standard extensions (`F D I`). Tarpit; rejected.
- *Inspired-by, fresh CLI (clap-idiomatic).* Easier to ship; breaks every existing script. Rejected because the audience is operators with existing trap-generation scripts.

**Rationale:** the working subset captures >95% of real-world `snmptrap` invocations. Existing scripts that don't use `-m`/`-M` and stick to standard type letters keep working after `s/snmptrap/snmptrap-rs/`.

### D2: ASN.1/BER via `rasn` + `rasn-snmp`

**Choice:** depend on `rasn` (`MIT OR Apache-2.0`) and `rasn-snmp` for SNMP type definitions and BER codec. Validate with golden-byte tests captured from Net-SNMP `snmptrap` for fixed inputs (fixed request-id, fixed uptime).

**Alternatives considered:**

- *Hand-rolled BER.* The SNMP subset needed for v1+v2c trap is small (~200 LoC). Removes a dep but adds a maintenance burden and a new place for bugs. Rejected.
- *`snmp` crate.* Older, client-focused, doesn't expose enough type control for trap construction. Rejected.

**Rationale:** `rasn-snmp` already has the types correct, has byte-level test coverage upstream, and is permissively licensed. Frees us to focus engineering on the CLI surface and the spoofing transport.

### D3: Two transport code paths, switched solely by presence of `--src-addr`

**Choice:**

```
   no --src-addr   →   ordinary UdpSocket  (no privilege; like snmptrap)
   --src-addr X    →   raw IPv4 + IP_HDRINCL (always, even if X is local)
```

No auto-detection of "host owns this IP" to fall back to `bind()`. One flag, one decision.

**Alternatives considered:**

- *Auto-detect: if host owns `--src-addr`, use `bind()`; otherwise raw.* Considered earlier in design conversation. Rejected because users of this tool know what they're doing and accept `setcap`; the auto-detect adds branching, two code paths to test, and surprises (different L3 behavior depending on whether the IP is local).
- *Always raw, even with no flag.* Rejected because it would force unprivileged users to setcap just to use the tool as a normal trap sender.

**Rationale:** clarity over cleverness. The presence of `--src-addr` is the user's explicit opt-in to the privileged path. The absence is the unprivileged default.

### D4: Raw IPv4 + IP_HDRINCL (not AF_PACKET, not TUN, not IP aliasing)

**Choice:** open `AF_INET / SOCK_RAW / IPPROTO_UDP` (or `IPPROTO_RAW`), set `IP_HDRINCL`, build IPv4 + UDP + SNMP in user space. The kernel handles route lookup, egress interface selection, and ARP / next-hop resolution.

**Alternatives considered:**

- *AF_PACKET (Linux) / BPF (BSD/macOS).* Requires building the Ethernet frame including src/dst MACs, doing our own ARP/ND, and choosing the egress interface ourselves. Most flexible, most fragile, biggest portability gulf between Linux and macOS. Rejected as overkill.
- *TUN/TAP + userspace TCP/IP (smoltcp).* Heaviest. Requires a virtual interface and elevated privileges to create it. Rejected.
- *IP aliasing (`ip addr add`) + bind().* Modifies host state; doesn't actually fit "spoof IPs the host doesn't own"; user explicitly rejected this class of solution by name.

**Rationale:** `IP_HDRINCL` gives us full control over the IPv4 header (where the spoof lives) while delegating L2 to the kernel. Linux and macOS/BSD both support this with near-identical code. Capability-gated rather than root-only on Linux.

### D5: Privilege-failure UX is differentiated, not generic

**Choice:** classify socket-level failures and only print the `setcap` remediation when the failure is `EPERM` / `EACCES` from raw socket creation or send. Routing errors, EMSGSIZE, address-in-use, etc. get distinct messages.

**Rationale:** "Operation not permitted: setcap cap_net_raw+ep …" printed on a routing failure trains users to ignore our error messages. Differentiation keeps the message trustworthy.

### D6: SNMPv1 in-PDU `agent-addr` defaults coherently with `--src-addr`

**Choice:** when v1 is used, `--src-addr` is set, and the user passes `''` for the v1 agent-addr positional, populate the in-PDU `agent-addr` field from `--src-addr`. An explicit non-empty positional always wins.

**Alternatives considered:**

- *Never link the two; user must always set both.* Rejected — surprising default behavior where a receiver sees one IP at L3 and a different "device identity" inside the PDU.

**Rationale:** the realistic intent of `--src-addr 10.1.2.3` is "I am pretending to be 10.1.2.3." That intent should propagate consistently; explicit overrides remain available for the rare decoupled case.

### D7: Uptime auto-fill matches Net-SNMP semantics (host uptime)

**Choice:** when v1 `<UPTIME>` or v2c `<UPTIME>` is `''`, substitute the host's current uptime in hundredths of a second.

- Linux: read `/proc/uptime`.
- macOS: `sysctl kern.boottime` (`CTL_KERN`/`KERN_BOOTTIME`) and subtract from `gettimeofday`. The implementation does proper carry/borrow on `tv_usec` (`if usecs < 0: secs -= 1; usecs += 1_000_000`) and clamps to 0 on negative skew (e.g. wall-clock-moved-back), then converts to centiseconds via saturating arithmetic. Naive subtraction without the borrow correction silently undercounts by ~1 s and produces 0 on backwards clock changes.

**Alternatives considered:**

- *Process-start `CLOCK_MONOTONIC`.* Simpler, deterministic for tests. Rejected because it diverges from `snmptrap`'s observable behavior; users diffing receiver logs would notice.

**Rationale:** wire-format parity with Net-SNMP includes parity in the auto-fill values where practical.

### D8: License = MIT, enforced in CI

**Choice:** the project ships under the MIT license. CI runs `cargo-deny check licenses` (or equivalent) with an allowlist limited to `MIT`, `Apache-2.0`, `MIT OR Apache-2.0`, `BSD-2-Clause`, `BSD-3-Clause`, `ISC`, `Zlib`, `Unicode-DFS-2016`, and `Unicode-3.0`. Any new dependency outside the allowlist fails the build.

**Rationale:** a lab tool that operators may bundle with internal test harnesses needs a permissive, predictable license story. Enforcement in CI prevents drift via transitive deps. `Unicode-3.0` is the modern SPDX identifier for the same Unicode license historically tracked as `Unicode-DFS-2016`; both are listed because crates in the dep graph (e.g. the `unicode-ident` family) have migrated to the new SPDX without functional change.

### D9: Build is driven by `make`, not `cargo` directly, in CI

**Choice:** a `Makefile` exposes `build`, `verify`, `lint`, `test`, `integration-test`, `release` targets that wrap `cargo` invocations and the Docker-based receiver test. CI workflows call `make verify`, never `cargo` directly. CI runs on **Ubuntu LTS (current)** plus an **Alpine container** for musl coverage; `macos-latest` is included as a best-effort lane that does not gate merges.

**Rationale:** matches the convention from project guidelines; keeps local and CI invocations in sync; isolates CI from `cargo` flag churn. Alpine in CI catches musl-vs-glibc divergences early because the release artifact ships musl-static (D11).

### D10: `--debug-print-pdu` for wire-bytes hex dump

**Choice:** add a `--debug-print-pdu` flag (no short alias). When set, immediately before send, the binary writes a hex+ASCII dump of the encoded SNMP message bytes to stderr. The dump SHALL include a one-line header (version, community redacted to `***`, dest, src, src-port, payload length) and the payload as a `xxd`-style hexdump. Stdout is unaffected.

**Source-IP / source-port placeholder rule:** the source IP and source port in the header are reported only when known at print time, since the dump fires *before* the kernel binds. Specifically:

- If `--src-addr` is set, the header reports its value; otherwise it reports the literal string `<kernel-selected>`.
- If `--src-port` is set, the header reports its value; otherwise it reports the literal string `<ephemeral>`.

The flag is **observation-only**: it MUST NOT alter any wire-emitted byte and MUST NOT trigger a probe (e.g. an egress-IP `connect()` to a UDP socket). An earlier draft of the implementation did probe the egress IP to fill the header; this was removed because it constituted a side effect attributable to the flag, contrary to the spec.

**Rationale:** when a receiver doesn't see what was expected, the first question is "what bytes did we actually emit?" — answering it without strapping `tcpdump` next to the run is high-value-per-line-of-code. Stderr keeps it out of any structured stdout consumers. The placeholder convention keeps the header truthful: predicting the kernel's eventual choice is not the same as observing it.

**Alternatives considered:**

- *Reuse `-v` for verbose.* `-v` is taken by SNMP version. Rejected.
- *`--debug` umbrella with sub-categories.* Premature; we only have one debug surface. Rejected.

### D11: Release binary is statically linked (musl on Linux)

**Choice:** the `release` Makefile target builds with the `x86_64-unknown-linux-musl` (and `aarch64-unknown-linux-musl`) targets to produce statically linked binaries on Linux. macOS release builds use the default toolchain (no equivalent of musl). Distribution artifacts attached to GitHub releases SHALL be the static Linux binaries plus a macOS binary marked best-effort.

**Best-effort marking convention:** macOS artifacts SHALL be uploaded with a `*-best-effort` filename suffix (e.g. `snmptrap-rs-aarch64-apple-darwin-best-effort`) so consumers can distinguish gated-Linux artifacts from non-gated macOS artifacts at a glance, without parsing release-notes prose. The release workflow's `publish` job does not depend on the macOS build legs, so a macOS failure is visible (red leg) but does not block the Linux release.

**Rationale:** binaries with file capabilities (`setcap cap_net_raw+ep`) refuse to honor `LD_LIBRARY_PATH` and have surprising runtime-loader interactions with dynamically-linked libc. Static linking sidesteps the entire failure mode and makes the install-and-setcap recipe two lines instead of "and-also-make-sure-the-loader-can-find-glibc-NN".

**Alternatives considered:**

- *Dynamic linking with glibc.* Smaller binary, simpler build. Rejected because of the `setcap`-vs-dynamic-linker pitfall.
- *Pure cargo dynamic + tell users to wrap in a privileged shell.* Worse UX; rejected.

### D12: Binary name is `snmptrap-rs`

**Choice:** the binary installed on `$PATH` is named `snmptrap-rs`. No alias, no `rsnmptrap` link.

**Rationale:** coexists alongside Net-SNMP's `snmptrap` without collision; `-rs` suffix telegraphs "Rust port" without overpromising drop-in compatibility.

## Risks / Trade-offs

- **BCP38 / cloud egress filters drop spoofed packets** → Document prominently in README that `--src-addr` packets do not traverse the public internet, AWS/GCP/Azure VPCs, ESXi vSwitch port-security, or any network with reverse-path filtering on egress. Working in containers, VLAN-isolated lab nets, and namespaces is the supported environment.
- **Linux `rp_filter` is mostly an ingress concern, but kernel hardening varies** → Smoke-test in CI on the Linux versions we claim to support; document any kernel sysctls that affect raw send if encountered.
- **macOS raw IPv4 has historic quirks** (kernel expects `ip_len` and `ip_off` in **host byte order**, not network byte order, when `IP_HDRINCL` is set; this is BSD-derived behavior) → **Resolved.** The implementation has a `cfg(any(macos, freebsd, openbsd, netbsd, dragonfly))` branch that writes those two fields in native byte order on BSDs and network byte order on Linux. Linux unit tests verify the network-byte-order path; macOS validation is done via the integration test harness when run with root.
- **Wire-format drift from Net-SNMP** as `rasn-snmp` evolves → Pin major versions; golden-byte tests guard against drift on every CI run.
- **Type-letter coverage gap** vs. libnetsnmp (we omit `F`, `D`, `I` non-standard extensions) → Document explicitly. Rejecting unknown letters with a clear error is better than silently mis-encoding.
- **Counter64 is BER-ambiguous between INTEGER and Application-class tag** → `rasn-snmp` handles this via the SNMP application tag for `Counter64`; covered by golden tests.
- **Don't-Fragment + large payloads** → If a user constructs a giant trap (large hex var-binds), the spoofed packet may exceed path MTU and be dropped silently because we set DF. Acceptable for v1; we can revisit (Path MTU? clear DF? fragment in software?) if it bites in practice.
- **Capability sticky-bits and `setcap` interactions with `LD_LIBRARY_PATH`** → A binary with file capabilities will refuse to honor `LD_LIBRARY_PATH` etc. Document this in the README so users debugging "why doesn't my dynamically-linked thing work" don't get surprised. (Static linking via `cargo build --release` largely avoids this.)
- **`snmpinform` operators get a worse experience by default** → Out of scope for this change, but the README should say so up-front so users don't try `-Ci` and get confused.

## Migration Plan

This is a new tool, not a replacement. There is nothing to migrate from in the current repository. Adoption is opt-in: users who currently run `snmptrap` keep running it; those who want the spoofing feature run `snmptrap-rs`.

Rollback is trivial — uninstall the binary. There is no on-disk state, no daemon, no persistent configuration.

## Open Questions

None remaining at proposal-review time. The five items raised during review were resolved in-place:

1. CI matrix — settled in **D9** (Ubuntu LTS current+previous, Alpine container, macOS best-effort).
2. `--from-list ips.txt` fan-out — **deferred** to a follow-up change; not tracked by this proposal.
3. Bytes-on-wire debug output — settled in **D10** (`--debug-print-pdu`).
4. Static vs dynamic linking — settled in **D11** (musl-static on Linux).
5. Binary name — settled in **D12** (`snmptrap-rs`).
