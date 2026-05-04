## Why

Testing trap receivers (e.g. OpenNMS, Zabbix, libre-NMS, custom handlers) routinely requires emitting traps that *appear* to originate from many different devices — without standing up those devices. With Net-SNMP's `snmptrap`, the L3 source IP is always the host's own egress address; pretending to be another device requires out-of-band tricks like `iptables`/`nftables` SNAT, network namespaces, or per-IP interface aliases. Those tricks modify host or firewall state, are awkward to script across many fake sources, and don't compose well with CI.

A small, self-contained Rust binary that **(a)** reproduces the parts of `snmptrap` people actually use and **(b)** carries an opt-in `--src-addr` flag that forges the L3 source address inside the process, with no host or firewall configuration, fills that gap. Spoofing requires `CAP_NET_RAW`; everything else runs unprivileged like the original tool.

## What Changes

- **NEW** `snmptrap-rs` binary (Rust, single crate) — sends SNMP traps over UDP/IPv4.
- **NEW** CLI compatible with a working subset of Net-SNMP's `snmptrap`: SNMPv1 trap and SNMPv2c trap PDUs, common flags (`-v {1|2c}`, `-c COMMUNITY`, `-r RETRIES`, `-t TIMEOUT`), positional argument shapes matching the reference, var-bind type letters `i u t a o s x n b U`. Numeric OIDs only (no MIB resolution).
- **NEW** `--src-addr <IP>` flag — when set, the trap is emitted with the chosen IPv4 source address via a raw IP socket with `IP_HDRINCL`. For SNMPv1 traps, the in-PDU `agent-addr` field is auto-populated from `--src-addr` if the user passes `""` for the agent positional, so receivers see a consistent identity at L3 and inside the PDU.
- **NEW** `--src-port <port>` flag — pin the UDP source port (default ephemeral).
- **NO** `setcap` is required unless `--src-addr` is used. When raw socket creation fails with `EPERM`, the binary prints a precise remediation message (the `setcap cap_net_raw+ep` recipe) and exits non-zero rather than surfacing a raw syscall error.
- **OUT OF SCOPE for this change** (deferred to a future change): SNMPv3 (USM auth/priv, engine-ID discovery), SNMPv2c/v3 inform PDUs, IPv6 spoofing, MIB resolution (`-m`/`-M`), Windows support, alternate transports (TCP, DTLS, TLS, Unix), `snmpinform` dual-naming.

## Capabilities

### New Capabilities

- `snmp-trap-cli`: Sending SNMPv1 and SNMPv2c trap PDUs from a command-line tool with a Net-SNMP-compatible argument surface. Owns CLI parsing, var-bind type-letter handling, ASN.1/BER encoding, and the default UDP transport.
- `source-ip-spoofing`: Forging the L3 IPv4 source address of an outbound trap from inside the binary, gated on `CAP_NET_RAW`, with deterministic, helpful failure modes when the capability is not granted.

### Modified Capabilities

None. This is a new project; `openspec/specs/` is currently empty.

## Impact

- **New crate**: a single Rust binary crate at the repository root (`Cargo.toml`, `src/`).
- **External dependencies** (proposed, finalized in design): `rasn` + `rasn-snmp` for ASN.1/BER, `clap` for CLI, `tokio` (or `std::net`) for normal UDP, `socket2`/`nix`/`libc` for raw socket setup with `IP_HDRINCL`.
- **Build/CI**: a `Makefile` exposes `make build` and `make verify` so CI invokes Makefile targets, not `cargo` directly. Integration tests run `snmptrapd` in a Docker container as the receive-side oracle.
- **Runtime privileges**: unprivileged for the default code path. The `--src-addr` path requires `CAP_NET_RAW` on Linux (or root on macOS); README documents the one-line `setcap` recipe.
- **Network behavior**: spoofed packets will not traverse public-internet egress filters (BCP38), cloud hypervisor port-security, or vSwitch antispoof — works in lab, container, and closed test networks. Documented.
- **No changes** to existing host configuration, firewall rules, or interface state. The tool is self-contained.
- **License**: the project SHALL ship under the **MIT License**. All proposed direct dependencies (`rasn`, `rasn-snmp`, `clap`, `tokio`, `socket2`, `nix`, `libc`, `anyhow`, `thiserror`) are licensed `MIT` or `MIT OR Apache-2.0`, which is compatible with downstream MIT distribution. CI SHALL run a license-audit step (e.g. `cargo-deny check licenses`) to fail the build if a transitive dependency outside an allowlist of permissive licenses is introduced.
