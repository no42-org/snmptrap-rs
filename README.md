# snmptrap-rs

A Rust port of Net-SNMP's `snmptrap` with one extra trick: **emit traps from any IPv4 source address you like**, without needing `iptables`/`nftables` SNAT, IP aliases, or network namespaces.

The default code path is unprivileged and behaves like `snmptrap`. The `--src-addr` flag opens a raw IPv4 socket with `IP_HDRINCL` and forges the L3 source — that path needs `CAP_NET_RAW` on Linux (or `sudo` on macOS).

## Why

Testing trap receivers (OpenNMS, Zabbix, custom handlers) routinely means simulating traps from many "fake" devices. The usual workarounds modify host or firewall state and don't compose well in CI. This binary keeps everything in-process: one flag, one capability bit, no host configuration changes.

## Install

**Recommended for `--src-addr` users — static musl binary.** A dynamically-linked binary plus `setcap` triggers a glibc-loader interaction that historically breaks (the loader refuses to honor `LD_LIBRARY_PATH` on a setcap-elevated binary). The static-musl release artifacts sidestep this entirely.

On Debian/Ubuntu install the cross prerequisites first:

```bash
sudo apt-get install musl-tools
rustup target add x86_64-unknown-linux-musl
# For aarch64 builds also:
# rustup target add aarch64-unknown-linux-musl
make release
# binaries land in target/release-static/
```

Then grant the raw-socket capability once:

```bash
sudo setcap cap_net_raw+ep target/release-static/snmptrap-rs-x86_64-unknown-linux-musl
```

**Quick path — `cargo install` (no spoofing).** Fine if you don't need `--src-addr`. Produces a glibc-dynamic binary; do **not** combine with `setcap` on hardened distros. MSRV is `rustc >= 1.87` (edition 2024).

```bash
cargo install --git https://github.com/no42-org/snmptrap-rs --locked
```

**macOS.** No static-musl equivalent. Build with the default toolchain (`make release-macos-x86` or `make release-macos-arm`) and run the `--src-addr` path under `sudo`:

```bash
sudo snmptrap-rs --src-addr 198.51.100.42 ...
```

## Usage

### SNMPv2c trap (no spoofing)

```bash
snmptrap-rs -v 2c -c public 192.0.2.50 \
    '' \
    1.3.6.1.6.3.1.1.5.1
```

`''` for `<UPTIME>` substitutes the host's uptime. The first positional after AGENT is `<UPTIME>`, the second is `<TRAP-OID>`, then optional `OID TYPE VALUE` triplets.

### SNMPv1 trap with explicit fields

```bash
snmptrap-rs -v 1 -c public 192.0.2.50 \
    1.3.6.1.4.1.8072.2.3.0.1 \
    10.0.0.1 \
    6 17 99999 \
    1.3.6.1.4.1.8072.2.3.2.1 i 42
```

Positionals after AGENT for v1: `<ENTERPRISE-OID> <AGENT-ADDR> <GENERIC> <SPECIFIC> <UPTIME> [OID TYPE VALUE]...`. Empty `<ENTERPRISE-OID>` defaults to `1.3.6.1.4.1.3.1.1` (matching Net-SNMP).

### Spoofed source IP

```bash
snmptrap-rs -v 2c -c public --src-addr 198.51.100.42 192.0.2.50 \
    '' 1.3.6.1.6.3.1.1.5.1
```

The receiver's `recvfrom()` will see `198.51.100.42` as the source, regardless of which interface this host actually has.

### Spoofed v1 trap with in-PDU agent-addr inheriting `--src-addr`

```bash
snmptrap-rs -v 1 -c public --src-addr 198.51.100.42 192.0.2.50 \
    '' '' 6 17 99999
```

For SNMPv1, an empty `<AGENT-ADDR>` positional automatically inherits `--src-addr` so the in-PDU device identity matches the L3 source. The receiver sees `198.51.100.42` at L3 *and* in the SNMPv1 trap PDU's `agent-addr` field.

### Debug the bytes on the wire

```bash
snmptrap-rs --debug-print-pdu -v 2c -c public 192.0.2.50 '' 1.3.6.1.6.3.1.1.5.1
```

A `xxd`-style hex+ASCII dump of the encoded SNMP message is written to stderr immediately before send. Stdout is unaffected. The header line redacts the community string to `***` and reports placeholder strings (`<kernel-selected>` for the source IP when `--src-addr` is unset, `<ephemeral>` for the source port when `--src-port` is unset) — the flag is observation-only and does not probe the network. The byte dump is the actual encoded BER and is byte-identical to a run without `--debug-print-pdu`.

## Supported flags

| Flag | Purpose | Default |
|---|---|---|
| `-v {1\|2c}` | SNMP version | required |
| `-c <COMMUNITY>` | Community string | required |
| `-r <RETRIES>` | Send retry count | 0 |
| `-t <SECONDS>` | Accepted for Net-SNMP CLI compat; **no effect on traps** (unconfirmed PDUs have no peer ack to time out against) | 1 |
| `--src-addr <IPv4>` | Spoof L3 source — requires `CAP_NET_RAW` | unset |
| `--src-port <PORT>` | Pin UDP source port. `0` is rejected (omit the flag for an ephemeral port) | ephemeral |
| `--debug-print-pdu` | Hexdump the encoded BER to stderr before send (observation-only) | off |
| `--binary-version` | Print binary version and exit. Note: `--version` is intentionally not bound — clap's default version flag is disabled because `-v` is taken by SNMP version. | — |
| `-h, --help` | Help (exits 0 to stdout) | — |

## Supported var-bind type letters

| Letter | ASN.1 type | v1 | v2c | Example |
|---|---|---|---|---|
| `i` | INTEGER (signed 32-bit) | yes | yes | `1.2.3.4 i 42` |
| `u` | Unsigned32 / Gauge32 | yes | yes | `1.2.3.4 u 1234` |
| `t` | TimeTicks | yes | yes | `1.2.3.4 t 12345` |
| `a` | IpAddress | yes | yes | `1.2.3.4 a 10.0.0.1` |
| `o` | OBJECT IDENTIFIER | yes | yes | `1.2.3.4 o 1.3.6.1.4.1.8072` |
| `s` | OCTET STRING (utf-8) | yes | yes | `1.2.3.4 s "hello"` |
| `x` | OCTET STRING (hex) — accepts `:`/whitespace separators and an optional `0x`/`0X` prefix | yes | yes | `1.2.3.4 x "de:ad:be:ef"` |
| `n` | NULL | yes | yes | `1.2.3.4 n ""` |
| `b` | BITS | **rejected** (SMIv2 only) | yes | `1.2.3.4 b "0,1,2"` |
| `U` | Counter64 | **rejected** (SMIv2 only) | yes | `1.2.3.4 U 99999999999` |

## Compatibility with Net-SNMP `snmptrap`

The CLI follows a subset of Net-SNMP's flags and positional shapes — scripts that don't reach for the unsupported features below should work after `s/snmptrap/snmptrap-rs/`.

**Supported:** v1 trap, v2c trap, common flags above, the var-bind type letters listed above (with v1/v2c rejection notes), numeric OIDs.

**Not supported in this version:**

- SNMPv3 (USM, auth/priv, engineID discovery, all `-3*` flags, `-u`, `-l`, `-a`, `-A`, `-x`, `-X`, `-e`, `-E`, `-n`)
- Inform PDUs (`-Ci` / `snmpinform`). If inform support is added in a future release, combining it with `--src-addr` will remain rejected at the CLI surface — see the **Caveats for `--src-addr`** section for why.
- IPv6 source spoofing (passing an IPv6 literal to `--src-addr` is rejected)
- IPv6 destinations (passing a bracketed IPv6 literal in AGENT is rejected)
- MIB resolution (`-m`, `-M`) — pass numeric OIDs only
- Alternate transports (TCP, DTLS, TLS, Unix domain) — UDP/IPv4 only
- Net-SNMP type letters: `c` (Counter32), `d` (decimal-byte-list), and the non-standard `F`, `D`, `I` (FLOAT, DOUBLE, signed64). Net-SNMP scripts that use `c` or `d` will need to switch to `u`/`U`/`x` respectively.
- Windows
- `-t/--timeout` is accepted for argv-compat but has no observable effect on traps (no peer ack to time out against). Reserved for future inform-PDU support.

## Caveats for `--src-addr`

Spoofed source IPs **don't traverse most production networks**:

- **BCP38** filters at ISP edges drop packets with source IPs outside the host's allocated range.
- **Cloud hypervisors** (AWS, GCP, Azure) drop spoofed packets at the virtual NIC layer.
- **VMware / Hyper-V port-security** modes drop them at the vSwitch.
- **Linux `rp_filter`** is purely an *ingress* concern (drops *received* packets that fail reverse-path lookup) — it does not affect egress. If spoofed packets get dropped on egress, look at `iptables`/`nftables` egress rules, eBPF egress hooks, or bridge-level filtering rather than `rp_filter`.

The supported environments are: lab networks, container networks (Docker bridge, Kubernetes pod networks), VLAN-isolated test segments, and network namespaces.

If `--src-addr` is set but the binary lacks `CAP_NET_RAW`, you'll see a structured error message naming the precise remediation (the `setcap` recipe on Linux, `sudo` on macOS) plus the underlying errno in parentheses. The default code path (without `--src-addr`) does not need any capability.

**Inform PDUs are intentionally out of scope for `--src-addr`, permanently.** Even if a future release adds inform-PDU emission to this binary, the `--src-addr` + inform combination will be rejected at the CLI surface. An InformRequest expects a Response from the receiver, addressed to the request's source IP — and that's the spoofed address, which routes elsewhere (or gets dropped at the same BCP38/cloud-NIC layers above). Recovering the Response would require raw L2 capture (AF_PACKET on Linux, `/dev/bpf*` on macOS), per-OS capability divergence beyond `CAP_NET_RAW`, and same-L2 placement relative to the receiver — out of scope for a single-binary CLI. The decision is captured as the `Requirement: --src-addr applies to trap PDUs only` clause in `openspec/specs/source-ip-spoofing/spec.md`.

## Build / Test

Prerequisites for `make verify` / `make license-audit`: install `cargo-deny` once.

```bash
cargo install --locked cargo-deny
```

Then:

```bash
make build             # cargo build
make test              # unit + golden-byte tests (offline)
make verify            # lint + test + license-audit (requires cargo-deny)
make integration-test  # spins up snmptrapd in Docker; serializes via --test-threads=1
make release           # static musl Linux binaries (x86_64 + aarch64) → target/release-static/
make release-macos-x86 # macOS x86_64 build (best-effort; default toolchain, no musl)
make release-macos-arm # macOS aarch64 build (best-effort)
```

## License

MIT — see [`LICENSE`](LICENSE). Direct dependencies are in the permissive license allowlist (`MIT`, `Apache-2.0`, `MIT OR Apache-2.0`, `BSD-2-Clause`, `BSD-3-Clause`, `ISC`, `Zlib`, `Unicode-DFS-2016`, `Unicode-3.0`); CI enforces the allowlist via `cargo-deny`.

## Acknowledgements

Wire-format compatibility is captured against committed Net-SNMP `snmptrap` byte fixtures (see `tests/fixtures/`); the test suite re-checks every PR via `tests/golden_bytes.rs`. The encoding is provided by the [`rasn`](https://github.com/librasn/rasn) crate family.
