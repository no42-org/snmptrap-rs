# snmptrap-rs

A Rust port of Net-SNMP's `snmptrap` with one extra trick: **emit traps from any IPv4 source address you like**, without needing `iptables`/`nftables` SNAT, IP aliases, or network namespaces.

The default code path is unprivileged and behaves like `snmptrap`. The `--src-addr` flag opens a raw IPv4 socket with `IP_HDRINCL` and forges the L3 source — that path needs `CAP_NET_RAW` on Linux (or `sudo` on macOS).

## Why

Testing trap receivers (OpenNMS, Zabbix, custom handlers) routinely means simulating traps from many "fake" devices. The usual workarounds modify host or firewall state and don't compose well in CI. This binary keeps everything in-process: one flag, one capability bit, no host configuration changes.

## Install

```bash
cargo install --git https://github.com/no42-org/snmptrap-rs --locked
```

To use `--src-addr` on Linux, grant the binary the raw-socket capability once:

```bash
sudo setcap cap_net_raw+ep "$(command -v snmptrap-rs)"
```

On macOS, raw sockets require root: `sudo snmptrap-rs --src-addr ...`.

If you want a fully self-contained binary (no glibc-vs-loader issues with `setcap`), build a static musl release:

```bash
rustup target add x86_64-unknown-linux-musl
make release
# binaries in target/release-static/
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

The receiver's `recvfrom()` will see `198.51.100.42` as the source, regardless of which interface this host actually has. For SNMPv1, an empty `<AGENT-ADDR>` positional automatically inherits `--src-addr` so the in-PDU device identity matches the L3 source.

### Debug the bytes on the wire

```bash
snmptrap-rs --debug-print-pdu -v 2c -c public 192.0.2.50 '' 1.3.6.1.6.3.1.1.5.1
```

A `xxd`-style hex+ASCII dump of the encoded SNMP message is written to stderr immediately before send. Stdout is unaffected. The community string is redacted in the header line; the byte dump is the actual encoded BER.

## Supported flags

| Flag | Purpose | Default |
|---|---|---|
| `-v {1\|2c}` | SNMP version | required |
| `-c <COMMUNITY>` | Community string | required |
| `-r <RETRIES>` | Send retry count | 0 |
| `-t <SECONDS>` | Per-attempt timeout | 1 |
| `--src-addr <IPv4>` | Spoof L3 source — requires `CAP_NET_RAW` | unset |
| `--src-port <PORT>` | Pin UDP source port | ephemeral |
| `--debug-print-pdu` | Hexdump the BER to stderr before send | off |
| `--binary-version` | Print binary version and exit | — |
| `-h, --help` | Help | — |

## Supported var-bind type letters

| Letter | ASN.1 type | Example |
|---|---|---|
| `i` | INTEGER (signed 32-bit) | `1.2.3.4 i 42` |
| `u` | Unsigned32 / Gauge32 | `1.2.3.4 u 1234` |
| `t` | TimeTicks | `1.2.3.4 t 12345` |
| `a` | IpAddress | `1.2.3.4 a 10.0.0.1` |
| `o` | OBJECT IDENTIFIER | `1.2.3.4 o 1.3.6.1.4.1.8072` |
| `s` | OCTET STRING (utf-8) | `1.2.3.4 s "hello"` |
| `x` | OCTET STRING (hex) | `1.2.3.4 x "de:ad:be:ef"` |
| `n` | NULL | `1.2.3.4 n ""` |
| `b` | BITS | `1.2.3.4 b "0,1,2"` |
| `U` | Counter64 (v2c only) | `1.2.3.4 U 99999999999` |

## Compatibility with Net-SNMP `snmptrap`

The CLI follows a subset of Net-SNMP's flags and positional shapes — scripts that don't reach for the unsupported features below should work after `s/snmptrap/snmptrap-rs/`.

**Supported:** v1 trap, v2c trap, common flags above, the var-bind type letters listed above, numeric OIDs.

**Not supported in this version:**

- SNMPv3 (USM, auth/priv, engineID discovery, all `-3*` flags, `-u`, `-l`, `-a`, `-A`, `-x`, `-X`, `-e`, `-E`, `-n`)
- Inform PDUs (`-Ci` / `snmpinform`)
- IPv6 source spoofing (passing an IPv6 literal to `--src-addr` is rejected)
- MIB resolution (`-m`, `-M`) — pass numeric OIDs only
- Alternate transports (TCP, DTLS, TLS, Unix domain) — UDP/IPv4 only
- Net-SNMP's non-standard type letters `F`, `D`, `I` (FLOAT, DOUBLE, signed64)
- Windows

## Caveats for `--src-addr`

Spoofed source IPs **don't traverse most production networks**:

- **BCP38** filters at ISP edges drop packets with source IPs outside the host's allocated range.
- **Cloud hypervisors** (AWS, GCP, Azure) drop spoofed packets at the virtual NIC layer.
- **VMware / Hyper-V port-security** modes drop them at the vSwitch.
- **Linux `rp_filter`** is mostly an *ingress* concern but check kernel hardening before assuming egress works.

The supported environments are: lab networks, container networks (Docker bridge, Kubernetes pod networks), VLAN-isolated test segments, and network namespaces.

If `--src-addr` is set but the binary lacks `CAP_NET_RAW`, you'll see a structured error message naming the precise remediation. The default code path (without `--src-addr`) does not need any capability.

## Build / Test

```bash
make build             # cargo build
make test              # unit + golden-byte tests (offline)
make verify            # lint + test + license-audit
make integration-test  # spins up snmptrapd in Docker; requires Docker
make release           # static musl Linux binaries -> target/release-static/
```

## License

MIT — see [`LICENSE`](LICENSE). All direct dependencies are `MIT` or `MIT OR Apache-2.0`. CI enforces the license allowlist via `cargo-deny`.

## Acknowledgements

Wire-format compatibility is verified against captures of Net-SNMP's `snmptrap` (`apps/snmptrap.c`). The encoding is provided by the [`rasn`](https://github.com/librasn/rasn) crate family.
