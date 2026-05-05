# snmptrap-rs

A Rust port of Net-SNMP's `snmptrap` with one extra trick: **emit traps from any IPv4 source address you like**, without needing `iptables`/`nftables` SNAT, IP aliases, or network namespaces.

Supports SNMPv1, SNMPv2c, and SNMPv3 trap PDUs. The default code path is unprivileged and behaves like `snmptrap`. The `--src-addr` flag opens a raw IPv4 socket with `IP_HDRINCL` and forges the L3 source — that path needs `CAP_NET_RAW` on Linux (or `sudo` on macOS).

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

**Quick path — `cargo install` (no spoofing).** Fine if you don't need `--src-addr`. SNMPv1/v2c/v3 trap emission all work without raw-socket privileges; only `--src-addr` requires `CAP_NET_RAW`. Produces a glibc-dynamic binary; do **not** combine with `setcap` on hardened distros. MSRV is `rustc >= 1.87` (edition 2024).

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

### SNMPv3 trap (authPriv)

```bash
snmptrap-rs -v 3 -u alice \
    -l authPriv \
    -a SHA-256 -A 'authpassword1234' \
    -x AES     -X 'privpassword1234' \
    192.0.2.50 \
    '' 1.3.6.1.6.3.1.1.5.1
```

Same trailing positionals as `-v 2c` (`<UPTIME> <TRAP-OID> [OID TYPE VALUE]...`). The community string (`-c`) is silently ignored under v3 — USM replaces it with `-u <USER>` plus auth/priv parameters.

Modern crypto only: `-a` accepts the SHA-2 family (`SHA`, `SHA-224`, `SHA-256`, `SHA-384`, `SHA-512`); `-x` accepts AES variants (`AES`, `AES-192`, `AES-256`). HMAC-MD5, DES-CBC, and 3DES-CBC are rejected at parse time with a deprecation hint pointing at the modern replacement. Passwords must be ≥8 characters per RFC 3414 §11.2 (enforced at the CLI surface, not just downstream). `-l noAuthNoPriv` is the default if `-l` is omitted; the auth/priv flags are then unused.

> **Note:** auth/priv passwords passed via `-A`/`-X` appear in `argv` and are visible in `ps` output and shell history. For sensitive credentials use a dedicated test or sandbox account, not a production one. Reading from stdin/file/env-var is a future addition.

### Spoofed v3 trap with engine-ID coherence

```bash
snmptrap-rs -v 3 -u alice -l authPriv \
    -a SHA-256 -A 'authpassword1234' \
    -x AES     -X 'privpassword1234' \
    --src-addr 198.51.100.42 \
    192.0.2.50 \
    '' 1.3.6.1.6.3.1.1.5.1
```

When `-E` is unset and `--src-addr` is set, the authoritative engine-ID is derived from the spoofed IPv4 per RFC 3411 §5 format 1: `80 00 F0 45 01 <X1 X2 X3 X4>` (the prefix is no42.org's IANA Private Enterprise Number 61509 with bit 7 of octet 0 set). The receiver sees `198.51.100.42` at L3 *and* the engine-ID encoding that same address — the v3 analogue of v1's `agent-addr` ↔ `--src-addr` coherence.

A receiver that performs USM key localization needs a `createUser -e <engine-id> <user> <auth-proto> "<auth-pass>" <priv-proto> "<priv-pass>"` entry matching the engine-ID on the wire; without that, snmptrapd silently drops the trap. See [Engine-ID handling (SNMPv3)](#engine-id-handling-snmpv3) below for the full default-resolution cascade.

### Debug the bytes on the wire

```bash
snmptrap-rs --debug-print-pdu -v 2c -c public 192.0.2.50 '' 1.3.6.1.6.3.1.1.5.1
```

A `xxd`-style hex+ASCII dump of the encoded SNMP message is written to stderr immediately before send. Stdout is unaffected. The header line redacts the community string to `***` and reports placeholder strings (`<kernel-selected>` for the source IP when `--src-addr` is unset, `<ephemeral>` for the source port when `--src-port` is unset) — the flag is observation-only and does not probe the network. The byte dump is the actual encoded BER and is byte-identical to a run without `--debug-print-pdu`.

## Supported flags

| Flag | Purpose | Default |
|---|---|---|
| `-v {1\|2c\|3}` | SNMP version | required |
| `-c <COMMUNITY>` | Community string. Required for v1/v2c; silently ignored under v3 (USM replaces it) | "" |
| `-r <RETRIES>` | Send retry count | 0 |
| `-t <SECONDS>` | Accepted for Net-SNMP CLI compat; **no effect on traps** (unconfirmed PDUs have no peer ack to time out against) | 1 |
| `--src-addr <IPv4>` | Spoof L3 source — requires `CAP_NET_RAW` | unset |
| `--src-port <PORT>` | Pin UDP source port. `0` is rejected (omit the flag for an ephemeral port) | ephemeral |
| `--debug-print-pdu` | Hexdump the encoded BER to stderr before send (observation-only) | off |
| `--binary-version` | Print binary version and exit. Note: `--version` is intentionally not bound — clap's default version flag is disabled because `-v` is taken by SNMP version. | — |
| `-h, --help` | Help (exits 0 to stdout) | — |

### SNMPv3 USM flags (only with `-v 3`)

These flags are rejected with a usage error if used under `-v 1` or `-v 2c`. Conditional requirements (e.g. `-a` and `-A` are mandatory once `-l authNoPriv` is selected) are enforced post-parse before any socket opens.

| Flag | Purpose | Default / required when |
|---|---|---|
| `-l <LEVEL>` | Security level: `noAuthNoPriv`, `authNoPriv`, or `authPriv`. Net-SNMP names accepted case-insensitively. | `noAuthNoPriv` if omitted under `-v 3` |
| `-u <USER>` | USM user name | required under `-v 3` |
| `-a <AUTH-PROTO>` | Auth protocol: `SHA` (= SHA-1), `SHA-224`, `SHA-256`, `SHA-384`, `SHA-512`. `MD5`/`HMAC-MD5` rejected at parse time. | required when `-l authNoPriv` or `-l authPriv` |
| `-A <AUTH-PASS>` | Auth password (≥8 chars per RFC 3414 §11.2). Visible in `ps` output — see Note above. | required when `-a` is set |
| `-x <PRIV-PROTO>` | Priv protocol: `AES` (= AES-128), `AES-192`, `AES-256`. `DES`/`3DES` rejected at parse time. | required when `-l authPriv` |
| `-X <PRIV-PASS>` | Priv password (≥8 chars). Same `argv` caveat as `-A`. | required when `-x` is set |
| `-e <ENGINE-ID>` | Context engine-ID (hex; `0x` prefix, `:` and whitespace separators all OK) | defaults to authoritative engine-ID |
| `-E <ENGINE-ID>` | Authoritative engine-ID (hex, same format) | derived per the cascade below |
| `-n <CONTEXT>` | Context name | empty |

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

**Supported:** v1 trap, v2c trap, **v3 trap with HMAC-SHA family auth + AES-128/192/256 priv** (modern crypto only), common flags above, the var-bind type letters listed above (with v1/v2c rejection notes), numeric OIDs, the Net-SNMP `-3*` USM flag family (`-l`, `-u`, `-a`, `-A`, `-x`, `-X`, `-e`, `-E`, `-n`).

**Not supported in this version:**

- HMAC-MD5 (`-a MD5`), DES-CBC (`-x DES`), 3DES-CBC (`-x 3DES`) — rejected at CLI parse time per RFC 8996 deprecation guidance. The error message points at the modern replacement. If a real receiver compels you to use legacy crypto, file an issue.
- SNMPv3 engine-ID **discovery** (RFC 3414 §4) — only relevant for inform PDUs; this binary emits traps, where the sender is the authoritative engine. Pass `-E` (or rely on the cascade) to set the engine-ID statically.
- SNMPv3 pre-localized binary keys (`-3k`/`-3K`); password-from-stdin/file/env-var. Net-SNMP advanced-flag corners; add per demand.
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

**`engineBoots = 1` per invocation (SNMPv3).** snmptrap-rs is stateless — there is no on-disk boot counter. Every v3 trap carries `engineBoots = 1` and `engineTime = elapsed seconds since process start`. RFC 3414 §3.2 makes timeliness windowing SHOULD-level for traps (vs MUST-level for confirmed PDUs), so most receivers tolerate this. Receivers configured with strict timeliness windows on traps may discard ours when they see `engineBoots = 1` repeatedly with monotonically-shifting `engineTime` and no boot increment between bursts. If you hit that, pass a fixed `-E ENGINE-ID` so the receiver gets per-engine state with a predictable boundary, or run the binary fresh each time so `engineTime` stays small. Persistent boot-counter state is a deferred follow-up.

**Inform PDUs are intentionally out of scope for `--src-addr`, permanently.** Even if a future release adds inform-PDU emission to this binary, the `--src-addr` + inform combination will be rejected at the CLI surface. An InformRequest expects a Response from the receiver, addressed to the request's source IP — and that's the spoofed address, which routes elsewhere (or gets dropped at the same BCP38/cloud-NIC layers above). Recovering the Response would require raw L2 capture (AF_PACKET on Linux, `/dev/bpf*` on macOS), per-OS capability divergence beyond `CAP_NET_RAW`, and same-L2 placement relative to the receiver — out of scope for a single-binary CLI. The decision is captured as the `Requirement: --src-addr applies to trap PDUs only` clause in `openspec/specs/source-ip-spoofing/spec.md`.

## Engine-ID handling (SNMPv3)

The authoritative engine-ID identifies the sending engine in the USM security parameters. The default-resolution cascade:

1. **`-E ENGINE-ID` user override** — used verbatim. Hex with or without `0x` prefix; `:` and whitespace separators are stripped. Length must be 5–32 octets per RFC 3411 §5.
2. **`--src-addr X` set, no `-E`** → RFC 3411 §5 **format 1 (IPv4)**: `0x80 0x00 0xF0 0x45 0x01 <X1 X2 X3 X4>` (9 octets total). The four-octet prefix is no42.org's IANA Private Enterprise Number 61509 (`0x0000F045`) with the high bit set on octet 0 per the RFC. This is the v3 analogue of v1's `agent-addr` ↔ `--src-addr` coherence: device identity at L3 and inside USM agree by default.
3. **Linux only — host primary-interface MAC** → format 3: `0x80 0x00 0xF0 0x45 0x03 <MAC bytes>` (11 octets). `host_mac()` reads `/sys/class/net/*/address` and skips virtual / bridge / bonded / tunnel / container interfaces (`docker*`, `br-*`, `bond*`, `virbr*`, `veth*`, `tun*`, `tap*`, `wg*`, `cni*`, `kube*`, `flannel*`, `cilium*`, `ovs*`, `dummy*`, `vboxnet*`, `vmnet*`) so engine-ID stays stable on developer workstations running Docker. Two-tier sort prefers `en*`/`eth*`/`wl*` interface names within the survivors.
4. **macOS / fallback** → format 4 (text), payload = the host's hostname truncated to 27 bytes. macOS MAC discovery via `getifaddrs()` is a future addition; until then macOS hosts get the hostname-derived engine-ID. Production users who need stable identity on macOS should pass `-E` directly.

The context engine-ID (`-e`) defaults to the authoritative engine-ID. Override independently if the receiver uses distinct context lookups.

A receiver that performs USM key localization must have its `createUser -e <engine-id> <user> ...` configuration matching the engine-ID on the wire — otherwise it computes keys against the wrong engine-ID and silently rejects the trap. The `tests/docker/snmptrapd.conf` fixture in this repo shows the pattern.

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
