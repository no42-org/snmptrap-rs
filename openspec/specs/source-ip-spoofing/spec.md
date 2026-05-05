# source-ip-spoofing Specification

## Purpose
TBD - created by archiving change add-snmptrap-rs. Update Purpose after archive.
## Requirements
### Requirement: Source-address override flag

The system SHALL accept a `--src-addr <IPv4>` flag that, when present, causes the L3 source IPv4 address of the emitted UDP datagram to equal the supplied address, regardless of whether the host owns that address. The flag SHALL accept any syntactically valid IPv4 address; the system SHALL NOT validate that the address is reachable, owned, routable, or otherwise legitimate.

When `--src-addr` is **absent**, the system SHALL use an ordinary unprivileged UDP socket and let the kernel select the source address (existing default behavior). The presence of `--src-addr` is the sole switch between unprivileged-default and privileged-raw code paths.

#### Scenario: Source address appears on the wire
- **WHEN** the user runs `snmptrap-rs -v 2c -c public --src-addr 198.51.100.42 192.0.2.50 '' 1.3.6.1.6.3.1.1.5.1`
- **AND** the binary has `CAP_NET_RAW`
- **THEN** the IPv4 datagram observed at the destination has source address `198.51.100.42`

#### Scenario: Absence of flag uses ordinary UDP socket
- **WHEN** the user does not pass `--src-addr`
- **THEN** the binary opens an ordinary UDP socket (no raw socket is created)
- **AND** no `CAP_NET_RAW` is required

### Requirement: --src-addr applies to trap PDUs only

The `--src-addr` capability SHALL apply to SNMP trap PDUs only (v1 Trap-PDU and v2c SNMPv2-Trap PDU). InformRequest PDUs (v2c or v3) are excluded from `--src-addr` by design; this exclusion is a permanent design boundary, not a scope cut to be revisited.

Rationale: An InformRequest expects a Response from the receiver, addressed to the request's source IP. With `--src-addr` set, that Response is destined for the spoofed address — not for this host — and either routes elsewhere or is dropped at network filters (BCP38, cloud virtual NICs, vSwitch port-security). Capturing such Responses would require raw L2 receive (AF_PACKET on Linux, `/dev/bpf*` on macOS), per-OS capability divergence beyond `CAP_NET_RAW`, and same-L2 placement of the spoofer relative to the receiver — all out of scope for this CLI's purpose as a single-binary spoofed-emit tool, not a network test harness.

When this binary implements inform-PDU emission, the implementation SHALL reject any invocation combining `--src-addr` with an inform-emission mode at CLI parse time, before any socket is opened, with a stderr message stating that `--src-addr` applies to trap PDUs only. The error SHALL NOT suggest installing capabilities, changing privileges, or otherwise circumventing the constraint — it is a design boundary, not a permissions issue.

#### Scenario: --src-addr is rejected with inform-PDU emission
- **WHEN** the binary supports inform-PDU emission
- **AND** the user combines `--src-addr <IPv4>` with any inform-emission mode (e.g. `-Ci`, or invocation as `snmpinform`)
- **THEN** the binary exits non-zero before opening any socket
- **AND** stderr names `--src-addr` as supported only for trap PDUs
- **AND** stderr does NOT contain the `setcap` remediation string or other capability/privilege guidance

### Requirement: Raw IPv4 transport via IP_HDRINCL

When `--src-addr` is set, the system SHALL emit the trap via a raw IPv4 socket (`AF_INET`, `SOCK_RAW`, `IPPROTO_UDP` or `IPPROTO_RAW`) with the `IP_HDRINCL` socket option enabled, and SHALL construct the IPv4 header, UDP header, and SNMP payload in user space.

The IPv4 header SHALL set:
- Version = 4, IHL = 5, TTL = 64, Protocol = 17 (UDP)
- Source address = value of `--src-addr`
- Destination address = resolved AGENT IPv4
- `Total Length` (octets 2–3) and `Flags+Fragment Offset` (octets 6–7): the system SHALL write these in the byte order the kernel expects for the platform — **network byte order on Linux**, **host byte order on macOS / FreeBSD / OpenBSD / NetBSD / DragonFlyBSD** (per `raw(4)` BSD-derived semantics; the kernel byte-swaps before transmit). All other multi-byte fields (`Identification`, `Source Address`, `Destination Address`, `Header Checksum`) SHALL be in network byte order on every platform.
- Don't-Fragment bit = set
- Header checksum = RFC 1071 one's-complement sum over the constructed header
- `Identification` = a fresh random 16-bit value **per send attempt** (RFC 6864) — retransmits SHALL NOT reuse the original packet's identification

The system SHALL reject SNMP payloads whose total IPv4 datagram size (20-byte IP header + 8-byte UDP header + payload) would exceed `u16::MAX` (i.e. payload bytes > `65507`); silent truncation of the IPv4 `Total Length` and UDP `Length` fields via narrowing-cast wrap is not acceptable.

The UDP header SHALL set:
- Source port = `--src-port` if provided, else an ephemeral port. The literal value `0` for `--src-port` is rejected by CLI validation (omit the flag for an ephemeral port).
- Destination port = AGENT port (default 162)
- Length = UDP header (8) + SNMP payload length
- Checksum = computed over the UDP pseudo-header **using the spoofed source address**, the UDP header, and the SNMP payload (RFC 768 / RFC 1071). The checksum SHALL NOT be 0; if the computed value is 0 it SHALL be transmitted as `0xFFFF`.

The kernel egress interface and L2 (ARP / next-hop) resolution SHALL be left to the kernel — the binary does not construct an Ethernet frame and does not perform its own ARP.

#### Scenario: UDP checksum is computed against the spoofed source
- **WHEN** the binary emits a packet with `--src-addr 198.51.100.42`
- **THEN** the UDP checksum field in the emitted datagram is the RFC 768 checksum computed with `198.51.100.42` in the pseudo-header source-address position
- **AND** a receiver validating the checksum (e.g. `tcpdump -vv`) reports the checksum as correct

#### Scenario: Don't-Fragment bit is set
- **WHEN** the binary emits a spoofed packet
- **THEN** the IPv4 DF bit is 1 in the emitted datagram

#### Scenario: Retries use a fresh IP `Identification`
- **WHEN** the binary is invoked with `--src-addr X -r 2` and the underlying `send_to` fails on the first two attempts
- **THEN** each of the three transmitted packets carries a different IPv4 `Identification` value
- **AND** receivers seeing duplicate (src,dst,proto,id) tuples cannot reassemble a stale fragment from a stranded prior attempt

#### Scenario: --src-port 0 is rejected
- **WHEN** the user runs `snmptrap-rs --src-addr 198.51.100.42 --src-port 0 192.0.2.50 ...`
- **THEN** the binary exits non-zero
- **AND** stderr names `--src-port 0` as not allowed and instructs the user to omit the flag for an ephemeral port

### Requirement: SNMPv1 in-PDU agent-addr coherence with --src-addr

When `--src-addr` is set and the user passes an empty string `''` for the SNMPv1 `<AGENT-ADDR>` positional, the system SHALL populate the in-PDU `agent-addr` IpAddress field with the value of `--src-addr`, so that the L3 source and the in-PDU device identity agree by default.

When the user passes a non-empty `<AGENT-ADDR>` positional, the system SHALL use that value verbatim for the in-PDU field, even if it differs from `--src-addr`. This permits intentional decoupling for advanced testing.

#### Scenario: Empty agent-addr inherits --src-addr
- **WHEN** the user runs `snmptrap-rs -v 1 -c public --src-addr 198.51.100.42 192.0.2.50 '' '' 6 0 ''`
- **THEN** the in-PDU `agent-addr` field decodes to `198.51.100.42`
- **AND** the L3 source address of the datagram is `198.51.100.42`

#### Scenario: Explicit agent-addr overrides
- **WHEN** the user runs `snmptrap-rs -v 1 -c public --src-addr 198.51.100.42 192.0.2.50 '' 203.0.113.5 6 0 ''`
- **THEN** the in-PDU `agent-addr` field decodes to `203.0.113.5`
- **AND** the L3 source address of the datagram is `198.51.100.42`

### Requirement: Privilege-failure diagnostics

When `--src-addr` is set and the raw socket cannot be created or used because the process lacks `CAP_NET_RAW` (Linux) or root privileges (macOS), the system SHALL exit non-zero with a structured stderr message that:

1. States the feature requires raw IP socket capability,
2. Names the platform-appropriate remediation (`setcap cap_net_raw+ep <binary>` on Linux; running as root on macOS),
3. Includes the underlying I/O error text (which itself contains the syscall errno) for debuggability.

A pointer to the project README section MAY be included but is not required.

The system SHALL distinguish capability-denied errors (raw-socket-open `EPERM`/`EACCES`) from unrelated socket failures (routing, address-in-use, MTU-related EMSGSIZE, broadcast destinations without `SO_BROADCAST`, etc.). For send-time failures (after the raw socket has already been opened), `EPERM`/`EACCES` SHALL be classified as routing-class rather than capability-class — once the open succeeds the process demonstrably has the capability, so a subsequent permission error is a destination-class problem (e.g. broadcast/multicast without the corresponding sockopt).

#### Scenario: EPERM at raw-socket open produces actionable error (Linux)
- **WHEN** an unprivileged user (no `CAP_NET_RAW`, not root) runs `snmptrap-rs --src-addr 198.51.100.42 ...` on a Linux host
- **AND** raw-socket creation returns `EPERM` or `EACCES`
- **THEN** stderr contains the literal substring `setcap cap_net_raw+ep`
- **AND** stderr contains the OS strerror text for the underlying errno (`Operation not permitted` for `EPERM`, `Permission denied` for `EACCES`)
- **AND** the binary exits non-zero

#### Scenario: Privilege denial on macOS produces an actionable error
- **WHEN** a non-root user runs `snmptrap-rs --src-addr 198.51.100.42 ...` on macOS
- **AND** raw-socket creation fails with permission denied
- **THEN** stderr contains the substring `sudo` or names root as the remediation
- **AND** stderr does NOT contain `setcap cap_net_raw+ep` (irrelevant on macOS)
- **AND** the binary exits non-zero

#### Scenario: Routing failure does not blame capabilities
- **WHEN** the binary is run with `--src-addr` and `CAP_NET_RAW`, but the destination is unreachable (e.g. no route)
- **THEN** stderr does NOT contain the `setcap` remediation message
- **AND** stderr names the routing condition (e.g. `Network is unreachable`)

#### Scenario: Send-time EACCES (broadcast without SO_BROADCAST) is classified as routing
- **WHEN** the binary is run with `--src-addr` and `CAP_NET_RAW` against a broadcast destination
- **AND** the kernel returns `EACCES` from `send_to`
- **THEN** stderr does NOT contain the `setcap` remediation message
- **AND** the error is presented as a routing/send-class condition

### Requirement: Platform support boundary

The system SHALL implement raw IPv4 + `IP_HDRINCL` source spoofing on **Linux** as the first-class target and on **macOS** as a best-effort target. The implementation gates the spoofed-send code path on `cfg(any(target_os = "linux", target_os = "macos"))`; on any other platform (FreeBSD, OpenBSD, NetBSD, DragonFlyBSD, Windows, etc.), the system SHALL exit non-zero with a clear "platform not supported for `--src-addr`" message when the flag is used. The unprivileged default code path (no `--src-addr`) SHOULD remain functional on those other platforms.

(Note: the IPv4-header byte-order shim is `cfg`-gated for the wider BSD family because Linux/BSD divergence is the relevant axis for that pure function, but the actual `send_spoofed` entry point is gated only on Linux + macOS. Extending support to FreeBSD/OpenBSD/NetBSD/DragonFlyBSD is a follow-up change.)

IPv6 source spoofing is explicitly out of scope for this change; passing an IPv6 literal to `--src-addr` SHALL be rejected with a stderr message identifying IPv6 spoofing as not supported.

#### Scenario: IPv6 literal rejected
- **WHEN** the user runs `snmptrap-rs --src-addr 2001:db8::1 ...`
- **THEN** the binary exits non-zero
- **AND** stderr names IPv6 spoofing as not supported

#### Scenario: Unsupported OS rejected
- **WHEN** the binary is run with `--src-addr` on a platform without raw IPv4 / `IP_HDRINCL` support
- **THEN** the binary exits non-zero
- **AND** stderr identifies the platform as unsupported for `--src-addr`

