## ADDED Requirements

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

### Requirement: Raw IPv4 transport via IP_HDRINCL

When `--src-addr` is set, the system SHALL emit the trap via a raw IPv4 socket (`AF_INET`, `SOCK_RAW`, `IPPROTO_UDP` or `IPPROTO_RAW`) with the `IP_HDRINCL` socket option enabled, and SHALL construct the IPv4 header, UDP header, and SNMP payload in user space.

The IPv4 header SHALL set:
- Source address = value of `--src-addr`
- Destination address = resolved AGENT IPv4
- Protocol = 17 (UDP)
- Total length, header checksum, identification, TTL, and flags = computed/sensible defaults
- Don't-Fragment bit = set

The UDP header SHALL set:
- Source port = `--src-port` if provided, else an ephemeral port
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
3. Includes the underlying syscall errno text in parentheses for debuggability,
4. Refers the user to the project README section that documents the spoofing feature.

The system SHALL distinguish this case from unrelated socket failures (routing, address-in-use, MTU-related EMSGSIZE, etc.) and SHALL NOT print the privilege-remediation message for those cases.

#### Scenario: EPERM produces actionable error
- **WHEN** an unprivileged user (no `CAP_NET_RAW`, not root) runs `snmptrap-rs --src-addr 198.51.100.42 ...`
- **AND** the raw socket creation returns `EPERM`
- **THEN** stderr contains the literal substring `setcap cap_net_raw+ep`
- **AND** stderr contains `Operation not permitted`
- **AND** the binary exits non-zero

#### Scenario: Routing failure does not blame capabilities
- **WHEN** the binary is run with `--src-addr` and `CAP_NET_RAW`, but the destination is unreachable (e.g. no route)
- **THEN** stderr does NOT contain the `setcap` remediation message
- **AND** stderr names the routing condition (e.g. `Network is unreachable`)

### Requirement: Platform support boundary

The system SHALL implement raw IPv4 + `IP_HDRINCL` source spoofing on **Linux** as the first-class target and on **macOS / BSD** as a best-effort target. On any other platform (notably Windows), the system SHALL exit non-zero with a clear "platform not supported for `--src-addr`" message when the flag is used; the unprivileged default code path SHOULD remain functional on those platforms.

IPv6 source spoofing is explicitly out of scope for this change; passing an IPv6 literal to `--src-addr` SHALL be rejected with a stderr message identifying IPv6 spoofing as not supported.

#### Scenario: IPv6 literal rejected
- **WHEN** the user runs `snmptrap-rs --src-addr 2001:db8::1 ...`
- **THEN** the binary exits non-zero
- **AND** stderr names IPv6 spoofing as not supported

#### Scenario: Unsupported OS rejected
- **WHEN** the binary is run with `--src-addr` on a platform without raw IPv4 / `IP_HDRINCL` support
- **THEN** the binary exits non-zero
- **AND** stderr identifies the platform as unsupported for `--src-addr`
