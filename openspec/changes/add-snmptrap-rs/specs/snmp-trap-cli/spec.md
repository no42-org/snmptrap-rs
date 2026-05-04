## ADDED Requirements

### Requirement: Binary invocation and argument parsing

The system SHALL provide a `snmptrap-rs` executable whose argument grammar is a working subset of Net-SNMP's `snmptrap` such that scripts using only the supported flags and positional forms produce equivalent SNMP traps on the wire.

The executable SHALL accept:

- `-v {1|2c}` — SNMP version selector. Required.
- `-c <COMMUNITY>` — community string. Required for v1 and v2c.
- `-r <RETRIES>` — retry count for transport-level resends. Default 0 for traps.
- `-t <TIMEOUT>` — per-attempt timeout in seconds. Default 1.
- `--src-addr <IPv4>` — see `source-ip-spoofing` capability.
- `--src-port <PORT>` — UDP source port; default ephemeral.
- A trailing positional `AGENT` specifying the destination, in `host`, `host:port`, or `udp:host:port` form. Default port is 162.
- Trap-shape positionals as defined per version below.

The executable SHALL reject unknown flags with a non-zero exit status and a usage message naming the offending flag.

OIDs in any positional argument SHALL be parsed as numeric (e.g. `1.3.6.1.6.3.1.1.4.1.0`). MIB-name resolution is out of scope.

#### Scenario: Help output lists supported flags
- **WHEN** the user runs `snmptrap-rs --help`
- **THEN** the output enumerates `-v`, `-c`, `-r`, `-t`, `--src-addr`, `--src-port`, and the v1 and v2c positional forms
- **AND** the exit status is 0

#### Scenario: Missing version flag is rejected
- **WHEN** the user runs `snmptrap-rs -c public 192.0.2.1 ...` without `-v`
- **THEN** the binary exits non-zero
- **AND** stderr names the missing required flag

#### Scenario: Unknown flag is rejected
- **WHEN** the user runs `snmptrap-rs -v 2c -c public --not-a-flag 192.0.2.1`
- **THEN** the binary exits non-zero
- **AND** stderr names `--not-a-flag` as unrecognized

### Requirement: SNMPv2c trap PDU emission

When invoked with `-v 2c`, the system SHALL construct and emit an SNMPv2-Trap PDU (RFC 3416) with the positional grammar:

```
snmptrap-rs -v 2c -c <COMMUNITY> <AGENT> <UPTIME> <TRAP-OID> [OID TYPE VALUE]...
```

- `<UPTIME>` SHALL populate the mandatory first variable binding `sysUpTime.0` (`1.3.6.1.2.1.1.3.0`) as TimeTicks. An empty string SHALL cause the system to substitute the host's current uptime in hundredths of a second.
- `<TRAP-OID>` SHALL populate the mandatory second variable binding `snmpTrapOID.0` (`1.3.6.1.6.3.1.1.4.1.0`) as an OBJECT IDENTIFIER.
- Subsequent triplets `OID TYPE VALUE` SHALL append additional variable bindings whose ASN.1 type follows the type-letter (see *Variable-binding type letters* requirement).
- The community string SHALL be encoded in the SNMPv2c message as the community `OCTET STRING`.
- `request-id`, `error-status`, and `error-index` SHALL be set per RFC 3416 (request-id randomized; error-status and error-index 0).

#### Scenario: Minimal v2c trap encodes mandatory varbinds
- **WHEN** the user runs `snmptrap-rs -v 2c -c public 127.0.0.1 '' 1.3.6.1.6.3.1.1.5.1`
- **THEN** the emitted UDP datagram is a valid SNMPv2-Trap PDU
- **AND** the first varbind is `sysUpTime.0` of type TimeTicks
- **AND** the second varbind is `snmpTrapOID.0` of type OBJECT IDENTIFIER with value `1.3.6.1.6.3.1.1.5.1`

#### Scenario: Empty uptime substitutes host uptime
- **WHEN** the user passes `''` as `<UPTIME>`
- **THEN** the `sysUpTime.0` varbind contains the host's current uptime expressed in hundredths of a second

#### Scenario: Additional varbinds are appended in order
- **WHEN** the user supplies trailing `1.3.6.1.4.1.8072.2.3.2.1 i 42` after the trap-OID
- **THEN** the third varbind is `1.3.6.1.4.1.8072.2.3.2.1` of type INTEGER with value 42

### Requirement: SNMPv1 trap PDU emission

When invoked with `-v 1`, the system SHALL construct and emit an SNMPv1 Trap-PDU (RFC 1157) with the positional grammar:

```
snmptrap-rs -v 1 -c <COMMUNITY> <AGENT> <ENTERPRISE-OID> <AGENT-ADDR> <GENERIC> <SPECIFIC> <UPTIME> [OID TYPE VALUE]...
```

- `<ENTERPRISE-OID>` empty string SHALL default to `1.3.6.1.4.1.3.1.1` (matching Net-SNMP's `objid_enterprise`).
- `<AGENT-ADDR>` SHALL populate the in-PDU `agent-addr` IpAddress (4 octets, IPv4). An empty string SHALL fall back to (in order): the value of `--src-addr` if set, otherwise the IP that the kernel selects as egress source for the destination (obtained by `connect(2)`-ing a UDP socket and reading `getsockname(2)`).
- `<GENERIC>` SHALL be parsed as an integer in the range 0–6 (RFC 1157 generic-trap codes).
- `<SPECIFIC>` SHALL be parsed as a 32-bit integer.
- `<UPTIME>` empty string SHALL substitute the host's current uptime in hundredths of a second.

#### Scenario: Empty enterprise-oid uses default
- **WHEN** the user passes `''` for `<ENTERPRISE-OID>`
- **THEN** the emitted PDU's `enterprise` field equals `1.3.6.1.4.1.3.1.1`

#### Scenario: Empty agent-addr defaults to egress IP
- **WHEN** `--src-addr` is not set and the user passes `''` for `<AGENT-ADDR>`
- **THEN** the in-PDU `agent-addr` equals the IPv4 address the kernel would have used as the L3 source for the destination

#### Scenario: Empty agent-addr inherits from --src-addr
- **WHEN** `--src-addr 198.51.100.42` is set and the user passes `''` for `<AGENT-ADDR>`
- **THEN** the in-PDU `agent-addr` equals `198.51.100.42`

### Requirement: Variable-binding type letters

The system SHALL parse the following type letters in `OID TYPE VALUE` triplets and encode each variable binding with the corresponding ASN.1 type:

| Letter | ASN.1 type           | Value parsing                                         |
|--------|----------------------|-------------------------------------------------------|
| `i`    | INTEGER              | signed 32-bit decimal                                 |
| `u`    | Unsigned32 / Gauge32 | unsigned 32-bit decimal                               |
| `t`    | TimeTicks            | unsigned 32-bit decimal (hundredths of a second)     |
| `a`    | IpAddress            | dotted-quad IPv4                                      |
| `o`    | OBJECT IDENTIFIER    | numeric dotted OID                                    |
| `s`    | OCTET STRING         | UTF-8 / 8-bit bytes as given                          |
| `x`    | OCTET STRING         | hex bytes, optional separators (`:` or whitespace)    |
| `n`    | NULL                 | value SHALL be empty/ignored                          |
| `b`    | BITS                 | comma- or whitespace-separated bit positions          |
| `U`    | Counter64            | unsigned 64-bit decimal                               |

Unknown type letters SHALL cause the binary to exit non-zero with a stderr message naming the offending letter and the OID it followed.

#### Scenario: Hex string parses with separators
- **WHEN** the user supplies `... 1.2.3.4 x 'de:ad:be:ef'`
- **THEN** the resulting varbind is an OCTET STRING of bytes `[0xde, 0xad, 0xbe, 0xef]`

#### Scenario: Unknown type letter is rejected
- **WHEN** the user supplies `... 1.2.3.4 q 'whatever'`
- **THEN** the binary exits non-zero
- **AND** stderr identifies `q` as an unknown type letter and references the OID `1.2.3.4`

### Requirement: Default UDP transport

When `--src-addr` is not provided, the system SHALL send the trap over an ordinary unprivileged UDP socket. The kernel SHALL select the source IP by routing to the destination. The binary SHALL NOT require any elevated capability or privilege for this code path.

#### Scenario: Unprivileged user can send a v2c trap
- **WHEN** an unprivileged user (no `CAP_NET_RAW`, not root) runs a valid `snmptrap-rs -v 2c ...` invocation without `--src-addr`
- **THEN** the trap is sent successfully
- **AND** the L3 source address of the datagram is the host's egress IPv4 for the destination

### Requirement: Debug hex dump of emitted PDU

The system SHALL accept a `--debug-print-pdu` flag. When set, immediately before transmitting the encoded SNMP message, the binary SHALL write to stderr:

1. A one-line header containing the SNMP version, the destination `host:port`, the source IPv4 (the spoofed `--src-addr` if set, otherwise a placeholder string `<kernel-selected>`), the source port, and the payload length in bytes. The community string SHALL be redacted to `***` in this header.
2. A `xxd`-style hexadecimal + ASCII dump of the BER-encoded SNMP message payload bytes.

Stdout SHALL NOT be affected by this flag. The flag SHALL NOT alter any wire-emitted bytes; it is observation-only.

#### Scenario: Flag emits header and hexdump to stderr
- **WHEN** the user runs `snmptrap-rs --debug-print-pdu -v 2c -c public 192.0.2.50 '' 1.3.6.1.6.3.1.1.5.1`
- **THEN** stderr contains a header line naming SNMP version `2c`, destination `192.0.2.50:162`, and payload length in bytes
- **AND** stderr contains a hex+ASCII dump of the encoded payload
- **AND** stdout is empty
- **AND** the bytes transmitted on the wire are byte-identical to the same invocation without `--debug-print-pdu`

#### Scenario: Community string is redacted in the header
- **WHEN** the user runs `snmptrap-rs --debug-print-pdu -v 2c -c s3cr3t 192.0.2.50 '' 1.3.6.1.6.3.1.1.5.1`
- **THEN** the header line on stderr contains `***` and does NOT contain the literal string `s3cr3t`
- **AND** the hexdump still represents the actual encoded payload (the community string remains in the bytes; redaction applies to the header only)

### Requirement: Wire-format compatibility with Net-SNMP

The bytes emitted by the binary for a given v1 or v2c invocation SHALL be ASN.1/BER-equivalent to the bytes emitted by Net-SNMP's `snmptrap` for the same invocation, modulo non-deterministic fields (`request-id`, `sysUpTime` when defaulted, source port). This is verified by golden-byte tests captured from Net-SNMP and parsed/normalized for comparison.

#### Scenario: v2c trap matches Net-SNMP byte output
- **WHEN** the same v2c invocation (fixed request-id, fixed uptime) is run through Net-SNMP `snmptrap` and `snmptrap-rs`
- **THEN** the resulting UDP payloads decode to the same SNMP message structure
- **AND** the BER encodings of the SNMPv2-Trap PDUs are byte-identical
