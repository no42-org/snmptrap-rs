# snmp-trap-cli Specification

## Purpose
TBD - created by archiving change add-snmptrap-rs. Update Purpose after archive.
## Requirements
### Requirement: Binary invocation and argument parsing

The system SHALL provide a `snmptrap-rs` executable whose argument grammar is a working subset of Net-SNMP's `snmptrap` such that scripts using only the supported flags and positional forms produce equivalent SNMP traps on the wire.

The executable SHALL accept:

- `-v {1|2c|3}` — SNMP version selector. Required.
- `-c <COMMUNITY>` — community string. Required for `-v 1` and `-v 2c`; empty community SHALL be rejected. Silently ignored for `-v 3` (matches Net-SNMP behavior; community is not used in USM).
- `-r <RETRIES>` — retry count for transport-level resends. Default 0 for traps.
- `-t <TIMEOUT>` — accepted for Net-SNMP CLI compatibility. Trap PDUs are unconfirmed (no peer ack to time out against), so `-t` SHALL have no observable effect on trap emission; the value is parsed and validated (must be > 0) but not honored. Reserved for future inform-PDU support.
- `--src-addr <IPv4>` — see `source-ip-spoofing` capability. Applies to trap PDUs only; combining `--src-addr` with inform-PDU emission is permanently unsupported by design (see the `Requirement: --src-addr applies to trap PDUs only` clause in the `source-ip-spoofing` spec).
- `--src-port <PORT>` — UDP source port; default ephemeral. The literal value `0` SHALL be rejected (omit the flag for an ephemeral port).
- `--debug-print-pdu` — see `Debug hex dump of emitted PDU` requirement.
- `--binary-version` — see `Binary version flag` requirement.
- A trailing positional `AGENT` specifying the destination, in `host`, `host:port`, or `udp:host:port` form. Default port is 162. Bracketed-IPv6 forms (`[::1]`, `[::1]:162`) and bare-IPv6 literals (`2001:db8::1`) SHALL be rejected (only IPv4 destinations are supported).
- Trap-shape positionals as defined per version below.

When `-v 3` is selected, the executable SHALL additionally accept the SNMPv3-specific flags (see the *SNMPv3 USM security parameters* and *SNMPv3 engine-ID handling* requirements):

- `-l <noAuthNoPriv|authNoPriv|authPriv>` — security level. Default `noAuthNoPriv` if omitted (matches Net-SNMP).
- `-u <USER>` — USM user name. Required when `-v 3`.
- `-a <SHA|SHA-224|SHA-256|SHA-384|SHA-512>` — auth protocol. Required when `-l` is `authNoPriv` or `authPriv`.
- `-A <AUTH-PASS>` — auth password. Required when `-a` is set.
- `-x <AES|AES-192|AES-256>` — priv protocol. Required when `-l` is `authPriv`.
- `-X <PRIV-PASS>` — priv password. Required when `-x` is set.
- `-e <ENGINE-ID>` — context engine ID; defaults to the authoritative engine-ID.
- `-E <ENGINE-ID>` — authoritative engine-ID; defaults derived per the *SNMPv3 engine-ID handling* requirement.
- `-n <CONTEXT-NAME>` — context name; default empty.

When `-v 1` or `-v 2c` is selected, the executable SHALL reject any of the v3-specific flags listed above with a non-zero exit status and a usage message naming the offending flag and the version.

The executable SHALL reject unknown flags with a non-zero exit status and a usage message naming the offending flag.

OIDs in any positional argument SHALL be parsed as numeric (e.g. `1.3.6.1.6.3.1.1.4.1.0`). MIB-name resolution is out of scope. OID arc constraints from ITU-T X.660 SHALL be enforced: `arc[0]` SHALL be in `{0, 1, 2}`, and when `arc[0] < 2`, `arc[1]` SHALL be `< 40`. OIDs that violate these constraints SHALL be rejected with a usage error rather than encoded with garbage first-byte semantics.

#### Scenario: Help output lists supported flags
- **WHEN** the user runs `snmptrap-rs --help`
- **THEN** the output enumerates `-v`, `-c`, `-r`, `-t`, `--src-addr`, `--src-port`, `--debug-print-pdu`, `--binary-version`, the v3 flags `-l`, `-u`, `-a`, `-A`, `-x`, `-X`, `-e`, `-E`, `-n`, and the v1, v2c, and v3 positional forms
- **AND** the output is written to stdout (not stderr)
- **AND** the exit status is 0

#### Scenario: Malformed trap-OID is rejected
- **WHEN** the user supplies a trap-OID with `arc[0] > 2` (e.g. `3.4.5`) or with `arc[0] < 2` and `arc[1] >= 40` (e.g. `1.40.5`)
- **THEN** the binary exits non-zero
- **AND** stderr names the offending OID and the violated arc constraint

#### Scenario: Missing version flag is rejected
- **WHEN** the user runs `snmptrap-rs -c public 192.0.2.1 ...` without `-v`
- **THEN** the binary exits non-zero
- **AND** stderr names the missing required flag

#### Scenario: Unknown flag is rejected
- **WHEN** the user runs `snmptrap-rs -v 2c -c public --not-a-flag 192.0.2.1`
- **THEN** the binary exits non-zero
- **AND** stderr names `--not-a-flag` as unrecognized

#### Scenario: v3-specific flag with non-v3 version is rejected
- **WHEN** the user runs `snmptrap-rs -v 2c -c public -u testuser 192.0.2.1 '' 1.3.6.1.6.3.1.1.5.1`
- **THEN** the binary exits non-zero
- **AND** stderr names `-u` as not valid with `-v 2c`

#### Scenario: -c is silently ignored under -v 3
- **WHEN** the user runs `snmptrap-rs -v 3 -c public -u testuser -l noAuthNoPriv 192.0.2.50 '' 1.3.6.1.6.3.1.1.5.1`
- **THEN** the binary does not reject `-c`
- **AND** the emitted v3 message contains no community string field
- **AND** the emitted v3 message contains the user name `testuser` in `msgSecurityParameters`

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

| Letter | ASN.1 type           | v1     | v2c    | Value parsing                                                              |
|--------|----------------------|--------|--------|----------------------------------------------------------------------------|
| `i`    | INTEGER              | yes    | yes    | signed 32-bit decimal                                                      |
| `u`    | Unsigned32 / Gauge32 | yes    | yes    | unsigned 32-bit decimal                                                    |
| `t`    | TimeTicks            | yes    | yes    | unsigned 32-bit decimal (hundredths of a second)                           |
| `a`    | IpAddress            | yes    | yes    | dotted-quad IPv4                                                           |
| `o`    | OBJECT IDENTIFIER    | yes    | yes    | numeric dotted OID; X.660 arc-0/arc-1 constraints SHALL be enforced        |
| `s`    | OCTET STRING         | yes    | yes    | UTF-8 / 8-bit bytes as given                                               |
| `x`    | OCTET STRING         | yes    | yes    | hex bytes; `:`/whitespace separators allowed; optional `0x`/`0X` prefix    |
| `n`    | NULL                 | yes    | yes    | value SHALL be empty/ignored                                               |
| `b`    | BITS                 | **no** | yes    | comma- or whitespace-separated bit positions; positions capped at `65535`  |
| `U`    | Counter64            | **no** | yes    | unsigned 64-bit decimal                                                    |

`b` and `U` are SMIv2-only types. When `-v 1` is selected, the system SHALL reject a varbind with type `b` or `U` and exit non-zero with a stderr message naming the offending type letter and pointing the user at `-v 2c`.

Unknown type letters SHALL cause the binary to exit non-zero with a stderr message naming the offending letter and the OID it followed. The TYPE token SHALL be exactly one character — multi-character values like `int` or `hex` SHALL be rejected (rather than silently coerced to their first character).

The hex parser (`x`) SHALL reject non-ASCII-hex characters with a hex-shaped error message. Multibyte UTF-8 input SHALL NOT surface as a UTF-8-decode error.

The `b` (BITS) parser SHALL reject bit positions greater than `65535` to prevent unbounded allocations from CLI input.

#### Scenario: Hex string parses with separators
- **WHEN** the user supplies `... 1.2.3.4 x 'de:ad:be:ef'`
- **THEN** the resulting varbind is an OCTET STRING of bytes `[0xde, 0xad, 0xbe, 0xef]`

#### Scenario: Hex string accepts `0x` prefix
- **WHEN** the user supplies `... 1.2.3.4 x '0xdeadbeef'` or `... 1.2.3.4 x '0XDEAD'`
- **THEN** the leading `0x`/`0X` is stripped before parsing
- **AND** the resulting varbind is the corresponding OCTET STRING

#### Scenario: Unknown type letter is rejected
- **WHEN** the user supplies `... 1.2.3.4 q 'whatever'`
- **THEN** the binary exits non-zero
- **AND** stderr identifies `q` as an unknown type letter and references the OID `1.2.3.4`

#### Scenario: SMIv2-only type letter is rejected under v1
- **WHEN** the user runs `snmptrap-rs -v 1 -c public 192.0.2.50 '' '' 6 0 '' 1.2.3.4 b '0,1,2'`
- **THEN** the binary exits non-zero
- **AND** stderr identifies `b` as not representable in SNMPv1
- **AND** stderr suggests `-v 2c`

#### Scenario: BITS position above the cap is rejected
- **WHEN** the user supplies `... 1.2.3.4 b '4294967295'`
- **THEN** the binary exits non-zero
- **AND** stderr names the offending position and the maximum (`65535`)

### Requirement: Binary version flag

The system SHALL accept a `--binary-version` flag that prints the binary's version string and exits with status 0. The output SHALL be written to stdout (not stderr).

The system SHALL NOT bind `--version` (which would conflict with the convention that `-v` selects the SNMP version). A user running `snmptrap-rs --version` SHALL receive the same unknown-flag error as any other unrecognized flag.

#### Scenario: --binary-version exits 0 to stdout
- **WHEN** the user runs `snmptrap-rs --binary-version`
- **THEN** the output containing the program name and version is written to stdout
- **AND** stderr is empty
- **AND** the exit status is 0

#### Scenario: --version is unrecognized
- **WHEN** the user runs `snmptrap-rs --version`
- **THEN** the binary exits non-zero
- **AND** stderr names `--version` as unrecognized

### Requirement: Default UDP transport

When `--src-addr` is not provided, the system SHALL send the trap over an ordinary unprivileged UDP socket. The kernel SHALL select the source IP by routing to the destination. The binary SHALL NOT require any elevated capability or privilege for this code path.

#### Scenario: Unprivileged user can send a v2c trap
- **WHEN** an unprivileged user (no `CAP_NET_RAW`, not root) runs a valid `snmptrap-rs -v 2c ...` invocation without `--src-addr`
- **THEN** the trap is sent successfully
- **AND** the L3 source address of the datagram is the host's egress IPv4 for the destination

### Requirement: Debug hex dump of emitted PDU

The system SHALL accept a `--debug-print-pdu` flag. When set, immediately before transmitting the encoded SNMP message, the binary SHALL write to stderr:

1. A one-line header containing the SNMP version, the destination `host:port`, the source IPv4 (the spoofed `--src-addr` if set, otherwise the literal placeholder string `<kernel-selected>`), the source port (the pinned `--src-port` if set, otherwise the literal placeholder string `<ephemeral>`), and the payload length in bytes. The community string SHALL be redacted to `***` in this header.
2. A `xxd`-style hexadecimal + ASCII dump of the BER-encoded SNMP message payload bytes.

Stdout SHALL NOT be affected by this flag. The flag SHALL NOT alter any wire-emitted bytes and SHALL NOT trigger any observable side effect (e.g. it MUST NOT probe the egress IP via a UDP `connect()` to predict what the kernel will choose); it is observation-only.

#### Scenario: Flag emits header and hexdump to stderr
- **WHEN** the user runs `snmptrap-rs --debug-print-pdu -v 2c -c public 192.0.2.50 '' 1.3.6.1.6.3.1.1.5.1`
- **THEN** stderr contains a header line naming SNMP version `2c`, destination `192.0.2.50:162`, source IP `<kernel-selected>`, source port `<ephemeral>`, and payload length in bytes
- **AND** stderr contains a hex+ASCII dump of the encoded payload
- **AND** stdout is empty
- **AND** the bytes transmitted on the wire are byte-identical to the same invocation without `--debug-print-pdu`

#### Scenario: Header reports `--src-addr` and `--src-port` literally when set
- **WHEN** the user runs `snmptrap-rs --debug-print-pdu -v 2c -c public --src-addr 198.51.100.42 --src-port 50000 192.0.2.50 '' 1.3.6.1.6.3.1.1.5.1`
- **THEN** the header line on stderr names source IP `198.51.100.42` and source port `50000`
- **AND** the header does NOT contain the strings `<kernel-selected>` or `<ephemeral>`

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

### Requirement: SNMPv3 trap PDU emission

When invoked with `-v 3`, the system SHALL construct and emit an SNMPv3 message (RFC 3412) carrying a scopedPDU whose payload is an SNMPv2-Trap PDU (RFC 3416), with the positional grammar:

```
snmptrap-rs -v 3 -u <USER> [v3 flags] <AGENT> <UPTIME> <TRAP-OID> [OID TYPE VALUE]...
```

- `<UPTIME>`, `<TRAP-OID>`, and the trailing `OID TYPE VALUE` triplets follow the same semantics as `-v 2c` (see *SNMPv2c trap PDU emission* requirement). The inner trap PDU SHALL be byte-identical to the v2c PDU that would be produced for the same positional arguments — only the outer message wrapper differs.
- `msgVersion` SHALL be `3`.
- `msgID` SHALL be a fresh random 32-bit integer per outbound message.
- `msgSecurityModel` SHALL be `3` (USM).
- `msgFlags` SHALL encode the security level using the bit layout from RFC 3412 §6.4 (bit 0 = auth, bit 1 = priv, bit 2 = reportable): `0b000` (`0x00`) for `noAuthNoPriv`, `0b001` (`0x01`) for `authNoPriv`, `0b011` (`0x03`) for `authPriv`. The reportable bit (bit 2) SHALL be **zero** for trap PDUs — RFC 3412 §6.4 makes this SHOULD-zero for unconfirmed PDUs, Net-SNMP's `snmptrap -v 3` emits zero, and Net-SNMP's `snmptrapd` silently drops messages where the reportable bit is set on a trap.
- `msgMaxSize` SHALL be `65507` (UDP maximum payload).
- The `scopedPDU.contextEngineID` SHALL default to the authoritative engine-ID (per the *SNMPv3 engine-ID handling* requirement); user-supplied `-e CONTEXT-ENGINE-ID` overrides.
- The `scopedPDU.contextName` SHALL default to an empty `OCTET STRING`; `-n NAME` overrides.

#### Scenario: Minimal v3 noAuthNoPriv trap encodes mandatory varbinds
- **WHEN** the user runs `snmptrap-rs -v 3 -u testuser -l noAuthNoPriv 127.0.0.1 '' 1.3.6.1.6.3.1.1.5.1`
- **THEN** the emitted UDP datagram is a valid SNMPv3 message
- **AND** the inner scopedPDU is an SNMPv2-Trap PDU
- **AND** the first varbind is `sysUpTime.0` of type TimeTicks
- **AND** the second varbind is `snmpTrapOID.0` of type OBJECT IDENTIFIER with value `1.3.6.1.6.3.1.1.5.1`

#### Scenario: v3 trap PDU is byte-identical to v2c trap PDU for same positionals
- **WHEN** the user runs the same positional arguments with `-v 2c -c public ...` and with `-v 3 -u testuser -l noAuthNoPriv ...`
- **THEN** the inner v2-Trap PDU bytes (the scopedPDU.data field of the v3 message) are byte-identical to the PDU bytes of the v2c message, modulo the request-id (which is randomized per message)

#### Scenario: msgFlags encodes security level
- **WHEN** the user runs with `-l noAuthNoPriv`
- **THEN** msgFlags has bits set: reportable=0, auth=0, priv=0 (byte = 0x00)
- **WHEN** the user runs with `-l authNoPriv`
- **THEN** msgFlags has bits set: reportable=0, auth=1, priv=0 (byte = 0x01)
- **WHEN** the user runs with `-l authPriv`
- **THEN** msgFlags has bits set: reportable=0, auth=1, priv=1 (byte = 0x03)

### Requirement: SNMPv3 USM security parameters and password localization

When `-v 3` is selected, the system SHALL populate the `msgSecurityParameters` field with USM-specific data per RFC 3414:

- `authoritativeEngineID` — the value resolved per the *SNMPv3 engine-ID handling* requirement.
- `authoritativeEngineBoots` — SHALL be `1` for every invocation. The system SHALL NOT persist a boot counter across invocations.
- `authoritativeEngineTime` — SHALL be the integer count of seconds elapsed since the process started.
- `userName` — the value passed via `-u USER`.
- `authenticationParameters`:
  - When `-l` is `noAuthNoPriv`: an empty `OCTET STRING` (zero bytes).
  - When `-l` is `authNoPriv` or `authPriv`: the truncated HMAC tag computed per RFC 7860 over the entire serialized message with `authenticationParameters` set to a zero-filled placeholder of the same length as the eventual tag, then spliced in. Tag length per protocol: SHA-1 → 12 bytes; SHA-224 → 16; SHA-256 → 24; SHA-384 → 32; SHA-512 → 48.
- `privacyParameters`:
  - When `-l` is `noAuthNoPriv` or `authNoPriv`: an empty `OCTET STRING`.
  - When `-l` is `authPriv`: an 8-byte salt drawn fresh from the RNG per outbound message. The salt is the second half of the 16-byte AES-CFB IV; the first half is `authoritativeEngineBoots || authoritativeEngineTime` (4 bytes each, big-endian) per RFC 3826 §3.

When `-l` requires authentication or encryption, the system SHALL derive auth and priv keys from the user-supplied passwords (`-A`, `-X`) per the RFC 3414 §A.2 password-to-key algorithm extended for the SHA-2 family per RFC 7860 §3.4. The KDF SHALL localize the digest against the authoritative engine-ID by hashing `digest || engineID || digest` with the auth protocol's hash function. The derived key length SHALL match the auth protocol's hash output (20/28/32/48/64 bytes for SHA-1/224/256/384/512).

For priv keys, the localized key SHALL be truncated or extended to match the AES variant's required key length (16/24/32 bytes for AES-128/192/256). Truncation rule per RFC 3826: the first N bytes of the localized key are used directly.

#### Scenario: authPriv produces an HMAC tag of the protocol's defined length
- **WHEN** the user runs with `-l authPriv -a SHA-256 -A 'authpassword1234' -x AES -X 'privpassword1234'`
- **THEN** the `authenticationParameters` field of the emitted message is exactly 24 bytes (SHA-256 truncated tag length per RFC 7860)
- **AND** re-computing HMAC-SHA-256 over the message with the placeholder reproduces the same 24 bytes

#### Scenario: privacyParameters salt is per-message random
- **WHEN** the user runs the same authPriv invocation twice
- **THEN** the `privacyParameters` field differs between the two emitted messages
- **AND** decrypting each message with the priv key + its own salt yields the same plaintext scopedPDU

#### Scenario: noAuthNoPriv has empty auth and priv parameters
- **WHEN** the user runs with `-l noAuthNoPriv`
- **THEN** the `authenticationParameters` field is an empty OCTET STRING
- **AND** the `privacyParameters` field is an empty OCTET STRING

#### Scenario: engineBoots is always 1 per invocation
- **WHEN** the user runs the same v3 invocation twice in quick succession
- **THEN** both emitted messages carry `authoritativeEngineBoots = 1`
- **AND** the `authoritativeEngineTime` of the second is greater than or equal to that of the first

### Requirement: SNMPv3 engine-ID handling

When `-v 3` is selected, the system SHALL resolve the authoritative engine-ID via this cascade:

1. If the user passed `-E <ENGINE-ID>`, use that value verbatim. The user-supplied value SHALL be parsed as either a hexadecimal byte string (with or without `0x` prefix; whitespace and `:` separators allowed) or as raw bytes; on parse failure, the binary SHALL exit non-zero with a usage error naming the offending value.
2. Otherwise, if `--src-addr <X>` is set, the authoritative engine-ID SHALL be constructed per RFC 3411 §5 format 1 (IPv4):
   - Octets 0–3: `0x80 0x00 0xF0 0x45` (IANA Private Enterprise Number 61509 with the high bit set on octet 0).
   - Octet 4: `0x01` (format selector for IPv4).
   - Octets 5–8: `X` encoded big-endian (4 bytes).
   - Total length: 9 octets.
3. Otherwise, if the host has a usable primary network interface, the authoritative engine-ID SHALL be constructed per RFC 3411 §5 format 3 (MAC):
   - Octets 0–3: `0x80 0x00 0xF0 0x45`.
   - Octet 4: `0x03` (format selector for MAC).
   - Octets 5–10: the 6-byte MAC address of the primary interface.
   - Total length: 11 octets.
4. Otherwise (no usable network interface), the authoritative engine-ID SHALL fall back to RFC 3411 §5 format 4 (text) with payload = the host's hostname truncated to 27 bytes:
   - Octets 0–3: `0x80 0x00 0xF0 0x45`.
   - Octet 4: `0x04` (format selector for text).
   - Octets 5–N: hostname bytes (UTF-8, truncated to fit).

The context engine-ID inside the scopedPDU SHALL default to the authoritative engine-ID. The user MAY override the context engine-ID independently via `-e <CONTEXT-ENGINE-ID>`; same parsing rules as `-E`.

#### Scenario: Default engine-ID with --src-addr uses IPv4 format
- **WHEN** the user runs `snmptrap-rs -v 3 -u testuser -l noAuthNoPriv --src-addr 198.51.100.42 192.0.2.50 '' 1.3.6.1.6.3.1.1.5.1`
- **AND** `-E` is not set
- **THEN** the `authoritativeEngineID` octets are `0x80 0x00 0xF0 0x45 0x01 0xC6 0x33 0x64 0x2A` (9 bytes total)

#### Scenario: Default engine-ID without --src-addr uses MAC format
- **WHEN** the user runs `snmptrap-rs -v 3 -u testuser -l noAuthNoPriv 192.0.2.50 '' 1.3.6.1.6.3.1.1.5.1`
- **AND** `-E` is not set
- **AND** `--src-addr` is not set
- **AND** the host has a usable primary interface
- **THEN** the `authoritativeEngineID` is 11 octets long
- **AND** the first 4 octets are `0x80 0x00 0xF0 0x45`
- **AND** octet 4 is `0x03`

#### Scenario: User-supplied -E overrides the cascade
- **WHEN** the user runs `... --src-addr 198.51.100.42 -E 80001fa0500102 ...`
- **THEN** the `authoritativeEngineID` is the user-supplied value (parsed from hex)
- **AND** the IPv4-derived default is NOT used

#### Scenario: -E parse failure produces a usage error
- **WHEN** the user passes `-E 'not-hex-or-bytes'`
- **THEN** the binary exits non-zero
- **AND** stderr names the offending value and the expected format

#### Scenario: contextEngineID defaults to authoritativeEngineID
- **WHEN** the user does not pass `-e`
- **THEN** the scopedPDU's `contextEngineID` octets equal the message's `authoritativeEngineID` octets

### Requirement: Legacy crypto rejection at CLI parse time

The system SHALL reject the following legacy crypto algorithms at CLI parse time, before any socket is opened and before any crypto module is invoked:

- `-a MD5` (HMAC-MD5, RFC 3414 default) — exit non-zero with stderr message naming HMAC-MD5 as not supported in this build and pointing at the SHA family as the modern replacement.
- `-x DES` (DES-CBC, RFC 3414 default) — exit non-zero with stderr message naming DES-CBC as not supported in this build and pointing at AES, AES-192, or AES-256 as the modern replacement.
- `-x 3DES` (3DES-CBC, Cisco extension) — exit non-zero with stderr message naming 3DES-CBC as not supported in this build and pointing at AES-256 as the modern replacement.

The error messages SHALL NOT instruct the user to install additional capabilities, change privileges, or otherwise circumvent the rejection — these are deliberate scope cuts driven by 2026 cryptographic guidance, not transient implementation gaps.

#### Scenario: -a MD5 rejected at parse
- **WHEN** the user runs `snmptrap-rs -v 3 -u testuser -l authNoPriv -a MD5 -A 'pw' 192.0.2.50 ...`
- **THEN** the binary exits non-zero
- **AND** stderr names HMAC-MD5 as not supported
- **AND** stderr suggests one of the SHA family
- **AND** no socket is opened

#### Scenario: -x DES rejected at parse
- **WHEN** the user runs `snmptrap-rs -v 3 -u testuser -l authPriv -a SHA -A 'pw' -x DES -X 'pw' 192.0.2.50 ...`
- **THEN** the binary exits non-zero
- **AND** stderr names DES-CBC as not supported
- **AND** stderr suggests AES, AES-192, or AES-256

#### Scenario: -x 3DES rejected at parse
- **WHEN** the user runs `snmptrap-rs -v 3 -u testuser -l authPriv -a SHA-256 -A 'pw' -x 3DES -X 'pw' 192.0.2.50 ...`
- **THEN** the binary exits non-zero
- **AND** stderr names 3DES-CBC as not supported
- **AND** stderr suggests AES-256

