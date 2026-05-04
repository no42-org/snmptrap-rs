use std::net::Ipv4Addr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VarBindValue {
    Integer(i32),
    Unsigned32(u32),
    TimeTicks(u32),
    IpAddress(Ipv4Addr),
    ObjectId(Vec<u32>),
    OctetString(Vec<u8>),
    Null,
    Bits(Vec<u8>),
    Counter64(u64),
}

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("unknown type letter '{letter}'")]
    UnknownLetter { letter: char },

    #[error("invalid value for type '{letter}': {detail}")]
    BadValue { letter: char, detail: String },
}

/// Parse `(letter, raw)` into a typed varbind value.
pub fn parse_typed_value(letter: char, raw: &str) -> Result<VarBindValue, ParseError> {
    match letter {
        'i' => raw
            .parse::<i32>()
            .map(VarBindValue::Integer)
            .map_err(|e| ParseError::BadValue {
                letter,
                detail: format!("expected signed 32-bit decimal, got '{raw}': {e}"),
            }),
        'u' => raw
            .parse::<u32>()
            .map(VarBindValue::Unsigned32)
            .map_err(|e| ParseError::BadValue {
                letter,
                detail: format!("expected unsigned 32-bit decimal, got '{raw}': {e}"),
            }),
        't' => raw
            .parse::<u32>()
            .map(VarBindValue::TimeTicks)
            .map_err(|e| ParseError::BadValue {
                letter,
                detail: format!("expected unsigned 32-bit decimal, got '{raw}': {e}"),
            }),
        'a' => raw
            .parse::<Ipv4Addr>()
            .map(VarBindValue::IpAddress)
            .map_err(|e| ParseError::BadValue {
                letter,
                detail: format!("expected dotted-quad IPv4, got '{raw}': {e}"),
            }),
        'o' => parse_oid(raw)
            .map(VarBindValue::ObjectId)
            .map_err(|detail| ParseError::BadValue { letter, detail }),
        's' => Ok(VarBindValue::OctetString(raw.as_bytes().to_vec())),
        'x' => parse_hex_string(raw)
            .map(VarBindValue::OctetString)
            .map_err(|detail| ParseError::BadValue { letter, detail }),
        'n' => Ok(VarBindValue::Null),
        'b' => parse_bits(raw)
            .map(VarBindValue::Bits)
            .map_err(|detail| ParseError::BadValue { letter, detail }),
        'U' => raw
            .parse::<u64>()
            .map(VarBindValue::Counter64)
            .map_err(|e| ParseError::BadValue {
                letter,
                detail: format!("expected unsigned 64-bit decimal, got '{raw}': {e}"),
            }),
        other => Err(ParseError::UnknownLetter { letter: other }),
    }
}

pub fn parse_oid(s: &str) -> Result<Vec<u32>, String> {
    if s.is_empty() {
        return Err("empty OID".into());
    }
    let trimmed = s.trim_start_matches('.');
    let mut parts = Vec::new();
    for tok in trimmed.split('.') {
        if tok.is_empty() {
            return Err(format!("empty arc in OID '{s}'"));
        }
        let n: u32 = tok
            .parse()
            .map_err(|e| format!("invalid arc '{tok}' in OID '{s}': {e}"))?;
        parts.push(n);
    }
    if parts.len() < 2 {
        return Err(format!("OID '{s}' has fewer than two arcs"));
    }
    // ITU-T X.660: the first arc must be 0, 1, or 2; when the first arc is 0
    // or 1, the second arc must be < 40 (these constraints are baked into BER's
    // first-octet encoding `40*first + second`). Letting larger values through
    // produces wire bytes that decode to a different OID than the user typed.
    if parts[0] > 2 {
        return Err(format!(
            "OID '{s}' first arc must be 0, 1, or 2, got {}",
            parts[0]
        ));
    }
    if parts[0] < 2 && parts[1] >= 40 {
        return Err(format!(
            "OID '{s}' second arc must be < 40 when first arc is {}, got {}",
            parts[0], parts[1]
        ));
    }
    Ok(parts)
}

fn parse_hex_string(raw: &str) -> Result<Vec<u8>, String> {
    // Strip a leading 0x/0X prefix on the trimmed input; common in copy-pasted
    // hex output from `tcpdump -x`, `xxd`, etc.
    let trimmed = raw.trim();
    let body = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    let cleaned: String = body
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':')
        .collect();
    if cleaned.is_empty() {
        return Ok(Vec::new());
    }
    // Reject any non-ASCII or non-hex character up front so the user gets a
    // hex-shaped error rather than an opaque UTF-8 decode failure.
    for c in cleaned.chars() {
        if !c.is_ascii_hexdigit() {
            return Err(format!("non-hex character '{c}' in '{raw}'"));
        }
    }
    if !cleaned.len().is_multiple_of(2) {
        return Err(format!(
            "hex string '{}' has odd character count after stripping separators ({})",
            raw,
            cleaned.len()
        ));
    }
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    for chunk in cleaned.as_bytes().chunks(2) {
        // Safe: we've already verified every char is ASCII hex.
        let s = std::str::from_utf8(chunk).expect("ASCII-hex slice");
        let byte =
            u8::from_str_radix(s, 16).map_err(|e| format!("non-hex character in '{raw}': {e}"))?;
        out.push(byte);
    }
    Ok(out)
}

/// Hard cap on BITS bit position. Generous enough for any realistic SNMP
/// BITS textual convention (RFC 2578 named-bits OBJECT-TYPEs are well under
/// this), and prevents a CLI argument from triggering an unbounded `Vec`
/// allocation.
const MAX_BIT_POSITION: u32 = 65535;

fn parse_bits(raw: &str) -> Result<Vec<u8>, String> {
    if raw.trim().is_empty() {
        return Ok(Vec::new());
    }
    let positions: Result<Vec<u32>, _> = raw
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|s| !s.is_empty())
        .map(|s| s.parse::<u32>())
        .collect();
    let positions = positions.map_err(|e| format!("invalid BITS positions in '{raw}': {e}"))?;
    if positions.is_empty() {
        return Ok(Vec::new());
    }
    let max = *positions.iter().max().unwrap();
    if max > MAX_BIT_POSITION {
        return Err(format!(
            "BITS position {max} exceeds maximum {MAX_BIT_POSITION}",
        ));
    }
    let bytes_needed = (max as usize / 8) + 1;
    let mut out = vec![0u8; bytes_needed];
    for p in positions {
        let byte_idx = (p / 8) as usize;
        let bit_in_byte = 7 - (p % 8) as u8;
        out[byte_idx] |= 1 << bit_in_byte;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integer_valid() {
        assert_eq!(
            parse_typed_value('i', "42").unwrap(),
            VarBindValue::Integer(42)
        );
        assert_eq!(
            parse_typed_value('i', "-7").unwrap(),
            VarBindValue::Integer(-7)
        );
    }

    #[test]
    fn integer_invalid() {
        assert!(matches!(
            parse_typed_value('i', "abc"),
            Err(ParseError::BadValue { letter: 'i', .. })
        ));
    }

    #[test]
    fn unsigned32_valid_invalid() {
        assert_eq!(
            parse_typed_value('u', "4294967295").unwrap(),
            VarBindValue::Unsigned32(u32::MAX)
        );
        assert!(parse_typed_value('u', "-1").is_err());
    }

    #[test]
    fn timeticks() {
        assert_eq!(
            parse_typed_value('t', "0").unwrap(),
            VarBindValue::TimeTicks(0)
        );
        assert!(parse_typed_value('t', "abc").is_err());
    }

    #[test]
    fn ipaddress_valid_invalid() {
        assert_eq!(
            parse_typed_value('a', "10.0.0.1").unwrap(),
            VarBindValue::IpAddress(Ipv4Addr::new(10, 0, 0, 1))
        );
        assert!(parse_typed_value('a', "not-an-ip").is_err());
    }

    #[test]
    fn objid_valid_invalid() {
        assert_eq!(
            parse_typed_value('o', "1.3.6.1.4.1.8072").unwrap(),
            VarBindValue::ObjectId(vec![1, 3, 6, 1, 4, 1, 8072])
        );
        assert!(parse_typed_value('o', "1").is_err());
        assert!(parse_typed_value('o', "1..3").is_err());
        assert!(parse_typed_value('o', "1.x.3").is_err());
    }

    #[test]
    fn string_valid() {
        let v = parse_typed_value('s', "hello").unwrap();
        assert_eq!(v, VarBindValue::OctetString(b"hello".to_vec()));
    }

    #[test]
    fn hex_with_separators() {
        let v = parse_typed_value('x', "de:ad:be:ef").unwrap();
        assert_eq!(v, VarBindValue::OctetString(vec![0xde, 0xad, 0xbe, 0xef]));

        let v = parse_typed_value('x', "DEADBEEF").unwrap();
        assert_eq!(v, VarBindValue::OctetString(vec![0xde, 0xad, 0xbe, 0xef]));

        let v = parse_typed_value('x', "de ad be ef").unwrap();
        assert_eq!(v, VarBindValue::OctetString(vec![0xde, 0xad, 0xbe, 0xef]));
    }

    #[test]
    fn hex_odd_length_rejected() {
        assert!(parse_typed_value('x', "abc").is_err());
        assert!(parse_typed_value('x', "ab:c").is_err());
    }

    #[test]
    fn hex_non_hex_rejected() {
        assert!(parse_typed_value('x', "zz").is_err());
    }

    #[test]
    fn null_ignores_value() {
        let v = parse_typed_value('n', "anything").unwrap();
        assert_eq!(v, VarBindValue::Null);
    }

    #[test]
    fn bits_valid() {
        // bit 0 alone -> 0b10000000 = 0x80
        let v = parse_typed_value('b', "0").unwrap();
        assert_eq!(v, VarBindValue::Bits(vec![0x80]));

        // bits 0,1,2 together -> 0b11100000 = 0xE0
        let v = parse_typed_value('b', "0,1,2").unwrap();
        assert_eq!(v, VarBindValue::Bits(vec![0xE0]));

        // bit 8 -> second byte, high bit -> [0x00, 0x80]
        let v = parse_typed_value('b', "8").unwrap();
        assert_eq!(v, VarBindValue::Bits(vec![0x00, 0x80]));

        // whitespace separator
        let v = parse_typed_value('b', "0 1 2").unwrap();
        assert_eq!(v, VarBindValue::Bits(vec![0xE0]));
    }

    #[test]
    fn bits_invalid() {
        assert!(parse_typed_value('b', "abc").is_err());
        assert!(parse_typed_value('b', "0,xx").is_err());
    }

    #[test]
    fn counter64_valid_invalid() {
        assert_eq!(
            parse_typed_value('U', "18446744073709551615").unwrap(),
            VarBindValue::Counter64(u64::MAX)
        );
        assert!(parse_typed_value('U', "-1").is_err());
    }

    #[test]
    fn unknown_letter_names_letter() {
        let err = parse_typed_value('q', "anything").unwrap_err();
        match err {
            ParseError::UnknownLetter { letter } => assert_eq!(letter, 'q'),
            other => panic!("expected UnknownLetter, got {other:?}"),
        }
    }

    #[test]
    fn oid_first_arc_above_two_rejected() {
        let err = parse_oid("3.4.5").unwrap_err();
        assert!(err.contains("first arc"), "got {err}");
    }

    #[test]
    fn oid_second_arc_too_large_rejected() {
        let err = parse_oid("1.40.5").unwrap_err();
        assert!(err.contains("second arc"), "got {err}");
        // 2.x is allowed to have second arc >= 40 (joint-iso-itu-t branch).
        assert!(parse_oid("2.999.5").is_ok());
    }

    #[test]
    fn bits_max_position_capped() {
        let err = parse_typed_value('b', "65536").unwrap_err();
        match err {
            ParseError::BadValue {
                letter: 'b',
                detail,
            } => {
                assert!(
                    detail.contains("65536") && detail.contains("65535"),
                    "got {detail}"
                );
            }
            other => panic!("expected BadValue, got {other:?}"),
        }
    }

    #[test]
    fn hex_strips_leading_0x_prefix() {
        let v = parse_typed_value('x', "0xdeadbeef").unwrap();
        assert_eq!(v, VarBindValue::OctetString(vec![0xde, 0xad, 0xbe, 0xef]));
        let v = parse_typed_value('x', "0XDEAD").unwrap();
        assert_eq!(v, VarBindValue::OctetString(vec![0xde, 0xad]));
    }

    #[test]
    fn hex_non_ascii_yields_hex_error() {
        let err = parse_typed_value('x', "deñdbeef").unwrap_err();
        match err {
            ParseError::BadValue {
                letter: 'x',
                detail,
            } => {
                assert!(detail.contains("non-hex"), "got {detail}");
            }
            other => panic!("expected BadValue, got {other:?}"),
        }
    }
}
