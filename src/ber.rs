//! Minimal BER (Basic Encoding Rules) / ASN.1 encoder and decoder.
//!
//! Only the subset required by SNMP is implemented here: integers,
//! octet strings, null, object identifiers, sequences and integers
//! of arbitrary length are supported.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BerError {
    Truncated,
    InvalidTag(u8),
    InvalidLength,
    InvalidOid,
    InvalidInteger,
}

impl fmt::Display for BerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BerError::Truncated => write!(f, "truncated BER input"),
            BerError::InvalidTag(t) => write!(f, "invalid BER tag 0x{t:02x}"),
            BerError::InvalidLength => write!(f, "invalid BER length"),
            BerError::InvalidOid => write!(f, "invalid OID"),
            BerError::InvalidInteger => write!(f, "invalid integer"),
        }
    }
}

impl std::error::Error for BerError {}

/// BER universal tag numbers used by SNMP.
pub mod tag {
    pub const INTEGER: u8 = 0x02;
    pub const OCTET_STRING: u8 = 0x04;
    pub const NULL: u8 = 0x05;
    pub const OBJECT_IDENTIFIER: u8 = 0x06;
    pub const SEQUENCE: u8 = 0x30;

    // SNMP application / SNMPv2c specific tags
    pub const IP_ADDRESS: u8 = 0x40;
    pub const COUNTER32: u8 = 0x41;
    pub const UNSIGNED32: u8 = 0x42;
    pub const TIMETICKS: u8 = 0x43;
    pub const OPAQUE: u8 = 0x44;
    pub const COUNTER64: u8 = 0x46;
    pub const NOSUCHOBJECT: u8 = 0x80;
    pub const NOSUCHINSTANCE: u8 = 0x81;
    pub const ENDOFMIBVIEW: u8 = 0x82;

    // SNMP PDU context tags (constructed, application class)
    pub const GET_REQUEST: u8 = 0xa0;
    pub const GETNEXT_REQUEST: u8 = 0xa1;
    pub const RESPONSE: u8 = 0xa2;
    pub const SET_REQUEST: u8 = 0xa3;
    pub const TRAP: u8 = 0xa4;
    pub const GETBULK_REQUEST: u8 = 0xa5;
}

/// A BER value: tag plus raw content bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BerValue {
    pub tag: u8,
    pub bytes: Vec<u8>,
}

impl BerValue {
    pub fn new(tag: u8, bytes: Vec<u8>) -> Self {
        Self { tag, bytes }
    }

    pub fn integer(value: i64) -> Self {
        Self::new(tag::INTEGER, encode_integer_bytes(value))
    }

    pub fn octet_string(value: impl AsRef<[u8]>) -> Self {
        Self::new(tag::OCTET_STRING, value.as_ref().to_vec())
    }

    pub fn null() -> Self {
        Self::new(tag::NULL, Vec::new())
    }

    pub fn oid(value: impl AsRef<[u64]>) -> Self {
        Self::new(tag::OBJECT_IDENTIFIER, encode_oid_bytes(value.as_ref()))
    }

    pub fn sequence(values: &[BerValue]) -> Self {
        Self::new(tag::SEQUENCE, encode_sequence_bytes(values))
    }

    pub fn unsigned32(value: u32) -> Self {
        Self::new(tag::UNSIGNED32, encode_unsigned_bytes(value))
    }

    pub fn counter32(value: u32) -> Self {
        Self::new(tag::COUNTER32, encode_unsigned_bytes(value))
    }

    pub fn timeticks(value: u32) -> Self {
        Self::new(tag::TIMETICKS, encode_unsigned_bytes(value))
    }

    pub fn counter64(value: u64) -> Self {
        Self::new(tag::COUNTER64, encode_u64_bytes(value))
    }

    pub fn ip_address(addr: [u8; 4]) -> Self {
        Self::new(tag::IP_ADDRESS, addr.to_vec())
    }

    pub fn no_such_object() -> Self {
        Self::new(tag::NOSUCHOBJECT, Vec::new())
    }

    pub fn no_such_instance() -> Self {
        Self::new(tag::NOSUCHINSTANCE, Vec::new())
    }

    pub fn end_of_mib_view() -> Self {
        Self::new(tag::ENDOFMIBVIEW, Vec::new())
    }

    /// Build a complete SNMPv1/v2c Response message.
    ///
    /// `varbinds` is a list of (oid, value) pairs to return.
    pub fn response(
        version: i64,
        community: &[u8],
        request_id: i64,
        error_status: i64,
        error_index: i64,
        varbinds: &[(Vec<u64>, BerValue)],
    ) -> Self {
        let vbs: Vec<BerValue> = varbinds
            .iter()
            .map(|(oid, val)| BerValue::sequence(&[BerValue::oid(oid), val.clone()]))
            .collect();
        let pdu_body = BerValue::sequence(&[
            BerValue::integer(request_id),
            BerValue::integer(error_status),
            BerValue::integer(error_index),
            BerValue::sequence(&vbs),
        ]);
        let pdu = BerValue::new(tag::RESPONSE, pdu_body.bytes);
        BerValue::sequence(&[
            BerValue::integer(version),
            BerValue::octet_string(community),
            pdu,
        ])
    }

    /// Encode this value (tag, length, content) into `out`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.tag);
        encode_length(self.bytes.len(), out);
        out.extend_from_slice(&self.bytes);
    }

    pub fn encode_to_vec(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode(&mut out);
        out
    }
}

/// Encode a BER length (short or long form).
pub fn encode_length(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let mut bytes = Vec::new();
        let mut n = len;
        while n > 0 {
            bytes.push((n & 0xff) as u8);
            n >>= 8;
        }
        bytes.reverse();
        out.push(0x80 | bytes.len() as u8);
        out.extend_from_slice(&bytes);
    }
}

fn encode_integer_bytes(value: i64) -> Vec<u8> {
    if value == 0 {
        return vec![0x00];
    }
    let mut bytes = value.to_be_bytes().to_vec();
    while bytes.len() > 1
        && ((bytes[0] == 0x00 && bytes[1] & 0x80 == 0)
            || (bytes[0] == 0xff && bytes[1] & 0x80 == 0x80))
    {
        bytes.remove(0);
    }
    bytes
}

fn encode_unsigned_bytes(value: u32) -> Vec<u8> {
    if value == 0 {
        return vec![0x00];
    }
    let mut bytes = value.to_be_bytes().to_vec();
    while bytes.len() > 1 && bytes[0] == 0x00 {
        bytes.remove(0);
    }
    // ensure high bit clear so it decodes as unsigned per SNMP convention
    if bytes[0] & 0x80 != 0 {
        bytes.insert(0, 0x00);
    }
    bytes
}

fn encode_u64_bytes(value: u64) -> Vec<u8> {
    if value == 0 {
        return vec![0x00];
    }
    let mut bytes = value.to_be_bytes().to_vec();
    while bytes.len() > 1 && bytes[0] == 0x00 {
        bytes.remove(0);
    }
    if bytes[0] & 0x80 != 0 {
        bytes.insert(0, 0x00);
    }
    bytes
}

fn encode_oid_bytes(arcs: &[u64]) -> Vec<u8> {
    if arcs.len() < 2 {
        return Vec::new();
    }
    let mut out = Vec::new();
    out.push((arcs[0] * 40 + arcs[1]) as u8);
    for &arc in &arcs[2..] {
        encode_base128(arc, &mut out);
    }
    out
}

fn encode_base128(value: u64, out: &mut Vec<u8>) {
    if value == 0 {
        out.push(0x00);
        return;
    }
    let mut buf = Vec::new();
    let mut v = value;
    while v > 0 {
        buf.push((v & 0x7f) as u8);
        v >>= 7;
    }
    buf.reverse();
    for i in 0..buf.len() - 1 {
        buf[i] |= 0x80;
    }
    out.extend_from_slice(&buf);
}

fn encode_sequence_bytes(values: &[BerValue]) -> Vec<u8> {
    let mut out = Vec::new();
    for v in values {
        v.encode(&mut out);
    }
    out
}

/// Parse a single BER TLV starting at `start`. Returns the value and the
/// index just past the end of the value.
pub fn parse(input: &[u8], start: usize) -> Result<(BerValue, usize), BerError> {
    let mut i = start;
    if i >= input.len() {
        return Err(BerError::Truncated);
    }
    let tag = input[i];
    i += 1;
    if i >= input.len() {
        return Err(BerError::Truncated);
    }
    let first = input[i];
    i += 1;
    let len = if first & 0x80 == 0 {
        first as usize
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || i + n > input.len() {
            return Err(BerError::InvalidLength);
        }
        let mut len = 0usize;
        for _ in 0..n {
            len = (len << 8) | input[i] as usize;
            i += 1;
        }
        len
    };
    if i + len > input.len() {
        return Err(BerError::Truncated);
    }
    let bytes = input[i..i + len].to_vec();
    Ok((BerValue { tag, bytes }, i + len))
}

/// Parse a sequence's children from a [`BerValue`] with tag [`tag::SEQUENCE`].
pub fn parse_sequence(value: &BerValue) -> Result<Vec<BerValue>, BerError> {
    if value.tag != tag::SEQUENCE {
        return Err(BerError::InvalidTag(value.tag));
    }
    let mut out = Vec::new();
    let mut i = 0;
    while i < value.bytes.len() {
        let (child, next) = parse(&value.bytes, i)?;
        out.push(child);
        i = next;
    }
    Ok(out)
}

/// Decode an integer's content bytes as an `i64`.
pub fn decode_integer(bytes: &[u8]) -> Result<i64, BerError> {
    if bytes.is_empty() {
        return Err(BerError::InvalidInteger);
    }
    let mut value = bytes[0] as i8 as i64;
    for &b in &bytes[1..] {
        value = (value << 8) | b as i64;
    }
    Ok(value)
}

/// Decode an OID's content bytes into its arcs.
pub fn decode_oid(bytes: &[u8]) -> Result<Vec<u64>, BerError> {
    if bytes.is_empty() {
        return Err(BerError::InvalidOid);
    }
    let first = bytes[0] as u64;
    let mut arcs = vec![first / 40, first % 40];
    let mut value = 0u64;
    let mut pending = false;
    for &b in &bytes[1..] {
        pending = true;
        value = (value << 7) | (b & 0x7f) as u64;
        if b & 0x80 == 0 {
            arcs.push(value);
            value = 0;
            pending = false;
        }
    }
    if pending {
        return Err(BerError::InvalidOid);
    }
    Ok(arcs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integer_roundtrip() {
        let v = BerValue::integer(42);
        let enc = v.encode_to_vec();
        let (parsed, end) = parse(&enc, 0).unwrap();
        assert_eq!(end, enc.len());
        assert_eq!(parsed.tag, tag::INTEGER);
        assert_eq!(decode_integer(&parsed.bytes).unwrap(), 42);
    }

    #[test]
    fn negative_integer_roundtrip() {
        let v = BerValue::integer(-1);
        let enc = v.encode_to_vec();
        let (parsed, _) = parse(&enc, 0).unwrap();
        assert_eq!(decode_integer(&parsed.bytes).unwrap(), -1);
    }

    #[test]
    fn oid_roundtrip() {
        let arcs = vec![1u64, 3, 6, 1, 2, 1, 1, 1];
        let v = BerValue::oid(&arcs);
        let enc = v.encode_to_vec();
        let (parsed, _) = parse(&enc, 0).unwrap();
        assert_eq!(decode_oid(&parsed.bytes).unwrap(), arcs);
    }

    #[test]
    fn sequence_roundtrip() {
        let seq = BerValue::sequence(&[BerValue::integer(1), BerValue::null()]);
        let enc = seq.encode_to_vec();
        let (parsed, _) = parse(&enc, 0).unwrap();
        let children = parse_sequence(&parsed).unwrap();
        assert_eq!(children.len(), 2);
        assert_eq!(children[0].tag, tag::INTEGER);
        assert_eq!(children[1].tag, tag::NULL);
    }
}
