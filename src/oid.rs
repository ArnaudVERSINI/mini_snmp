//! OID helpers built on top of the `snmp2::Oid` type.

use snmp2::Oid;

/// Decode an `snmp2::Oid` into a `Vec<u64>` of arcs by parsing its raw
/// BER content bytes.
pub fn oid_to_vec(oid: &Oid) -> Vec<u64> {
    decode_oid_bytes(oid.as_bytes())
}

/// Alias for [`oid_to_vec`].
pub fn oid_from_bytes(oid: &Oid) -> Vec<u64> {
    oid_to_vec(oid)
}

/// Lexicographic comparison of two OIDs (as arc slices).
pub fn cmp_oid(a: &[u64], b: &[u64]) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    let mut i = 0;
    loop {
        match (a.get(i), b.get(i)) {
            (Some(x), Some(y)) => match x.cmp(y) {
                Ordering::Equal => i += 1,
                ord => return ord,
            },
            (Some(_), None) => return Ordering::Greater,
            (None, Some(_)) => return Ordering::Less,
            (None, None) => return Ordering::Equal,
        }
    }
}

/// Build an `snmp2::Oid` from a slice of arcs.
pub fn oid_from_arcs(arcs: &[u64]) -> Option<Oid<'static>> {
    Oid::from(arcs).ok()
}

fn decode_oid_bytes(bytes: &[u8]) -> Vec<u64> {
    if bytes.is_empty() {
        return Vec::new();
    }
    let first = bytes[0] as u64;
    let mut arcs = vec![first / 40, first % 40];
    let mut value = 0u64;
    for &b in &bytes[1..] {
        value = (value << 7) | (b & 0x7f) as u64;
        if b & 0x80 == 0 {
            arcs.push(value);
            value = 0;
        }
    }
    arcs
}
