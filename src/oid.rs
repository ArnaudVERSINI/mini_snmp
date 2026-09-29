//! OID helpers built on top of the `snmp2::Oid` type.

use snmp2::Oid;

use crate::ber::decode_oid;

/// Decode an `snmp2::Oid` into a `Vec<u64>` of arcs by parsing its raw
/// BER content bytes.
pub fn oid_to_vec(oid: &Oid) -> Vec<u64> {
    decode_oid(oid.as_bytes()).unwrap_or_default()
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
