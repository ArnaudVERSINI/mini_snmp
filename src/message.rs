//! SNMP message model and (de)serialization.
//!
//! Only the SNMPv2c message format is implemented here, which is a
//! straightforward subset of SNMPv3 and is interoperable with the vast
//! majority of devices.
//!
//! See RFC 3416 for the protocol definition.

use crate::ber::{self, tag, BerError, BerValue};

/// PDU operation type (RFC 3416).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PduType {
    GetRequest = 0xa0,
    GetNextRequest = 0xa1,
    Response = 0xa2,
    SetRequest = 0xa3,
    Trap = 0xa4,
    GetBulkRequest = 0xa5,
    InformRequest = 0xa6,
    Report = 0xa7,
}

impl PduType {
    fn as_u8(self) -> u8 {
        self as u8
    }

    fn from_u8(tag: u8) -> Option<Self> {
        match tag {
            0xa0 => Some(Self::GetRequest),
            0xa1 => Some(Self::GetNextRequest),
            0xa2 => Some(Self::Response),
            0xa3 => Some(Self::SetRequest),
            0xa4 => Some(Self::Trap),
            0xa5 => Some(Self::GetBulkRequest),
            0xa6 => Some(Self::InformRequest),
            0xa7 => Some(Self::Report),
            _ => None,
        }
    }
}

/// A single variable binding (OID + value).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VarBind {
    pub oid: Vec<u64>,
    pub value: BerValue,
}

/// A protocol data unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pdu {
    pub request_id: i64,
    pub error_status: i64,
    pub error_index: i64,
    pub bindings: Vec<VarBind>,
}

/// An SNMPv2c message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub version: i64,
    pub community: Vec<u8>,
    pub pdu_type: PduType,
    pub pdu: Pdu,
}

impl Message {
    /// Convenience constructor for a v2c message.
    pub fn v2c(community: impl AsRef<[u8]>, pdu_type: PduType, pdu: Pdu) -> Self {
        Self {
            version: 1, // SNMPv2c
            community: community.as_ref().to_vec(),
            pdu_type,
            pdu,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let varbinds: Vec<BerValue> = self
            .pdu
            .bindings
            .iter()
            .map(|b| {
                BerValue::sequence(&[BerValue::oid(&b.oid), b.value.clone()])
            })
            .collect();
        let pdu_body = BerValue::sequence(&[
            BerValue::integer(self.pdu.request_id),
            BerValue::integer(self.pdu.error_status),
            BerValue::integer(self.pdu.error_index),
            BerValue::sequence(&varbinds),
        ]);
        let pdu = BerValue::new(self.pdu_type.as_u8(), pdu_body.bytes);
        BerValue::sequence(&[
            BerValue::integer(self.version),
            BerValue::octet_string(&self.community),
            pdu,
        ])
        .encode_to_vec()
    }

    pub fn decode(input: &[u8]) -> Result<Self, BerError> {
        let (top, _) = ber::parse(input, 0)?;
        let mut parts = ber::parse_sequence(&top)?;
        if parts.len() != 3 {
            return Err(BerError::Truncated);
        }
        let version = ber::decode_integer(&parts[0].bytes)?;
        let community = parts[1].bytes.clone();
        let pdu_value = parts.remove(2);
        let pdu_type =
            PduType::from_u8(pdu_value.tag).ok_or(BerError::InvalidTag(pdu_value.tag))?;
        let pdu_children = ber::parse_sequence(&BerValue::new(tag::SEQUENCE, pdu_value.bytes))?;
        if pdu_children.len() != 4 {
            return Err(BerError::Truncated);
        }
        let request_id = ber::decode_integer(&pdu_children[0].bytes)?;
        let error_status = ber::decode_integer(&pdu_children[1].bytes)?;
        let error_index = ber::decode_integer(&pdu_children[2].bytes)?;
        let vb_list = ber::parse_sequence(&pdu_children[3])?;
        let mut bindings = Vec::with_capacity(vb_list.len());
        for vb in vb_list {
            let mut fields = ber::parse_sequence(&vb)?;
            if fields.len() != 2 {
                return Err(BerError::Truncated);
            }
            let oid = ber::decode_oid(&fields[0].bytes)?;
            let value = fields.remove(1);
            bindings.push(VarBind { oid, value });
        }
        Ok(Self {
            version,
            community,
            pdu_type,
            pdu: Pdu {
                request_id,
                error_status,
                error_index,
                bindings,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_message() -> Message {
        Message::v2c(
            b"public",
            PduType::GetRequest,
            Pdu {
                request_id: 1,
                error_status: 0,
                error_index: 0,
                bindings: vec![VarBind {
                    oid: vec![1, 3, 6, 1, 2, 1, 1, 1, 0],
                    value: BerValue::null(),
                }],
            },
        )
    }

    #[test]
    fn message_roundtrip() {
        let msg = sample_message();
        let encoded = msg.encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded.version, 1);
        assert_eq!(decoded.community, b"public");
        assert_eq!(decoded.pdu_type, PduType::GetRequest);
        assert_eq!(decoded.pdu.request_id, 1);
        assert_eq!(decoded.pdu.bindings.len(), 1);
        assert_eq!(decoded.pdu.bindings[0].oid, vec![1, 3, 6, 1, 2, 1, 1, 1, 0]);
    }

    #[test]
    fn empty_bindings_decode() {
        let msg = Message::v2c(
            b"private",
            PduType::Response,
            Pdu {
                request_id: 7,
                error_status: 0,
                error_index: 0,
                bindings: vec![],
            },
        );
        let encoded = msg.encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert!(decoded.pdu.bindings.is_empty());
        assert_eq!(decoded.pdu_type, PduType::Response);
    }
}
