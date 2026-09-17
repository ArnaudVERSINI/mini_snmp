//! Example entrypoint: encode and decode a sample SNMPv2c GetRequest.

use mini_snmp::{BerValue, Message, Pdu, PduType, VarBind};

fn main() {
    let message = Message::v2c(
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
    );

    let encoded = message.encode();
    println!("Encoded {} bytes: {:02x?}", encoded.len(), encoded);

    match Message::decode(&encoded) {
        Ok(decoded) => {
            println!(
                "Decoded: version={} community={:?} pdu_type={:?} bindings={}",
                decoded.version,
                String::from_utf8_lossy(&decoded.community),
                decoded.pdu_type,
                decoded.pdu.bindings.len()
            );
        }
        Err(e) => eprintln!("Decode error: {e}"),
    }
}
