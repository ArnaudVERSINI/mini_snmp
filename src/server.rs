//! Static test SNMP server.
//!
//! Listens on a UDP port, parses incoming requests with the `snmp2`
//! crate, serves them from an in-memory static store, and replies with
//! SNMPv2c Response PDUs built by our own BER encoder.
//!
//! Supports GetRequest, GetNextRequest, GetBulkRequest and SetRequest.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;

use snmp2::{MessageType, Pdu, Value};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;

use crate::ber::{tag, BerValue};
use crate::oid::{cmp_oid, oid_from_bytes, oid_to_vec};

/// Error status codes (RFC 3416).
const ERR_NOERROR: i64 = 0;
const ERR_NOSUCHNAME: i64 = 2;
const ERR_WRONGVALUE: i64 = 10;
const ERR_NOTWRITABLE: i64 = 11;

/// The single OID which may be modified with a SET request (sysContact.0).
const WRITABLE_OID: &[u64] = &[1, 3, 6, 1, 2, 1, 1, 4, 0];

/// Maximum SNMP datagram size.
const MAX_SNMP_SIZE: usize = 65_500;

/// Upper bound on max-repetitions accepted from a GetBulk request,
/// to prevent a single datagram from exhausting server resources.
const MAX_REPETITIONS_CAP: usize = 64;

/// Tag of the value type expected for sysContact.0 (OCTET STRING).
const WRITABLE_VALUE_TAG: u8 = crate::ber::tag::OCTET_STRING;

fn is_v1(version: snmp2::Version) -> bool {
    version == snmp2::Version::V1
}

/// An in-memory, mutable SNMP object store backed by a sorted map.
pub type Store = Arc<RwLock<BTreeMap<Vec<u64>, BerValue>>>;

/// Build the default static data set exposed by the test server.
pub fn default_store() -> Store {
    let mut map = BTreeMap::new();
    map.insert(
        vec![1, 3, 6, 1, 2, 1, 1, 1, 0],
        BerValue::octet_string(b"mini_snmp test server"),
    );
    map.insert(
        vec![1, 3, 6, 1, 2, 1, 1, 2, 0],
        BerValue::oid([1, 3, 6, 1, 4, 1, 99999, 1]),
    );
    map.insert(vec![1, 3, 6, 1, 2, 1, 1, 3, 0], BerValue::timeticks(123456));
    map.insert(
        vec![1, 3, 6, 1, 2, 1, 1, 4, 0],
        BerValue::octet_string(b"admin@example.com"),
    );
    map.insert(
        vec![1, 3, 6, 1, 2, 1, 1, 5, 0],
        BerValue::octet_string(b"test-host"),
    );
    map.insert(
        vec![1, 3, 6, 1, 2, 1, 1, 6, 0],
        BerValue::octet_string(b"Rack 1"),
    );
    map.insert(vec![1, 3, 6, 1, 2, 1, 1, 7, 0], BerValue::integer(72));
    map.insert(vec![1, 3, 6, 1, 2, 1, 2, 1, 0], BerValue::integer(2));
    map.insert(vec![1, 3, 6, 1, 2, 1, 4, 1, 0], BerValue::unsigned32(1));
    map.insert(
        vec![1, 3, 6, 1, 2, 1, 5, 1, 0],
        BerValue::counter32(4294967295),
    );
    map.insert(
        vec![1, 3, 6, 1, 2, 1, 6, 1, 0],
        BerValue::counter64(18446744073709551615),
    );
    Arc::new(RwLock::new(map))
}

/// Run the SNMP server until `shutdown` is triggered (or forever if never sent).
pub async fn run(
    addr: SocketAddr,
    community: Vec<u8>,
    store: Store,
    shutdown: tokio::sync::oneshot::Receiver<()>,
) -> std::io::Result<()> {
    let socket = UdpSocket::bind(addr).await?;
    run_on(socket, community, store, shutdown).await
}

/// Run the SNMP server on an already-bound socket until `shutdown` is
/// triggered (or forever if never sent).
pub async fn run_on(
    socket: UdpSocket,
    community: Vec<u8>,
    store: Store,
    shutdown: tokio::sync::oneshot::Receiver<()>,
) -> std::io::Result<()> {
    let socket = Arc::new(socket);
    eprintln!("SNMP server listening on {}", socket.local_addr()?);
    let community = Arc::new(community);
    let mut buf = vec![0u8; MAX_SNMP_SIZE];
    let mut shutdown = shutdown;

    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => {
                eprintln!("shutting down SNMP server");
                break;
            }
            res = socket.recv_from(&mut buf) => {
                let (len, peer) = match res {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("recv error: {e}");
                        continue;
                    }
                };
                let data = buf[..len].to_vec();
                let sock = socket.clone();
                let store = store.clone();
                let community = community.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle(&sock, peer, &data, &community, &store).await {
                        eprintln!("handler error from {peer}: {e}");
                    }
                });
            }
        }
    }
    Ok(())
}

async fn handle(
    socket: &UdpSocket,
    peer: SocketAddr,
    data: &[u8],
    community: &[u8],
    store: &Store,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let pdu = match Pdu::from_bytes(data) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("dropping malformed PDU from {peer}: {e}");
            return Ok(());
        }
    };

    if pdu.community != community {
        eprintln!("community mismatch from {peer}");
        return Ok(());
    }

    let version = pdu.version()?;
    let bindings: Vec<(snmp2::Oid<'_>, snmp2::Value<'_>)> = pdu.varbinds.clone().collect();

    match pdu.message_type {
        MessageType::GetRequest => {
            let store = store.read().await;
            let v1 = is_v1(version);
            let mut err_status = ERR_NOERROR;
            let mut err_index = 0i64;
            let out: Vec<(Vec<u64>, BerValue)> = bindings
                .iter()
                .enumerate()
                .map(|(i, (oid, _))| {
                    let oid_vec = oid_from_bytes(oid);
                    match store.get(&oid_vec) {
                        Some(val) => (oid_vec, val.clone()),
                        None => {
                            if v1 {
                                err_status = ERR_NOSUCHNAME;
                                err_index = (i + 1) as i64;
                                (oid_vec, BerValue::null())
                            } else {
                                (oid_vec, BerValue::no_such_instance())
                            }
                        }
                    }
                })
                .collect();
            send_response_err(
                socket, peer, version, community, pdu.req_id, err_status, err_index, out,
            )
            .await?;
        }
        MessageType::GetNextRequest => {
            let store = store.read().await;
            let v1 = is_v1(version);
            let mut err_status = ERR_NOERROR;
            let mut err_index = 0i64;
            let out: Vec<(Vec<u64>, BerValue)> = bindings
                .iter()
                .enumerate()
                .map(|(i, (oid, _))| {
                    let oid_vec = oid_from_bytes(oid);
                    match next_in_store(&store, &oid_vec) {
                        Some((next_oid, val)) => (next_oid.clone(), val.clone()),
                        None => {
                            if v1 {
                                err_status = ERR_NOSUCHNAME;
                                err_index = (i + 1) as i64;
                                (oid_vec, BerValue::null())
                            } else {
                                (oid_vec, BerValue::end_of_mib_view())
                            }
                        }
                    }
                })
                .collect();
            send_response_err(
                socket, peer, version, community, pdu.req_id, err_status, err_index, out,
            )
            .await?;
        }
        MessageType::GetBulkRequest => {
            let non_repeaters = (pdu.error_status as usize).min(bindings.len());
            let max_repetitions = (pdu.error_index as usize).min(MAX_REPETITIONS_CAP);
            let store = store.read().await;
            let mut out: Vec<(Vec<u64>, BerValue)> = Vec::new();

            for (oid, _) in bindings.iter().take(non_repeaters) {
                let oid_vec = oid_from_bytes(oid);
                match next_in_store(&store, &oid_vec) {
                    Some((next_oid, val)) => out.push((next_oid.clone(), val.clone())),
                    None => out.push((oid_vec, BerValue::end_of_mib_view())),
                }
            }
            let mut cursors: Vec<Option<Vec<u64>>> = bindings
                .iter()
                .skip(non_repeaters)
                .map(|(oid, _)| Some(oid_from_bytes(oid)))
                .collect();
            let mut active = cursors.len();
            for _ in 0..max_repetitions {
                if active == 0 {
                    break;
                }
                for cursor in cursors.iter_mut() {
                    let Some(cur) = cursor.clone() else {
                        continue;
                    };
                    match next_in_store(&store, &cur) {
                        Some((next_oid, val)) => {
                            out.push((next_oid.clone(), val.clone()));
                            *cursor = Some(next_oid.clone());
                        }
                        None => {
                            out.push((cur, BerValue::end_of_mib_view()));
                            *cursor = None;
                            active -= 1;
                        }
                    }
                }
            }
            send_response(socket, peer, version, community, pdu.req_id, out).await?;
        }
        MessageType::SetRequest => {
            let mut store = store.write().await;
            let mut out = Vec::with_capacity(bindings.len());
            let mut err_status = ERR_NOERROR;
            let mut err_index = 0i64;
            let mut staged: Vec<(Vec<u64>, BerValue)> = Vec::with_capacity(bindings.len());
            for (i, (oid, val)) in bindings.iter().enumerate() {
                let oid_vec = oid_from_bytes(oid);
                if oid_vec.as_slice() != WRITABLE_OID {
                    err_status = ERR_NOTWRITABLE;
                    err_index = (i + 1) as i64;
                    break;
                }
                match value_from_snmp(val) {
                    Some(bv) if bv.tag == WRITABLE_VALUE_TAG => {
                        staged.push((oid_vec, bv));
                    }
                    _ => {
                        err_status = ERR_WRONGVALUE;
                        err_index = (i + 1) as i64;
                        break;
                    }
                }
            }
            if err_status == ERR_NOERROR {
                for (oid_vec, bv) in &staged {
                    store.insert(oid_vec.clone(), bv.clone());
                }
                out = staged;
            }
            send_response_err(
                socket, peer, version, community, pdu.req_id, err_status, err_index, out,
            )
            .await?;
        }
        other => {
            eprintln!("unsupported message type {other:?} from {peer}");
        }
    }
    Ok(())
}

async fn send_response(
    socket: &UdpSocket,
    peer: SocketAddr,
    version: snmp2::Version,
    community: &[u8],
    req_id: i32,
    varbinds: Vec<(Vec<u64>, BerValue)>,
) -> Result<(), std::io::Error> {
    send_response_err(
        socket,
        peer,
        version,
        community,
        req_id,
        ERR_NOERROR,
        0,
        varbinds,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn send_response_err(
    socket: &UdpSocket,
    peer: SocketAddr,
    version: snmp2::Version,
    community: &[u8],
    req_id: i32,
    error_status: i64,
    error_index: i64,
    varbinds: Vec<(Vec<u64>, BerValue)>,
) -> Result<(), std::io::Error> {
    let ver = version as i64;
    let resp = BerValue::response(
        ver,
        community,
        i64::from(req_id),
        error_status,
        error_index,
        &varbinds,
    );
    let bytes = resp.encode_to_vec();
    if bytes.len() > MAX_SNMP_SIZE {
        let too_big = BerValue::response(ver, community, i64::from(req_id), 1, 0, &[]);
        socket.send_to(&too_big.encode_to_vec(), peer).await?;
        return Ok(());
    }
    socket.send_to(&bytes, peer).await?;
    Ok(())
}

fn next_in_store<'a>(
    store: &'a BTreeMap<Vec<u64>, BerValue>,
    oid: &[u64],
) -> Option<(&'a Vec<u64>, &'a BerValue)> {
    store
        .range(oid.to_vec()..)
        .find(|(k, _)| cmp_oid(k.as_slice(), oid) != std::cmp::Ordering::Equal)
}

fn value_from_snmp(v: &snmp2::Value) -> Option<BerValue> {
    match v {
        Value::Integer(i) => Some(BerValue::integer(*i)),
        Value::OctetString(s) => Some(BerValue::octet_string(*s)),
        Value::Null => Some(BerValue::null()),
        Value::ObjectIdentifier(o) => Some(BerValue::oid(oid_to_vec(o))),
        Value::IpAddress(ip) => Some(BerValue::ip_address(*ip)),
        Value::Counter32(c) => Some(BerValue::counter32(*c)),
        Value::Unsigned32(u) => Some(BerValue::unsigned32(*u)),
        Value::Timeticks(t) => Some(BerValue::timeticks(*t)),
        Value::Counter64(c) => Some(BerValue::counter64(*c)),
        Value::Opaque(o) => Some(BerValue::new(tag::OPAQUE, o.to_vec())),
        Value::Boolean(b) => Some(BerValue::new(tag::INTEGER, vec![if *b { 1 } else { 0 }])),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ber::BerValue as Bv;
    use crate::message::{Message, Pdu, PduType, VarBind};
    use std::time::Duration;

    /// Each test gets its own server on an ephemeral port with its own
    /// store, so tests are fully isolated and can run in parallel.
    async fn spawn_server() -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        std::mem::forget(tx);
        let store = default_store();
        tokio::spawn(async move {
            if let Err(e) = run_on(socket, b"public".to_vec(), store, rx).await {
                eprintln!("test server error: {e}");
            }
        });
        addr
    }

    async fn roundtrip(addr: SocketAddr, msg: &Message) -> Message {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sock.send_to(&msg.encode(), addr).await.unwrap();
        let mut buf = vec![0u8; MAX_SNMP_SIZE];
        let (len, _) = tokio::time::timeout(Duration::from_secs(2), sock.recv_from(&mut buf))
            .await
            .expect("timeout waiting for response")
            .unwrap();
        Message::decode(&buf[..len]).expect("valid response")
    }

    fn get_msg(req_id: i64, oid_arcs: &[u64]) -> Message {
        Message::v2c(
            b"public",
            PduType::GetRequest,
            Pdu {
                request_id: req_id,
                error_status: 0,
                error_index: 0,
                bindings: vec![VarBind {
                    oid: oid_arcs.to_vec(),
                    value: Bv::null(),
                }],
            },
        )
    }

    fn set_msg(req_id: i64, bindings: Vec<VarBind>) -> Message {
        Message::v2c(
            b"public",
            PduType::SetRequest,
            Pdu {
                request_id: req_id,
                error_status: 0,
                error_index: 0,
                bindings,
            },
        )
    }

    fn bulk_msg(oids: &[&[u64]], non_repeaters: i64, max_repetitions: i64) -> Message {
        Message::v2c(
            b"public",
            PduType::GetBulkRequest,
            Pdu {
                request_id: 3,
                error_status: non_repeaters,
                error_index: max_repetitions,
                bindings: oids
                    .iter()
                    .map(|o| VarBind {
                        oid: o.to_vec(),
                        value: Bv::null(),
                    })
                    .collect(),
            },
        )
    }

    #[tokio::test]
    async fn get_existing_and_missing() {
        let addr = spawn_server().await;
        let resp = roundtrip(addr, &get_msg(1, &[1, 3, 6, 1, 2, 1, 1, 1, 0])).await;
        assert_eq!(resp.pdu.error_status, 0);
        assert_eq!(resp.pdu.bindings[0].value.tag, tag::OCTET_STRING);
        assert_eq!(
            resp.pdu.bindings[0].value.bytes,
            b"mini_snmp test server".to_vec()
        );

        let resp = roundtrip(addr, &get_msg(2, &[1, 3, 6, 1, 2, 1, 99, 0])).await;
        assert_eq!(resp.pdu.bindings[0].value.tag, tag::NOSUCHINSTANCE);
    }

    #[tokio::test]
    async fn getnext_walks_store() {
        let addr = spawn_server().await;
        let msg = Message::v2c(
            b"public",
            PduType::GetNextRequest,
            Pdu {
                request_id: 4,
                error_status: 0,
                error_index: 0,
                bindings: vec![VarBind {
                    oid: vec![1, 3, 6, 1, 2, 1, 1, 1, 0],
                    value: Bv::null(),
                }],
            },
        );
        let resp = roundtrip(addr, &msg).await;
        assert_eq!(resp.pdu.bindings[0].oid, vec![1, 3, 6, 1, 2, 1, 1, 2, 0]);
    }

    #[tokio::test]
    async fn getbulk_returns_rows_and_stops_at_end() {
        let addr = spawn_server().await;
        let resp = roundtrip(addr, &bulk_msg(&[&[1, 3, 6, 1, 2, 1, 1, 1, 0]], 0, 5)).await;
        assert_eq!(resp.pdu.bindings.len(), 5);

        // Huge max-repetitions must stay bounded and EndOfMibView stops the walk.
        let resp = roundtrip(
            addr,
            &bulk_msg(&[&[1, 3, 6, 1, 2, 1, 9, 0]], 0, 2_000_000_000),
        )
        .await;
        assert_eq!(resp.pdu.bindings.len(), 1);
        assert_eq!(resp.pdu.bindings[0].value.tag, tag::ENDOFMIBVIEW);
    }

    #[tokio::test]
    async fn set_ok_and_get_reflects_it() {
        let addr = spawn_server().await;
        let resp = roundtrip(
            addr,
            &set_msg(
                5,
                vec![VarBind {
                    oid: vec![1, 3, 6, 1, 2, 1, 1, 4, 0],
                    value: Bv::octet_string(b"ops@mini.snmp"),
                }],
            ),
        )
        .await;
        assert_eq!(resp.pdu.error_status, 0);
        assert_eq!(resp.pdu.bindings[0].value.bytes, b"ops@mini.snmp".to_vec());

        let resp = roundtrip(addr, &get_msg(6, &[1, 3, 6, 1, 2, 1, 1, 4, 0])).await;
        assert_eq!(resp.pdu.bindings[0].value.bytes, b"ops@mini.snmp".to_vec());
    }

    #[tokio::test]
    async fn set_not_writable() {
        let addr = spawn_server().await;
        let resp = roundtrip(
            addr,
            &set_msg(
                7,
                vec![VarBind {
                    oid: vec![1, 3, 6, 1, 2, 1, 1, 5, 0],
                    value: Bv::octet_string(b"renamed"),
                }],
            ),
        )
        .await;
        assert_eq!(resp.pdu.error_status, ERR_NOTWRITABLE);
        assert_eq!(resp.pdu.error_index, 1);
    }

    #[tokio::test]
    async fn set_wrong_value_type() {
        let addr = spawn_server().await;
        let resp = roundtrip(
            addr,
            &set_msg(
                8,
                vec![VarBind {
                    oid: vec![1, 3, 6, 1, 2, 1, 1, 4, 0],
                    value: Bv::integer(42),
                }],
            ),
        )
        .await;
        assert_eq!(resp.pdu.error_status, ERR_WRONGVALUE);
    }

    #[tokio::test]
    async fn set_is_atomic_on_error() {
        let addr = spawn_server().await;
        // Plant our own sentinel so this test is independent of concurrent
        // tests that also SET sysContact.0.
        let resp = roundtrip(
            addr,
            &set_msg(
                13,
                vec![VarBind {
                    oid: vec![1, 3, 6, 1, 2, 1, 1, 4, 0],
                    value: Bv::octet_string(b"atomic-sentinel"),
                }],
            ),
        )
        .await;
        assert_eq!(resp.pdu.error_status, 0);

        // Multi-binding SET whose second binding fails: the first binding
        // must NOT have been applied (atomic SET).
        let resp = roundtrip(
            addr,
            &set_msg(
                9,
                vec![
                    VarBind {
                        oid: vec![1, 3, 6, 1, 2, 1, 1, 4, 0],
                        value: Bv::octet_string(b"new-contact"),
                    },
                    VarBind {
                        oid: vec![1, 3, 6, 1, 2, 1, 1, 5, 0],
                        value: Bv::octet_string(b"hacked"),
                    },
                ],
            ),
        )
        .await;
        assert_eq!(resp.pdu.error_status, ERR_NOTWRITABLE);
        assert_eq!(resp.pdu.error_index, 2);

        let resp = roundtrip(addr, &get_msg(10, &[1, 3, 6, 1, 2, 1, 1, 4, 0])).await;
        assert_eq!(
            resp.pdu.bindings[0].value.bytes,
            b"atomic-sentinel".to_vec()
        );
    }

    #[tokio::test]
    async fn bad_community_gets_no_response() {
        let addr = spawn_server().await;
        let mut msg = get_msg(11, &[1, 3, 6, 1, 2, 1, 1, 1, 0]);
        msg.community = b"wrong".to_vec();
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sock.send_to(&msg.encode(), addr).await.unwrap();
        let mut buf = vec![0u8; 1024];
        let res = tokio::time::timeout(Duration::from_millis(300), sock.recv_from(&mut buf)).await;
        assert!(res.is_err(), "server must not reply to bad community");
    }
}
