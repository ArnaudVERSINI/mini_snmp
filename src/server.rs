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
const ERR_BADVALUE: i64 = 3;

/// Maximum SNMP datagram size.
const MAX_SNMP_SIZE: usize = 65_500;

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
    let socket = Arc::new(UdpSocket::bind(addr).await?);
    eprintln!("SNMP server listening on {addr}");
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
            let out: Vec<(Vec<u64>, BerValue)> = bindings
                .iter()
                .map(|(oid, _)| {
                    let oid_vec = oid_from_bytes(oid);
                    match store.get(&oid_vec) {
                        Some(val) => (oid_vec.clone(), val.clone()),
                        None => (oid_vec.clone(), BerValue::no_such_instance()),
                    }
                })
                .collect();
            send_response(socket, peer, version, community, pdu.req_id, out).await?;
        }
        MessageType::GetNextRequest => {
            let store = store.read().await;
            let out: Vec<(Vec<u64>, BerValue)> = bindings
                .iter()
                .map(|(oid, _)| {
                    let oid_vec = oid_from_bytes(oid);
                    match next_in_store(&store, &oid_vec) {
                        Some((next_oid, val)) => (next_oid.clone(), val.clone()),
                        None => (oid_vec.clone(), BerValue::end_of_mib_view()),
                    }
                })
                .collect();
            send_response(socket, peer, version, community, pdu.req_id, out).await?;
        }
        MessageType::GetBulkRequest => {
            let non_repeaters = pdu.error_status as usize;
            let max_repetitions = pdu.error_index as usize;
            let store = store.read().await;
            let mut out: Vec<(Vec<u64>, BerValue)> = Vec::new();

            let nr_count = non_repeaters.min(bindings.len());
            for (oid, _) in bindings.iter().take(nr_count) {
                let oid_vec = oid_from_bytes(oid);
                match next_in_store(&store, &oid_vec) {
                    Some((next_oid, val)) => out.push((next_oid.clone(), val.clone())),
                    None => out.push((oid_vec.clone(), BerValue::end_of_mib_view())),
                }
            }
            let mut cursors: Vec<Vec<u64>> = bindings
                .iter()
                .skip(nr_count)
                .map(|(oid, _)| oid_from_bytes(oid))
                .collect();
            for _ in 0..max_repetitions {
                for cursor in cursors.iter_mut() {
                    match next_in_store(&store, cursor) {
                        Some((next_oid, val)) => {
                            out.push((next_oid.clone(), val.clone()));
                            *cursor = next_oid.clone();
                        }
                        None => out.push((cursor.clone(), BerValue::end_of_mib_view())),
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
            for (i, (oid, val)) in bindings.iter().enumerate() {
                let oid_vec = oid_from_bytes(oid);
                match value_from_snmp(val) {
                    Some(bv) => {
                        store.insert(oid_vec.clone(), bv.clone());
                        out.push((oid_vec.clone(), bv));
                    }
                    None => {
                        err_status = ERR_BADVALUE;
                        err_index = (i + 1) as i64;
                        out.push((oid_vec.clone(), BerValue::no_such_instance()));
                        break;
                    }
                }
            }
            if err_status != ERR_NOERROR {
                out.truncate(err_index as usize);
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
