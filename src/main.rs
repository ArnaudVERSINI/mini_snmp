//! Test server binary: launches a static SNMP server and runs a small
//! self-test client (GET / GETNEXT / GETBULK / SET) against it using
//! `snmp2::AsyncSession`.

use std::net::SocketAddr;
use std::time::Duration;

use mini_snmp::server;

const COMMUNITY: &[u8] = b"public";
const BIND_ADDR: &str = "127.0.0.1:11161";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr: SocketAddr = BIND_ADDR.parse()?;
    let store = server::default_store();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();

    let server_store = store.clone();
    let server_handle = tokio::spawn(async move {
        server::run(addr, COMMUNITY.to_vec(), server_store, rx)
            .await
            .expect("server failed");
    });

    // give the server a moment to bind
    tokio::time::sleep(Duration::from_millis(150)).await;

    println!("=== mini_snmp self-test against {BIND_ADDR} ===\n");
    run_client(addr).await?;

    tx.send(()).ok();
    let _ = tokio::time::timeout(Duration::from_secs(1), server_handle).await;
    Ok(())
}

async fn run_client(addr: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
    use snmp2::{AsyncSession, Oid, Value};

    let mut sess = AsyncSession::new_v2c(addr.to_string(), COMMUNITY, 0).await?;

    let sys_descr = Oid::from(&[1, 3, 6, 1, 2, 1, 1, 1, 0]).unwrap();
    let sys_uptime = Oid::from(&[1, 3, 6, 1, 2, 1, 1, 3, 0]).unwrap();
    let sys_contact = Oid::from(&[1, 3, 6, 1, 2, 1, 1, 4, 0]).unwrap();
    let unknown = Oid::from(&[1, 3, 6, 1, 2, 1, 99, 99, 0]).unwrap();
    let system = Oid::from(&[1, 3, 6, 1, 2, 1, 1]).unwrap();

    println!("[GET] sysDescr.0");
    let resp = tokio::time::timeout(Duration::from_secs(2), sess.get(&sys_descr)).await??;
    print_varbinds(&resp.varbinds);

    println!("\n[GET] sysUpTime.0");
    let resp = tokio::time::timeout(Duration::from_secs(2), sess.get(&sys_uptime)).await??;
    print_varbinds(&resp.varbinds);

    println!("\n[GET] unknown OID (expect NoSuchInstance)");
    let resp = tokio::time::timeout(Duration::from_secs(2), sess.get(&unknown)).await??;
    print_varbinds(&resp.varbinds);

    println!("\n[GETNEXT] sysDescr.0");
    let resp = tokio::time::timeout(Duration::from_secs(2), sess.getnext(&sys_descr)).await??;
    print_varbinds(&resp.varbinds);

    println!("\n[GETBULK] system subtree (non_repeaters=0, max=10)");
    let resp =
        tokio::time::timeout(Duration::from_secs(2), sess.getbulk(&[&system], 0, 10)).await??;
    print_varbinds(&resp.varbinds);

    println!("\n[SET] sysContact.0 = \"ops@mini.snmp\"");
    let new_contact = Value::OctetString(b"ops@mini.snmp");
    let resp = tokio::time::timeout(
        Duration::from_secs(2),
        sess.set(&[(&sys_contact, new_contact)]),
    )
    .await??;
    println!("  error_status = {} (0 = noError)", resp.error_status);
    print_varbinds(&resp.varbinds);

    println!("\n[GET] sysContact.0 (verify SET)");
    let resp = tokio::time::timeout(Duration::from_secs(2), sess.get(&sys_contact)).await??;
    print_varbinds(&resp.varbinds);

    Ok(())
}

fn print_varbinds(vbs: &snmp2::Varbinds<'_>) {
    for (oid, val) in vbs.clone() {
        println!("  {oid} => {val:?}");
    }
}
