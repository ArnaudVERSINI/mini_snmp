//! Test server binary: launches the static SNMP server and serves it
//! over UDP. Use any standard SNMP client (snmpget/snmpwalk/...) to
//! query it.
//!
//! Only `sysContact.0` (1.3.6.1.2.1.1.4.0) is writable; any SET on
//! another OID returns a `notWritable` error.

use std::net::SocketAddr;

use mini_snmp::server;

const COMMUNITY: &[u8] = b"public";
const BIND_ADDR: &str = "127.0.0.1:11161";

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let addr: SocketAddr = BIND_ADDR.parse().expect("valid bind address");
    let store = server::default_store();
    let (_tx, rx) = tokio::sync::oneshot::channel::<()>();
    server::run(addr, COMMUNITY.to_vec(), store, rx).await
}
