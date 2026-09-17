# mini_snmp

A minimal [SNMP](https://datatracker.ietf.org/doc/html/rfc1157) (Simple Network Management Protocol) implementation written in Rust.

## Features

- SNMP v1/v2c message encoding and decoding (custom BER/ASN.1 codec in `src/ber.rs`)
- BER/ASN.1 serialization: integers (signed), octet strings, null, OIDs, sequences,
  plus SNMPv2c application types (Counter32, Unsigned32, Timeticks, Counter64,
  IpAddress, Opaque, NoSuchObject/Instance, EndOfMibView)
- **Static test SNMP server** (`src/server.rs`) built with **tokio** + **snmp2**:
  - Parses incoming requests with the `snmp2` crate (`Pdu::from_bytes`)
  - Serves data from an in-memory sorted store (`BTreeMap`)
  - Builds and sends `Response` PDUs with the built-in BER encoder
  - Supports **GetRequest**, **GetNextRequest**, **GetBulkRequest** and **SetRequest**
  - Returns `NoSuchInstance` / `EndOfMibView` where appropriate
  - Mutable store: `SET` updates the values held in memory

## Building

```sh
cargo build
```

## Running the self-test

The binary launches the test server on `127.0.0.1:11161` (community `public`)
and runs a GET / GETNEXT / GETBULK / SET self-test against it using
`snmp2::AsyncSession`:

```sh
cargo run
```

Example output:

```
SNMP server listening on 127.0.0.1:11161
=== mini_snmp self-test against 127.0.0.1:11161 ===

[GET] sysDescr.0
  1.3.6.1.2.1.1.1.0 => OCTET STRING: mini_snmp test server
[GET] sysUpTime.0
  1.3.6.1.2.1.1.3.0 => TIMETICKS: 123456
[GET] unknown OID (expect NoSuchInstance)
  1.3.6.1.2.1.99.99.0 => NO SUCH INSTANCE
[GETBULK] system subtree (non_repeaters=0, max=10)
  1.3.6.1.2.1.1.1.0 => OCTET STRING: mini_snmp test server
  ... (10 varbinds)
[SET] sysContact.0 = "ops@mini.snmp"
  error_status = 0 (0 = noError)
[GET] sysContact.0 (verify SET)
  1.3.6.1.2.1.1.4.0 => OCTET STRING: ops@mini.snmp
```

You can also point any standard SNMP client at the server, e.g.:

```sh
snmpget -v 2c -c public 127.0.0.1:11161 1.3.6.1.2.1.1.1.0
snmpwalk -v 2c -c public 127.0.0.1:11161 1.3.6.1.2.1.1
snmpbulkwalk -v 2c -c public 127.0.0.1:11161 1.3.6.1.2.1.1
```

## Embedding the server

```rust
use mini_snmp::server;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let store = server::default_store();
    let (_tx, rx) = tokio::sync::oneshot::channel::<()>();
    server::run("127.0.0.1:11161".parse().unwrap(), b"public".to_vec(), store, rx).await
}
```

## Testing

```sh
cargo test
```

## License

MIT
