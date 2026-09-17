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
  - **Only one OID is writable**: `sysContact.0` (1.3.6.1.2.1.1.4.0)
  - Any `SET` on any other OID returns a `notWritable` error (RFC 3416)

## Building

```sh
cargo build
```

## Running the server

The binary launches the test server on `127.0.0.1:11161` (community `public`):

```sh
cargo run
```

It only serves requests — point any standard SNMP client at it:

```sh
snmpget -v 2c -c public 127.0.0.1:11161 1.3.6.1.2.1.1.1.0
snmpwalk -v 2c -c public 127.0.0.1:11161 1.3.6.1.2.1.1
snmpbulkwalk -v 2c -c public 127.0.0.1:11161 1.3.6.1.2.1.1

# writable OID
snmpset -v 2c -c public 127.0.0.1:11161 1.3.6.1.2.1.1.4.0 s "ops@mini.snmp"

# non-writable OID -> returns notWritable (error_status 11)
snmpset -v 2c -c public 127.0.0.1:11161 1.3.6.1.2.1.1.5.0 s "renamed"
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
