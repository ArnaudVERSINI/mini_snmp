# mini_snmp

A minimal [SNMP](https://datatracker.ietf.org/doc/html/rfc1157) (Simple Network Management Protocol) implementation written in Rust.

## Features

- SNMP v1/v2c message encoding and decoding
- BER/ASN.1 serialization
- Basic GET / GETNEXT / SET / RESPONSE operations
- Lightweight, dependency-free core

## Building

```sh
cargo build
```

## Running

```sh
cargo run
```

## Testing

```sh
cargo test
```

## License

MIT
