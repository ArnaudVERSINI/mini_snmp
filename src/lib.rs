//! mini_snmp — a minimal SNMP implementation in Rust.
//!
//! The crate exposes a small BER/ASN.1 codec and an SNMPv2c message
//! model. Higher-level helpers (transports, MIB handling) are kept
//! intentionally out of scope.

pub mod ber;
pub mod message;

pub use ber::{BerError, BerValue};
pub use message::{Message, Pdu, PduType, VarBind};
