pub use anyhow::{anyhow, bail, ensure, Error};

#[derive(Debug, thiserror::Error)]
pub enum DSError {
    #[error("Packet too small")]
    PacketTooSmall,
    #[error("Packet too large")]
    PacketTooLarge,
    #[error("Unsupported class: {0}")]
    UnsupportedClass(u16),
    #[error("Internal error: {0}")]
    InternalError(&'static str),
    #[error("Invalid name in a DNS record: {0}")]
    InvalidName(&'static str),
    #[error("Invalid DNS packet: {0}")]
    InvalidPacket(&'static str),
    #[error("Unsupported RR type: {0}")]
    UnsupportedRRType(String),
    #[error("Unsupported class type: {0}")]
    UnsupportedRRClass(String),
    #[error("Void record")]
    VoidRecord,
    #[error("Property not found")]
    PropertyNotFound,
    #[error("Wrong address family")]
    WrongAddressFamily,
    #[error("Parse error")]
    ParseError,
}
