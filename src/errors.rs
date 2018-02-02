#[derive(Debug, Fail)]
pub enum DSError {
    #[fail(display = "Packet too small")]
    PacketTooSmall,
    #[fail(display = "Packet too large")]
    PacketTooLarge,
    #[fail(display = "Unsupported class: {}", _0)]
    UnsupportedClass(u16),
    #[fail(display = "Internal error: {}", _0)]
    InternalError(&'static str),
    #[fail(display = "Invalid name in a DNS record: {}", _0)]
    InvalidName(&'static str),
    #[fail(display = "Invalid DNS packet: {}", _0)]
    InvalidPacket(&'static str),
    #[fail(display = "Unsupported RR type: {}", _0)]
    UnsupportedRRType(String),
    #[fail(display = "Void record")]
    VoidRecord,
    #[fail(display = "Property not found")]
    PropertyNotFound,
    #[fail(display = "Wrong address family")]
    WrongAddressFamily,
    #[fail(display = "Parse error")]
    ParseError,
}
