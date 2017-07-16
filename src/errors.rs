error_chain! {
    errors {
        PacketTooSmall
        PacketTooLarge
        UnsupportedClass
        InternalError(t: &'static str) {
            description("Internal error")
            display("Internal error: '{}'", t)
        }
        InvalidName(t: &'static str) {
            description("Invalid name in a DNS record")
            display("Invalid name in a DNS record: '{}'", t)
        }
        InvalidPacket(t: &'static str) {
            description("Invalid DNS packet")
            display("Invalid DNS packet: '{}'", t)
        }
        UnsupportedRRType(t: String) {
            description("Unsupported record type")
            display("Unsupported record type: '{}'", t)
        }
        VoidRecord
        PropertyNotFound
        WrongAddressFamily
    }
}
