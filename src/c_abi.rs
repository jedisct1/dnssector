use parsed_packet::*;

const ABI_VERSION: u64 = 0x1;

unsafe extern "C" fn flags(parsed_packet: *const ParsedPacket) -> u32 {
    (*parsed_packet).flags()
}

unsafe extern "C" fn set_flags(parsed_packet: *mut ParsedPacket, flags: u32) {
    (*parsed_packet).set_flags(flags)
}

unsafe extern "C" fn rcode(parsed_packet: *const ParsedPacket) -> u8 {
    (*parsed_packet).rcode()
}

unsafe extern "C" fn set_rcode(parsed_packet: *mut ParsedPacket, rcode: u8) {
    (*parsed_packet).set_rcode(rcode)
}

unsafe extern "C" fn opcode(parsed_packet: *const ParsedPacket) -> u8 {
    (*parsed_packet).opcode()
}

unsafe extern "C" fn set_opcode(parsed_packet: *mut ParsedPacket, opcode: u8) {
    (*parsed_packet).set_opcode(opcode)
}

/// C wrappers to the internal API
#[repr(C)]
pub struct FnTable {
    pub abi_version: u64,
    pub flags: unsafe extern "C" fn(parsed_packet: *const ParsedPacket) -> u32,
    pub set_flags: unsafe extern "C" fn(parsed_packet: *mut ParsedPacket, flags: u32),
    pub rcode: unsafe extern "C" fn(parsed_packet: *const ParsedPacket) -> u8,
    pub set_rcode: unsafe extern "C" fn(parsed_packet: *mut ParsedPacket, rcode: u8),
    pub opcode: unsafe extern "C" fn(parsed_packet: *const ParsedPacket) -> u8,
    pub set_opcode: unsafe extern "C" fn(parsed_packet: *mut ParsedPacket, opcode: u8),
}

pub fn fn_table() -> FnTable {
    FnTable {
        abi_version: ABI_VERSION,
        flags,
        set_flags,
        rcode,
        set_rcode,
        opcode,
        set_opcode,
    }
}
