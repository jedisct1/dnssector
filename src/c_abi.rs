use crate::constants::*;
use crate::edns_iterator::*;
use crate::errors::*;
use crate::parsed_packet::*;
use crate::question_iterator::*;
use crate::response_iterator::*;
use crate::rr_iterator::*;
use crate::synth::gen;
use failure;
use libc::{c_char, c_int, c_void, size_t};
use std::cell::RefCell;
use std::convert::From;
use std::ffi::{CStr, CString};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::slice;

const ABI_VERSION: u64 = 0x2;

#[repr(C)]
pub struct CErr {
    description_cs: CString,
}

thread_local!(
    static CERR: RefCell<CErr> = RefCell::new(CErr {
        description_cs: CString::new("".as_bytes()).unwrap()
    })
);

fn throw_err(e: failure::Error, c_err: *mut *const CErr) -> c_int {
    if !c_err.is_null() {
        CERR.with(|tc_err| {
            let mut tc_err = tc_err.borrow_mut();
            tc_err.description_cs = CString::new(e.to_string()).unwrap();
            unsafe { *c_err = &*tc_err };
        });
    }
    -1
}

unsafe extern "C" fn error_description(c_err: *const CErr) -> *const c_char {
    (*c_err).description_cs.as_bytes() as *const _ as *const c_char
}

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

const SECTION_ITERATOR_MAGIC: u64 = 0x08af4e661b92fda3;

#[repr(C)]
pub struct SectionIterator {
    magic: u64,
    section: Section,
    it: *mut c_void,
}

unsafe extern "C" fn iter_answer(
    parsed_packet: *mut ParsedPacket,
    cb: unsafe extern "C" fn(ctx: *mut c_void, section_iterator: *const SectionIterator) -> bool,
    ctx: *mut c_void,
) {
    let mut it = (*parsed_packet).into_iter_answer();
    while let Some(mut item) = it {
        let section_iterator = SectionIterator {
            magic: SECTION_ITERATOR_MAGIC,
            section: Section::Answer,
            it: &mut item as *mut _ as *mut _,
        };
        if (cb)(ctx, &section_iterator as *const _ as *const _) {
            break;
        }
        it = item.next();
    }
}

unsafe extern "C" fn iter_nameservers(
    parsed_packet: *mut ParsedPacket,
    cb: unsafe extern "C" fn(ctx: *mut c_void, section_iterator: *const SectionIterator) -> bool,
    ctx: *mut c_void,
) {
    let mut it = (*parsed_packet).into_iter_nameservers();
    while let Some(mut item) = it {
        let section_iterator = SectionIterator {
            magic: SECTION_ITERATOR_MAGIC,
            section: Section::NameServers,
            it: &mut item as *mut _ as *mut _,
        };
        if (cb)(ctx, &section_iterator as *const _ as *const _) {
            break;
        }
        it = item.next();
    }
}

unsafe extern "C" fn iter_additional(
    parsed_packet: *mut ParsedPacket,
    cb: unsafe extern "C" fn(ctx: *mut c_void, section_iterator: *const SectionIterator) -> bool,
    ctx: *mut c_void,
) {
    let mut it = (*parsed_packet).into_iter_additional();
    while let Some(mut item) = it {
        let section_iterator = SectionIterator {
            magic: SECTION_ITERATOR_MAGIC,
            section: Section::Additional,
            it: &mut item as *mut _ as *mut _,
        };
        if (cb)(ctx, &section_iterator as *const _ as *const _) {
            break;
        }
        it = item.next();
    }
}

unsafe extern "C" fn iter_edns(
    parsed_packet: *mut ParsedPacket,
    cb: unsafe extern "C" fn(ctx: *mut c_void, section_iterator: *const EdnsIterator) -> bool,
    ctx: *mut c_void,
) {
    let mut it = (*parsed_packet).into_iter_edns();
    while let Some(mut item) = it {
        let section_iterator = SectionIterator {
            magic: SECTION_ITERATOR_MAGIC,
            section: Section::Edns,
            it: &mut item as *mut _ as *mut _,
        };
        if (cb)(ctx, &section_iterator as *const _ as *const _) {
            break;
        }
        it = item.next();
    }
}

unsafe extern "C" fn rr_type(section_iterator: &mut SectionIterator) -> u16 {
    assert_eq!(section_iterator.magic, SECTION_ITERATOR_MAGIC);
    match section_iterator.section {
        Section::Question => (&*(section_iterator.it as *mut QuestionIterator)).rr_type(),
        Section::Answer | Section::NameServers | Section::Additional => {
            (&*(section_iterator.it as *mut ResponseIterator)).rr_type()
        }
        _ => panic!("rr_type() called on a record with no type"),
    }
}

unsafe extern "C" fn rr_class(section_iterator: &mut SectionIterator) -> u16 {
    assert_eq!(section_iterator.magic, SECTION_ITERATOR_MAGIC);
    match section_iterator.section {
        Section::Question => (&*(section_iterator.it as *mut QuestionIterator)).rr_class(),
        Section::Answer | Section::NameServers | Section::Additional => {
            (&*(section_iterator.it as *mut ResponseIterator)).rr_class()
        }
        _ => panic!("rr_class() called on a record with no class"),
    }
}

unsafe extern "C" fn name(
    section_iterator: &mut SectionIterator,
    name: &mut [u8; DNS_MAX_HOSTNAME_LEN + 1],
) {
    assert_eq!(section_iterator.magic, SECTION_ITERATOR_MAGIC);
    let name_vec = match section_iterator.section {
        Section::Question => (&*(section_iterator.it as *mut QuestionIterator)).name(),
        Section::Answer | Section::NameServers | Section::Additional => {
            (&*(section_iterator.it as *mut ResponseIterator)).name()
        }
        _ => panic!("name() called on a record with no name"),
    };
    let name_len = name_vec.len();
    assert!(name_len <= DNS_MAX_HOSTNAME_LEN);
    name[..name_len].copy_from_slice(&name_vec);
    name[name_len] = 0;
}

unsafe extern "C" fn rr_ttl(section_iterator: &mut SectionIterator) -> u32 {
    assert_eq!(section_iterator.magic, SECTION_ITERATOR_MAGIC);
    match section_iterator.section {
        Section::Answer | Section::NameServers | Section::Additional => {
            (&*(section_iterator.it as *mut ResponseIterator)).rr_ttl()
        }
        _ => panic!("ttl() called on a record with no TTL"),
    }
}

unsafe extern "C" fn set_rr_ttl(section_iterator: &mut SectionIterator, ttl: u32) {
    assert_eq!(section_iterator.magic, SECTION_ITERATOR_MAGIC);
    match section_iterator.section {
        Section::Answer | Section::NameServers | Section::Additional => {
            (&mut *(section_iterator.it as *mut ResponseIterator)).set_rr_ttl(ttl)
        }
        _ => panic!("set_ttl() called on a record with no TTL"),
    }
}

unsafe extern "C" fn rr_ip(
    section_iterator: &mut SectionIterator,
    addr: *mut u8,
    addr_len: &mut size_t,
) {
    assert_eq!(section_iterator.magic, SECTION_ITERATOR_MAGIC);
    let ip = match section_iterator.section {
        Section::Answer | Section::NameServers | Section::Additional => (&mut *(section_iterator.it
            as *mut ResponseIterator))
            .rr_ip()
            .expect("rr_ip() called on a record with no IP"),
        _ => panic!("rr_ip() called on a record with no IP"),
    };
    match ip {
        IpAddr::V4(ip) => {
            assert!(*addr_len >= 4);
            *addr_len = 4;
            slice::from_raw_parts_mut(addr, *addr_len).copy_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            assert!(*addr_len >= 16);
            *addr_len = 16;
            slice::from_raw_parts_mut(addr, *addr_len).copy_from_slice(&ip.octets());
        }
    }
}

unsafe extern "C" fn set_rr_ip(
    section_iterator: &mut SectionIterator,
    addr: *const u8,
    addr_len: size_t,
) {
    assert_eq!(section_iterator.magic, SECTION_ITERATOR_MAGIC);
    match section_iterator.section {
        Section::Answer | Section::NameServers | Section::Additional => (&mut *(section_iterator.it
            as *mut ResponseIterator))
            .rr_ip()
            .expect("set_rr_ip() called on a record with no IP"),
        _ => panic!("set_rr_ip() called on a record with no IP"),
    };
    let ip = match addr_len {
        4 => {
            let mut ipo = [0u8; 4];
            ipo.copy_from_slice(slice::from_raw_parts(addr, addr_len));
            IpAddr::V4(Ipv4Addr::from(ipo))
        }
        16 => {
            let mut ipo = [0u8; 16];
            ipo.copy_from_slice(slice::from_raw_parts(addr, addr_len));
            IpAddr::V6(Ipv6Addr::from(ipo))
        }
        _ => panic!("Unsupported address length"),
    };
    (&mut *(section_iterator.it as *mut ResponseIterator))
        .set_rr_ip(&ip)
        .expect("Wrong IP address family for this record");
}

unsafe extern "C" fn raw_name_from_str(
    raw_name: &mut [u8; DNS_MAX_HOSTNAME_LEN + 1],
    raw_name_len: *mut size_t,
    c_err: *mut *const CErr,
    name: *const c_char,
    name_len: size_t,
) -> c_int {
    let raw_name_ =
        match gen::raw_name_from_str(slice::from_raw_parts(name as *const u8, name_len), None) {
            Err(e) => return throw_err(e, c_err),
            Ok(raw_name_) => raw_name_,
        };
    let raw_name_len_ = raw_name_.len();
    assert!(raw_name_len_ <= DNS_MAX_HOSTNAME_LEN + 1);
    raw_name[..raw_name_len_].copy_from_slice(&raw_name_);
    *raw_name_len = raw_name_len_;
    0
}

unsafe extern "C" fn set_raw_name(
    section_iterator: &mut SectionIterator,
    c_err: *mut *const CErr,
    raw_name: *const u8,
    raw_name_len: size_t,
) -> c_int {
    assert_eq!(section_iterator.magic, SECTION_ITERATOR_MAGIC);
    let raw_name = slice::from_raw_parts(raw_name, raw_name_len);
    match section_iterator.section {
        Section::Answer | Section::NameServers | Section::Additional => {
            match (&mut *(section_iterator.it as *mut ResponseIterator)).set_raw_name(raw_name) {
                Err(e) => throw_err(e, c_err),
                Ok(()) => 0,
            }
        }
        _ => panic!("set_raw_name() called on a record with no name"),
    }
}

unsafe extern "C" fn set_name(
    section_iterator: &mut SectionIterator,
    c_err: *mut *const CErr,
    name: *const c_char,
    name_len: size_t,
    default_zone_raw: *const u8,
    default_zone_raw_len: size_t,
) -> c_int {
    assert_eq!(section_iterator.magic, SECTION_ITERATOR_MAGIC);
    let default_zone_raw = if default_zone_raw.is_null() || default_zone_raw_len <= 0 {
        None
    } else {
        Some(slice::from_raw_parts(
            default_zone_raw,
            default_zone_raw_len,
        ))
    };
    let raw_name = match gen::raw_name_from_str(
        slice::from_raw_parts(name as *const u8, name_len),
        default_zone_raw,
    ) {
        Err(e) => return throw_err(e, c_err),
        Ok(raw_name) => raw_name,
    };
    match section_iterator.section {
        Section::Answer | Section::NameServers | Section::Additional => {
            match (&mut *(section_iterator.it as *mut ResponseIterator)).set_raw_name(&raw_name) {
                Err(e) => throw_err(e, c_err),
                Ok(()) => 0,
            }
        }
        _ => panic!("set_name() called on a record with no name"),
    }
}

unsafe extern "C" fn delete(
    section_iterator: &mut SectionIterator,
    c_err: *mut *const CErr,
) -> c_int {
    assert_eq!(section_iterator.magic, SECTION_ITERATOR_MAGIC);
    match section_iterator.section {
        Section::Question | Section::Answer | Section::NameServers | Section::Additional => {
            match (&mut *(section_iterator.it as *mut ResponseIterator)).delete() {
                Err(e) => throw_err(e, c_err),
                Ok(()) => 0,
            }
        }
        _ => panic!("delete() called in a pseudosection"),
    }
}

unsafe fn add_to_section(
    parsed_packet: *mut ParsedPacket,
    section: Section,
    rr_str: *const i8,
) -> Result<(), failure::Error> {
    let rr_str = match CStr::from_ptr(rr_str).to_str() {
        Err(_) => bail!(DSError::ParseError),
        Ok(rr_str) => rr_str,
    };
    (*parsed_packet).insert_rr_from_string(section, rr_str)
}

unsafe extern "C" fn add_to_question(
    parsed_packet: *mut ParsedPacket,
    c_err: *mut *const CErr,
    rr_str: *const i8,
) -> c_int {
    match add_to_section(parsed_packet, Section::Question, rr_str) {
        Err(e) => throw_err(e, c_err),
        Ok(_) => 0,
    }
}

unsafe extern "C" fn add_to_answer(
    parsed_packet: *mut ParsedPacket,
    c_err: *mut *const CErr,
    rr_str: *const i8,
) -> c_int {
    match add_to_section(parsed_packet, Section::Answer, rr_str) {
        Err(e) => throw_err(e, c_err),
        Ok(_) => 0,
    }
}

unsafe extern "C" fn add_to_nameservers(
    parsed_packet: *mut ParsedPacket,
    c_err: *mut *const CErr,
    rr_str: *const i8,
) -> c_int {
    match add_to_section(parsed_packet, Section::NameServers, rr_str) {
        Err(e) => throw_err(e, c_err),
        Ok(_) => 0,
    }
}

unsafe extern "C" fn add_to_additional(
    parsed_packet: *mut ParsedPacket,
    c_err: *mut *const CErr,
    rr_str: *const i8,
) -> c_int {
    match add_to_section(parsed_packet, Section::Additional, rr_str) {
        Err(e) => throw_err(e, c_err),
        Ok(_) => 0,
    }
}

unsafe extern "C" fn raw_packet(
    parsed_packet: *const ParsedPacket,
    raw_packet_: &mut [u8; DNS_MAX_UNCOMPRESSED_SIZE],
    raw_packet_len: *mut size_t,
    raw_packet_max_len: size_t,
) -> c_int {
    let packet = &(*parsed_packet).packet();
    let packet_len = packet.len();
    if packet_len > raw_packet_max_len {
        return -1;
    }
    raw_packet_[..packet_len].copy_from_slice(packet);
    *raw_packet_len = packet_len;
    0
}

unsafe extern "C" fn question(
    parsed_packet: *mut ParsedPacket,
    name: &mut [u8; DNS_MAX_HOSTNAME_LEN + 1],
    rr_type: *mut u16,
) -> c_int {
    match (*parsed_packet).question() {
        None => {
            name[0] = 0;
            *rr_type = 0;
            -1
        }
        Some((name_str, rr_type_, _)) => {
            *rr_type = rr_type_;
            let name_str_len = name_str.len();
            if name_str_len > DNS_MAX_HOSTNAME_LEN {
                name[0] = 0;
                return -1;
            }
            name[..name_str_len].copy_from_slice(&name_str);
            name[name_str_len] = 0;
            0
        }
    }
}

unsafe extern "C" fn rename_with_raw_names(
    parsed_packet: *mut ParsedPacket,
    c_err: *mut *const CErr,
    raw_target_name: *const u8,
    raw_target_name_len: size_t,
    raw_source_name: *const u8,
    raw_source_name_len: size_t,
    match_suffix: bool,
) -> c_int {
    let raw_target_name = slice::from_raw_parts(raw_target_name, raw_target_name_len);
    let raw_source_name = slice::from_raw_parts(raw_source_name, raw_source_name_len);
    match (*parsed_packet).rename_with_raw_names(raw_target_name, raw_source_name, match_suffix) {
        Err(e) => throw_err(e, c_err),
        Ok(_) => 0,
    }
}

/// C wrappers to the internal API
#[repr(C)]
pub struct FnTable {
    pub error_description: unsafe extern "C" fn(c_err: *const CErr) -> *const c_char,
    pub flags: unsafe extern "C" fn(parsed_packet: *const ParsedPacket) -> u32,
    pub set_flags: unsafe extern "C" fn(parsed_packet: *mut ParsedPacket, flags: u32),
    pub rcode: unsafe extern "C" fn(parsed_packet: *const ParsedPacket) -> u8,
    pub set_rcode: unsafe extern "C" fn(parsed_packet: *mut ParsedPacket, rcode: u8),
    pub opcode: unsafe extern "C" fn(parsed_packet: *const ParsedPacket) -> u8,
    pub set_opcode: unsafe extern "C" fn(parsed_packet: *mut ParsedPacket, opcode: u8),
    pub iter_answer:
        unsafe extern "C" fn(
            parsed_packet: *mut ParsedPacket,
            cb: unsafe extern "C" fn(
                ctx: *mut c_void,
                section_iterator: *const SectionIterator,
            ) -> bool,
            *mut c_void,
        ),
    pub iter_nameservers:
        unsafe extern "C" fn(
            parsed_packet: *mut ParsedPacket,
            cb: unsafe extern "C" fn(
                ctx: *mut c_void,
                section_iterator: *const SectionIterator,
            ) -> bool,
            *mut c_void,
        ),
    pub iter_additional:
        unsafe extern "C" fn(
            parsed_packet: *mut ParsedPacket,
            cb: unsafe extern "C" fn(
                ctx: *mut c_void,
                section_iterator: *const SectionIterator,
            ) -> bool,
            *mut c_void,
        ),
    pub iter_edns:
        unsafe extern "C" fn(
            parsed_packet: *mut ParsedPacket,
            cb: unsafe extern "C" fn(
                ctx: *mut c_void,
                section_iterator: *const EdnsIterator,
            ) -> bool,
            *mut c_void,
        ),
    pub name: unsafe extern "C" fn(
        section_iterator: &mut SectionIterator,
        name: &mut [u8; DNS_MAX_HOSTNAME_LEN + 1],
    ),
    pub rr_type: unsafe extern "C" fn(section_iterator: &mut SectionIterator) -> u16,
    pub rr_class: unsafe extern "C" fn(section_iterator: &mut SectionIterator) -> u16,
    pub rr_ttl: unsafe extern "C" fn(section_iterator: &mut SectionIterator) -> u32,
    pub set_rr_ttl: unsafe extern "C" fn(section_iterator: &mut SectionIterator, ttl: u32),
    pub rr_ip: unsafe extern "C" fn(
        section_iterator: &mut SectionIterator,
        addr: *mut u8,
        addr_len: &mut size_t,
    ),
    pub set_rr_ip: unsafe extern "C" fn(
        section_iterator: &mut SectionIterator,
        addr: *const u8,
        addr_len: size_t,
    ),
    pub raw_name_from_str: unsafe extern "C" fn(
        raw_name: &mut [u8; DNS_MAX_HOSTNAME_LEN + 1],
        raw_name_len: *mut size_t,
        c_err: *mut *const CErr,
        name: *const c_char,
        name_len: size_t,
    ) -> c_int,
    pub set_raw_name: unsafe extern "C" fn(
        section_iterator: &mut SectionIterator,
        c_err: *mut *const CErr,
        name: *const u8,
        len: size_t,
    ) -> c_int,
    pub set_name: unsafe extern "C" fn(
        section_iterator: &mut SectionIterator,
        c_err: *mut *const CErr,
        name: *const c_char,
        len: size_t,
        default_zone_raw: *const u8,
        default_zone_raw_len: size_t,
    ) -> c_int,
    pub delete:
        unsafe extern "C" fn(section_iterator: &mut SectionIterator, c_err: *mut *const CErr)
            -> c_int,
    pub add_to_question: unsafe extern "C" fn(
        parsed_packet: *mut ParsedPacket,
        c_err: *mut *const CErr,
        rr_str: *const i8,
    ) -> c_int,
    pub add_to_answer: unsafe extern "C" fn(
        parsed_packet: *mut ParsedPacket,
        c_err: *mut *const CErr,
        rr_str: *const i8,
    ) -> c_int,
    pub add_to_nameservers: unsafe extern "C" fn(
        parsed_packet: *mut ParsedPacket,
        c_err: *mut *const CErr,
        rr_str: *const i8,
    ) -> c_int,
    pub add_to_additional: unsafe extern "C" fn(
        parsed_packet: *mut ParsedPacket,
        c_err: *mut *const CErr,
        rr_str: *const i8,
    ) -> c_int,
    pub raw_packet: unsafe extern "C" fn(
        parsed_packet: *const ParsedPacket,
        raw_packet_: &mut [u8; DNS_MAX_UNCOMPRESSED_SIZE],
        raw_packet_len: *mut size_t,
        raw_packet_max_len: size_t,
    ) -> c_int,
    pub question: unsafe extern "C" fn(
        parsed_packet: *mut ParsedPacket,
        name: &mut [u8; DNS_MAX_HOSTNAME_LEN + 1],
        rr_type: *mut u16,
    ) -> c_int,
    pub rename_with_raw_names: unsafe extern "C" fn(
        parsed_packet: *mut ParsedPacket,
        c_err: *mut *const CErr,
        raw_target_name: *const u8,
        raw_target_name_len: size_t,
        raw_source_name: *const u8,
        raw_source_name_len: size_t,
        match_suffix: bool,
    ) -> c_int,
    pub abi_version: u64,
}

pub fn fn_table() -> FnTable {
    FnTable {
        error_description,
        flags,
        set_flags,
        rcode,
        set_rcode,
        opcode,
        set_opcode,
        iter_answer,
        iter_nameservers,
        iter_additional,
        iter_edns,
        name,
        rr_type,
        rr_class,
        rr_ttl,
        set_rr_ttl,
        rr_ip,
        set_rr_ip,
        raw_name_from_str,
        set_raw_name,
        set_name,
        delete,
        add_to_question,
        add_to_answer,
        add_to_nameservers,
        add_to_additional,
        raw_packet,
        question,
        rename_with_raw_names,
        abi_version: ABI_VERSION,
    }
}
