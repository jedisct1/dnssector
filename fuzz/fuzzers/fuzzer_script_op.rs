#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate dnssector;

use compress::*;
use dnssector::*;

fuzz_target!(|input: &[u8]| {
    if input.len() < 8 {
        return;
    }
    let (ops, packet) = input.split_at(8);
    let mut cloned_packet  = packet.to_vec();
    let mut cloned_packet = cloned_packet.as_mut();
    let dns_sector = DNSSector::new(packet.to_vec()).unwrap();
    let mut cloned_dns_sector = dns_sector.clone();
    let parsed = dns_sector.parse();
    if parsed.is_err() {
        return;
    }
    let mut parsed = parsed.unwrap();
    let mut prev_op = 0 as u32;
    let mut prev_prev_op = 0 as u32;
    for op in ops {
        let u8_arg: u8 = (0xff & prev_op) as u8;
        let u16_arg: u16 = (0xffff & prev_op) as u16;
        let u32_arg: u32 = prev_op << 16 | prev_prev_op;
        let _ = match *op {
            0 => parsed.tid() as u64,
            1 => {parsed.set_tid(u16_arg); 1},
            2 => parsed.flags() as u64,
            3 => {parsed.set_flags(u32_arg); 1},
            4 => parsed.rcode() as u64,
            5 => {parsed.set_rcode(u8_arg); 1},
            6 => parsed.opcode() as u64,
            7 => {parsed.set_opcode(u8_arg); 1},
            8 => {parsed.recompute(); 1},
            9 => {parsed.into_iter_question(); 1}
            10 => {parsed.into_iter_answer(); 1}
            11 => {parsed.into_iter_nameservers(); 1}
            12 => {parsed.into_iter_additional(); 1}
            13 => {parsed.into_iter_additional_including_opt(); 1}
            14 => {parsed.into_iter_edns(); 1}
            15 => DNSSector::qdcount(cloned_packet) as u64,
            16 => {DNSSector::set_qdcount(cloned_packet, u16_arg); 1}
            17 => DNSSector::ancount(cloned_packet) as u64,
            18 => {DNSSector::set_ancount(cloned_packet, u16_arg); 1}
            19 => DNSSector::nscount(cloned_packet) as u64,
            20 => {DNSSector::set_nscount(cloned_packet, u16_arg); 1}
            21 => DNSSector::arcount(cloned_packet) as u64,
            22 => {DNSSector::set_arcount(cloned_packet, u16_arg); 1}
            23 => if cloned_dns_sector.set_offset(u32_arg as usize).is_ok() { 1 } else { 0 },
            24 => if cloned_dns_sector.increment_offset(u32_arg as usize).is_ok() { 1 } else { 0 },
            25 => if cloned_dns_sector.rr_rdlen().is_ok() { 1 } else { 0 },
            26 => {
                let mut maybe_parsed = cloned_dns_sector.clone().parse();
                if maybe_parsed.is_ok() {
                    let mut parsed = maybe_parsed.unwrap();
                    let mut packet = parsed.into_packet();
                    let cloned_dns_sector = DNSSector::new(packet).unwrap();
                    1
                } else {
                    0
                }
            },
            27 => if cloned_dns_sector.edns_rr_rdlen().is_ok() { 1 } else { 0 },
            _ => 0,
        };
        prev_prev_op = *op as u32;
        prev_op = *op as u32;
    }

    let packet = parsed.into_packet();
    let uncompressed = match Compress::uncompress(&packet) {
        Err(_) => {},
        Ok(packet) => {
            let dns_sector = DNSSector::new(packet).unwrap();
            let _ = dns_sector.parse();
        }
    };
});
