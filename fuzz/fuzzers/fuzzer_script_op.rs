#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate dnssector;

use compress::*;
use dnssector::*;

fn iter_ops(i: &mut DNSIterable, ops: &[u8]) -> u64
{
    let mut ret = 0;
    let mut prev_op = 0 as u8;
    for op in ops {
        let res = match *op {
            0 => {
                match i.offset() {
                    Some(x) => x,
                    None => 0,
                }
            },
            1 => { i.offset_next() },
            2 => { i.set_offset((prev_op * *op) as usize); 1 },
            3 => { i.set_offset_next((prev_op * *op) as usize); 1 },
            4 => { i.invalidate(); 1 },
            5 => { if i.is_tombstone() { 0 } else { 1 } },
            6 => { i.recompute_rr(); 1 },
            7 => { i.recompute_sections();1  },
            8 => { let p = i.packet(); p[0] as usize },
            9 => { let slice = i.name_slice(); slice[0] as usize },
            10 => { let slice = i.rdata_slice(); slice[0] as usize },
            11 => { let mut slice = i.rdata_slice_mut(); slice[0] /= 2; slice[0] as usize },
            12 => {
                match i.uncompress() {
                    Ok(()) => 1,
                    _ => 2,
                }
            },
            _ => 1,
        };
        ret += res;
        prev_op = *op;
    }
    ret as u64
}
fuzz_target!(|input: &[u8]| {
    if input.len() < 64 {
        return;
    }
    let (all_ops, packet) = input.split_at(64);
    let (ops, rr_ops) = input.split_at(32);
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
            9 => {
                match parsed.into_iter_question() {
                    Some(mut i) => iter_ops(&mut i, rr_ops),
                    None => 0,
                }
            }
            10 => {
                match parsed.into_iter_answer() {
                    Some(mut i) => iter_ops(&mut i, rr_ops),
                    None => 0,
                }
            }
            11 => {
                match parsed.into_iter_nameservers() {
                    Some(mut i) => iter_ops(&mut i, rr_ops),
                    None => 0,
                }
            }
            12 => {
                match parsed.into_iter_additional() {
                    Some(mut i) => iter_ops(&mut i, rr_ops),
                    None => 0,
                }
            }
            13 => {
                match parsed.into_iter_additional_including_opt() {
                    Some(mut i) => iter_ops(&mut i, rr_ops),
                    None => 0,
                }
            }
            14 => {
                match parsed.into_iter_edns() {
                    Some(mut i) => iter_ops(&mut i, rr_ops),
                    None => 0,
                }
            }
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
