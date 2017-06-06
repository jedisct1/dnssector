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
    let dns_sector = DNSSector::new(packet.to_vec()).unwrap();
    let cloned_dns_sector = dns_sector.clone();
    let parsed = dns_sector.parse();
    if parsed.is_err() {
        return;
    }
    let parsed = parsed.unwrap();
    for op in ops {
        let _ = match *op {
            0 => parsed.tid() as u64,
            1 => parsed.flags() as u64,
            2 => parsed.rcode() as u64,
            3 => parsed.opcode() as u64,
            4 => if cloned_dns_sector.rr_rdlen().is_ok() { 1 } else { 0 },
            5 => if cloned_dns_sector.edns_rr_rdlen().is_ok() { 1 } else { 0 },
            _ => 0,
        };
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
