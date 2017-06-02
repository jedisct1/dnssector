#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate dnssector;

use compress::*;
use dnssector::*;

fuzz_target!(|packet: &[u8]| {
    let dns_sector = DNSSector::new(packet.to_vec()).unwrap();
    let parsed = dns_sector.parse();
    let packet = match parsed {
        Err(_) => return,
        Ok(packet) => packet.into_packet()
    };
    let uncompressed = match Compress::uncompress(&packet) {
        Err(_) => {},
        Ok(packet) => {
            let dns_sector = DNSSector::new(packet).unwrap();
            let _ = dns_sector.parse();
        }
    };
});
