#![no_main]
extern crate dnssector;
#[macro_use]
extern crate libfuzzer_sys;

use dnssector::*;

/// Parse a packet, do not change anything, check that the resulting packet is identical to the original one
fuzz_target!(|packet: &[u8]| {
    let dns_sector = match DNSSector::new(packet.to_vec()) {
        Err(_) => return,
        Ok(dns_sector) => dns_sector,
    };
    let mut parsed = match dns_sector.parse() {
        Err(_) => return,
        Ok(parsed) => parsed,
    };
    let renamed = Renamer::rename_with_raw_names(
        &mut parsed,
        b"\x1aabcdefghijklmnopqrstuvwxyz\x00",
        b"\x1aabcdefghijklmnopqrstuvwxyz\x00",
        true,
    ).expect("No match");
    let dns_sector_2 = DNSSector::new(renamed).expect("Cannot reparse packet");
    let reparsed_packet = dns_sector_2
        .parse()
        .expect("Valid packet couldn't be parsed");
    let packet2 = reparsed_packet.into_packet();
    let uncompressed =
        Compress::uncompress(&packet).expect("Unable to uncompress the original packet");
    let uncompressed2 =
        Compress::uncompress(&packet2).expect("Unable to uncompress the recreated packet");
    assert_eq!(uncompressed, uncompressed2);
});
