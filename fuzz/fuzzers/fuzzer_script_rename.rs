#![no_main]
extern crate dnssector;
#[macro_use]
extern crate libfuzzer_sys;

use dnssector::*;

fuzz_target!(|packet: &[u8]| {
    let dns_sector = DNSSector::new(packet.to_vec()).unwrap();
    let mut parsed = match dns_sector.parse() {
        Err(_) => return,
        Ok(parsed) => parsed,
    };
    let renamed = Renamer::rename_with_raw_names(&mut parsed, b"\x02fr\x00", b"\x03net\x00", true)
        .expect("No match");
    let dns_sector_2 = DNSSector::new(renamed).expect("Cannot reparse packet");
    let mut reparsed_packet = dns_sector_2
        .parse()
        .expect("Valid packet couldn't be parsed");
    {
        let mut it = reparsed_packet.into_iter_question();
        while let Some(item) = it {
            let _name = item.name();
            it = item.next();
        }
    }
    {
        let mut it = reparsed_packet.into_iter_answer();
        while let Some(item) = it {
            let _name = item.name();
            it = item.next();
        }
    }
    {
        let mut it = reparsed_packet.into_iter_nameservers();
        while let Some(item) = it {
            let _name = item.name();
            it = item.next();
        }
    }
    {
        let mut it = reparsed_packet.into_iter_additional();
        while let Some(item) = it {
            let _name = item.name();
            it = item.next();
        }
    }
});
