#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate dnssector;

use dnssector::*;

fuzz_target!(|data: &[u8]| {
    let dns_sector = DNSSector::new(data.to_vec()).unwrap();
    let _ = dns_sector.parse();
});
