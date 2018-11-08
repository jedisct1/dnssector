#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate dnssector;

use dnssector::synth::gen::RR;

fuzz_target!(|synth: &[u8]| {
    let synth = String::from_utf8_lossy(synth);
    RR::from_string(&synth);
});
