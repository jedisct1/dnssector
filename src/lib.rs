#![recursion_limit = "128"]
#![allow(clippy::absurd_extreme_comparisons)]
#![allow(clippy::assertions_on_constants)]
#![allow(clippy::block_in_if_condition_stmt)]
#![allow(clippy::bool_comparison)]
#![allow(clippy::cast_lossless)]
#![allow(clippy::comparison_chain)]
#![allow(clippy::int_plus_one)]
#![allow(clippy::string_lit_as_bytes)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::try_err)]
#![allow(clippy::type_complexity)]
#![allow(clippy::unreadable_literal)]
#![allow(clippy::useless_let_if_seq)]
#![allow(clippy::wrong_self_convention)]

#[macro_use]
extern crate chomp;

pub mod c_abi;
pub mod compress;
pub mod constants;
pub mod dns_sector;
pub mod edns_iterator;
pub mod errors;
pub mod parsed_packet;
pub mod question_iterator;
pub mod renamer;
pub mod response_iterator;
pub mod rr_iterator;
pub mod synth;

pub use crate::c_abi::*;
pub use crate::compress::*;
pub use crate::constants::*;
pub use crate::dns_sector::*;
pub use crate::edns_iterator::*;
pub use crate::errors::*;
pub use crate::parsed_packet::*;
pub use crate::question_iterator::*;
pub use crate::renamer::*;
pub use crate::response_iterator::*;
pub use crate::rr_iterator::*;
pub use crate::synth::*;
