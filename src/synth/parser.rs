use constants::*;
use errors::*;
use chomp::ascii::*;
use chomp::combinators::*;
use chomp::prelude::{eof, not_token, parse_only, satisfy, skip_while, token, Buffer, Input,
                     SimpleResult, U8Input, take_while1};
use chomp::parsers;
use chomp::primitives::Primitives;
use std::ascii::AsciiExt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::{self, FromStr};
use std::u32;
use super::gen::*;

#[inline]
pub fn string_nocase<I: Input<Token = u8>>(mut i: I, s: &[u8]) -> SimpleResult<I, I::Buffer> {
    let mut n = 0;
    let len = s.len();
    let b = i.consume_while(|c| if n >= len || !c.eq_ignore_ascii_case(&s[n]) {
        false
    } else {
        n += 1;
        true
    });
    if n >= len {
        i.ret(b)
    } else {
        i.err(parsers::Error::expected(s[n]))
    }
}

fn is_horizontal_whitespace(c: u8) -> bool {
    c == b' ' || c == b'\t'
}

fn is_not_horizontal_whitespace(c: u8) -> bool {
    !is_horizontal_whitespace(c)
}

fn horizontal_whitespace<I: Input<Token = u8>>(i: I) -> SimpleResult<I, ()> {
    satisfy(i, is_horizontal_whitespace).map(|_| ())
}

fn not_horizontal_whitespace<I: Input<Token = u8>>(i: I) -> SimpleResult<I, ()> {
    satisfy(i, is_not_horizontal_whitespace).map(|_| ())
}

fn maybe_skip_horizontal_whitespaces<I: Input<Token = u8>>(i: I) -> SimpleResult<I, ()> {
    skip_while(i, is_horizontal_whitespace)
}

fn skip_horizontal_whitespaces<I: Input<Token = u8>>(i: I) -> SimpleResult<I, ()> {
    parse!{i;
        horizontal_whitespace();
        maybe_skip_horizontal_whitespaces();
        ret ()
    }
}

fn decimal_u8<I: Input<Token = u8>>(i: I) -> SimpleResult<I, u8> {
    take_while1(i, is_digit).bind(|i, it| {
        let v = it.fold(Some(0u8), |x, c| {
            x.and_then(|x| x.checked_mul(10))
                .and_then(|x| x.checked_add((c - b'0') as _))
        });
        match v {
            None => i.err(parsers::Error::unexpected()),
            Some(acc) => i.ret(acc),
        }
    })
}

fn decimal_u16<I: Input<Token = u8>>(i: I) -> SimpleResult<I, u16> {
    take_while1(i, is_digit).bind(|i, it| {
        let v = it.fold(Some(0u16), |x, c| {
            x.and_then(|x| x.checked_mul(10))
                .and_then(|x| x.checked_add((c - b'0') as _))
        });
        match v {
            None => i.err(parsers::Error::unexpected()),
            Some(acc) => i.ret(acc),
        }
    })
}

fn decimal_u32<I: Input<Token = u8>>(i: I) -> SimpleResult<I, u32> {
    take_while1(i, is_digit).bind(|i, it| {
        let v = it.fold(Some(0u32), |x, c| {
            x.and_then(|x| x.checked_mul(10))
                .and_then(|x| x.checked_add((c - b'0') as _))
        });
        match v {
            None => i.err(parsers::Error::unexpected()),
            Some(acc) => i.ret(acc),
        }
    })
}

fn is_hexdigit(c: u8) -> bool {
    match c {
        b'0'...b'9' | b'a'...b'f' | b'A'...b'F' => true,
        _ => false,
    }
}

fn from_hexdigit(c: u8) -> u8 {
    match c {
        b'0'...b'9' => c - b'0',
        b'a'...b'f' => c - b'a' + 10,
        b'A'...b'F' => c - b'A' + 10,
        _ => panic!("Invalid hex digit"),
    }
}

fn hex_u16<I: Input<Token = u8>>(i: I) -> SimpleResult<I, u16> {
    take_while1(i, is_hexdigit).bind(|i, it| {
        let v = it.fold(Some(0u16), |x, c| {
            x.and_then(|x| x.checked_mul(0x10))
                .and_then(|x| x.checked_add(from_hexdigit(c) as _))
        });
        match v {
            None => i.err(parsers::Error::unexpected()),
            Some(acc) => i.ret(acc),
        }
    })
}

fn escaped_char<I: U8Input>(i: I) -> SimpleResult<I, u8> {
    parse!(i;
        let a = digit();
        let b = digit();
        let c = digit();
        let v = i -> {
            let r = (a as i16 - 48) * 100 + (b as i16 - 48) * 10 + (c as i16 - 48);
            match r {
                0...255 => i.ret(r as u8),
                _ => i.err(parsers::Error::unexpected())
            }
        };
        ret v
    )
}

fn maybe_escaped_char<I: U8Input>(i: I) -> SimpleResult<I, u8> {
    parse!{i;
        let v = (token(b'\\') >> escaped_char()) <|> satisfy(|c| c > 31 && c < 128 && c != b'\\');
        ret v
    }
}

fn escaped_string_until_whitespace<I: U8Input>(i: I) -> SimpleResult<I, Vec<u8>> {
    parse!{i;
        let all = i -> {
            many1(i, |i| look_ahead(i, |i| not_horizontal_whitespace(i)).then(|i| maybe_escaped_char(i)))
        };
        ret all
    }
}

fn quoted_and_escaped_string<I: U8Input>(i: I) -> SimpleResult<I, Vec<u8>> {
    parse!{i;
        token(b'"');
        let all = i -> {
            many1(i, |i| look_ahead(i, |i| not_token(i, b'"')).then(|i| maybe_escaped_char(i)))
        };
        token(b'"');
        ret all
    }
}

fn ttl_parser<I: U8Input>(i: I) -> SimpleResult<I, u32> {
    parse!{i;
        let ttl: u32 = decimal_u32() <* horizontal_whitespace();
        ret ttl
    }
}

fn class_parser<I: U8Input>(i: I) -> SimpleResult<I, ()> {
    parse!{i;
        satisfy(|c| c == b'I' || c == b'i');
        satisfy(|c| c == b'N' || c == b'n');
        ret ()
    }
}

pub fn rr_type_parser<I: U8Input>(i: I) -> SimpleResult<I, Type> {
    take_while1(i, is_alphanumeric).bind(|i, it| match rr_type_from_str(&it.into_vec()) {
        Ok(rr_type) => i.ret(rr_type),
        Err(_) => i.err(parsers::Error::unexpected()),
    })
}

fn ipv4_parser<I: U8Input>(i: I) -> SimpleResult<I, Ipv4Addr> {
    parse!{i;
        let a: u8 = decimal_u8() <* token(b'.');
        let b: u8 = decimal_u8() <* token(b'.');
        let c: u8 = decimal_u8() <* token(b'.');
        let d: u8 = decimal_u8();
        ret Ipv4Addr::new(a, b, c, d)
    }
}

fn ipv6_parser<I: U8Input>(i: I) -> SimpleResult<I, Ipv6Addr> {
    take_while1(i, |c| is_hexdigit(c) || c == b':').bind(|i, addr_str| {
        match Ipv6Addr::from_str(str::from_utf8(&addr_str.into_vec()).unwrap()) {
            Ok(addr) => i.ret(addr),
            _ => i.err(parsers::Error::unexpected()),
        }
    })
}

fn hexstring_parser<I: U8Input>(i: I) -> SimpleResult<I, String> {
    take_while1(i, |c| is_hexdigit(c)).bind(|i, hex_str| {
        i.ret(str::from_utf8(&hex_str.into_vec()).unwrap().to_owned())
    })
}

fn label_parser<I: U8Input>(i: I) -> SimpleResult<I, ()> {
    parse!{i;
        satisfy(|c| is_alpha(c) || c == b'_');
        i -> {
            bounded::skip_many(i, ..63, |i| {
                satisfy(i, |c| { is_alphanumeric(c) || c == b'-' })
            })
        };
        i -> {
            either(i, |i| token(i, b'.'), |i| eof(i))
        };
        ret ()
    }
}

fn hostname_parser<I: U8Input>(i: I) -> SimpleResult<I, Vec<u8>> {
    parse!{i;
        let res = i -> {
            matched_by(i, |i| bounded::skip_many(i, 1..32, label_parser)).
            map(|(h, _)| {
                if h.len() > 253 {
                    Err(parsers::Error::unexpected())
                } else {
                    Ok(h.into_vec())
                }
            }).bind(|i, h| {
                match h {
                    Ok(h) => i.ret(h),
                    Err(e) => i.err(e),
                }
            })
        };
        ret res
    }
}

fn rr_common_parser<I: U8Input>(i: I) -> SimpleResult<I, RRHeader> {
    let class = Class::IN;
    parse!{i;
        maybe_skip_horizontal_whitespaces();
        let name = hostname_parser();
        maybe_skip_horizontal_whitespaces();
        let ttl: u32 = ttl_parser();
        maybe_skip_horizontal_whitespaces();
        class_parser();
        skip_horizontal_whitespaces();
        let rr_type = rr_type_parser();
        ret RRHeader {
            name, ttl, class, rr_type
        }
    }
}

fn rr_rdata_a_parser<I: U8Input>(i: I) -> SimpleResult<I, Ipv4Addr> {
    parse!{i;
        let ip = ipv4_parser();
        maybe_skip_horizontal_whitespaces();
        eof();
        ret ip
    }
}

fn rr_rdata_aaaa_parser<I: U8Input>(i: I) -> SimpleResult<I, Ipv6Addr> {
    parse!{i;
        let ip = ipv6_parser();
        maybe_skip_horizontal_whitespaces();
        eof();
        ret ip
    }
}

fn rr_rdata_hostname_parser<I: U8Input>(i: I) -> SimpleResult<I, Vec<u8>> {
    parse!{i;
        let hostname = hostname_parser();
        maybe_skip_horizontal_whitespaces();
        eof();
        ret hostname
    }
}

fn rr_rdata_string_parser<I: U8Input>(i: I) -> SimpleResult<I, Vec<u8>> {
    parse!{i;
        let txt = quoted_and_escaped_string();
        maybe_skip_horizontal_whitespaces();
        eof();
        ret txt
    }
}

fn rr_rdata_mx_parser<I: U8Input>(i: I) -> SimpleResult<I, (u16, Vec<u8>)> {
    parse!{i;
        let preference = decimal_u16();
        skip_horizontal_whitespaces();
        let mxname = hostname_parser();
        maybe_skip_horizontal_whitespaces();
        eof();
        ret (preference, mxname)
    }
}

fn rr_type_from_str(rr_type_str: &[u8]) -> Result<Type> {
    match rr_type_str {
        s if s.eq_ignore_ascii_case(b"A") => Ok(Type::A),
        s if s.eq_ignore_ascii_case(b"AAAA") => Ok(Type::AAAA),
        s if s.eq_ignore_ascii_case(b"NS") => Ok(Type::NS),
        s if s.eq_ignore_ascii_case(b"CNAME") => Ok(Type::CNAME),
        s if s.eq_ignore_ascii_case(b"PTR") => Ok(Type::PTR),
        s if s.eq_ignore_ascii_case(b"TXT") => Ok(Type::TXT),
        s if s.eq_ignore_ascii_case(b"MX") => Ok(Type::MX),
        _ => bail!(ErrorKind::UnsupportedRRType(
            str::from_utf8(rr_type_str)
                .unwrap_or("<invalid UTF8 sequence>")
                .to_owned()
        )),
    }
}

pub fn rr_parser<I: U8Input>(i: I) -> SimpleResult<I, Result<RR>> {
    parse!{i;
        let rr_common = rr_common_parser();
        skip_horizontal_whitespaces();
        let rr = i -> {
            match rr_common.rr_type {
                Type::A => {
                    rr_rdata_a_parser(i).map(|ip| A::build(rr_common, ip))
                },
                Type::AAAA => {
                    rr_rdata_aaaa_parser(i).map(|ip| AAAA::build(rr_common, ip))
                },
                Type::NS => {
                    rr_rdata_hostname_parser(i).map(|ns| NS::build(rr_common, ns))
                },
                Type::CNAME => {
                    rr_rdata_hostname_parser(i).map(|cname| CNAME::build(rr_common, cname))
                },
                Type::PTR => {
                    rr_rdata_hostname_parser(i).map(|ptr| PTR::build(rr_common, ptr))
                },
                Type::TXT => {
                    rr_rdata_string_parser(i).map(|txt| TXT::build(rr_common, txt))
                },
                Type::MX => {
                    rr_rdata_mx_parser(i).map(|(preference, mxname)| MX::build(rr_common, preference, mxname))
                },
                _ => i.err(parsers::Error::unexpected())
            }
        };
        ret rr
    }
}
