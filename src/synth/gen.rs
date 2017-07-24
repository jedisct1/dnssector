use byteorder::{BigEndian, ByteOrder};
use constants::*;
use errors::*;
use chomp::prelude::parse_only;
use std::net::{Ipv4Addr, Ipv6Addr};
use super::parser::*;

#[derive(Clone, Debug)]
pub struct RRHeader {
    pub name: Vec<u8>,
    pub ttl: u32,
    pub class: Class,
    pub rr_type: Type,
}

pub fn copy_raw_name_from_str(
    raw_name: &mut Vec<u8>,
    name: &[u8],
    raw_zone: Option<&[u8]>,
) -> Result<()> {
    let mut label_len = 0u8;
    let mut label_start = 0;
    if name.len() > 253 {
        bail!(ErrorKind::InvalidName("Name too long"))
    }
    for (i, &c) in name.iter().enumerate() {
        match c {
            b'.' if label_len == 0 => if name.len() != 1 {
                bail!(ErrorKind::InvalidName("Spurious dot in a label"))
            },
            b'.' => {
                raw_name.push(label_len);
                raw_name.extend_from_slice(&name[label_start..i]);
                label_len = 0;
            }
            _ if label_len >= 63 - 1 => bail!(ErrorKind::InvalidName("Label too long")),
            c if c > 128 => bail!(ErrorKind::InvalidName("Non-ASCII character in a label")),
            _ if label_len == 0 => {
                label_start = i;
                label_len += 1;
            }
            _ => label_len += 1,
        }
    }
    if label_len == 0 {
        raw_name.push(0);
    } else {
        raw_name.push(label_len);
        raw_name.extend_from_slice(&name[label_start..]);
        match raw_zone {
            None => raw_name.push(0),
            Some(raw_zone) => raw_name.extend_from_slice(raw_zone),
        }
    }
    if raw_name.len() > 253 {
        bail!(ErrorKind::InvalidName("Name too long"))
    }
    Ok(())
}

pub fn raw_name_from_str(name: &[u8], raw_zone: Option<&[u8]>) -> Result<Vec<u8>> {
    let mut raw_name = Vec::with_capacity(name.len() + raw_zone.map_or(1, |x| x.len()));
    copy_raw_name_from_str(&mut raw_name, name, raw_zone)?;
    Ok(raw_name)
}

#[derive(Clone, Debug)]
pub struct RR {
    pub packet: Vec<u8>,
}

impl RR {
    fn new(rr_header: RRHeader, rdata: &[u8]) -> Result<Self> {
        let rdlen = rdata.len();
        if rdlen > 0xffff {
            bail!(ErrorKind::InvalidPacket("RDATA too long"));
        }
        let mut packet = Vec::with_capacity(rr_header.name.len() + 1 + DNS_RR_HEADER_SIZE + rdlen);
        copy_raw_name_from_str(&mut packet, &rr_header.name, None)?;
        let mut header = [0u8; DNS_RR_HEADER_SIZE];
        BigEndian::write_u32(&mut header[DNS_RR_TTL_OFFSET..], rr_header.ttl);
        BigEndian::write_u16(&mut header[DNS_RR_CLASS_OFFSET..], rr_header.class.into());
        BigEndian::write_u16(&mut header[DNS_RR_TYPE_OFFSET..], rr_header.rr_type.into());
        BigEndian::write_u16(&mut header[DNS_RR_RDLEN_OFFSET..], rdlen as u16);
        packet.extend_from_slice(&header);
        packet.extend_from_slice(rdata);
        Ok(RR { packet: packet })
    }

    pub fn from_string(s: &str) -> Result<RR> {
        match parse_only(rr_parser, s.as_bytes()) {
            Err(_) => bail!(ErrorKind::ParseError),
            Ok(rr) => match rr {
                Err(e) => bail!(e),
                Ok(rr) => Ok(rr),
            },
        }
    }
}

pub struct A;

impl A {
    pub fn build(rr_header: RRHeader, ip: Ipv4Addr) -> Result<RR> {
        let rdata = ip.octets();
        RR::new(rr_header, &rdata)
    }
}

pub struct AAAA;

impl AAAA {
    pub fn build(rr_header: RRHeader, ip: Ipv6Addr) -> Result<RR> {
        let rdata = ip.octets();
        RR::new(rr_header, &rdata)
    }
}

pub struct NS;

impl NS {
    pub fn build(rr_header: RRHeader, name: Vec<u8>) -> Result<RR> {
        let rdata = raw_name_from_str(&name, None)?;
        RR::new(rr_header, &rdata)
    }
}

pub struct CNAME;

impl CNAME {
    pub fn build(rr_header: RRHeader, name: Vec<u8>) -> Result<RR> {
        let rdata = raw_name_from_str(&name, None)?;
        RR::new(rr_header, &rdata)
    }
}

pub struct PTR;

impl PTR {
    pub fn build(rr_header: RRHeader, name: Vec<u8>) -> Result<RR> {
        let rdata = raw_name_from_str(&name, None)?;
        RR::new(rr_header, &rdata)
    }
}

pub struct TXT;

impl TXT {
    pub fn build(rr_header: RRHeader, txt: Vec<u8>) -> Result<RR> {
        if txt.len() > (4096 - DNS_HEADER_SIZE - 1 - DNS_RR_HEADER_SIZE) / 256 * 255 {
            bail!(ErrorKind::InvalidPacket("Text too long"));
        }
        let mut rdata = Vec::with_capacity(1 + txt.len());
        for chunk in txt.chunks(255) {
            rdata.push(chunk.len() as u8);
            rdata.extend_from_slice(chunk);
        }
        RR::new(rr_header, &rdata)
    }
}

pub struct MX;

impl MX {
    pub fn build(rr_header: RRHeader, preference: u16, mxhost: Vec<u8>) -> Result<RR> {
        let mut rdata = Vec::with_capacity(2 + 1 + mxhost.len());
        rdata.push(0);
        rdata.push(0);
        BigEndian::write_u16(&mut rdata[0..2], preference);
        copy_raw_name_from_str(&mut rdata, &mxhost, None)?;
        RR::new(rr_header, &rdata)
    }
}

pub struct SOA;

impl SOA {
    pub fn build(
        rr_header: RRHeader,
        primary_ns: Vec<u8>,
        contact: Vec<u8>,
        ts: u32,
        refresh_ttl: u32,
        retry_ttl: u32,
        auth_ttl: u32,
        neg_ttl: u32,
    ) -> Result<RR> {
        let mut rdata = Vec::with_capacity(primary_ns.len() + 1 + contact.len() + 1 + 20);
        let mut meta = [0u8; 20];
        copy_raw_name_from_str(&mut rdata, &primary_ns, None)?;
        copy_raw_name_from_str(&mut rdata, &contact, None)?;
        BigEndian::write_u32(&mut meta[0..], ts);
        BigEndian::write_u32(&mut meta[4..], refresh_ttl);
        BigEndian::write_u32(&mut meta[8..], retry_ttl);
        BigEndian::write_u32(&mut meta[12..], auth_ttl);
        BigEndian::write_u32(&mut meta[16..], neg_ttl);
        rdata.extend_from_slice(&meta);
        RR::new(rr_header, &rdata)
    }
}
