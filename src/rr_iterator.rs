use std::ascii::AsciiExt;
use byteorder::{BigEndian, ByteOrder};
use compress::*;
use constants::*;
use parsed_packet::*;
use std::marker;

/// Accessor to the raw packet data.
/// `offset` is the offset to the current RR.
/// `name_end` is the offset to the data right after the name.
pub struct RRRaw<'t> {
    pub packet: &'t [u8],
    pub offset: usize,
    pub name_end: usize,
}

/// Mutable accessor to the raw packet data.
/// `offset` is the offset to the current RR.
/// `name_end` is the offset to the data right after the name.
pub struct RRRawMut<'t> {
    pub packet: &'t mut [u8],
    pub offset: usize,
    pub name_end: usize,
}

/// The `DNSIterable` trait represents a set of records that can be iterated over.
pub trait DNSIterable {
    /// Returns the next record, or `None` if there aren't any left.
    fn next(self) -> Option<Self> where Self: marker::Sized;

    /// Returns the offset of the current RR, or `None` if we haven't started iterating yet.
    fn offset(&self) -> Option<usize>;

    /// Accesses the raw packet data.
    fn raw(&self) -> RRRaw;

    /// Accesses the mutable raw packet data.
    fn raw_mut(&mut self) -> RRRawMut;

    /// Raw packet data.
    #[inline]
    fn packet(&self) -> &[u8] {
        let raw = self.raw();
        raw.packet
    }

    /// Accesses the raw packet data, starting from the name.
    #[inline]
    fn name_slice(&self) -> &[u8] {
        let raw = self.raw();
        &raw.packet[raw.offset..raw.name_end]
    }

    /// Access the raw packet data, starting from right after the name.
    #[inline]
    fn rdata_slice(&self) -> &[u8] {
        let raw = self.raw();
        &raw.packet[raw.name_end..]
    }

    /// Accesses the mutable raw packet data, starting from the name.
    #[inline]
    fn name_slice_mut(&mut self) -> &mut [u8] {
        let raw = self.raw_mut();
        &mut raw.packet[raw.offset..raw.name_end]
    }

    /// Accesses the mutable raw packet data, starting from right after the name.
    #[inline]
    fn rdata_slice_mut(&mut self) -> &mut [u8] {
        let raw = self.raw_mut();
        &mut raw.packet[raw.name_end..]
    }
}

pub trait TypedIterable {
    /// Returns the RR name (labels are dot-telimited), as a byte vector. The name is not supposed to be valid UTF-8.
    fn name(&self) -> Vec<u8>
        where Self: DNSIterable
    {
        let raw = self.raw();
        let mut offset = raw.offset;
        let mut res: Vec<u8> = Vec::with_capacity(64);
        if raw.name_end <= offset {
            return res;
        }
        let packet = raw.packet;
        loop {
            let label_len = match packet[offset] {
                0 => break,
                len if len & 0xc0 == 0xc0 => {
                    let new_offset = (BigEndian::read_u16(&packet[offset..]) & 0x3fff) as usize;
                    assert!(new_offset < offset);
                    offset = new_offset;
                    continue;
                }
                len => len,
            } as usize;
            offset += 1;
            let label = &packet[offset..offset + label_len];
            offset += label_len;
            if !res.is_empty() {
                res.push(b'.');
            }
            res.extend(label);
        }
        res.make_ascii_lowercase();
        res
    }

    /// Appends the uncompressed RR name (raw format, with labels prefixed by their length) to the given vector.
    /// Returns the length of the uncompressed name.
    fn copy_raw_name(&self, name: &mut Vec<u8>) -> usize
        where Self: DNSIterable
    {
        let raw = self.raw();
        if raw.name_end <= raw.offset {
            return 0;
        }
        let packet = raw.packet;
        Compress::copy_uncompressed_name(name, raw.packet, raw.offset).name_len
    }

    /// Returns the query type for the current RR.
    #[inline]
    fn rr_type(&self) -> u16
        where Self: DNSIterable
    {
        BigEndian::read_u16(&self.rdata_slice()[DNS_RR_TYPE_OFFSET..])
    }

    /// Returns the query class for the current RR.
    #[inline]
    fn rr_class(&self) -> u16
        where Self: DNSIterable
    {
        BigEndian::read_u16(&self.rdata_slice()[DNS_RR_CLASS_OFFSET..])
    }
}

pub trait RdataIterable {
    /// Returns the TTL for the current RR.
    #[inline]
    fn rr_ttl(&self) -> u32
        where Self: DNSIterable + TypedIterable
    {
        BigEndian::read_u32(&self.rdata_slice()[DNS_RR_TTL_OFFSET..])
    }

    /// Returns the record length for the current RR.
    #[inline]
    fn rr_rdlen(&self) -> usize
        where Self: DNSIterable + TypedIterable
    {
        BigEndian::read_u16(&self.rdata_slice()[DNS_RR_RDLEN_OFFSET..]) as usize
    }
}

/// An `RRIterator` structure is a generic way to iterate over the records
/// of a pre-parsed DNS packet. The packet is assumed to have been previously
/// verified for conformance, so the functions provided here are optimized for
/// speed instead of paranoia, and don't return catchable errors: out-of-bounds
/// accesses will make the thread panic, which is exactly what we want: if this
/// ever happens, it means that we failed at properly verifying the packet, so
/// this is a bug, and it has to be fixed, not ignored.
#[derive(Debug)]
pub struct RRIterator<'t> {
    pub parsed_packet: &'t mut ParsedPacket,
    pub section: Section,
    pub offset: Option<usize>,
    pub offset_next: usize,
    pub name_end: usize,
    pub rrs_left: u16,
}

impl<'t> RRIterator<'t> {
    /// Creates a new iterator over a pre-parsed packet, for the given `section`.
    pub fn new(parsed_packet: &'t mut ParsedPacket, section: Section) -> Self {
        RRIterator {
            parsed_packet,
            section,
            offset: None,
            offset_next: 0,
            name_end: 0,
            rrs_left: 0,
        }
    }

    /// Quickly skips over a DNS name, without validation/decompression.
    /// Returns the location right after the name.
    pub fn skip_name(packet: &[u8], mut offset: usize) -> usize {
        let packet_len = packet.len();
        loop {
            let label_len = match packet[offset] {
                len if len & 0xc0 == 0xc0 => {
                    assert!(packet_len - offset > 2);
                    offset += 2;
                    break;
                }
                len => len,
            } as usize;
            assert!(label_len < packet_len - offset - 1);
            offset += label_len + 1;
            if label_len == 0 {
                break;
            }
        }
        offset
    }

    #[inline]
    fn rr_rdlen(packet: &[u8], offset: usize) -> usize {
        BigEndian::read_u16(&packet[offset + DNS_RR_RDLEN_OFFSET..]) as usize
    }

    #[inline]
    pub fn skip_rdata(packet: &[u8], offset: usize) -> usize {
        offset + DNS_RR_HEADER_SIZE + Self::rr_rdlen(packet, offset)
    }

    #[inline]
    pub fn skip_rr(packet: &[u8], offset: usize) -> usize {
        Self::skip_rdata(packet, Self::skip_name(packet, offset))
    }

    #[inline]
    fn edns_rr_rdlen(packet: &[u8], offset: usize) -> usize {
        BigEndian::read_u16(&packet[offset + DNS_EDNS_RR_RDLEN_OFFSET..]) as usize
    }

    pub fn edns_skip_rr(packet: &[u8], mut offset: usize) -> usize {
        offset += DNS_EDNS_RR_HEADER_SIZE + Self::edns_rr_rdlen(packet, offset);
        offset
    }
}
