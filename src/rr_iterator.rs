use std::ascii::AsciiExt;
use byteorder::{BigEndian, ByteOrder};
use compress::*;
use constants::*;
use dns_sector::*;
use errors::*;
use parsed_packet::*;
use std::marker;
use std::ptr;

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
    fn next(self) -> Option<Self>
    where
        Self: marker::Sized;

    /// Returns the offset of the current RR, or `None` if we haven't started iterating yet.
    fn offset(&self) -> Option<usize>;

    /// Returns the offset right after the current RR
    fn offset_next(&self) -> usize;

    /// Sets the offset of the current RR
    fn set_offset(&mut self, offset: usize);

    /// Sets the offset of the next RR
    fn set_offset_next(&mut self, offset: usize);

    /// Updates the precomputed RR information
    fn recompute_rr(&mut self);

    /// Updates the precomputed offsets of each section.
    fn recompute_sections(&mut self);

    /// Accesses the raw packet data.
    fn raw(&self) -> RRRaw;

    /// Accesses the mutable raw packet data.
    fn raw_mut(&mut self) -> RRRawMut;

    /// Accesses the parsed packet structure.
    fn parsed_packet(&mut self) -> &mut ParsedPacket;

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

    /// Decompresses the whole packet while keeping the iterator available.
    fn uncompress(&mut self) -> Result<()> {
        if !self.parsed_packet().maybe_compressed {
            return Ok(());
        }
        let (uncompressed, new_offset_next) = {
            let ref_offset_next = self.offset_next();
            let compressed = self.raw_mut().packet;
            Compress::uncompress_with_previous_offset(compressed, ref_offset_next)?
        };
        self.parsed_packet().packet = uncompressed;
        self.set_offset_next(new_offset_next);
        self.recompute_sections();
        self.recompute_rr();
        Ok(())
    }
}

pub trait TypedIterable {
    /// Returns the RR name (labels are dot-telimited), as a byte vector. The name is not supposed to be valid UTF-8.
    fn name(&self) -> Vec<u8>
    where
        Self: DNSIterable,
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
    where
        Self: DNSIterable,
    {
        let raw = self.raw();
        if raw.name_end <= raw.offset {
            return 0;
        }
        Compress::copy_uncompressed_name(name, raw.packet, raw.offset).name_len
    }

    /// Returns the section the current record belongs to.
    fn current_section(&mut self) -> Result<Section>
    where
        Self: DNSIterable,
    {
        let offset = self.offset();
        let parsed_packet = self.parsed_packet();
        let section = match offset {
            x if x < parsed_packet.offset_question => {
                bail!(ErrorKind::InternalError("name before the question section"))
            }
            x if x < parsed_packet.offset_answers => Section::Question,
            x if x < parsed_packet.offset_nameservers => Section::Answer,
            x if x < parsed_packet.offset_additional => Section::NameServers,                
            _ => Section::Additional,
        };
        Ok(section)
    }

    /// Resizes the current record, by growing or shrinking (with a negative value) the current
    /// record size by `shift` bytes.
    fn resize_rr(&mut self, shift: isize) -> Result<()>
    where
        Self: DNSIterable,
    {
        {
            if shift == 0 {
                return Ok(());
            }
            let offset = self.offset()
                .expect("Setting raw name with no known offset");
            let mut packet = &mut self.parsed_packet().packet;
            let packet_len = packet.len();
            let packet_ptr = packet.as_mut_ptr();
            if shift > 0 {
                let new_packet_len = packet_len + shift as usize;
                if new_packet_len > 0xffff {
                    bail!(ErrorKind::PacketTooLarge);
                }
                packet.resize(new_packet_len, 0);
                debug_assert_eq!(
                    new_packet_len,
                    (offset as isize + shift) as usize + (packet_len - offset) as usize
                );
                unsafe {
                    ptr::copy(
                        packet_ptr.offset(offset as isize),
                        packet_ptr.offset((offset as isize + shift) as isize),
                        packet_len - offset,
                    );
                }
            } else if shift < 0 {
                assert!(packet_len >= (-shift) as usize);
                unsafe {
                    ptr::copy(
                        packet_ptr.offset((offset as isize - shift) as isize),
                        packet_ptr.offset(offset as isize),
                        packet_len - (offset as isize - shift) as usize,
                    );
                }
                packet.truncate((packet_len as isize + shift) as usize);
            }
        }
        let new_offset_next = (self.offset_next() as isize + shift) as usize;
        self.set_offset_next(new_offset_next);
        let section = self.current_section()?;
        let parsed_packet = self.parsed_packet();
        if section == Section::NameServers || section == Section::Answer ||
            section == Section::Question
        {
            parsed_packet.offset_additional = Some(
                (parsed_packet.offset_additional.unwrap() as isize + shift) as usize,
            )
        }
        if section == Section::Answer || section == Section::Question {
            parsed_packet.offset_nameservers = Some(
                (parsed_packet.offset_nameservers.unwrap() as isize + shift) as usize,
            )
        }
        if section == Section::Question {
            parsed_packet.offset_answers = Some(
                (parsed_packet.offset_answers.unwrap() as isize + shift) as usize,
            )
        }
        Ok(())
    }

    /// Changes the name (raw format, untrusted content).
    fn set_raw_name(&mut self, name: &[u8]) -> Result<()>
    where
        Self: DNSIterable,
    {
        let new_name_len = DNSSector::check_uncompressed_name(name, 0)?;
        let name = &name[..new_name_len];
        if self.parsed_packet().maybe_compressed {
            let (uncompressed, new_offset) = {
                let ref_offset = self.offset()
                    .expect("Setting raw name with no known offset");
                let compressed = self.raw_mut().packet;
                Compress::uncompress_with_previous_offset(compressed, ref_offset)?
            };
            self.parsed_packet().packet = uncompressed;
            self.set_offset(new_offset);
            self.recompute_rr(); // XXX - Just for sanity, but not strictly required here
            self.recompute_sections();
        }

        let offset = self.offset()
            .expect("Setting raw name with no known offset");
        debug_assert_eq!(self.parsed_packet().maybe_compressed, false);
        let current_name_len = Compress::raw_name_len(self.name_slice());
        let shift = new_name_len as isize - current_name_len as isize;
        self.resize_rr(shift)?;
        {
            let mut packet = &mut self.parsed_packet().packet;
            &mut packet[offset..offset + new_name_len].copy_from_slice(name);
        }
        self.recompute_rr();

        Ok(())
    }

    /// Returns the query type for the current RR.
    #[inline]
    fn rr_type(&self) -> u16
    where
        Self: DNSIterable,
    {
        BigEndian::read_u16(&self.rdata_slice()[DNS_RR_TYPE_OFFSET..])
    }

    /// Returns the query class for the current RR.
    #[inline]
    fn rr_class(&self) -> u16
    where
        Self: DNSIterable,
    {
        BigEndian::read_u16(&self.rdata_slice()[DNS_RR_CLASS_OFFSET..])
    }
}

pub trait RdataIterable {
    /// Returns the TTL for the current RR.
    #[inline]
    fn rr_ttl(&self) -> u32
    where
        Self: DNSIterable + TypedIterable,
    {
        BigEndian::read_u32(&self.rdata_slice()[DNS_RR_TTL_OFFSET..])
    }

    /// Changes the TTL of a record.
    fn set_rr_ttl(&mut self, ttl: u32)
    where
        Self: DNSIterable + TypedIterable,
    {
        BigEndian::write_u32(&mut self.rdata_slice_mut()[DNS_RR_TTL_OFFSET..], ttl);
    }

    /// Returns the record length for the current RR.
    #[inline]
    fn rr_rdlen(&self) -> usize
    where
        Self: DNSIterable + TypedIterable,
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

    pub fn recompute(&mut self) {
        let offset = self.offset
            .expect("recompute() called prior to iterating over RRs");
        let name_end = Self::skip_name(&self.parsed_packet.packet, offset);
        let offset_next = Self::skip_rdata(&self.parsed_packet.packet, name_end);
        self.name_end = name_end;
        self.offset_next = offset_next;
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
