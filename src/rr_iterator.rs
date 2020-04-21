use crate::compress::*;
use crate::constants::*;
use crate::dns_sector::*;
use crate::errors::*;
use crate::parsed_packet::*;
use byteorder::{BigEndian, ByteOrder};
use std::marker;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr;

/// Accessor to the raw packet data.
/// `offset` is the offset to the current RR.
/// `name_end` is the offset to the data right after the name.
#[derive(Copy, Clone, Debug)]
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

    /// Returns the offset of the current RR, or `None` if we haven't started iterating yet
    /// or if the current record has been deleted.
    ///
    /// In order to check for the later, please use `is_tombstone()` instead for clarity.
    fn offset(&self) -> Option<usize>;

    /// Returns the offset right after the current RR.
    fn offset_next(&self) -> usize;

    /// Sets the offset of the current RR.
    fn set_offset(&mut self, offset: usize);

    /// Sets the offset of the next RR.
    fn set_offset_next(&mut self, offset: usize);

    /// Prevents access to the current record.
    /// This is useful after a delete operation: from a user perspective, the current
    /// iterator doesn't point to a valid RR any more.
    fn invalidate(&mut self);

    /// Returns `true` if the record has been invalidated by a previous call to `delete()`
    fn is_tombstone(&self) -> bool {
        self.offset().is_none()
    }

    /// Updates the precomputed RR information
    fn recompute_rr(&mut self);

    /// Updates the precomputed offsets of each section.
    fn recompute_sections(&mut self);

    /// Accesses the raw packet data.
    fn raw(&self) -> RRRaw<'_>;

    /// Accesses the mutable raw packet data.
    fn raw_mut(&mut self) -> RRRawMut<'_>;

    /// Accesses the parsed packet structure.
    fn parsed_packet(&self) -> &ParsedPacket;

    /// Accesses the parsed packet structure.
    fn parsed_packet_mut(&mut self) -> &mut ParsedPacket;

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
    fn uncompress(&mut self) -> Result<(), Error> {
        if !self.parsed_packet().maybe_compressed {
            return Ok(());
        }
        let (uncompressed, new_offset_next) = {
            let ref_offset_next = self.offset_next();
            let compressed = self.raw_mut().packet;
            Compress::uncompress_with_previous_offset(compressed, ref_offset_next)?
        };
        self.parsed_packet_mut().packet = Some(uncompressed);
        self.set_offset_next(new_offset_next);
        self.recompute_sections();
        self.recompute_rr();
        Ok(())
    }
}

pub trait TypedIterable {
    /// Returns the RR name (labels are dot-delimited), as a byte vector. The name is not supposed to be valid UTF-8. It will be converted to lower-case, though, using traditional DNS conversion rules
    fn name(&self) -> Vec<u8>
    where
        Self: DNSIterable,
    {
        let raw = self.raw();
        let offset = raw.offset;
        if raw.name_end <= offset {
            return Vec::new();
        }
        let packet = raw.packet;
        let mut name = Compress::raw_name_to_str(&packet, offset);
        name.make_ascii_lowercase();
        name
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
    fn current_section(&self) -> Result<Section, Error>
    where
        Self: DNSIterable,
    {
        let offset = self.offset();
        let parsed_packet = self.parsed_packet();
        if offset < parsed_packet.offset_question {
            bail!(DSError::InternalError("name before the question section"));
        }
        let mut section = Section::Question;
        if parsed_packet.offset_answers.is_some() && offset >= parsed_packet.offset_answers {
            section = Section::Answer;
        }
        if parsed_packet.offset_nameservers.is_some() && offset >= parsed_packet.offset_nameservers
        {
            section = Section::NameServers
        }
        if parsed_packet.offset_additional.is_some() && offset >= parsed_packet.offset_additional {
            section = Section::Additional;
        }
        Ok(section)
    }

    /// Resizes the current record, by growing or shrinking (with a negative value) the current
    /// record size by `shift` bytes.
    fn resize_rr(&mut self, shift: isize) -> Result<(), Error>
    where
        Self: DNSIterable,
    {
        {
            if shift == 0 {
                return Ok(());
            }
            let offset = self.offset().ok_or(DSError::VoidRecord)?;
            let packet = &mut self.parsed_packet_mut().packet_mut();
            let packet_len = packet.len();
            if shift > 0 {
                let new_packet_len = packet_len + shift as usize;
                if new_packet_len > 0xffff {
                    bail!(DSError::PacketTooLarge);
                }
                packet.resize(new_packet_len, 0);
                debug_assert_eq!(
                    new_packet_len,
                    (offset as isize + shift) as usize + (packet_len - offset) as usize
                );
                unsafe {
                    let packet_ptr = packet.as_mut_ptr();
                    ptr::copy(
                        packet_ptr.add(offset),
                        packet_ptr.offset((offset as isize + shift) as isize),
                        packet_len - offset,
                    );
                }
            } else if shift < 0 {
                assert!(packet_len >= (-shift) as usize);
                unsafe {
                    let packet_ptr = packet.as_mut_ptr();
                    ptr::copy(
                        packet_ptr.offset((offset as isize - shift) as isize),
                        packet_ptr.add(offset),
                        packet_len - (offset as isize - shift) as usize,
                    );
                }
                packet.truncate((packet_len as isize + shift) as usize);
            }
        }
        let new_offset_next = (self.offset_next() as isize + shift) as usize;
        self.set_offset_next(new_offset_next);
        let section = self.current_section()?;
        let parsed_packet = self.parsed_packet_mut();
        if section == Section::NameServers
            || section == Section::Answer
            || section == Section::Question
        {
            parsed_packet.offset_additional = parsed_packet
                .offset_additional
                .map(|x| (x as isize + shift) as usize)
        }
        if section == Section::Answer || section == Section::Question {
            parsed_packet.offset_nameservers = parsed_packet
                .offset_nameservers
                .map(|x| (x as isize + shift) as usize)
        }
        if section == Section::Question {
            parsed_packet.offset_answers = parsed_packet
                .offset_answers
                .map(|x| (x as isize + shift) as usize)
        }
        Ok(())
    }

    /// Changes the name (raw format, untrusted content).
    fn set_raw_name(&mut self, name: &[u8]) -> Result<(), Error>
    where
        Self: DNSIterable,
    {
        let new_name_len = DNSSector::check_uncompressed_name(name, 0)?;
        let name = &name[..new_name_len];
        if self.parsed_packet().maybe_compressed {
            let (uncompressed, new_offset) = {
                let ref_offset = self.offset().ok_or(DSError::VoidRecord)?;
                let compressed = self.raw_mut().packet;
                Compress::uncompress_with_previous_offset(compressed, ref_offset)?
            };
            self.parsed_packet_mut().packet = Some(uncompressed);
            self.set_offset(new_offset);
            self.recompute_rr(); // XXX - Just for sanity, but not strictly required here
            self.recompute_sections();
        }
        let offset = self.offset().ok_or(DSError::VoidRecord)?;
        debug_assert_eq!(self.parsed_packet().maybe_compressed, false);
        let current_name_len = Compress::raw_name_len(self.name_slice());
        let shift = new_name_len as isize - current_name_len as isize;
        self.resize_rr(shift)?;
        {
            let packet = &mut self.parsed_packet_mut().packet_mut();
            packet[offset..offset + new_name_len].copy_from_slice(name);
        }
        self.recompute_rr();

        Ok(())
    }

    /// Deletes the record
    fn delete(&mut self) -> Result<(), Error>
    where
        Self: DNSIterable,
    {
        self.offset().ok_or(DSError::VoidRecord)?;
        let section = self.current_section()?;
        if self.parsed_packet().maybe_compressed {
            let (uncompressed, new_offset) = {
                let ref_offset = self.offset().expect("delete() called on a tombstone");
                let compressed = self.raw_mut().packet;
                Compress::uncompress_with_previous_offset(compressed, ref_offset)?
            };
            self.parsed_packet_mut().packet = Some(uncompressed);
            self.set_offset(new_offset);
            self.recompute_rr(); // XXX - Just for sanity, but not strictly required here
            self.recompute_sections();
        }
        let rr_len = self.offset_next()
            - self
                .offset()
                .expect("Deleting record with no known offset after optional decompression");
        assert!(rr_len > 0);
        self.resize_rr(-(rr_len as isize))?;
        let offset = self.offset().unwrap();
        self.set_offset_next(offset);
        self.invalidate();
        let parsed_packet = self.parsed_packet_mut();
        let rrcount = parsed_packet.rrcount_dec(section)?;
        if rrcount <= 0 {
            let offset = match section {
                Section::Question => &mut parsed_packet.offset_question,
                Section::Answer => &mut parsed_packet.offset_answers,
                Section::NameServers => &mut parsed_packet.offset_nameservers,
                Section::Additional => &mut parsed_packet.offset_additional,
                _ => panic!("delete() cannot be used to delete EDNS pseudo-records"),
            };
            *offset = None;
        }
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

    /// Retrieves the string of an `TXT` record.
    fn rr_txt(&self) -> Result<Vec<u8>, Error>
    where
        Self: DNSIterable + TypedIterable,
    {
        match self.rr_type() {
            x if x == Type::TXT.into() => {
                let rdata = self.rdata_slice();
                let mut text: Vec<u8> = Vec::new();
                let mut i = usize::from(DNS_RR_HEADER_SIZE);
                while i < rdata.len() {
                    let chunklen = usize::from(rdata[i]);
                    i = i+1;
                    text.extend_from_slice(&rdata[i..i+chunklen]);
                    i += chunklen
                }
                if i > DNS_RR_HEADER_SIZE {
                    Ok(text)
                } else {
                    bail!(DSError::PropertyNotFound)
                }
            }
            _ => bail!(DSError::PropertyNotFound),
        }
    }

    /// Retrieves the IP address of an `A` or `AAAA` record.
    fn rr_ip(&self) -> Result<IpAddr, Error>
    where
        Self: DNSIterable + TypedIterable,
    {
        match self.rr_type() {
            x if x == Type::A.into() => {
                let rdata = self.rdata_slice();
                assert!(rdata.len() >= DNS_RR_HEADER_SIZE + 4);
                let mut ip = [0u8; 4];
                ip.copy_from_slice(&rdata[DNS_RR_HEADER_SIZE..DNS_RR_HEADER_SIZE + 4]);
                Ok(IpAddr::V4(Ipv4Addr::from(ip)))
            }
            x if x == Type::AAAA.into() => {
                let rdata = self.rdata_slice();
                assert!(rdata.len() >= DNS_RR_HEADER_SIZE + 16);
                let mut ip = [0u8; 16];
                ip.copy_from_slice(&rdata[DNS_RR_HEADER_SIZE..DNS_RR_HEADER_SIZE + 16]);
                Ok(IpAddr::V6(Ipv6Addr::from(ip)))
            }
            _ => bail!(DSError::PropertyNotFound),
        }
    }

    /// Changes the IP address of an `A` or `AAAA` record.
    fn set_rr_ip(&mut self, ip: &IpAddr) -> Result<(), Error>
    where
        Self: DNSIterable + TypedIterable,
    {
        match self.rr_type() {
            x if x == Type::A.into() => match *ip {
                IpAddr::V4(ip) => {
                    let rdata = self.rdata_slice_mut();
                    assert!(rdata.len() >= DNS_RR_HEADER_SIZE + 4);
                    rdata[DNS_RR_HEADER_SIZE..DNS_RR_HEADER_SIZE + 4].copy_from_slice(&ip.octets());
                    Ok(())
                }
                _ => bail!(DSError::WrongAddressFamily),
            },
            x if x == Type::AAAA.into() => match *ip {
                IpAddr::V6(ip) => {
                    let rdata = self.rdata_slice_mut();
                    assert!(rdata.len() >= DNS_RR_HEADER_SIZE + 16);
                    rdata[DNS_RR_HEADER_SIZE..DNS_RR_HEADER_SIZE + 16]
                        .copy_from_slice(&ip.octets());
                    Ok(())
                }
                _ => bail!(DSError::WrongAddressFamily),
            },
            _ => bail!(DSError::PropertyNotFound),
        }
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
        let offset = self
            .offset
            .expect("recompute() called prior to iterating over RRs");
        let name_end = Self::skip_name(&self.parsed_packet.packet(), offset);
        let offset_next = Self::skip_rdata(&self.parsed_packet.packet(), name_end);
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
