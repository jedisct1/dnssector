use byteorder::{BigEndian, ByteOrder};
use compress::*;
use constants::*;
use errors::*;
use parsed_packet::*;
use std::mem;

/// A `DNSSector` object summarizes the structure of a DNS packet,
/// so that individual sections can be accessed quickly.
///
/// The functions implemented here assume an untrusted input packet.
#[derive(Clone, Debug)]
pub struct DNSSector {
    pub packet: Vec<u8>,
    pub offset: usize,
    pub edns_start: Option<usize>,
    pub edns_end: Option<usize>,
    pub edns_count: u16,
    pub ext_rcode: Option<u8>,
    pub edns_version: Option<u8>,
    pub ext_flags: Option<u16>,
}

impl DNSSector {
    /// Returns the number of records in the question section.
    #[inline]
    pub fn qdcount(packet: &[u8]) -> u16 {
        BigEndian::read_u16(&packet[4..])
    }

    /// Changes the number of questions.
    #[allow(dead_code)]
    #[inline]
    pub fn set_qdcount(packet: &mut [u8], value: u16) {
        BigEndian::write_u16(&mut packet[4..], value);
    }

    /// Returns the numbersof records in the answer section.
    #[inline]
    pub fn ancount(packet: &[u8]) -> u16 {
        BigEndian::read_u16(&packet[6..])
    }

    /// Changes the number of records in the answer section.
    #[allow(dead_code)]
    #[inline]
    pub fn set_ancount(packet: &mut [u8], value: u16) {
        BigEndian::write_u16(&mut packet[6..], value)
    }

    /// Returns the number of records in the nameservers section.
    #[inline]
    pub fn nscount(packet: &[u8]) -> u16 {
        BigEndian::read_u16(&packet[8..])
    }

    /// Changes the number of records in the nameservers section.
    #[allow(dead_code)]
    #[inline]
    pub fn set_nscount(packet: &mut [u8], value: u16) {
        BigEndian::write_u16(&mut packet[8..], value)
    }

    /// Returns the number of records in the additional section.
    #[inline]
    pub fn arcount(packet: &[u8]) -> u16 {
        BigEndian::read_u16(&packet[10..])
    }

    /// Changes the number of records in the additional section.
    #[allow(dead_code)]
    #[inline]
    pub fn set_arcount(packet: &mut [u8], value: u16) {
        BigEndian::write_u16(&mut packet[10..], value)
    }

    /// Returns the number of yet unparsed bytes.
    #[inline]
    fn remaining_len(&self) -> usize {
        self.packet.len() - self.offset
    }

    /// Makes sure that at least `len` bytes remain to be parsed.
    #[inline]
    fn ensure_remaining_len(&self, len: usize) -> Result<()> {
        if self.remaining_len() < len {
            bail!(ErrorKind::PacketTooSmall)
        }
        Ok(())
    }

    /// Sets the internal offset to the data to be parsed to an arbitrary location
    pub fn set_offset(&mut self, offset: usize) -> Result<usize> {
        if offset >= self.packet.len() {
            bail!(ErrorKind::InternalError(
                "Setting offset past the end of the packet",
            ))
        }
        Ok(mem::replace(&mut self.offset, offset))
    }

    /// Increments the internal offset
    #[inline]
    pub fn increment_offset(&mut self, n: usize) -> Result<usize> {
        self.ensure_remaining_len(n)?;
        let new_offset = self.offset + n;
        Ok(mem::replace(&mut self.offset, new_offset))
    }

    #[inline]
    fn u8_load(&self, rr_offset: usize) -> Result<u8> {
        self.ensure_remaining_len(rr_offset + 1)?;
        let offset = self.offset + rr_offset;
        Ok(self.packet[offset])
    }

    #[inline]
    fn be16_load(&self, rr_offset: usize) -> Result<u16> {
        self.ensure_remaining_len(rr_offset + 2)?;
        let offset = self.offset + rr_offset;
        Ok((BigEndian::read_u16(&self.packet[offset..])))
    }

    #[inline]
    fn be32_load(&self, rr_offset: usize) -> Result<u32> {
        self.ensure_remaining_len(rr_offset + 4)?;
        let offset = self.offset + rr_offset;
        Ok((BigEndian::read_u32(&self.packet[offset..])))
    }

    /// Checks that an encoded DNS name is valid. This includes following indirections for
    /// compressed names, checks for label lengths, checks for truncated names and checks for
    /// cycles.
    fn check_compressed_name(&self, offset: usize) -> Result<usize> {
        Compress::check_compressed_name(&self.packet, offset)
    }

    /// Verifies that a name has been properly encoded, and sets the internal
    /// offset to the location right after than name.
    fn skip_name(&mut self) -> Result<()> {
        let offset = self.check_compressed_name(self.offset)?;
        self.set_offset(offset).map(|_| {})
    }

    /// Returns the type of the record currently being parsed.
    #[inline]
    fn rr_type(&self) -> Result<u16> {
        self.be16_load(DNS_RR_TYPE_OFFSET)
    }

    /// Returns the class of the record currently being parsed.
    #[inline]
    fn rr_class(&self) -> Result<u16> {
        self.be16_load(DNS_RR_CLASS_OFFSET)
    }

    /// Returns the TTL of the record currently being parsed.
    #[inline]
    fn rr_ttl(&self) -> Result<u32> {
        self.be32_load(DNS_RR_TTL_OFFSET)
    }

    /// Returns the length of the data for the record currently being parsed.
    #[inline]
    pub fn rr_rdlen(&self) -> Result<usize> {
        self.be16_load(DNS_RR_RDLEN_OFFSET).map(|x| x as usize)
    }

    /// Ensure that the record currently being parsed has the `IN` class.
    #[inline]
    fn ensure_in_class(&self) -> Result<()> {
        if self.rr_class()? != Class::IN.into() {
            bail!(ErrorKind::UnsupportedClass);
        }
        Ok(())
    }

    /// Builds a `DNSSector` structure for a given untrusted DNS packet.
    pub fn new(packet: Vec<u8>) -> Result<Self> {
        let dns_sector = DNSSector {
            packet: packet,
            offset: 0,
            edns_start: None,
            edns_end: None,
            edns_count: 0,
            ext_rcode: None,
            edns_version: None,
            ext_flags: None,
        };
        Ok(dns_sector)
    }

    /// Parses and validates all records from all sections of an untrusted DNS packet.
    /// If the validation succeeds, a `ParsedPacket` structure containing information
    /// to quickly access (extended) flags and individual sections is returned.
    pub fn parse(mut self) -> Result<ParsedPacket> {
        let packet_len = self.packet.len();
        if packet_len < DNS_HEADER_SIZE {
            bail!(ErrorKind::PacketTooSmall)
        }
        let qdcount = Self::qdcount(&self.packet);
        if qdcount > 1 {
            bail!(ErrorKind::InvalidPacket(
                "A DNS packet cannot contain more than one question",
            ));
        }
        self.set_offset(DNS_QUESTION_OFFSET)?;
        let offset_question = if qdcount > 0 { Some(self.offset) } else { None };
        if qdcount != 0 {
            assert_eq!(qdcount, 1);
            self.parse_question()?;
        }
        let ancount = Self::ancount(&self.packet);
        let offset_answers = if ancount > 0 { Some(self.offset) } else { None };
        for _ in 0..ancount {
            self.parse_rr(Section::Answer)?;
        }
        let nscount = Self::nscount(&self.packet);
        let offset_nameservers = if nscount > 0 { Some(self.offset) } else { None };
        for _ in 0..nscount {
            self.parse_rr(Section::NameServers)?;
        }
        let arcount = Self::arcount(&self.packet);
        let offset_additional = if arcount > 0 { Some(self.offset) } else { None };
        for _ in 0..arcount {
            self.parse_rr(Section::Additional)?;
        }
        if self.remaining_len() > 0 {
            bail!(ErrorKind::InvalidPacket(
                "Extra data found after the last record",
            ));
        }
        let edns_start = self.edns_start;
        let ext_rcode = self.ext_rcode;
        let edns_version = self.edns_version;
        let ext_flags = self.ext_flags;
        let edns_count = self.edns_count;
        let parsed_packet = ParsedPacket {
            dns_sector: self,
            offset_question: offset_question,
            offset_answers: offset_answers,
            offset_nameservers: offset_nameservers,
            offset_additional: offset_additional,
            offset_edns: edns_start,
            ext_rcode: ext_rcode,
            edns_version: edns_version,
            ext_flags: ext_flags,
            edns_count: edns_count,
        };
        Ok(parsed_packet)
    }

    /// Parses a question RR.
    fn parse_question(&mut self) -> Result<()> {
        self.skip_name()?;
        self.ensure_in_class()?;
        if self.rr_class()? != Class::IN.into() {
            bail!(ErrorKind::UnsupportedClass);
        }
        self.increment_offset(DNS_RR_QUESTION_HEADER_SIZE)?;
        Ok(())
    }

    /// Parses a RR from the answer, nameservers or additional sections.
    fn parse_rr(&mut self, section: Section) -> Result<()> {
        self.skip_name()?;
        let rr_type = self.rr_type()?;
        match rr_type {
            x if x == Type::OPT.into() => {
                if section != Section::Additional {
                    bail!(ErrorKind::InvalidPacket(
                        "OPT RRs must be in the additional section",
                    ));
                }
                return self.parse_opt();
            }
            _ => {}
        }
        let inc = DNS_RR_HEADER_SIZE + self.rr_rdlen()?;
        self.increment_offset(inc)?;
        Ok(())
    }

    /// Returns the number of unparsed bytes from the edns pseudo-section.
    #[inline]
    fn edns_remaining_len(&self) -> usize {
        match self.edns_end {
            None => 0,
            Some(edns_end) => edns_end - self.offset,
        }
    }

    /// Makes sure that at least `len` bytes remain to be parsed in the edns pseudo-section.
    #[inline]
    fn edns_ensure_remaining_len(&self, len: usize) -> Result<()> {
        if self.edns_remaining_len() < len {
            bail!(ErrorKind::PacketTooSmall)
        }
        Ok(())
    }

    /// Increments the internal offset of the edns pseudo-section.
    #[inline]
    fn edns_increment_offset(&mut self, n: usize) -> Result<usize> {
        self.edns_ensure_remaining_len(n)?;
        let new_offset = self.offset + n;
        Ok(mem::replace(&mut self.offset, new_offset))
    }

    #[inline]
    fn edns_be16_load(&self, rr_offset: usize) -> Result<u16> {
        self.edns_ensure_remaining_len(rr_offset + 2)?;
        let offset = self.offset + rr_offset;
        Ok(
            (self.packet[offset] as u16) << 8 | self.packet[offset + 1] as u16,
        )
    }

    #[inline]
    fn edns_be32_load(&self, rr_offset: usize) -> Result<u32> {
        self.edns_ensure_remaining_len(rr_offset + 4)?;
        let offset = self.offset + rr_offset;
        Ok(
            (self.packet[offset] as u32) << 24 | (self.packet[offset + 1] as u32) << 16 |
                (self.packet[offset + 2] as u32) << 8 | self.packet[offset + 3] as u32,
        )
    }

    /// Returns the extended code of a record within the edns pseudo-section.
    #[inline]
    fn edns_rr_code(&self) -> Result<u16> {
        self.edns_be16_load(DNS_EDNS_RR_CODE_OFFSET)
    }

    /// Returns the record length of a record within the edns pseudo-section.
    #[inline]
    pub fn edns_rr_rdlen(&self) -> Result<usize> {
        self.edns_be16_load(DNS_EDNS_RR_RDLEN_OFFSET).map(
            |x| x as usize,
        )
    }

    /// Skips over a record of the edns pseudo-section.
    #[inline]
    fn edns_skip_rr(&mut self) -> Result<()> {
        let inc = DNS_EDNS_RR_HEADER_SIZE + self.edns_rr_rdlen()?;
        self.edns_increment_offset(inc).map(|_| {})
    }

    /// Returns the maximum payload size for UDP packets, from an optional `OPT` record.
    #[inline]
    fn opt_rr_max_payload(&self) -> Result<usize> {
        self.be16_load(DNS_OPT_RR_MAX_PAYLOAD_OFFSET).map(
            |x| x as usize,
        )
    }

    /// Returns the extended return code, from an optional `OPT` record.
    #[inline]
    fn opt_rr_ext_rcode(&self) -> Result<u8> {
        self.u8_load(DNS_OPT_RR_EXT_RCODE_OFFSET)
    }

    /// Returns the edns version, from an optional `OPT` record.
    #[inline]
    fn opt_rr_edns_version(&self) -> Result<u8> {
        self.u8_load(DNS_OPT_RR_EDNS_VERSION_OFFSET)
    }

    /// Returns the edns extended flags, from an optional `OPT` record.
    #[inline]
    fn opt_rr_edns_ext_flags(&self) -> Result<u16> {
        self.be16_load(DNS_OPT_RR_EDNS_EXT_FLAGS_OFFSET)
    }

    /// Returns the length of the data contained within an `OPT` record.
    #[inline]
    fn opt_rr_rdlen(&self) -> Result<usize> {
        self.be16_load(DNS_OPT_RR_RDLEN_OFFSET).map(|x| x as usize)
    }

    /// Parses and validates an `OPT` section.
    fn parse_opt(&mut self) -> Result<()> {
        if self.edns_end.is_some() {
            bail!(ErrorKind::InvalidPacket("Only one OPT record is allowed"));
        }
        self.ext_rcode = Some(self.opt_rr_ext_rcode()?);
        self.edns_version = Some(self.opt_rr_edns_version()?);
        self.ext_flags = Some(self.opt_rr_edns_ext_flags()?);
        let edns_len = self.opt_rr_rdlen()?;
        self.increment_offset(DNS_OPT_RR_HEADER_SIZE)?;
        self.edns_start = Some(self.offset);
        self.ensure_remaining_len(edns_len)?;
        self.edns_end = Some(self.offset + edns_len);
        self.edns_count = 0;
        while self.edns_remaining_len() > 0 {
            self.edns_skip_rr()?;
            self.edns_count += 1;
        }
        Ok(())
    }
}
