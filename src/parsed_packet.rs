use byteorder::{BigEndian, ByteOrder};
use constants::*;
use dns_sector::*;
use edns_iterator::*;
use errors::*;
use response_iterator::*;
use question_iterator::*;
use rr_iterator::*;

/// A `ParsedPacket` structure contains information about a successfully parsed
/// DNS packet, that allows quick access to (extended) flags and to individual sections.
#[derive(Debug)]
pub struct ParsedPacket {
    pub dns_sector: DNSSector,
    pub offset_question: Option<usize>,
    pub offset_answers: Option<usize>,
    pub offset_nameservers: Option<usize>,
    pub offset_additional: Option<usize>,
    pub offset_edns: Option<usize>,
    pub edns_count: u16,
    pub ext_rcode: Option<u8>,
    pub edns_version: Option<u8>,
    pub ext_flags: Option<u16>,
}

impl ParsedPacket {
    /// Converts a `ParsedPacket` back into a raw packet.
    pub fn into_packet(self) -> Vec<u8> {
        self.dns_sector.packet
    }

    /// Iterates over the question section.
    pub fn into_iter_question(&mut self) -> Option<QuestionIterator> {
        QuestionIterator::new(RRIterator::new(self, Section::Question)).next()
    }

    /// Iterates over the answer section.
    pub fn into_iter_answer(&mut self) -> Option<AnswerIterator> {
        AnswerIterator::new(RRIterator::new(self, Section::Answer)).next()
    }

    /// Iterates over the list of name servers.
    pub fn into_iter_nameservers(&mut self) -> Option<NameServersIterator> {
        NameServersIterator::new(RRIterator::new(self, Section::NameServers)).next()
    }

    /// Iterates over the additional section - OPT RRs are skipped.
    pub fn into_iter_additional(&mut self) -> Option<AdditionalIterator> {
        AdditionalIterator::new(RRIterator::new(self, Section::Additional)).next()
    }

    /// Iterates over the additional section - OPT RRs are included.
    pub fn into_iter_additional_including_opt(&mut self) -> Option<AdditionalIterator> {
        AdditionalIterator::new(RRIterator::new(self, Section::Additional)).next_including_opt()
    }

    /// Iterates over the records from the optional edns pseudo-section.
    pub fn into_iter_edns(&mut self) -> Option<EdnsIterator> {
        EdnsIterator::new(RRIterator::new(self, Section::Edns)).next()
    }

    /// Returns the transaction ID.
    #[inline]
    pub fn tid(&self) -> u16 {
        BigEndian::read_u16(&self.dns_sector.packet[DNS_TID_OFFSET..])
    }

    /// Changes the transaction ID.
    pub fn set_tid(&mut self, tid: u16) {
        BigEndian::write_u16(&mut self.dns_sector.packet[DNS_TID_OFFSET..], tid)
    }

    /// Returns the flags, including extended flags.
    /// The extended flags optionally obtained using edns are exposed as the highest 16 bits,
    /// instead of having distinct sets of flags.
    /// The opcode and rcode are intentionally masked in order to prevent misuse:
    /// these bits are never supposed to be accessed individually.
    pub fn flags(&self) -> u32 {
        let mut rflags = BigEndian::read_u16(&self.dns_sector.packet[DNS_FLAGS_OFFSET..]);
        rflags &= !0x7800; // mask opcode
        rflags &= !0x000f; // mask rcode
        (self.ext_flags.unwrap_or(0) as u32) << 16 | (rflags as u32)
    }

    /// Changes the flags.
    /// Extended flags from the OPT section are currently ignored.
    pub fn set_flags(&mut self, flags: u32) {
        let mut rflags = (flags & 0xffff) as u16;
        rflags &= !0x7800; // mask opcode
        rflags &= !0x000f; // mask rcode
        let mut v = BigEndian::read_u16(&self.dns_sector.packet[DNS_FLAGS_OFFSET..]);
        v &= !0x7800;
        v &= !0x000f;
        v |= rflags;
        BigEndian::write_u16(&mut self.dns_sector.packet[DNS_FLAGS_OFFSET..], v);
    }

    /// Returns the return code.
    #[inline]
    pub fn rcode(&self) -> u8 {
        let rflags = self.dns_sector.packet[DNS_FLAGS_OFFSET + 1];
        rflags & 0x0f
    }

    /// Changes the return code.
    pub fn set_rcode(&mut self, rcode: u8) {
        let p = &mut self.dns_sector.packet[DNS_FLAGS_OFFSET + 1];
        *p &= !0x0f;
        *p |= rcode & 0x0f;
    }

    /// Returns the opcode.
    #[inline]
    pub fn opcode(&self) -> u8 {
        let rflags = self.dns_sector.packet[DNS_FLAGS_OFFSET];
        (rflags & 0x78) >> 3
    }

    /// Changes the operation code.
    pub fn set_opcode(&mut self, opcode: u8) {
        let p = &mut self.dns_sector.packet[DNS_FLAGS_OFFSET];
        *p &= !0x78;
        *p |= (opcode << 3) & 0x78;
    }

    /// Recomputes all offsets after an in-place update of the packet.
    /// This is commonly required after a forced decompression.
    /// It is currently re-parsing everything by calling `parse()`, but this can be
    /// optimized later to skip over RDATA, and maybe assume that the input
    /// is always well-formed.
    pub fn recompute(&mut self) -> Result<()> {
        let dns_sector = DNSSector::new(self.dns_sector.packet.clone())?;
        let parsed_packet = dns_sector.parse()?;
        self.offset_question = parsed_packet.offset_question;
        self.offset_answers = parsed_packet.offset_answers;
        self.offset_nameservers = parsed_packet.offset_nameservers;
        self.offset_edns = parsed_packet.offset_edns;
        Ok(())
    }
}
