use constants::*;
use dns_sector::*;
use edns_iterator::*;
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
    /// Converts a `ParsedPacket` back into a `DNSSector`.
    pub fn into_dns_sector(self) -> DNSSector {
        self.dns_sector
    }

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

    /// Iterates over the additional section.
    pub fn into_iter_additional(&mut self) -> Option<AdditionalIterator> {
        AdditionalIterator::new(RRIterator::new(self, Section::Additional)).next()
    }

    /// Iterates over the records from the optional edns pseudo-section.
    pub fn into_iter_edns(&mut self) -> Option<EdnsIterator> {
        EdnsIterator::new(RRIterator::new(self, Section::Edns)).next()
    }

    /// Returns the transaction ID.
    #[inline]
    pub fn tid(&self) -> u16 {
        RRIterator::be16_load(&self.dns_sector.packet, DNS_TID_OFFSET)
    }

    /// Returns the flags, including extended flags.
    /// The extended flags optionally obtained using edns are exposed as the highest 16 bits,
    /// instead of having distinct sets of flags.
    /// The opcode and rcode are intentionally masked in order to prevent misuse:
    /// these bits are never supposed to be accessed individually.
    pub fn flags(&self) -> u32 {
        let mut rflags = RRIterator::be16_load(&self.dns_sector.packet, DNS_FLAGS_OFFSET);
        rflags &= ! 0x7800; // mask opcode
        rflags &= ! 0x000f; // mask rcode
        (self.ext_flags.unwrap_or(0) as u32) << 16 | (rflags as u32)
    }

    /// Returns the return code.
    #[inline]
    pub fn rcode(&self) -> u8 {
        let rflags = RRIterator::u8_load(&self.dns_sector.packet, DNS_FLAGS_OFFSET + 1);
        rflags & 0x0f
    }

    /// Returns the opcode.
    #[inline]
    pub fn opcode(&self) -> u8 {
        let rflags = RRIterator::u8_load(&self.dns_sector.packet, DNS_FLAGS_OFFSET);
        (rflags & 0x78) >> 3
    }
}
