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
}
