use byteorder::{BigEndian, ByteOrder};
use compress::*;
use constants::*;
use dns_sector::*;
use edns_iterator::*;
use errors::*;
use response_iterator::*;
use question_iterator::*;
use rr_iterator::*;
use std::ptr;
use synth::gen;

/// A `ParsedPacket` structure contains information about a successfully parsed
/// DNS packet, that allows quick access to (extended) flags and to individual sections.
#[derive(Debug)]
pub struct ParsedPacket {
    pub packet: Vec<u8>,
    pub offset_question: Option<usize>,
    pub offset_answers: Option<usize>,
    pub offset_nameservers: Option<usize>,
    pub offset_additional: Option<usize>,
    pub offset_edns: Option<usize>,
    pub edns_count: u16,
    pub ext_rcode: Option<u8>,
    pub edns_version: Option<u8>,
    pub ext_flags: Option<u16>,
    pub maybe_compressed: bool,
}

impl ParsedPacket {
    /// Converts a `ParsedPacket` back into a raw packet.
    pub fn into_packet(self) -> Vec<u8> {
        self.packet
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
        BigEndian::read_u16(&self.packet[DNS_TID_OFFSET..])
    }

    /// Changes the transaction ID.
    pub fn set_tid(&mut self, tid: u16) {
        BigEndian::write_u16(&mut self.packet[DNS_TID_OFFSET..], tid)
    }

    /// Returns the flags, including extended flags.
    /// The extended flags optionally obtained using edns are exposed as the highest 16 bits,
    /// instead of having distinct sets of flags.
    /// The opcode and rcode are intentionally masked in order to prevent misuse:
    /// these bits are never supposed to be accessed individually.
    pub fn flags(&self) -> u32 {
        let mut rflags = BigEndian::read_u16(&self.packet[DNS_FLAGS_OFFSET..]);
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
        let mut v = BigEndian::read_u16(&self.packet[DNS_FLAGS_OFFSET..]);
        v &= !0x7800;
        v &= !0x000f;
        v |= rflags;
        BigEndian::write_u16(&mut self.packet[DNS_FLAGS_OFFSET..], v);
    }

    /// Returns the return code.
    #[inline]
    pub fn rcode(&self) -> u8 {
        let rflags = self.packet[DNS_FLAGS_OFFSET + 1];
        rflags & 0x0f
    }

    /// Changes the return code.
    pub fn set_rcode(&mut self, rcode: u8) {
        let p = &mut self.packet[DNS_FLAGS_OFFSET + 1];
        *p &= !0x0f;
        *p |= rcode & 0x0f;
    }

    /// Returns the opcode.
    #[inline]
    pub fn opcode(&self) -> u8 {
        let rflags = self.packet[DNS_FLAGS_OFFSET];
        (rflags & 0x78) >> 3
    }

    /// Changes the operation code.
    pub fn set_opcode(&mut self, opcode: u8) {
        let p = &mut self.packet[DNS_FLAGS_OFFSET];
        *p &= !0x78;
        *p |= (opcode << 3) & 0x78;
    }

    /// Increments the number of records in a given section
    pub fn rrcount_inc(&mut self, section: Section) -> Result<u16> {
        let mut packet = &mut self.packet;
        let mut rrcount = match section {
            Section::Question => {
                let rrcount = DNSSector::qdcount(&mut packet);
                if rrcount >= 1 {
                    bail!(ErrorKind::InvalidPacket(
                        "A DNS packet can only contain up to one question"
                    ));
                }
                rrcount
            }
            Section::Answer => DNSSector::ancount(&mut packet),
            Section::NameServers => DNSSector::nscount(&mut packet),
            Section::Additional => DNSSector::arcount(&mut packet),
            _ => panic!("Trying to increment a the number of records in a pseudosection"),
        };
        if rrcount >= 0xffff {
            bail!(ErrorKind::InvalidPacket(
                "Too many records in the same question"
            ));
        }
        rrcount += 1;
        match section {
            Section::Question => DNSSector::set_qdcount(&mut packet, rrcount),
            Section::Answer => DNSSector::set_ancount(&mut packet, rrcount),
            Section::NameServers => DNSSector::set_nscount(&mut packet, rrcount),
            Section::Additional => DNSSector::set_arcount(&mut packet, rrcount),
            _ => panic!("EDNS section doesn't have a records count"),
        }
        Ok(rrcount)
    }

    /// Decrements the number of records in a given section
    pub fn rrcount_dec(&mut self, section: Section) -> Result<u16> {
        let mut packet = &mut self.packet;
        let mut rrcount = match section {
            Section::Question => DNSSector::qdcount(&mut packet),
            Section::Answer => DNSSector::ancount(&mut packet),
            Section::NameServers => DNSSector::nscount(&mut packet),
            Section::Additional => DNSSector::arcount(&mut packet),
            _ => panic!("Trying to decrement a the number of records in a pseudosection"),
        };
        if rrcount <= 0 {
            panic!("Trying to decrement a number of records that was already 0");
        }
        rrcount -= 1;
        match section {
            Section::Question => DNSSector::set_qdcount(&mut packet, rrcount),
            Section::Answer => DNSSector::set_ancount(&mut packet, rrcount),
            Section::NameServers => DNSSector::set_nscount(&mut packet, rrcount),
            Section::Additional => DNSSector::set_arcount(&mut packet, rrcount),
            _ => panic!("EDNS section doesn't have a records count"),
        }
        Ok(rrcount)
    }

    fn insertion_offset(&self, section: Section) -> Result<usize> {
        let offset = match section {
            Section::Question => self.offset_answers
                .or(self.offset_nameservers)
                .or(self.offset_additional)
                .unwrap_or(self.packet.len()),
            Section::Answer => self.offset_nameservers
                .or(self.offset_additional)
                .unwrap_or(self.packet.len()),
            Section::NameServers => self.offset_additional.unwrap_or(self.packet.len()),
            Section::Additional => self.packet.len(),
            _ => panic!("insertion_offset() is not suitable to adding EDNS pseudorecords"),
        };
        Ok(offset)
    }

    pub fn insert(&mut self, section: Section, rr: gen::RR) -> Result<()> {
        if self.maybe_compressed {
            let uncompressed = Compress::uncompress(&self.packet)?;
            self.packet = uncompressed;
            self.maybe_compressed = false;
        }
        let rr_len = rr.packet.len();
        if DNS_MAX_UNCOMPRESSED_SIZE - self.packet.len() < rr_len {
            bail!(ErrorKind::PacketTooLarge)
        }
        let insertion_offset = self.insertion_offset(section)?;
        self.packet.reserve(rr_len);
        if insertion_offset == rr_len {
            self.packet.extend_from_slice(&rr.packet);
        } else {
            unsafe {
                let packet_ptr = self.packet.as_mut_ptr();
                ptr::copy(
                    packet_ptr.offset(insertion_offset as isize),
                    packet_ptr.offset((insertion_offset + rr_len) as isize),
                    self.packet.len() - insertion_offset,
                );
            }
            &self.packet[insertion_offset..insertion_offset + rr_len].copy_from_slice(&rr.packet);
        }
        self.rrcount_inc(section)?;
        match section {
            Section::Question => {
                self.offset_answers = self.offset_answers.map(|x| x + rr_len);
                self.offset_nameservers = self.offset_nameservers.map(|x| x + rr_len);
                self.offset_additional = self.offset_additional.map(|x| x + rr_len);
                self.offset_edns = self.offset_edns.map(|x| x + rr_len);
            }
            Section::Answer => {
                self.offset_nameservers = self.offset_nameservers.map(|x| x + rr_len);
                self.offset_additional = self.offset_additional.map(|x| x + rr_len);
                self.offset_edns = self.offset_edns.map(|x| x + rr_len);
            }
            Section::NameServers => {
                self.offset_additional = self.offset_additional.map(|x| x + rr_len);
                self.offset_edns = self.offset_edns.map(|x| x + rr_len);
            }
            _ => {}
        }
        Ok(())
    }

    /// Recomputes all section offsets after an in-place decompression of the packet.
    /// It is currently re-parsing everything by calling `parse()`, but this can be
    /// optimized later to skip over RDATA, and by assuming that the input
    /// is always well-formed.
    pub fn recompute(&mut self) -> Result<()> {
        if !self.maybe_compressed {
            return Ok(());
        }
        let dns_sector = DNSSector::new(self.packet.clone())?; // XXX - TODO: This doesnt't require cloning.
        let parsed_packet = dns_sector.parse()?;
        self.offset_question = parsed_packet.offset_question;
        self.offset_answers = parsed_packet.offset_answers;
        self.offset_nameservers = parsed_packet.offset_nameservers;
        self.offset_additional = parsed_packet.offset_additional;
        self.offset_edns = parsed_packet.offset_edns;
        assert_eq!(self.edns_count, parsed_packet.edns_count);
        assert_eq!(self.ext_rcode, parsed_packet.ext_rcode);
        assert_eq!(self.edns_version, parsed_packet.edns_version);
        assert_eq!(self.ext_flags, parsed_packet.ext_flags);
        self.maybe_compressed = false;
        Ok(())
    }
}
