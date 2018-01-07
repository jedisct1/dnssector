use byteorder::{BigEndian, ByteOrder};
use compress::*;
use constants::*;
use dns_sector::*;
use edns_iterator::*;
use errors::*;
use failure;
use question_iterator::*;
use renamer::*;
use response_iterator::*;
use rr_iterator::*;
use std::ptr;
use synth::gen;

/// A `ParsedPacket` structure contains information about a successfully parsed
/// DNS packet, that allows quick access to (extended) flags and to individual sections.
#[derive(Debug)]
pub struct ParsedPacket {
    pub packet: Option<Vec<u8>>,
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
    pub max_payload: usize,
    pub cached: Option<(Vec<u8>, u16, u16)>,
}

impl ParsedPacket {
    /// Converts a `ParsedPacket` back into a raw packet.
    #[inline]
    pub fn into_packet(self) -> Vec<u8> {
        self.packet.unwrap()
    }

    /// Returns a reference to the packet
    #[inline]
    pub fn packet(&self) -> &[u8] {
        self.packet.as_ref().unwrap()
    }

    #[inline]
    pub fn packet_mut(&mut self) -> &mut Vec<u8> {
        self.packet.as_mut().unwrap()
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

    /// Copy the packet header
    pub fn copy_header(&self, header: &mut Vec<u8>) {
        header.extend(&self.packet()[..DNS_HEADER_SIZE]);
    }

    /// Copy the EDNS section
    pub fn copy_raw_edns_section(&self, raw_edns: &mut Vec<u8>) -> usize {
        let offset_edns = match self.offset_edns {
            None => return 0,
            Some(offset_edns) => offset_edns,
        };
        debug_assert!(offset_edns >= 1 + DNS_RR_HEADER_SIZE);
        if offset_edns < 1 + DNS_RR_HEADER_SIZE {
            return 0;
        }
        let offset_edns_header = offset_edns - (1 + DNS_RR_HEADER_SIZE);
        debug_assert_eq!(self.packet()[offset_edns_header], 0);
        let edns_len = self.packet().len() - offset_edns_header;
        raw_edns.extend_from_slice(&self.packet()[offset_edns_header..]);
        edns_len
    }

    /// Returns the transaction ID.
    #[inline]
    pub fn tid(&self) -> u16 {
        BigEndian::read_u16(&self.packet()[DNS_TID_OFFSET..])
    }

    /// Changes the transaction ID.
    pub fn set_tid(&mut self, tid: u16) {
        BigEndian::write_u16(&mut self.packet_mut()[DNS_TID_OFFSET..], tid)
    }

    /// Returns the flags, including extended flags.
    /// The extended flags optionally obtained using edns are exposed as the highest 16 bits,
    /// instead of having distinct sets of flags.
    /// The opcode and rcode are intentionally masked in order to prevent misuse:
    /// these bits are never supposed to be accessed individually.
    pub fn flags(&self) -> u32 {
        let mut rflags = BigEndian::read_u16(&self.packet()[DNS_FLAGS_OFFSET..]);
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
        let mut v = BigEndian::read_u16(&self.packet()[DNS_FLAGS_OFFSET..]);
        v &= !0x7800;
        v &= !0x000f;
        v |= rflags;
        BigEndian::write_u16(&mut self.packet_mut()[DNS_FLAGS_OFFSET..], v);
    }

    /// Check if this is question with the DO bit, or a response with the AD bit
    pub fn dnssec(&self) -> bool {
        let flags = self.flags();
        if flags & DNS_FLAG_QR == 0 {
            (flags & DNS_FLAG_DO) != 0
        } else {
            (flags & DNS_FLAG_AD) != 0
        }
    }

    /// Returns the return code.
    #[inline]
    pub fn rcode(&self) -> u8 {
        let rflags = self.packet()[DNS_FLAGS_OFFSET + 1];
        rflags & 0x0f
    }

    /// Changes the return code.
    pub fn set_rcode(&mut self, rcode: u8) {
        let p = &mut self.packet_mut()[DNS_FLAGS_OFFSET + 1];
        *p &= !0x0f;
        *p |= rcode & 0x0f;
    }

    /// Returns the opcode.
    #[inline]
    pub fn opcode(&self) -> u8 {
        let rflags = self.packet()[DNS_FLAGS_OFFSET];
        (rflags & 0x78) >> 3
    }

    /// Changes the operation code.
    pub fn set_opcode(&mut self, opcode: u8) {
        let p = &mut self.packet_mut()[DNS_FLAGS_OFFSET];
        *p &= !0x78;
        *p |= (opcode << 3) & 0x78;
    }

    /// Maximum payload size when using UDP
    #[inline]
    pub fn max_payload(&self) -> usize {
        self.max_payload
    }

    /// Increments the number of records in a given section
    pub fn rrcount_inc(&mut self, section: Section) -> Result<u16, failure::Error> {
        let mut packet = &mut self.packet_mut();
        let mut rrcount = match section {
            Section::Question => {
                let rrcount = DNSSector::qdcount(&mut packet);
                if rrcount >= 1 {
                    bail!(DSError::InvalidPacket(
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
            bail!(DSError::InvalidPacket(
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
    pub fn rrcount_dec(&mut self, section: Section) -> Result<u16, failure::Error> {
        let mut packet = &mut self.packet_mut();
        let mut rrcount = match section {
            Section::Question => DNSSector::qdcount(&mut packet),
            Section::Answer => DNSSector::ancount(&mut packet),
            Section::NameServers => DNSSector::nscount(&mut packet),
            Section::Additional => DNSSector::arcount(&mut packet),
            _ => panic!("Trying to decrement a the number of records in a pseudosection"),
        };
        if rrcount <= 0 {
            panic!(
                "Trying to decrement a number of records that was already 0 in section {:?}",
                section
            );
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

    fn insertion_offset(&self, section: Section) -> Result<usize, failure::Error> {
        let offset = match section {
            Section::Question => self.offset_answers
                .or(self.offset_nameservers)
                .or(self.offset_additional)
                .unwrap_or(self.packet().len()),
            Section::Answer => self.offset_nameservers
                .or(self.offset_additional)
                .unwrap_or(self.packet().len()),
            Section::NameServers => self.offset_additional.unwrap_or(self.packet().len()),
            Section::Additional => self.packet().len(),
            _ => panic!("insertion_offset() is not suitable to adding EDNS pseudorecords"),
        };
        Ok(offset)
    }

    pub fn insert_rr(&mut self, section: Section, rr: gen::RR) -> Result<(), failure::Error> {
        if self.maybe_compressed {
            let uncompressed = Compress::uncompress(&self.packet())?;
            self.packet = Some(uncompressed);
            self.recompute()?;
            debug_assert_eq!(self.maybe_compressed, false);
        }
        let rr_len = rr.packet.len();
        if DNS_MAX_UNCOMPRESSED_SIZE - self.packet().len() < rr_len {
            bail!(DSError::PacketTooLarge)
        }
        let insertion_offset = self.insertion_offset(section)?;
        let new_len = self.packet().len() + rr_len;
        self.packet_mut().reserve(rr_len);
        if insertion_offset == new_len {
            self.packet_mut().extend_from_slice(&rr.packet);
        } else {
            unsafe {
                self.packet_mut().set_len(new_len);
                let packet_ptr = self.packet_mut().as_mut_ptr();
                ptr::copy(
                    packet_ptr.offset(insertion_offset as isize),
                    packet_ptr.offset((insertion_offset + rr_len) as isize),
                    self.packet().len() - insertion_offset,
                );
            }
            &self.packet_mut()[insertion_offset..insertion_offset + rr_len]
                .copy_from_slice(&rr.packet);
        }
        self.rrcount_inc(section)?;
        match section {
            Section::Question => {
                self.offset_question = self.offset_question.or(Some(insertion_offset));

                self.offset_answers = self.offset_answers.map(|x| x + rr_len);
                self.offset_nameservers = self.offset_nameservers.map(|x| x + rr_len);
                self.offset_additional = self.offset_additional.map(|x| x + rr_len);
                self.offset_edns = self.offset_edns.map(|x| x + rr_len);
            }
            Section::Answer => {
                self.offset_answers = self.offset_answers.or(Some(insertion_offset));

                self.offset_nameservers = self.offset_nameservers.map(|x| x + rr_len);
                self.offset_additional = self.offset_additional.map(|x| x + rr_len);
                self.offset_edns = self.offset_edns.map(|x| x + rr_len);
            }
            Section::NameServers => {
                self.offset_nameservers = self.offset_nameservers.or(Some(insertion_offset));

                self.offset_additional = self.offset_additional.map(|x| x + rr_len);
                self.offset_edns = self.offset_edns.map(|x| x + rr_len);
            }
            Section::Additional => {
                self.offset_additional = self.offset_additional.or(Some(insertion_offset));
            }
            _ => panic!("insertion_offset() is not suitable to adding EDNS pseudorecords"),
        }
        Ok(())
    }

    pub fn insert_rr_from_string(
        &mut self,
        section: Section,
        rr_str: &str,
    ) -> Result<(), failure::Error> {
        let rr = gen::RR::from_string(rr_str)?;
        self.insert_rr(section, rr)
    }

    /// Recomputes all section offsets after an in-place decompression of the packet.
    /// It is currently re-parsing everything by calling `parse()`, but this can be
    /// optimized later to skip over RDATA, and by assuming that the input
    /// is always well-formed.
    pub fn recompute(&mut self) -> Result<(), failure::Error> {
        if !self.maybe_compressed {
            return Ok(());
        }
        let dns_sector = DNSSector::new(self.packet.take().expect("self.packet is None"))?;
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
        self.packet = Some(parsed_packet.into_packet());
        self.cached = None;
        Ok(())
    }

    /// Returns the question as a string, without case conversion, as well as the query type and class
    pub fn question(&mut self) -> Option<((&[u8], u16, u16))> {
        match self.cached {
            Some(ref cached) => return Some((&cached.0, cached.1, cached.2)),
            None => {}
        };
        let offset = match self.offset_question {
            None => return None,
            Some(offset) => offset,
        };
        let name_str = Compress::raw_name_to_str(&self.packet(), offset);
        let offset = offset + Compress::raw_name_len(&self.packet()[offset..]);
        let (rr_type, rr_class) = {
            let rdata = &self.packet()[offset..];
            let rr_type = BigEndian::read_u16(&rdata[DNS_RR_TYPE_OFFSET..]);
            let rr_class = BigEndian::read_u16(&rdata[DNS_RR_CLASS_OFFSET..]);
            (rr_type, rr_class)
        };
        self.cached = Some((name_str, rr_type, rr_class));
        let cached = self.cached.as_ref().unwrap();
        Some((&cached.0, cached.1, cached.2))
    }

    /// Return the query type and class
    pub fn qtype_qclass(&self) -> Option<(u16, u16)> {
        match self.cached {
            Some(ref cached) => return Some((cached.1, cached.2)),
            None => {}
        };
        let offset = match self.offset_question {
            None => return None,
            Some(offset) => offset,
        };
        let offset = offset + Compress::raw_name_len(&self.packet()[offset..]);
        let (rr_type, rr_class) = {
            let rdata = &self.packet()[offset..];
            let rr_type = BigEndian::read_u16(&rdata[DNS_RR_TYPE_OFFSET..]);
            let rr_class = BigEndian::read_u16(&rdata[DNS_RR_CLASS_OFFSET..]);
            (rr_type, rr_class)
        };
        Some((rr_type, rr_class))
    }

    /// Replaces `source_name` with `target_name` in all names, in all records.
    /// If `match_suffix` is `true`, do suffix matching instead of exact matching
    /// This allows renaming `*.example.com` into `*.example.net`.
    pub fn rename_with_raw_names(
        &mut self,
        target_name: &[u8],
        source_name: &[u8],
        match_suffix: bool,
    ) -> Result<(), failure::Error> {
        let packet = Renamer::rename_with_raw_names(self, target_name, source_name, match_suffix)?;
        self.packet = Some(packet);
        let dns_sector = DNSSector::new(self.packet.take().unwrap())?;
        let parsed_packet = dns_sector.parse()?; // XXX - This can be recomputed on the fly by Renamer::rename_with_raw_names()
        self.offset_question = parsed_packet.offset_question;
        self.offset_answers = parsed_packet.offset_answers;
        self.offset_nameservers = parsed_packet.offset_nameservers;
        self.offset_additional = parsed_packet.offset_additional;
        self.offset_edns = parsed_packet.offset_edns;
        assert_eq!(self.edns_count, parsed_packet.edns_count);
        assert_eq!(self.ext_rcode, parsed_packet.ext_rcode);
        assert_eq!(self.edns_version, parsed_packet.edns_version);
        assert_eq!(self.ext_flags, parsed_packet.ext_flags);
        self.maybe_compressed = true;
        Ok(())
    }
}
