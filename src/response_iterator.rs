use crate::constants::*;
use crate::dns_sector::*;
use crate::parsed_packet::*;
use crate::rr_iterator::*;

#[derive(Debug)]
pub struct ResponseIterator<'t> {
    rr_iterator: RRIterator<'t>,
}

pub type AnswerIterator<'t> = ResponseIterator<'t>;
pub type NameServersIterator<'t> = ResponseIterator<'t>;
pub type AdditionalIterator<'t> = ResponseIterator<'t>;

impl<'t> TypedIterable for ResponseIterator<'t> {}
impl<'t> RdataIterable for ResponseIterator<'t> {}

impl<'t> DNSIterable for ResponseIterator<'t> {
    #[inline]
    fn offset(&self) -> Option<usize> {
        self.rr_iterator.offset
    }

    #[inline]
    fn offset_next(&self) -> usize {
        self.rr_iterator.offset_next
    }

    fn set_offset(&mut self, offset: usize) {
        debug_assert!(offset <= self.packet().len());
        self.rr_iterator.offset = Some(offset);
    }

    fn set_offset_next(&mut self, offset: usize) {
        debug_assert!(offset <= self.packet().len());
        self.rr_iterator.offset_next = offset;
    }

    fn invalidate(&mut self) {
        self.rr_iterator.offset = None;
    }

    fn recompute_rr(&mut self) {
        self.rr_iterator.recompute();
    }

    fn recompute_sections(&mut self) {
        self.rr_iterator.parsed_packet.recompute().unwrap();
    }

    #[inline]
    fn raw(&self) -> RRRaw<'_> {
        RRRaw {
            packet: &self.rr_iterator.parsed_packet.packet(),
            offset: self.rr_iterator.offset.unwrap(),
            name_end: self.rr_iterator.name_end,
        }
    }

    #[inline]
    fn raw_mut(&mut self) -> RRRawMut<'_> {
        RRRawMut {
            packet: self.rr_iterator.parsed_packet.packet_mut(),
            offset: self.rr_iterator.offset.unwrap(),
            name_end: self.rr_iterator.name_end,
        }
    }

    #[inline]
    fn parsed_packet(&self) -> &ParsedPacket {
        &self.rr_iterator.parsed_packet
    }

    #[inline]
    fn parsed_packet_mut(&mut self) -> &mut ParsedPacket {
        &mut self.rr_iterator.parsed_packet
    }

    fn next(self) -> Option<Self> {
        self.next_including_opt()
            .and_then(move |this| this.maybe_skip_opt_section())
    }
}

impl<'t> ResponseIterator<'t> {
    pub fn new(rr_iterator: RRIterator<'t>) -> Self {
        ResponseIterator { rr_iterator }
    }

    pub fn next_including_opt(mut self) -> Option<Self> {
        {
            let rr_iterator = &mut self.rr_iterator;
            let parsed_packet = &mut rr_iterator.parsed_packet;
            if rr_iterator.offset.is_none() {
                let (count, offset) = match rr_iterator.section {
                    Section::Answer => (
                        DNSSector::ancount(&parsed_packet.packet()),
                        parsed_packet.offset_answers,
                    ),
                    Section::NameServers => (
                        DNSSector::nscount(&parsed_packet.packet()),
                        parsed_packet.offset_nameservers,
                    ),
                    Section::Additional => (
                        DNSSector::arcount(&parsed_packet.packet()),
                        parsed_packet.offset_additional,
                    ),
                    _ => unreachable!("Unexpected section"),
                };
                if count == 0 {
                    return None;
                }
                rr_iterator.rrs_left = count;
                rr_iterator.offset_next = offset.unwrap();
            }
            if rr_iterator.rrs_left == 0 {
                return None;
            }
            rr_iterator.rrs_left -= 1;
            rr_iterator.offset = Some(rr_iterator.offset_next);
            rr_iterator.name_end =
                RRIterator::skip_name(&parsed_packet.packet(), rr_iterator.offset.unwrap());
            let offset_next = RRIterator::skip_rdata(&parsed_packet.packet(), rr_iterator.name_end);
            rr_iterator.offset_next = offset_next;
        }
        Some(self)
    }

    fn maybe_skip_opt_section(mut self) -> Option<Self> {
        if self.rr_type() == Type::OPT.into() {
            let rr_iterator = &mut self.rr_iterator;
            debug_assert_eq!(rr_iterator.section, Section::Additional);
            let parsed_packet = &mut rr_iterator.parsed_packet;
            if rr_iterator.rrs_left == 0 {
                return None;
            }
            rr_iterator.offset = Some(rr_iterator.offset_next);
            rr_iterator.name_end =
                RRIterator::skip_name(&parsed_packet.packet(), rr_iterator.offset.unwrap());
            let offset_next = RRIterator::skip_rdata(&parsed_packet.packet(), rr_iterator.name_end);
            rr_iterator.offset_next = offset_next;
        }
        debug_assert!(self.rr_type() != Type::OPT.into());
        Some(self)
    }
}
