use crate::constants::*;
use crate::dns_sector::*;
use crate::parsed_packet::*;
use crate::rr_iterator::*;

#[derive(Debug)]
pub struct QuestionIterator<'t> {
    rr_iterator: RRIterator<'t>,
}

impl TypedIterable for QuestionIterator<'_> {}

impl DNSIterable for QuestionIterator<'_> {
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
            packet: self.rr_iterator.parsed_packet.packet(),
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
        self.rr_iterator.parsed_packet
    }

    #[inline]
    fn parsed_packet_mut(&mut self) -> &mut ParsedPacket {
        self.rr_iterator.parsed_packet
    }

    fn next(mut self) -> Option<Self> {
        {
            let rr_iterator = &mut self.rr_iterator;
            debug_assert_eq!(rr_iterator.section, Section::Question);
            if rr_iterator.offset.is_none() {
                let count = DNSSector::qdcount(rr_iterator.parsed_packet.packet());
                if count == 0 {
                    return None;
                }
                debug_assert_eq!(count, 1);
                rr_iterator.rrs_left = count;
                rr_iterator.offset_next = rr_iterator.parsed_packet.offset_question.unwrap();
            }
            if rr_iterator.rrs_left == 0 {
                return None;
            }
            rr_iterator.rrs_left -= 1;
            rr_iterator.offset = Some(rr_iterator.offset_next);
            rr_iterator.name_end = RRIterator::skip_name(
                rr_iterator.parsed_packet.packet(),
                rr_iterator.offset.unwrap(),
            );
            let offset_next = rr_iterator.name_end + DNS_RR_QUESTION_HEADER_SIZE;
            rr_iterator.offset_next = offset_next;
        }
        Some(self)
    }
}

impl<'t> QuestionIterator<'t> {
    pub fn new(rr_iterator: RRIterator<'t>) -> Self {
        QuestionIterator { rr_iterator }
    }
}
