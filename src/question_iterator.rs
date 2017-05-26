use constants::*;
use dns_sector::*;
use rr_iterator::*;

#[derive(Debug)]
pub struct QuestionIterator<'t> {
    rr_iterator: RRIterator<'t>,
}

impl<'t> TypedIterable for QuestionIterator<'t> {}

impl<'t> DNSIterable for QuestionIterator<'t> {
    #[inline]
    fn offset(&self) -> Option<usize> {
        self.rr_iterator.offset
    }

    #[inline]
    fn raw(&self) -> RRRaw {
        RRRaw {
            packet: &self.rr_iterator.parsed_packet.dns_sector.packet,
            offset: self.rr_iterator.offset.unwrap(),
            name_end: self.rr_iterator.name_end,
        }
    }

    #[inline]
    fn raw_mut(&mut self) -> RRRawMut {
        RRRawMut {
            packet: &mut self.rr_iterator.parsed_packet.dns_sector.packet,
            offset: self.rr_iterator.offset.unwrap(),
            name_end: self.rr_iterator.name_end,
        }
    }

    fn next(mut self) -> Option<Self> {
        {
            let rr_iterator = &mut self.rr_iterator;
            debug_assert_eq!(rr_iterator.section, Section::Question);
            if rr_iterator.offset.is_none() {
                let count = DNSSector::qdcount(&rr_iterator.parsed_packet.dns_sector.packet);
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
            rr_iterator.name_end =
                RRIterator::skip_name(&rr_iterator.parsed_packet.dns_sector.packet,
                                      rr_iterator.offset.unwrap());
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
