use constants::*;
use rr_iterator::*;

#[derive(Debug)]
pub struct EdnsIterator<'t> {
    rr_iterator: RRIterator<'t>,
}

impl<'t> DNSIterable for EdnsIterator<'t> {
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
            let parsed_packet = &mut rr_iterator.parsed_packet;
            debug_assert_eq!(rr_iterator.section, Section::Edns);
            if rr_iterator.offset.is_none() {
                let count = parsed_packet.edns_count;
                let offset = parsed_packet.offset_edns;
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
            rr_iterator.name_end = rr_iterator.offset.unwrap();
            let offset_next = RRIterator::edns_skip_rr(&parsed_packet.dns_sector.packet,
                                                       rr_iterator.name_end);
            rr_iterator.offset_next = offset_next;
        }
        Some(self)
    }
}

impl<'t> EdnsIterator<'t> {
    pub fn new(rr_iterator: RRIterator<'t>) -> Self {
        EdnsIterator { rr_iterator }
    }
}
