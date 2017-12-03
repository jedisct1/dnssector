use constants::*;
use parsed_packet::*;
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
    fn raw(&self) -> RRRaw {
        RRRaw {
            packet: &self.rr_iterator.parsed_packet.packet(),
            offset: self.rr_iterator.offset.unwrap(),
            name_end: self.rr_iterator.name_end,
        }
    }

    #[inline]
    fn raw_mut(&mut self) -> RRRawMut {
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
            let offset_next =
                RRIterator::edns_skip_rr(&parsed_packet.packet(), rr_iterator.name_end);
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
