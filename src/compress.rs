use constants::*;
use dns_sector::*;
use errors::*;
use rr_iterator::*;

pub struct Compress;

impl Compress {
    fn uncompress_rdata(uncompressed: &mut Vec<u8>, rdata: &[u8]) {
        uncompressed.extend_from_slice(rdata);
    }

    pub fn uncompress(packet: &[u8]) -> Result<Vec<u8>> {
        let packet = packet.to_owned(); // XXX - TODO: use `ParsedPacket` directly after having removed its dependency on `dns_sector`
        if packet.len() < DNS_HEADER_SIZE {
            bail!(ErrorKind::PacketTooSmall);
        }
        let mut uncompressed = Vec::new();
        uncompressed.extend_from_slice(&packet[0..DNS_HEADER_SIZE]);
        let mut parsed_packet = DNSSector::new(packet)?.parse()?;
        {
            let mut it = parsed_packet.into_iter_question();
            while let Some(item) = it {
                item.copy_raw_name(&mut uncompressed);
                Self::uncompress_rdata(&mut uncompressed,
                                       &item.rdata_slice()[..DNS_RR_QUESTION_HEADER_SIZE]);
                it = item.next();
            }
        }
        {
            let mut it = parsed_packet.into_iter_answer();
            while let Some(item) = it {
                item.copy_raw_name(&mut uncompressed);
                Self::uncompress_rdata(&mut uncompressed,
                                       &item.rdata_slice()[..DNS_RR_HEADER_SIZE + item.rr_rdlen()]);
                it = item.next();
            }
        }
        {
            let mut it = parsed_packet.into_iter_nameservers();
            while let Some(item) = it {
                item.copy_raw_name(&mut uncompressed);
                Self::uncompress_rdata(&mut uncompressed,
                                       &item.rdata_slice()[..DNS_RR_HEADER_SIZE + item.rr_rdlen()]);
                it = item.next();
            }
        }
        {
            let mut it = parsed_packet.into_iter_additional_including_opt();
            while let Some(item) = it {
                item.copy_raw_name(&mut uncompressed);
                Self::uncompress_rdata(&mut uncompressed,
                                       &item.rdata_slice()[..DNS_RR_HEADER_SIZE + item.rr_rdlen()]);
                it = item.next_including_opt();
            }
        }
        Ok(uncompressed)
    }
}
