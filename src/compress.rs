use byteorder::{BigEndian, ByteOrder};
use constants::*;
use dns_sector::*;
use errors::*;
use rr_iterator::*;


/// Output of the `copy_uncompressed_name()` function.
#[derive(Copy, Clone, Debug)]
pub struct UncompressedNameResult {
    pub name_len: usize,
    pub final_offset: usize,
}

pub struct Compress;

impl Compress {
    /// Checks that an encoded DNS name is valid. This includes following indirections for
    /// compressed names, checks for label lengths, checks for truncated names and checks for
    /// cycles.
    /// Returns the location right after the name.
    pub fn check_compressed_name(packet: &[u8], mut offset: usize) -> Result<usize> {
        let packet_len = packet.len();
        let mut name_len = 0;
        let (mut barrier_offset, mut lowest_offset, mut final_offset) = (packet_len, offset, None);
        let mut refs_allowed = DNS_MAX_HOSTNAME_INDIRECTIONS;
        if offset >= packet_len {
            bail!(ErrorKind::InternalError("Offset outside packet boundaries"));
        }
        if 1 > packet_len - offset {
            bail!(ErrorKind::InvalidName("Empty name"));
        }
        loop {
            if offset >= barrier_offset {
                if offset >= packet_len {
                    bail!(ErrorKind::InvalidName("Truncated name"));
                }
                bail!(ErrorKind::InvalidName("Cycle"));
            }
            let label_len = match packet[offset] {
                len if len & 0xc0 == 0xc0 => {
                    if refs_allowed <= 0 {
                        bail!(ErrorKind::InvalidName("Too many indirections"));
                    }
                    refs_allowed -= 1;
                    if 2 > packet_len - offset {
                        bail!(ErrorKind::InvalidName("Invalid internal offset"));
                    }
                    let ref_offset = ((((len & 0x3f) as u16) << 8) | (packet[offset + 1]) as u16) as
                                     usize;
                    if ref_offset >= lowest_offset {
                        bail!(ErrorKind::InvalidName("Forward/self reference"));
                    }
                    final_offset = final_offset.or(Some(offset + 2));
                    offset = ref_offset;
                    barrier_offset = lowest_offset;
                    lowest_offset = ref_offset;
                    continue;
                }
                len if len > 0x3f => bail!(ErrorKind::InvalidName("Label length too long")),
                len => len as usize,
            };
            if label_len >= packet_len - offset {
                bail!(ErrorKind::InvalidName("Out-of-bounds name"));
            }
            name_len += label_len + 1;
            if name_len > DNS_MAX_HOSTNAME_LEN {
                bail!(ErrorKind::InvalidName("Name too long"));
            }
            offset += label_len + 1;
            if label_len == 0 {
                break;
            }
        }
        let final_offset = final_offset.unwrap_or(offset);
        Ok(final_offset)
    }

    /// Uncompresses a name starting at `offset`, and puts the result into `name`.
    /// This function assumes that the input is trusted and doesn't perform any checks.
    /// Returns the length of the name as well as the location right after the (possibly compressed) name.
    pub fn copy_uncompressed_name(name: &mut Vec<u8>,
                                  packet: &[u8],
                                  mut offset: usize)
                                  -> UncompressedNameResult {
        let mut name_len = 0;
        let mut final_offset = None;
        loop {
            let label_len = match packet[offset] {
                len if len & 0xc0 == 0xc0 => {
                    final_offset = final_offset.or(Some(offset + 2));
                    let new_offset = (BigEndian::read_u16(&packet[offset..]) & 0x3fff) as usize;
                    assert!(new_offset < offset);
                    offset = new_offset;
                    continue;
                }
                len => len,
            } as usize;
            let prefixed_label_len = 1 + label_len;
            name.extend(&packet[offset..offset + prefixed_label_len]);
            name_len += prefixed_label_len;
            offset += prefixed_label_len;
            if label_len == 0 {
                break;
            }
        }
        let final_offset = final_offset.unwrap_or(offset);
        UncompressedNameResult {
            name_len,
            final_offset,
        }
    }

    /// Uncompresses untrusted record's data and puts the result into `name`.
    fn uncompress_rdata(mut uncompressed: &mut Vec<u8>,
                        raw: RRRaw,
                        rr_type: Option<u16>,
                        rr_rdlen: Option<usize>) {
        let packet = &raw.packet;
        let offset_rdata = raw.name_end;
        let rdata = &packet[offset_rdata..];
        match rr_type {
            None => {
                debug_assert!(rr_rdlen.is_none());
                uncompressed.extend_from_slice(&rdata[..DNS_RR_QUESTION_HEADER_SIZE]);
            }
            Some(x) if x == Type::NS.into() || x == Type::CNAME.into() || x == Type::PTR.into() => {
                let offset = uncompressed.len();
                uncompressed.extend_from_slice(&rdata[..DNS_RR_HEADER_SIZE]);
                let new_rdlen = Compress::copy_uncompressed_name(&mut uncompressed,
                                                                 packet,
                                                                 offset_rdata + DNS_RR_HEADER_SIZE)
                    .name_len;
                BigEndian::write_u16(&mut uncompressed[offset + DNS_RR_RDLEN_OFFSET..],
                                     new_rdlen as u16);
            }
            Some(x) if x == Type::MX.into() => {
                let offset = uncompressed.len();
                uncompressed.extend_from_slice(&rdata[..DNS_RR_HEADER_SIZE + 2]);
                let new_rdlen = 2 +
                                Compress::copy_uncompressed_name(&mut uncompressed,
                                                                 packet,
                                                                 offset_rdata + DNS_RR_HEADER_SIZE +
                                                                 2)
                                    .name_len;
                BigEndian::write_u16(&mut uncompressed[offset + DNS_RR_RDLEN_OFFSET..],
                                     new_rdlen as u16);
            }
            Some(x) if x == Type::SOA.into() => {
                let offset = uncompressed.len();
                uncompressed.extend_from_slice(&rdata[..DNS_RR_HEADER_SIZE]);
                let u1 = Compress::copy_uncompressed_name(&mut uncompressed,
                                                          packet,
                                                          offset_rdata + DNS_RR_HEADER_SIZE);
                let u2 =
                    Compress::copy_uncompressed_name(&mut uncompressed, packet, u1.final_offset);
                uncompressed.extend_from_slice(&packet[u2.final_offset..u2.final_offset + 20]);
                let new_rdlen = u1.name_len + u2.name_len + 20;
                BigEndian::write_u16(&mut uncompressed[offset + DNS_RR_RDLEN_OFFSET..],
                                     new_rdlen as u16);
            }
            _ => {
                uncompressed.extend_from_slice(&rdata[..DNS_RR_HEADER_SIZE + rr_rdlen.unwrap()]);
            }
        }
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
                Self::uncompress_rdata(&mut uncompressed, item.raw(), None, None);
                it = item.next();
            }
        }
        {
            let mut it = parsed_packet.into_iter_answer();
            while let Some(item) = it {
                item.copy_raw_name(&mut uncompressed);
                Self::uncompress_rdata(&mut uncompressed,
                                       item.raw(),
                                       Some(item.rr_type()),
                                       Some(item.rr_rdlen()));
                it = item.next();
            }
        }
        {
            let mut it = parsed_packet.into_iter_nameservers();
            while let Some(item) = it {
                item.copy_raw_name(&mut uncompressed);
                Self::uncompress_rdata(&mut uncompressed,
                                       item.raw(),
                                       Some(item.rr_type()),
                                       Some(item.rr_rdlen()));
                it = item.next();
            }
        }
        {
            let mut it = parsed_packet.into_iter_additional_including_opt();
            while let Some(item) = it {
                item.copy_raw_name(&mut uncompressed);
                Self::uncompress_rdata(&mut uncompressed,
                                       item.raw(),
                                       Some(item.rr_type()),
                                       Some(item.rr_rdlen()));
                it = item.next_including_opt();
            }
        }
        Ok(uncompressed)
    }
}
