use byteorder::{BigEndian, ByteOrder};
use constants::*;
use dns_sector::*;
use errors::*;
use rr_iterator::*;
use std::ascii::AsciiExt;
use std::cmp;

/// Output of the `copy_uncompressed_name()` function.
#[derive(Copy, Clone, Debug)]
pub struct UncompressedNameResult {
    pub name_len: usize,
    pub final_offset: usize,
}

/// Output of the `copy_compressed_name()` function.
#[derive(Copy, Clone, Debug)]
pub struct CompressedNameResult {
    pub name_len: usize,
    pub final_offset: usize,
}

pub struct Compress;

impl Compress {
    /// Checks that an untrusted encoded DNS name is valid. This includes following indirections for
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
                    let ref_offset =
                        ((((len & 0x3f) as u16) << 8) | (packet[offset + 1]) as u16) as usize;
                    if ref_offset == offset || ref_offset >= lowest_offset {
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
    pub fn copy_uncompressed_name(
        name: &mut Vec<u8>,
        packet: &[u8],
        mut offset: usize,
    ) -> UncompressedNameResult {
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

    /// Uncompresses trusted record's data and puts the result into `name`.
    fn uncompress_rdata(
        mut uncompressed: &mut Vec<u8>,
        raw: RRRaw,
        rr_type: Option<u16>,
        rr_rdlen: Option<usize>,
    ) {
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
                let new_rdlen = Compress::copy_uncompressed_name(
                    &mut uncompressed,
                    packet,
                    offset_rdata + DNS_RR_HEADER_SIZE,
                ).name_len;
                BigEndian::write_u16(
                    &mut uncompressed[offset + DNS_RR_RDLEN_OFFSET..],
                    new_rdlen as u16,
                );
            }
            Some(x) if x == Type::MX.into() => {
                let offset = uncompressed.len();
                uncompressed.extend_from_slice(&rdata[..DNS_RR_HEADER_SIZE + 2]);
                let new_rdlen = 2 +
                    Compress::copy_uncompressed_name(
                        &mut uncompressed,
                        packet,
                        offset_rdata + DNS_RR_HEADER_SIZE + 2,
                    ).name_len;
                BigEndian::write_u16(
                    &mut uncompressed[offset + DNS_RR_RDLEN_OFFSET..],
                    new_rdlen as u16,
                );
            }
            Some(x) if x == Type::SOA.into() => {
                let offset = uncompressed.len();
                uncompressed.extend_from_slice(&rdata[..DNS_RR_HEADER_SIZE]);
                let u1 = Compress::copy_uncompressed_name(
                    &mut uncompressed,
                    packet,
                    offset_rdata + DNS_RR_HEADER_SIZE,
                );
                let u2 =
                    Compress::copy_uncompressed_name(&mut uncompressed, packet, u1.final_offset);
                uncompressed.extend_from_slice(&packet[u2.final_offset..u2.final_offset + 20]);
                let new_rdlen = u1.name_len + u2.name_len + 20;
                BigEndian::write_u16(
                    &mut uncompressed[offset + DNS_RR_RDLEN_OFFSET..],
                    new_rdlen as u16,
                );
            }
            _ => {
                uncompressed.extend_from_slice(&rdata[..DNS_RR_HEADER_SIZE + rr_rdlen.unwrap()]);
            }
        }
    }

    /// Compresses trusted record's data and puts the result into `name`.
    fn compress_rdata(
        mut dict: &mut SuffixDict,
        mut compressed: &mut Vec<u8>,
        raw: RRRaw,
        rr_type: Option<u16>,
        rr_rdlen: Option<usize>,
    ) {
        let packet = &raw.packet;
        let offset_rdata = raw.name_end;
        let rdata = &packet[offset_rdata..];
        match rr_type {
            None => {
                debug_assert!(rr_rdlen.is_none());
                compressed.extend_from_slice(&rdata[..DNS_RR_QUESTION_HEADER_SIZE]);
            }
            Some(x) if x == Type::NS.into() || x == Type::CNAME.into() || x == Type::PTR.into() => {
                let offset = compressed.len();
                compressed.extend_from_slice(&rdata[..DNS_RR_HEADER_SIZE]);
                let new_rdlen = Compress::copy_compressed_name(
                    &mut dict,
                    &mut compressed,
                    packet,
                    offset_rdata + DNS_RR_HEADER_SIZE,
                ).name_len;
                BigEndian::write_u16(
                    &mut compressed[offset + DNS_RR_RDLEN_OFFSET..],
                    new_rdlen as u16,
                );
            }
            Some(x) if x == Type::MX.into() => {
                let offset = compressed.len();
                compressed.extend_from_slice(&rdata[..DNS_RR_HEADER_SIZE + 2]);
                let new_rdlen = 2 +
                    Compress::copy_compressed_name(
                        &mut dict,
                        &mut compressed,
                        packet,
                        offset_rdata + DNS_RR_HEADER_SIZE + 2,
                    ).name_len;
                BigEndian::write_u16(
                    &mut compressed[offset + DNS_RR_RDLEN_OFFSET..],
                    new_rdlen as u16,
                );
            }
            Some(x) if x == Type::SOA.into() => {
                let offset = compressed.len();
                compressed.extend_from_slice(&rdata[..DNS_RR_HEADER_SIZE]);
                let u1 = Compress::copy_compressed_name(
                    &mut dict,
                    &mut compressed,
                    packet,
                    offset_rdata + DNS_RR_HEADER_SIZE,
                );
                let u2 = Compress::copy_compressed_name(
                    &mut dict,
                    &mut compressed,
                    packet,
                    u1.final_offset,
                );
                compressed.extend_from_slice(&packet[u2.final_offset..u2.final_offset + 20]);
                let new_rdlen = u1.name_len + u2.name_len + 20;
                BigEndian::write_u16(
                    &mut compressed[offset + DNS_RR_RDLEN_OFFSET..],
                    new_rdlen as u16,
                );
            }
            _ => {
                compressed.extend_from_slice(&rdata[..DNS_RR_HEADER_SIZE + rr_rdlen.unwrap()]);
            }
        }
    }

    pub fn uncompress_with_previous_offset(
        packet: &[u8],
        ref_offset: usize,
    ) -> Result<(Vec<u8>, usize)> {
        let packet = packet.to_owned(); // XXX - TODO: use `ParsedPacket` directly after having removed its dependency on `dns_sector`
        if packet.len() < DNS_HEADER_SIZE {
            bail!(ErrorKind::PacketTooSmall);
        }
        let mut new_offset = None;
        let mut uncompressed = Vec::new();
        uncompressed.extend_from_slice(&packet[..DNS_HEADER_SIZE]);
        let mut parsed_packet = DNSSector::new(packet)?.parse()?;
        {
            let mut it = parsed_packet.into_iter_question();
            while let Some(item) = it {
                if Some(ref_offset) == item.offset() {
                    new_offset = Some(uncompressed.len());
                }
                item.copy_raw_name(&mut uncompressed);
                Self::uncompress_rdata(&mut uncompressed, item.raw(), None, None);
                it = item.next();
            }
        }
        {
            let mut it = parsed_packet.into_iter_answer();
            while let Some(item) = it {
                if Some(ref_offset) == item.offset() {
                    new_offset = Some(uncompressed.len());
                }
                item.copy_raw_name(&mut uncompressed);
                Self::uncompress_rdata(
                    &mut uncompressed,
                    item.raw(),
                    Some(item.rr_type()),
                    Some(item.rr_rdlen()),
                );
                it = item.next();
            }
        }
        {
            let mut it = parsed_packet.into_iter_nameservers();
            while let Some(item) = it {
                if Some(ref_offset) == item.offset() {
                    new_offset = Some(uncompressed.len());
                }
                item.copy_raw_name(&mut uncompressed);
                Self::uncompress_rdata(
                    &mut uncompressed,
                    item.raw(),
                    Some(item.rr_type()),
                    Some(item.rr_rdlen()),
                );
                it = item.next();
            }
        }
        {
            let mut it = parsed_packet.into_iter_additional_including_opt();
            while let Some(item) = it {
                if Some(ref_offset) == item.offset() {
                    new_offset = Some(uncompressed.len());
                }
                item.copy_raw_name(&mut uncompressed);
                Self::uncompress_rdata(
                    &mut uncompressed,
                    item.raw(),
                    Some(item.rr_type()),
                    Some(item.rr_rdlen()),
                );
                it = item.next_including_opt();
            }
        }
        if ref_offset == parsed_packet.packet.len() {
            new_offset = Some(uncompressed.len());
        }
        Ok((
            uncompressed,
            new_offset.expect("Previous offset not found at a record boundary"),
        ))
    }

    pub fn uncompress(packet: &[u8]) -> Result<Vec<u8>> {
        Self::uncompress_with_previous_offset(packet, DNS_HEADER_SIZE).map(|x| x.0)
    }

    pub fn compress(packet: &[u8]) -> Result<Vec<u8>> {
        let packet = packet.to_owned(); // XXX - TODO: use `ParsedPacket` directly after having removed its dependency on `dns_sector`
        if packet.len() < DNS_HEADER_SIZE {
            bail!(ErrorKind::PacketTooSmall);
        }
        let mut compressed = Vec::new();
        compressed.extend_from_slice(&packet[..DNS_HEADER_SIZE]);
        let mut parsed_packet = DNSSector::new(packet)?.parse()?;
        let mut dict = SuffixDict::new();
        {
            let mut it = parsed_packet.into_iter_question();
            while let Some(item) = it {
                {
                    let mut raw = item.raw();
                    raw.offset = Self::copy_compressed_name(
                        &mut dict,
                        &mut compressed,
                        raw.packet,
                        raw.offset,
                    ).final_offset;
                    Self::compress_rdata(&mut dict, &mut compressed, raw, None, None);
                }
                it = item.next();
            }
        }
        {
            let mut it = parsed_packet.into_iter_answer();
            while let Some(item) = it {
                {
                    let mut raw = item.raw();
                    raw.offset = Self::copy_compressed_name(
                        &mut dict,
                        &mut compressed,
                        raw.packet,
                        raw.offset,
                    ).final_offset;
                    Self::compress_rdata(
                        &mut dict,
                        &mut compressed,
                        raw,
                        Some(item.rr_type()),
                        Some(item.rr_rdlen()),
                    );
                }
                it = item.next();
            }
        }
        {
            let mut it = parsed_packet.into_iter_nameservers();
            while let Some(item) = it {
                {
                    let mut raw = item.raw();
                    raw.offset = Self::copy_compressed_name(
                        &mut dict,
                        &mut compressed,
                        raw.packet,
                        raw.offset,
                    ).final_offset;
                    Self::compress_rdata(
                        &mut dict,
                        &mut compressed,
                        raw,
                        Some(item.rr_type()),
                        Some(item.rr_rdlen()),
                    );
                }
                it = item.next();
            }
        }
        {
            let mut it = parsed_packet.into_iter_additional_including_opt();
            while let Some(item) = it {
                {
                    let mut raw = item.raw();
                    raw.offset = Self::copy_compressed_name(
                        &mut dict,
                        &mut compressed,
                        raw.packet,
                        raw.offset,
                    ).final_offset;
                    Self::compress_rdata(
                        &mut dict,
                        &mut compressed,
                        raw,
                        Some(item.rr_type()),
                        Some(item.rr_rdlen()),
                    );
                }
                it = item.next();
            }
        }
        Ok(compressed)
    }

    /// Returns the total length of an uncompressed raw name, including the final `0` label length.
    pub fn raw_name_len(name: &[u8]) -> usize {
        let mut i = 0;
        while name[i] != 0 {
            i += name[i] as usize + 1
        }
        i + 1
    }

    /// Comvert a trusted raw name to a string
    pub fn raw_name_to_str(packet: &[u8], mut offset: usize) -> Vec<u8> {
        let mut indirections = 0;
        let mut res: Vec<u8> = Vec::with_capacity(64);
        loop {
            let label_len = match packet[offset] {
                0 => break,
                len if len & 0xc0 == 0xc0 => {
                    let new_offset = (BigEndian::read_u16(&packet[offset..]) & 0x3fff) as usize;
                    if new_offset == offset || indirections > DNS_MAX_HOSTNAME_INDIRECTIONS {
                        return res;
                    }
                    indirections += 1;
                    offset = new_offset;
                    continue;
                }
                len => len,
            } as usize;
            offset += 1;
            let label = &packet[offset..offset + label_len];
            offset += label_len;
            if !res.is_empty() {
                res.push(b'.');
            }
            res.extend(label);
        }
        res.make_ascii_lowercase();
        res
    }

    /// Compress a name starting at `offset` using the suffix dictionary `dict`
    /// This function assumes that the input is trusted and uncompressed, and doesn't perform any checks.
    /// Returns the length of the name as well as the location right after the uncompressed name.
    //  XXX - TODO: `compressed` could be a slice, since compression will never increase the required capacity.
    pub fn copy_compressed_name(
        dict: &mut SuffixDict,
        compressed: &mut Vec<u8>,
        packet: &[u8],
        mut offset: usize,
    ) -> CompressedNameResult {
        let uncompressed_name_len = Compress::raw_name_len(&packet[offset..]);
        let initial_compressed_len = compressed.len();
        let final_offset = offset + uncompressed_name_len;
        loop {
            if let Some(ref_offset) = dict.insert(&packet[offset..final_offset], offset) {
                assert!(offset < 65536 >> 2); // Checked in dict.insert()
                compressed.push((ref_offset >> 8) as u8 | 0xc0);
                compressed.push((ref_offset & 0xff) as u8);
                break;
            }
            let label_len = packet[offset] as usize;
            let offset_next = offset + 1 + label_len;
            compressed.extend_from_slice(&packet[offset..offset_next]);
            offset = offset_next;
            if label_len == 0 {
                break;
            }
        }
        CompressedNameResult {
            name_len: compressed.len() - initial_compressed_len,
            final_offset,
        }
    }
}

const MAX_SUFFIX_LEN: usize = 127;
const MAX_SUFFIXES: usize = 32;

struct Suffix {
    offset: usize,
    len: usize,
    suffix: [u8; MAX_SUFFIX_LEN],
}

impl Default for Suffix {
    fn default() -> Self {
        Self {
            offset: 0,
            len: 0,
            suffix: [0u8; MAX_SUFFIX_LEN],
        }
    }
}

#[derive(Default)]
pub struct SuffixDict {
    count: usize,
    index: usize,
    suffixes: [Suffix; MAX_SUFFIXES],
}

impl SuffixDict {
    /// Creates a new suffix dictionary
    pub fn new() -> Self {
        SuffixDict::default()
    }

    /// Inserts a new suffix into the suffix table
    /// Returns the offset of an existing suffix, if there is any, or `None` if there was none.
    fn insert(&mut self, suffix: &[u8], offset: usize) -> Option<usize> {
        if offset >= 65536 >> 2 {
            return None;
        }
        let suffix_len = suffix.len();
        if suffix_len <= 2 || suffix_len > MAX_SUFFIX_LEN {
            return None;
        }
        for i in 0..self.count {
            let candidate = &self.suffixes[i];
            if candidate.len <= suffix_len &&
                Self::raw_names_eq_ignore_case(suffix, &candidate.suffix[..candidate.len])
            {
                return Some(candidate.offset);
            }
        }

        let entry = &mut self.suffixes[self.index];
        let len = Self::raw_name_copy(&mut entry.suffix, suffix);
        debug_assert_eq!(len, suffix_len);
        entry.len = suffix_len;
        entry.offset = offset;
        self.index += 1;
        self.count = cmp::max(self.index, self.count);
        if self.index == MAX_SUFFIXES {
            debug_assert!(MAX_SUFFIXES > 1);
            self.index = 1; // keep the first entry, which is likely to be the question
        }
        None
    }

    /// Copy a trusted raw DNS name into a `to` slice.
    /// This doesn't perform any check nor decompression, but stops after the last label
    /// even if this is not the end of the slice.
    /// Returns the length of the name.
    fn raw_name_copy(to: &mut [u8], name: &[u8]) -> usize {
        let len = Compress::raw_name_len(name);
        &to[..len].copy_from_slice(&name[..len]);
        len
    }

    /// Compares two trusted raw DNS names.
    /// Returns `true` if they are equivalent, using a case-insensitive comparison.
    /// Stops after the last label even if there are more data in the slice.
    fn raw_names_eq_ignore_case(name1: &[u8], name2: &[u8]) -> bool {
        let mut label_len = 0;
        for (&c1, &c2) in name1.iter().zip(name2.iter()) {
            if !c1.eq_ignore_ascii_case(&c2) {
                return false;
            }
            if label_len == 0 {
                if c1 == 0 {
                    return true;
                }
                label_len = c1;
            } else {
                label_len -= 1
            }
        }
        false
    }
}
