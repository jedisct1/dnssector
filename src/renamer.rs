use crate::compress::*;
use crate::constants::*;
use crate::errors::*;
use crate::parsed_packet::*;
use crate::response_iterator::*;
use crate::rr_iterator::*;
use byteorder::{BigEndian, ByteOrder};

pub struct Renamer;

impl Renamer {
    /// Remplaces the substring `source_name`  in `name` with `target_name`.
    /// These are assumed to be strings (not raw names).
    /// If `match_suffix` is `true`, match the suffix instead of doing an exact match.
    pub fn replace_raw(
        name: &[u8],
        target_name: &[u8],
        source_name: &[u8],
        match_suffix: bool,
    ) -> Result<Option<Vec<u8>>, Error> {
        let (name_len, source_name_len, target_name_len) =
            (name.len(), source_name.len(), target_name.len());
        if name_len < source_name_len || (match_suffix == false && name_len != source_name_len) {
            return Ok(None);
        }
        if source_name_len <= 0 || target_name_len <= 0 {
            bail!(DSError::InvalidName("Empty name"));
        }
        if source_name[0] == 0 || target_name[0] == 0 {
            bail!(DSError::InvalidName(
                "A non-empty name cannot start with a NUL byte"
            ));
        }
        let offset = name_len - source_name_len;

        let mut i = 0;
        while name[i] != 0 {
            if i == offset {
                break;
            }
            i += name[i] as usize + 1;
        }
        if i >= name_len || (name[i] == 0 && name_len > 0) {
            return Ok(None);
        }
        if i != offset {
            bail!(DSError::InvalidName("Inconsistent encoding"));
        }
        assert_eq!(i, offset);
        while name[i] != 0 {
            let label_len = name[i] as usize;
            let source_label_len = source_name[i - offset] as usize;
            if label_len != source_label_len {
                return Ok(None);
            }
            i += 1;
            if !(0..label_len).all(|j| {
                name[i + j].to_ascii_lowercase() == source_name[i + j - offset].to_ascii_lowercase()
            }) {
                return Ok(None);
            }
            i += label_len;
        }
        if offset + target_name_len > DNS_MAX_HOSTNAME_LEN {
            bail!(DSError::InvalidName("Name too long"));
        }
        let mut res: Vec<u8> = Vec::with_capacity(offset + target_name_len);
        res.extend(&name[0..offset]);
        res.extend(target_name);
        Ok(Some(res))
    }

    fn copy_with_replaced_name(
        mut renamed_packet: &mut Vec<u8>,
        packet: &[u8],
        offset: usize,
        mut suffix_dict: &mut SuffixDict,
        target_name: &[u8],
        source_name: &[u8],
        match_suffix: bool,
    ) -> Result<(), Error> {
        let mut name = Vec::with_capacity(DNS_MAX_HOSTNAME_LEN);
        let _compressed_name_len = Compress::copy_uncompressed_name(&mut name, packet, offset);
        let replaced_name = Self::replace_raw(&name, target_name, source_name, match_suffix)?;
        let renamed_packet_len = renamed_packet.len();
        match replaced_name {
            None => {
                Compress::copy_compressed_name_with_base_offset(
                    &mut suffix_dict,
                    &mut renamed_packet,
                    &name,
                    0,
                    renamed_packet_len,
                );
            }
            Some(replaced_name) => {
                Compress::copy_compressed_name_with_base_offset(
                    &mut suffix_dict,
                    &mut renamed_packet,
                    &replaced_name,
                    0,
                    renamed_packet_len,
                );
            }
        };
        Ok(())
    }

    fn rename_question_section(
        mut renamed_packet: &mut Vec<u8>,
        parsed_packet: &mut ParsedPacket,
        mut suffix_dict: &mut SuffixDict,
        target_name: &[u8],
        source_name: &[u8],
        match_suffix: bool,
    ) -> Result<(), Error> {
        let mut it = parsed_packet.into_iter_question();
        while let Some(item) = it {
            {
                let raw = item.raw();
                Self::copy_with_replaced_name(
                    &mut renamed_packet,
                    &raw.packet,
                    raw.offset,
                    &mut suffix_dict,
                    &target_name,
                    &source_name,
                    match_suffix,
                )?;
                if raw.packet.len() < raw.name_end + DNS_RR_QUESTION_HEADER_SIZE {
                    bail!(DSError::PacketTooSmall)
                }
                renamed_packet
                    .extend(&raw.packet[raw.name_end..raw.name_end + DNS_RR_QUESTION_HEADER_SIZE]);
            }
            it = item.next();
        }
        Ok(())
    }

    fn rename_response_section(
        mut it: Option<ResponseIterator<'_>>,
        mut renamed_packet: &mut Vec<u8>,
        mut suffix_dict: &mut SuffixDict,
        target_name: &[u8],
        source_name: &[u8],
        match_suffix: bool,
    ) -> Result<(), Error> {
        while let Some(item) = it {
            {
                let raw = item.raw();
                Self::copy_with_replaced_name(
                    &mut renamed_packet,
                    &raw.packet,
                    raw.offset,
                    &mut suffix_dict,
                    &target_name,
                    &source_name,
                    match_suffix,
                )?;
                if raw.packet.len() < raw.name_end + DNS_RR_HEADER_SIZE {
                    bail!(DSError::PacketTooSmall)
                }
                let renamed_packet_offset_data = renamed_packet.len();
                renamed_packet.extend(&raw.packet[raw.name_end..raw.name_end + DNS_RR_HEADER_SIZE]);
                let rr_type = item.rr_type();
                match rr_type {
                    x if x == Type::NS.into()
                        || x == Type::CNAME.into()
                        || x == Type::PTR.into() =>
                    {
                        let offset_rdata = raw.name_end;
                        Self::copy_with_replaced_name(
                            &mut renamed_packet,
                            &raw.packet,
                            offset_rdata + DNS_RR_HEADER_SIZE,
                            &mut suffix_dict,
                            &target_name,
                            &source_name,
                            match_suffix,
                        )?;
                        let new_rdlen =
                            renamed_packet.len() - renamed_packet_offset_data - DNS_RR_HEADER_SIZE;
                        BigEndian::write_u16(
                            &mut renamed_packet[renamed_packet_offset_data + DNS_RR_RDLEN_OFFSET..],
                            new_rdlen as u16,
                        );
                    }
                    x if x == Type::MX.into() => {
                        let offset_rdata = raw.name_end;
                        renamed_packet.extend(
                            &raw.packet[offset_rdata + DNS_RR_HEADER_SIZE
                                ..offset_rdata + DNS_RR_HEADER_SIZE + 2],
                        );
                        let renamed_packet_name_offset = renamed_packet.len();
                        Self::copy_with_replaced_name(
                            &mut renamed_packet,
                            &raw.packet,
                            offset_rdata + DNS_RR_HEADER_SIZE + 2,
                            &mut suffix_dict,
                            &target_name,
                            &source_name,
                            match_suffix,
                        )?;
                        let new_rdlen = 2 + renamed_packet.len()
                            - renamed_packet_name_offset
                            - DNS_RR_HEADER_SIZE;
                        BigEndian::write_u16(
                            &mut renamed_packet[renamed_packet_offset_data + DNS_RR_RDLEN_OFFSET..],
                            new_rdlen as u16,
                        );
                    }
                    x if x == Type::SOA.into() => {
                        let offset_rdata = raw.name_end;
                        let renamed_packet_name1_offset = renamed_packet.len();
                        let name1_offset = offset_rdata + DNS_RR_HEADER_SIZE;
                        let name1_len = Compress::raw_name_len(&raw.packet[name1_offset..]);
                        Self::copy_with_replaced_name(
                            &mut renamed_packet,
                            &raw.packet,
                            name1_offset,
                            &mut suffix_dict,
                            &target_name,
                            &source_name,
                            match_suffix,
                        )?;
                        let name2_offset = name1_offset + name1_len;
                        let name2_len = Compress::raw_name_len(&raw.packet[name2_offset..]);
                        Self::copy_with_replaced_name(
                            &mut renamed_packet,
                            &raw.packet,
                            name2_offset,
                            &mut suffix_dict,
                            &target_name,
                            &source_name,
                            match_suffix,
                        )?;
                        let soa_metadata_offset = name2_offset + name2_len;
                        renamed_packet
                            .extend(&raw.packet[soa_metadata_offset..soa_metadata_offset + 20]);
                        let new_rdlen =
                            renamed_packet.len() - renamed_packet_name1_offset - DNS_RR_HEADER_SIZE;
                        BigEndian::write_u16(
                            &mut renamed_packet[renamed_packet_offset_data + DNS_RR_RDLEN_OFFSET..],
                            new_rdlen as u16,
                        );
                    }
                    _ => {
                        let rd_len = item.rr_rdlen();
                        let packet = &raw.packet;
                        let offset_rdata = raw.name_end;
                        let rdata =
                            &packet[offset_rdata..offset_rdata + DNS_RR_HEADER_SIZE + rd_len];
                        renamed_packet.extend(&rdata[DNS_RR_HEADER_SIZE..]);
                    }
                };
            }
            it = item.next();
        }
        Ok(())
    }

    fn rename_answer_section(
        renamed_packet: &mut Vec<u8>,
        parsed_packet: &mut ParsedPacket,
        suffix_dict: &mut SuffixDict,
        target_name: &[u8],
        source_name: &[u8],
        match_suffix: bool,
    ) -> Result<(), Error> {
        let it = parsed_packet.into_iter_answer() as Option<ResponseIterator<'_>>;
        Self::rename_response_section(
            it,
            renamed_packet,
            suffix_dict,
            target_name,
            source_name,
            match_suffix,
        )
    }

    fn rename_nameservers_section(
        renamed_packet: &mut Vec<u8>,
        parsed_packet: &mut ParsedPacket,
        suffix_dict: &mut SuffixDict,
        target_name: &[u8],
        source_name: &[u8],
        match_suffix: bool,
    ) -> Result<(), Error> {
        let it = parsed_packet.into_iter_nameservers() as Option<ResponseIterator<'_>>;
        Self::rename_response_section(
            it,
            renamed_packet,
            suffix_dict,
            target_name,
            source_name,
            match_suffix,
        )
    }

    fn rename_additional_section(
        renamed_packet: &mut Vec<u8>,
        parsed_packet: &mut ParsedPacket,
        suffix_dict: &mut SuffixDict,
        target_name: &[u8],
        source_name: &[u8],
        match_suffix: bool,
    ) -> Result<(), Error> {
        let it = parsed_packet.into_iter_additional() as Option<ResponseIterator<'_>>;
        Self::rename_response_section(
            it,
            renamed_packet,
            suffix_dict,
            target_name,
            source_name,
            match_suffix,
        )
    }

    /// Replaces `source_name` with `target_name` in all names, in all records.
    /// If `match_suffix` is `true`, do suffix matching instead of exact matching
    /// This allows renaming `*.example.com` into `*.example.net`.
    pub fn rename_with_raw_names(
        mut parsed_packet: &mut ParsedPacket,
        target_name: &[u8],
        source_name: &[u8],
        match_suffix: bool,
    ) -> Result<Vec<u8>, Error> {
        if target_name.len() <= 0 || source_name.len() <= 0 {
            bail!(DSError::InvalidName("Empty name"));
        }
        if target_name.len() > DNS_MAX_HOSTNAME_LEN || source_name.len() > DNS_MAX_HOSTNAME_LEN {
            bail!(DSError::InvalidName("Name too long"));
        }
        let mut renamed_packet = Vec::with_capacity(parsed_packet.packet().len());
        parsed_packet.copy_header(&mut renamed_packet);
        let mut suffix_dict = SuffixDict::new();
        Self::rename_question_section(
            &mut renamed_packet,
            &mut parsed_packet,
            &mut suffix_dict,
            target_name,
            source_name,
            match_suffix,
        )?;
        Self::rename_answer_section(
            &mut renamed_packet,
            &mut parsed_packet,
            &mut suffix_dict,
            target_name,
            source_name,
            match_suffix,
        )?;
        Self::rename_nameservers_section(
            &mut renamed_packet,
            &mut parsed_packet,
            &mut suffix_dict,
            target_name,
            source_name,
            match_suffix,
        )?;
        Self::rename_additional_section(
            &mut renamed_packet,
            &mut parsed_packet,
            &mut suffix_dict,
            target_name,
            source_name,
            match_suffix,
        )?;
        parsed_packet.copy_raw_edns_section(&mut renamed_packet);
        Ok(renamed_packet)
    }
}
