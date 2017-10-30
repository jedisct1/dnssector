use compress::*;
use constants::*;
use errors::*;
use parsed_packet::*;
use rr_iterator::*;
use std::ascii::AsciiExt;
use synth::gen;

pub struct Renamer;

impl Renamer {
    /// Remplaces the substring `source_name`  in `name` with `target_name`.
    /// These are assumed to be strings (not raw names).
    /// If `match_suffix` is `true`, match the suffix instead of doing an exact match.
    pub fn replace_str(
        name: &[u8],
        target_name: &[u8],
        source_name: &[u8],
        match_suffix: bool,
    ) -> Result<Option<Vec<u8>>> {
        let (name_len, source_name_len, target_name_len) =
            (name.len(), source_name.len(), target_name.len());
        if name_len < source_name_len || (match_suffix == false && name_len != source_name_len) {
            return Ok(None);
        }
        if source_name_len <= 0 {
            bail!("Empty name");
        }
        if source_name[0] == b'.' || (target_name_len > 0 && target_name[0] == b'.') {
            bail!("A name shouldn't start with a dot");
        }
        let offset = name_len - source_name_len;
        if offset != 0 && name[offset - 1] != b'.' {
            return Ok(None);
        }
        if !(offset..name_len).all(|i| {
            name[i].to_ascii_lowercase() == source_name[i - offset].to_ascii_lowercase()
        }) {
            return Ok(None);
        }
        if offset + target_name_len > DNS_MAX_HOSTNAME_LEN {
            bail!("Name too long");
        }
        let mut res: Vec<u8> = Vec::with_capacity(offset + target_name_len);
        res.extend(&name[0..offset]);
        res.extend(target_name);
        Ok(Some(res))
    }

    pub fn rename_with_str_names(
        parsed_packet: &mut ParsedPacket,
        target_name: &[u8],
        source_name: &[u8],
        match_suffix: bool,
    ) -> Result<Vec<u8>> {
        if target_name.len() <= 0 || source_name.len() <= 0 {
            bail!("Empty name");
        }
        if target_name.len() > DNS_MAX_HOSTNAME_LEN || source_name.len() > DNS_MAX_HOSTNAME_LEN {
            bail!("Name too long");
        }
        let mut renamed_packet: Vec<u8> = Vec::with_capacity(parsed_packet.packet.len());
        let mut suffix_dict = SuffixDict::new();

        let mut it = parsed_packet.into_iter_question();
        while let Some(item) = it {
            {
                let raw = item.raw();
                let name = Compress::raw_name_to_str(raw.packet, raw.offset);
                let replaced_name =
                    Self::replace_str(&name, target_name, source_name, match_suffix)?;
                match replaced_name {
                    None => {
                        Compress::copy_compressed_name(
                            &mut suffix_dict,
                            &mut renamed_packet,
                            raw.packet,
                            raw.offset,
                        );
                    }
                    Some(replaced_name) => {
                        let raw_replaced_name = gen::raw_name_from_str(&replaced_name, None)?;
                        Compress::copy_compressed_name(
                            &mut suffix_dict,
                            &mut renamed_packet,
                            &raw_replaced_name,
                            0,
                        );
                    }
                }
                if raw.packet.len() < raw.name_end + DNS_RR_QUESTION_HEADER_SIZE {
                    bail!("Short question RR");
                }
                renamed_packet
                    .extend(&raw.packet[raw.name_end..raw.name_end + DNS_RR_QUESTION_HEADER_SIZE]);
            }
            it = item.next();
        }
        Ok(Vec::new())
    }
}
