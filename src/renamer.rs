use compress::*;
use constants::*;
use errors::*;
use parsed_packet::*;
use rr_iterator::*;
#[allow(unused_imports)]
use std::ascii::AsciiExt;

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
    ) -> Result<Option<Vec<u8>>> {
        let (name_len, source_name_len, target_name_len) =
            (name.len(), source_name.len(), target_name.len());
        if name_len < source_name_len || (match_suffix == false && name_len != source_name_len) {
            return Ok(None);
        }
        if source_name_len <= 0 || target_name_len <= 0 {
            bail!("Empty name");
        }
        if source_name[0] == 0 || target_name[0] == 0 {
            bail!("A non-empty name cannot start with a NUL byte");
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
            bail!("Inconsistent encoding");
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
            bail!("Name too long");
        }
        let mut res: Vec<u8> = Vec::with_capacity(offset + target_name_len);
        res.extend(&name[0..offset]);
        res.extend(target_name);
        Ok(Some(res))
    }

    pub fn rename_with_raw_names(
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
        let mut renamed_packet = Vec::with_capacity(parsed_packet.packet.len());
        let mut suffix_dict = SuffixDict::new();

        let mut it = parsed_packet.into_iter_question();
        while let Some(item) = it {
            {
                let raw = item.raw();
                let mut name = Vec::with_capacity(DNS_MAX_HOSTNAME_LEN);
                let _compressed_name_len =
                    Compress::copy_uncompressed_name(&mut name, raw.packet, raw.offset);
                let replaced_name =
                    Self::replace_raw(&name, target_name, source_name, match_suffix)?;
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
                        Compress::copy_compressed_name(
                            &mut suffix_dict,
                            &mut renamed_packet,
                            &replaced_name,
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
