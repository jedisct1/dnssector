#[cfg(test)]

extern crate dnssector;

use dnssector::*;

mod tests {
    #[test]
    fn test_empty_packet() {
        let data : Vec<u8> = vec![];
        let dns_sector = super::DNSSector::new(data).unwrap();
        assert!(dns_sector.parse().is_err());
    }

    #[test]
    fn test_packet_too_small() {
        let data_small : Vec<u8> = vec![1; 11];
        let dns_sector = super::DNSSector::new(data_small).unwrap();
        let ret = dns_sector.parse();
        assert!(ret.is_err());
        match ret.err() {
            Some(super::errors::Error(super::errors::ErrorKind::PacketTooSmall, _)) => { assert!(true) },
            _ => { assert!(false) },
        }
    }

    #[test]
    fn test_packet_has_two_questions() {
        let data_small : Vec<u8> = vec![0, 0, 0, 0,
                                        0, 2, 0, 0,
                                        0, 0, 0, 0, ];
        let dns_sector = super::DNSSector::new(data_small).unwrap();
        let ret = dns_sector.parse();
        assert!(ret.is_err());
        match ret.err() {
            Some(super::errors::Error(super::errors::ErrorKind::InvalidPacket(_), _)) => { assert!(true) },
            a => { assert!(false, "type: {:?}", a) },
        }
    }

    #[test]
    fn test_packet_advertises_one_question_but_is_missing_section() {
        let data_small : Vec<u8> = vec![0, 0, 0, 0,
                                        0, 1, 0, 0,
                                        0, 0, 0, 0,
                                        ];
        let dns_sector = super::DNSSector::new(data_small).unwrap();
        let ret = dns_sector.parse();
        assert!(ret.is_err());
        match ret.err() {
            Some(super::errors::Error(super::errors::ErrorKind::InternalError(_), _)) => { assert!(true) },
            a => { assert!(false, "type: {:?}", a) },
        }
    }

    #[test]
    fn test_packet_has_empty_name() {
        let data_small : Vec<u8> = vec![0, 0, 0, 0,
                                        0, 1, 0, 0,
                                        0, 0, 0, 0,
                                        0,
                                        0, 0, 0, 1,
                                        ];
        let dns_sector = super::DNSSector::new(data_small).unwrap();
        let ret = dns_sector.parse();
        assert!(ret.is_ok());
    }

    #[test]
    fn test_packet_name_does_not_end() {
        let data_small : Vec<u8> = vec![0, 0, 0, 0,
                                        0, 1, 0, 0,
                                        0, 0, 0, 0,
                                        1, 'a' as u8,
                                        0, 0, 0, 1,
                                        ];
        let dns_sector = super::DNSSector::new(data_small).unwrap();
        let ret = dns_sector.parse();
        assert!(ret.is_err());
        match ret.err() {
            Some(super::errors::Error(super::errors::ErrorKind::PacketTooSmall, _)) => { assert!(true) },
            a => { assert!(false, "type: {:?}", a) },
        }
    }

    #[test]
    fn test_packet_label_too_long() {
        let data_small : Vec<u8> = vec![0, 0, 0, 0,
                                        0, 1, 0, 0,
                                        0, 0, 0, 0,
                                        64, 97, 97, 97, 97, 97, 97, 97,
                                        97, 97, 97, 97, 97, 97, 97, 97,
                                        97, 97, 97, 97, 97, 97, 97, 97,
                                        97, 97, 97, 97, 97, 97, 97, 97,
                                        97, 97, 97, 97, 97, 97, 97, 97,
                                        97, 97, 97, 97, 97, 97, 97, 97,
                                        97, 97, 97, 97, 97, 97, 97, 97,
                                        97, 97, 97, 97, 97, 97, 97, 97,
                                        97, 0,
                                        0, 0, 0, 1,
                                        ];
        let dns_sector = super::DNSSector::new(data_small).unwrap();
        let ret = dns_sector.parse();
        assert!(ret.is_err());
        match ret.err() {
            Some(super::errors::Error(super::errors::ErrorKind::InvalidName(_), _)) => { assert!(true) },
            a => { assert!(false, "type: {:?}", a) },
        }
    }

    #[test]
    fn test_packet_name_too_long() {
        let data_small : Vec<u8> = vec![0, 0, 0, 0,
                                        0, 1, 0, 0,
                                        0, 0, 0, 0,
                                        63, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97,
                                        97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97,
                                        97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97,
                                        97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97,
                                        63, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97,
                                        97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97,
                                        97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97,
                                        97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97,
                                        63, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97,
                                        97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97,
                                        97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97,
                                        97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97,
                                        63, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97,
                                        97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97,
                                        97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97,
                                        97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97,
                                        0,
                                        0, 0, 0, 1,
                                        ];
        let dns_sector = super::DNSSector::new(data_small).unwrap();
        let ret = dns_sector.parse();
        assert!(ret.is_err());
        match ret.err() {
            Some(super::errors::Error(super::errors::ErrorKind::InvalidName(_), _)) => { assert!(true) },
            a => { assert!(false, "type: {:?}", a) },
        }
    }

    #[test]
    fn test_packet_name_too_long_with_compression() {
        let data_small : Vec<u8> = vec![0, 0, 0, 0,
                                        0, 1, 0, 3,
                                        0, 0, 0, 0,
                                        /* query */
                                        63, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97,
                                        97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97,
                                        97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97,
                                        97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97,
                                        0,
                                        0, 1, 0, 1,
                                        /* 1st answer */
                                        63, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97,
                                        97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97,
                                        97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97,
                                        97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97,
                                        0xc0, 0x0c,
                                        0, 1, 0, 1,
                                        0, 0, 0, 0,
                                        0, 0,
                                        /* 2nd answer */
                                        63, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97,
                                        97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97,
                                        97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97,
                                        97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97,
                                        0xc0, 0x51,
                                        0, 1, 0, 1,
                                        0, 0, 0, 0,
                                        0, 0,
                                        /* 3rd answer */
                                        63, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97,
                                        97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97,
                                        97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97,
                                        97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 97,
                                        0xc0, 0x9d,
                                        0, 1, 0, 1,
                                        0, 0, 0, 0,
                                        0, 0,
                                        ];
        let dns_sector = super::DNSSector::new(data_small).unwrap();
        let ret = dns_sector.parse();
        assert!(ret.is_err());
        match ret.err() {
            Some(super::errors::Error(super::errors::ErrorKind::InvalidName("Name too long"), _)) => { assert!(true) },
            a => { assert!(false, "type: {:?}", a) },
        }
    }
}
