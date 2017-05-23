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

    #[test]
    fn test_packet_valid_response_1() {
        let data = vec![
             38, 44, 129, 160, 0, 1, 0, 2, 0, 0, 0, 1, 3, 99, 57, 120, 3, 111, 114, 71, 0, 0, 1,
             0, 1, 192, 12, 0, 1, 0, 1, 0, 0, 167, 29, 0, 4, 78, 194, 219, 1, 192, 12, 0, 46, 0,
             1, 0, 0, 167, 29, 0, 91, 0, 1, 13, 2, 0, 0, 168, 192, 89, 56, 71, 147, 89, 16, 186,
             147, 82, 60, 3, 99, 57, 120, 3, 111, 114, 103, 0, 153, 235, 139, 49, 43, 255, 159,
             252, 196, 189, 29, 77, 88, 132, 233, 31, 133, 88, 104, 42, 139, 12, 101, 158, 121,
             95, 105, 180, 59, 216, 202, 174, 113, 201, 121, 23, 4, 26, 241, 134, 233, 52, 104,
             120, 80, 237, 252, 215, 146, 44, 120, 229, 63, 16, 95, 19, 209, 103, 165, 196, 195,
             151, 222, 52, 0, 0, 41, 2, 0, 0, 0, 128, 0, 0, 0];
        let dns_sector = super::DNSSector::new(data).unwrap();
        let ret = dns_sector.parse().expect("Valid packet couldn't be parsed");
        let flags = ret.flags();
        assert_eq!(flags, 0x800081a0);
    }
}
