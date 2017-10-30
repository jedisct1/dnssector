extern crate dnssector;

mod tests {
    use super::dnssector::synth::gen::RR;

    #[test]
    fn test_gen_a() {
        assert!(RR::from_string("example.com. 3599 IN A 1.2.3.4").is_ok());
        assert!(RR::from_string("example.com. 3599 IN A 350.2.3.4").is_err());
        assert!(RR::from_string("example.com. 3599 IN A 1.2.3").is_err());
        assert!(RR::from_string("example.com. 3599 IN A 1.2.3..4").is_err());
        assert!(RR::from_string("example.com. 3599 IN A").is_err());
    }

    #[test]
    fn test_gen_aaaa() {
        assert!(RR::from_string("example.com. 3599 IN AAAA fe80::64a0:11ff:dcb6:4b4d").is_ok());
        assert!(RR::from_string("example.com. 3599 IN AAAA fe80:::64a0:11ff:dcb6:4b4d").is_err());
        assert!(RR::from_string("example.com. 3599 IN AAAA 1.2.3.4").is_err());
        assert!(RR::from_string("example.com. 3599 IN AAAA").is_err());
    }

    #[test]
    fn test_gen_ptr() {
        assert!(RR::from_string("4.3.2.1.in-addr.arpa. 3599 IN PTR host.example.com.").is_ok());
        assert!(RR::from_string("4.3.2.1 3599 IN PTR host.example.com.").is_ok());
        assert!(RR::from_string("4.3.2.1. 3599 IN PTR host.example.com.").is_err());
        assert!(RR::from_string("4.3.2.1.in-addr.arpa. 3599 IN PTR 1.2.3.4").is_ok());
        assert!(RR::from_string("4.3.2.1.in-addr.arpa. 3599 IN PTR 1.2.3.4.").is_err());
    }

    #[test]
    fn test_gen_soa() {
        assert!(
            RR::from_string(
                "example.com. 86399 IN SOA ns1.example.com. hostmaster.example.com. (289 21600 3600 604800 3600)"
            ).is_ok()
        );
    }

    #[test]
    fn test_gen_txt() {
        assert!(RR::from_string("example.com. 86399 IN TXT \"Sample text\"").is_ok());
        assert!(
            RR::from_string(
                "example.com. 86399 IN TXT \"Sample escaped \\000\\008\\128\\255 text\""
            ).is_ok()
        );
        assert!(
            RR::from_string(
                "example.com. 86399 IN TXT \"Long text that has to be split into chunks: Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.\""
            ).is_ok()
        );
        assert!(RR::from_string("example.com. 86399 IN TXT \"\"").is_err());
        assert!(RR::from_string("example.com. 86399 IN TXT unquoted").is_err());
        assert!(RR::from_string("example.com. 86399 IN TXT").is_err());
    }

    #[test]
    fn test_gen_mx() {
        assert!(RR::from_string("example.com. 86399 IN MX 0 mx.example.com.").is_ok());
        assert!(RR::from_string("example.com. 86399 IN MX 1000 mx.example.com.").is_ok());
        assert!(RR::from_string("example.com. 86399 IN MX 1000000000 mx.example.com.").is_err());
        assert!(RR::from_string("example.com. 86399 IN MX 1000000000").is_err());
        assert!(RR::from_string("example.com. 86399 IN MX mx.example.com.").is_err());
        assert!(RR::from_string("example.com. 86399 IN MX").is_err());
    }

    #[test]
    fn test_gen_cname() {
        assert!(RR::from_string("example.com. 86399 IN CNAME www.example.com.").is_ok());
        assert!(RR::from_string("example.com. 86399 IN CNAME www1.example.com.").is_ok());
        assert!(RR::from_string("example.com. 86399 IN CNAME 1www.example.com.").is_ok());
        assert!(RR::from_string("example.com. 86399 IN CNAME").is_err());
    }

    #[test]
    fn test_gen_ns() {
        assert!(RR::from_string("example.com. 86399 IN NS www.example.com.").is_ok());
        assert!(RR::from_string("example.com. 86399 IN NS www1.example.com.").is_ok());
        assert!(RR::from_string("example.com. 86399 IN NS 1www.example.com.").is_ok());
        assert!(RR::from_string("example.com. 86399 IN NS").is_err());
    }
}
