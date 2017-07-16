#![allow(dead_code)]

use std::convert::From;
use std::mem;

/// Size of the main DNS header, that includes flags and the size of each section.
pub const DNS_HEADER_SIZE: usize = 12;

/// Offset to the first (and usually only) record of the question section, from the start of the packet.
pub const DNS_QUESTION_OFFSET: usize = DNS_HEADER_SIZE;

/// Maximum length of a host name.
pub const DNS_MAX_HOSTNAME_LEN: usize = 255;

/// Maximum number of indirections in a compressed name.
pub const DNS_MAX_HOSTNAME_INDIRECTIONS: u16 = 16;

/// Size of the header for a RR in the question section.
pub const DNS_RR_QUESTION_HEADER_SIZE: usize = 4;

/// Size of the header for a RR in a section that is not the question section.
pub const DNS_RR_HEADER_SIZE: usize = 10;

/// Offset to the type identifier, from the location right after the RR name.
pub const DNS_RR_TYPE_OFFSET: usize = 0;

/// Offset to the class identifier, from the location right after the RR name.
pub const DNS_RR_CLASS_OFFSET: usize = 2;

/// Offset to the TTL, from the location right after the RR name.
pub const DNS_RR_TTL_OFFSET: usize = 4;

/// Offset to the rdata length, from the location right after the RR name.
pub const DNS_RR_RDLEN_OFFSET: usize = 8;

/// Offset to the maximum payload for edns0-enabled UDP packets, for OPT RRs.
pub const DNS_OPT_RR_MAX_PAYLOAD_OFFSET: usize = 2;

/// Offset to the extended rcode, for OPT RRs.
pub const DNS_OPT_RR_EXT_RCODE_OFFSET: usize = 4;

/// Offset to the edns version number, for OPT RRs.
pub const DNS_OPT_RR_EDNS_VERSION_OFFSET: usize = 5;

/// Offset to the edns extended flags, for OPT RRs.
pub const DNS_OPT_RR_EDNS_EXT_FLAGS_OFFSET: usize = 6;

/// Offset to the total size of the edns records, within OPT RRS.
pub const DNS_OPT_RR_RDLEN_OFFSET: usize = 8;

/// Size of the header of an edns section.
pub const DNS_OPT_RR_HEADER_SIZE: usize = 10;

/// Offset to the extended RR code, from the beginning of an extended RR.
pub const DNS_EDNS_RR_CODE_OFFSET: usize = 0;

/// Offset to the length of an extended RR, from the beginning of the extended RR.
pub const DNS_EDNS_RR_RDLEN_OFFSET: usize = 2;

/// Size of the header of an extended RR.
pub const DNS_EDNS_RR_HEADER_SIZE: usize = 4;

/// Offset to the transaction ID, from the beginning of a DNS packet
pub const DNS_TID_OFFSET: usize = 0;

/// Offset to the flags (including rcode and opcode), from the beginning of the DNS packet
pub const DNS_FLAGS_OFFSET: usize = 2;

/// Offset to the return code, from the beginning of the DNS packet
pub const DNS_RCODE_OFFSET: usize = 3;

// DNS flags - 32 bit because we include extended flags
pub const DNS_FLAG_QR: u32 = 1 << 15;
pub const DNS_FLAG_AA: u32 = 1 << 10;
pub const DNS_FLAG_TC: u32 = 1 << 9;
pub const DNS_FLAG_RD: u32 = 1 << 8;
pub const DNS_FLAG_RA: u32 = 1 << 7;
pub const DNS_FLAG_AD: u32 = 1 << 5;
pub const DNS_FLAG_CD: u32 = 1 << 4;
pub const DNS_FLAG_DO: u32 = 1 << 31;

/// DNS query class
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Class {
    IN = 1,
    CH = 3,
    HS = 4,
    NONE = 254,
    ANY = 255,
}

impl From<Class> for u16 {
    fn from(v: Class) -> u16 {
        unsafe { mem::transmute(v as u16) }
    }
}

/// DNS query type
#[allow(non_camel_case_types)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Type {
    A = 1,
    NS = 2,
    MD = 3,
    MF = 4,
    CNAME = 5,
    SOA = 6,
    MB = 7,
    MG = 8,
    MR = 9,
    NULL = 10,
    WKS = 11,
    PTR = 12,
    HINFO = 13,
    MINFO = 14,
    MX = 15,
    TXT = 16,
    RP = 17,
    AFSDB = 18,
    X25 = 19,
    ISDN = 20,
    RT = 21,
    NSAP = 22,
    NSAP_PTR = 23,
    SIG = 24,
    KEY = 25,
    PX = 26,
    GPOS = 27,
    AAAA = 28,
    LOC = 29,
    NXT = 30,
    EID = 31,
    NIMLOC = 32,
    SRV = 33,
    ATMA = 34,
    NAPTR = 35,
    KX = 36,
    CERT = 37,
    A6 = 38,
    DNAME = 39,
    SINK = 40,
    OPT = 41,
    APL = 42,
    DS = 43,
    SSHFP = 44,      /* RFC 4255 */
    IPSECKEY = 45,   /* RFC 4025 */
    RRSIG = 46,      /* RFC 4034 */
    NSEC = 47,       /* RFC 4034 */
    DNSKEY = 48,     /* RFC 4034 */
    DHCID = 49,      /* RFC 4701 */
    NSEC3 = 50,      /* RFC 5155 */
    NSEC3PARAM = 51, /* RFC 5155 */
    TLSA = 52,       /* RFC 6698 */
    SMIMEA = 53,     /* draft-ietf-dane-smime */
    HIP = 55,        /* RFC 5205 */
    NINFO = 56,
    RKEY = 57,
    TALINK = 58,
    CDS = 59,        /* RFC 7344 */
    CDNSKEY = 60,    /* RFC 7344 */
    OPENPGPKEY = 61, /* RFC 7929 */
    CSYNC = 62,      /* RFC 7477 */
    SPF = 99,        /* RFC 4408 */
    UINFO = 100,
    UID = 101,
    GID = 102,
    UNSPEC = 103,
    NID = 104,   /* RFC 6742 */
    L32 = 105,   /* RFC 6742 */
    L64 = 106,   /* RFC 6742 */
    LP = 107,    /* RFC 6742 */
    EUI48 = 108, /* RFC 7043 */
    EUI64 = 109, /* RFC 7043 */
    TKEY = 249,  /* RFC 2930 */
    TSIG = 250,
    IXFR = 251,
    AXFR = 252,
    MAILB = 253,
    MAILA = 254,
    ANY = 255,
    URI = 256, /* RFC 7553 */
    CAA = 257, /* RFC 6844 */
    AVC = 258, /* Cisco's DNS-AS RR, see www.dns-as.org */
    TA = 32768,
    DLV = 32769,
}

impl From<Type> for u16 {
    fn from(v: Type) -> u16 {
        unsafe { mem::transmute(v as u16) }
    }
}

/// EDNS option
#[allow(non_camel_case_types)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum EdnsOption {
    LLQ = 1,
    UL = 2,
    NSID = 3,
    DAU = 5,
    DHU = 6,
    N3U = 7,
    CLIENT_SUBNET = 8,
    KEEPALIVE = 11,
    PADDING = 12,
}

impl From<EdnsOption> for u16 {
    fn from(v: EdnsOption) -> u16 {
        unsafe { mem::transmute(v as u16) }
    }
}

/// DNS return codes
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Rcode {
    NOERROR = 0,
    FORMERR = 1,
    SERVFAIL = 2,
    NXDOMAIN = 3,
    NOTIMPL = 4,
    REFUSED = 5,
    YXDOMAIN = 6,
    YXRRSET = 7,
    NXRRSET = 8,
    NOTAUTH = 9,
    NOTZONE = 10,
}

impl From<Rcode> for u8 {
    fn from(v: Rcode) -> u8 {
        unsafe { mem::transmute(v as u8) }
    }
}

/// DNS opcodes
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Opcode {
    QUERY = 0,
    IQUERY = 1,
    STATUS = 2,
    NOTIFY = 4,
    UPDATE = 5,
}

impl From<Opcode> for u8 {
    fn from(v: Opcode) -> u8 {
        unsafe { mem::transmute(v as u8) }
    }
}

/// DNS packet section
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Section {
    Question,
    Answer,
    NameServers,
    Additional,
    Edns,
}

impl From<Section> for u8 {
    fn from(v: Section) -> u8 {
        unsafe { mem::transmute(v as u8) }
    }
}
