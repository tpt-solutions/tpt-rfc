//! IKEv2 protocol enums and constants (RFC 7296).

#![allow(clippy::upper_case_acronyms)]

/// IKEv2 payload types (Next Payload field values, RFC 7296 §3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PayloadType {
    None = 0,
    Sa = 33,
    Ke = 34,
    Idi = 35,
    Idr = 36,
    Cert = 37,
    CertReq = 38,
    Auth = 39,
    Nonce = 40,
    Notify = 41,
    Delete = 42,
    Vendor = 43,
    TSi = 44,
    TSr = 45,
    Sk = 46,
    Cp = 47,
    Eap = 48,
}

impl PayloadType {
    /// Parse a payload-type byte, mapping 0 to `None`.
    pub fn from_u8(v: u8) -> Option<PayloadType> {
        Some(match v {
            0 => PayloadType::None,
            33 => PayloadType::Sa,
            34 => PayloadType::Ke,
            35 => PayloadType::Idi,
            36 => PayloadType::Idr,
            37 => PayloadType::Cert,
            38 => PayloadType::CertReq,
            39 => PayloadType::Auth,
            40 => PayloadType::Nonce,
            41 => PayloadType::Notify,
            42 => PayloadType::Delete,
            43 => PayloadType::Vendor,
            44 => PayloadType::TSi,
            45 => PayloadType::TSr,
            46 => PayloadType::Sk,
            47 => PayloadType::Cp,
            48 => PayloadType::Eap,
            _ => return None,
        })
    }

    /// Numeric value for wire encoding.
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

/// IKEv2 exchange types (RFC 7296 §3.1, "Exchange Type").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ExchangeType {
    IkeSaInit = 34,
    IkeAuth = 35,
    CreateChildSa = 36,
    Informational = 37,
}

impl ExchangeType {
    pub fn from_u8(v: u8) -> Option<ExchangeType> {
        Some(match v {
            34 => ExchangeType::IkeSaInit,
            35 => ExchangeType::IkeAuth,
            36 => ExchangeType::CreateChildSa,
            37 => ExchangeType::Informational,
            _ => return None,
        })
    }
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

/// Protocol identifiers used in SA payloads (RFC 7296 §3.3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ProtocolId {
    Ike = 1,
    Ah = 2,
    Esp = 3,
}

impl ProtocolId {
    pub fn from_u8(v: u8) -> Option<ProtocolId> {
        Some(match v {
            1 => ProtocolId::Ike,
            2 => ProtocolId::Ah,
            3 => ProtocolId::Esp,
            _ => return None,
        })
    }
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

/// Transform types within a proposal (RFC 7296 §3.3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TransformType {
    Encr = 1,
    Prf = 2,
    Integ = 3,
    Dh = 4,
    Esn = 5,
}

impl TransformType {
    pub fn from_u8(v: u8) -> Option<TransformType> {
        Some(match v {
            1 => TransformType::Encr,
            2 => TransformType::Prf,
            3 => TransformType::Integ,
            4 => TransformType::Dh,
            5 => TransformType::Esn,
            _ => return None,
        })
    }
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

/// Encryption transform identifiers (RFC 7296 §3.3.2 / RFC 8221).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum EncrId {
    AesCbc128 = 12,
    AesCbc192 = 13,
    AesCbc256 = 14,
    AesGcm16_128 = 18,
    AesGcm16_192 = 19,
    AesGcm16_256 = 20,
}

impl EncrId {
    pub fn from_u16(v: u16) -> Option<EncrId> {
        Some(match v {
            12 => EncrId::AesCbc128,
            13 => EncrId::AesCbc192,
            14 => EncrId::AesCbc256,
            18 => EncrId::AesGcm16_128,
            19 => EncrId::AesGcm16_192,
            20 => EncrId::AesGcm16_256,
            _ => return None,
        })
    }
    pub fn to_u16(self) -> u16 {
        self as u16
    }
    /// Symmetric key length in bytes (the AES key, excluding any AEAD salt).
    pub fn key_len(self) -> usize {
        match self {
            EncrId::AesCbc128 | EncrId::AesGcm16_128 => 16,
            EncrId::AesCbc192 | EncrId::AesGcm16_192 => 24,
            EncrId::AesCbc256 | EncrId::AesGcm16_256 => 32,
        }
    }
    /// Whether this is an AEAD transform (no separate integrity algorithm).
    pub fn is_aead(self) -> bool {
        matches!(
            self,
            EncrId::AesGcm16_128 | EncrId::AesGcm16_192 | EncrId::AesGcm16_256
        )
    }
}

/// PRF transform identifiers (RFC 7296 §3.3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum PrfId {
    HmacSha1 = 1,
    HmacSha256 = 2,
    HmacSha384 = 3,
    HmacSha512 = 4,
}

impl PrfId {
    pub fn from_u16(v: u16) -> Option<PrfId> {
        Some(match v {
            1 => PrfId::HmacSha1,
            2 => PrfId::HmacSha256,
            3 => PrfId::HmacSha384,
            4 => PrfId::HmacSha512,
            _ => return None,
        })
    }
    pub fn to_u16(self) -> u16 {
        self as u16
    }
    /// Output size of the underlying PRF in bytes.
    pub fn output_len(self) -> usize {
        match self {
            PrfId::HmacSha1 => 20,
            PrfId::HmacSha256 => 32,
            PrfId::HmacSha384 => 48,
            PrfId::HmacSha512 => 64,
        }
    }
}

/// Integrity transform identifiers (RFC 7296 §3.3.2 / RFC 8221).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum IntegId {
    HmacSha1_96 = 1,
    HmacSha256_128 = 12,
    HmacSha384_192 = 13,
    HmacSha512_256 = 14,
}

impl IntegId {
    pub fn from_u16(v: u16) -> Option<IntegId> {
        Some(match v {
            1 => IntegId::HmacSha1_96,
            12 => IntegId::HmacSha256_128,
            13 => IntegId::HmacSha384_192,
            14 => IntegId::HmacSha512_256,
            _ => return None,
        })
    }
    pub fn to_u16(self) -> u16 {
        self as u16
    }
    /// Key length of the integrity algorithm in bytes.
    pub fn key_len(self) -> usize {
        match self {
            IntegId::HmacSha1_96 => 20,
            IntegId::HmacSha256_128 => 32,
            IntegId::HmacSha384_192 => 48,
            IntegId::HmacSha512_256 => 64,
        }
    }
    /// Truncated ICV length in bytes.
    pub fn icv_len(self) -> usize {
        match self {
            IntegId::HmacSha1_96 => 12,
            IntegId::HmacSha256_128 => 16,
            IntegId::HmacSha384_192 => 24,
            IntegId::HmacSha512_256 => 32,
        }
    }
}

/// Diffie-Hellman group identifiers (RFC 7296 Appendix B / RFC 8031).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum DhGroup {
    Modp768 = 1,
    Modp1024 = 2,
    Modp1536 = 5,
    Modp2048 = 14,
    Modp3072 = 15,
    Modp4096 = 16,
    Curve25519 = 31,
}

impl DhGroup {
    pub fn from_u16(v: u16) -> Option<DhGroup> {
        Some(match v {
            1 => DhGroup::Modp768,
            2 => DhGroup::Modp1024,
            5 => DhGroup::Modp1536,
            14 => DhGroup::Modp2048,
            15 => DhGroup::Modp3072,
            16 => DhGroup::Modp4096,
            31 => DhGroup::Curve25519,
            _ => return None,
        })
    }
    pub fn to_u16(self) -> u16 {
        self as u16
    }
    /// The length of a public value / shared secret in bytes.
    pub fn key_len(self) -> usize {
        match self {
            DhGroup::Modp768 => 96,
            DhGroup::Modp1024 => 128,
            DhGroup::Modp1536 => 192,
            DhGroup::Modp2048 => 256,
            DhGroup::Modp3072 => 384,
            DhGroup::Modp4096 => 512,
            DhGroup::Curve25519 => 32,
        }
    }
}

/// Authentication method identifiers (RFC 7296 §3.8 / RFC 7420).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AuthMethod {
    Rsa = 1,
    Psk = 2,
    Ecdsa = 3,
    DigitalSignature = 14,
}

impl AuthMethod {
    pub fn from_u8(v: u8) -> Option<AuthMethod> {
        Some(match v {
            1 => AuthMethod::Rsa,
            2 => AuthMethod::Psk,
            3 => AuthMethod::Ecdsa,
            14 => AuthMethod::DigitalSignature,
            _ => return None,
        })
    }
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

/// Identification type values (RFC 7296 §3.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IdType {
    Ipv4 = 1,
    Fqdn = 2,
    Rfc822 = 3,
    Ipv6 = 5,
    KeyId = 11,
}

impl IdType {
    pub fn from_u8(v: u8) -> Option<IdType> {
        Some(match v {
            1 => IdType::Ipv4,
            2 => IdType::Fqdn,
            3 => IdType::Rfc822,
            5 => IdType::Ipv6,
            11 => IdType::KeyId,
            _ => return None,
        })
    }
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

/// Certificate encoding identifiers (RFC 7296 §3.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CertEncoding {
    Pkcs7 = 1,
    Pgp = 2,
    Dns = 3,
    X509 = 4,
    RawRsa = 5,
    X509Attr = 6,
    HashUrlX509 = 7,
    HashUrlX509Bundle = 8,
    OCSP = 9,
    RawPublicKey = 11,
}

impl CertEncoding {
    pub fn from_u8(v: u8) -> Option<CertEncoding> {
        Some(match v {
            1 => CertEncoding::Pkcs7,
            2 => CertEncoding::Pgp,
            3 => CertEncoding::Dns,
            4 => CertEncoding::X509,
            5 => CertEncoding::RawRsa,
            6 => CertEncoding::X509Attr,
            7 => CertEncoding::HashUrlX509,
            8 => CertEncoding::HashUrlX509Bundle,
            9 => CertEncoding::OCSP,
            11 => CertEncoding::RawPublicKey,
            _ => return None,
        })
    }
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

/// IKEv2 header flags (RFC 7296 §3.1).
pub mod flags {
    /// Set if the message is from the original initiator of the IKE_SA.
    pub const INITIATOR: u8 = 0x08;
    /// Set if the message is a response.
    pub const RESPONSE: u8 = 0x20;
    /// Set if the message is an IKEv2 version negotiation attempt.
    pub const VERSION: u8 = 0x10;
    /// Critical bit in a payload's flags octet.
    pub const CRITICAL: u8 = 0x80;
}

/// IKE version byte (2.0).
pub const IKE_VERSION: u8 = 0x20;

/// Traffic selector types (RFC 7296 §3.13.1).
pub mod ts_type {
    pub const IPV4_ADDR: u8 = 7;
    pub const IPV6_ADDR: u8 = 8;
    pub const IPV4_ADDR_RANGE: u8 = 9;
    pub const IPV6_ADDR_RANGE: u8 = 10;
    pub const FQDN: u8 = 11;
    pub const USER_FQDN: u8 = 12;
}
