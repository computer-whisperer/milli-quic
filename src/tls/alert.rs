//! TLS 1.3 alert descriptions (RFC 8446 section 6).

/// TLS alert description codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AlertDescription {
    CloseNotify = 0,
    UnexpectedMessage = 10,
    BadRecordMac = 20,
    DecryptionFailed = 21,
    HandshakeFailure = 40,
    BadCertificate = 42,
    CertificateExpired = 45,
    CertificateUnknown = 46,
    IllegalParameter = 47,
    UnknownCa = 48,
    DecodeError = 50,
    DecryptError = 51,
    ProtocolVersion = 70,
    InsufficientSecurity = 71,
    InternalError = 80,
    MissingExtension = 109,
    UnsupportedExtension = 110,
    NoApplicationProtocol = 120,
}

impl AlertDescription {
    /// Convert from a raw u8 byte.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::CloseNotify),
            10 => Some(Self::UnexpectedMessage),
            20 => Some(Self::BadRecordMac),
            21 => Some(Self::DecryptionFailed),
            40 => Some(Self::HandshakeFailure),
            42 => Some(Self::BadCertificate),
            45 => Some(Self::CertificateExpired),
            46 => Some(Self::CertificateUnknown),
            47 => Some(Self::IllegalParameter),
            48 => Some(Self::UnknownCa),
            50 => Some(Self::DecodeError),
            51 => Some(Self::DecryptError),
            70 => Some(Self::ProtocolVersion),
            71 => Some(Self::InsufficientSecurity),
            80 => Some(Self::InternalError),
            109 => Some(Self::MissingExtension),
            110 => Some(Self::UnsupportedExtension),
            120 => Some(Self::NoApplicationProtocol),
            _ => None,
        }
    }

    /// Convert to raw u8 byte.
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_alert_codes() {
        let codes = [
            AlertDescription::CloseNotify,
            AlertDescription::UnexpectedMessage,
            AlertDescription::BadRecordMac,
            AlertDescription::DecryptionFailed,
            AlertDescription::HandshakeFailure,
            AlertDescription::BadCertificate,
            AlertDescription::CertificateExpired,
            AlertDescription::CertificateUnknown,
            AlertDescription::IllegalParameter,
            AlertDescription::UnknownCa,
            AlertDescription::DecodeError,
            AlertDescription::DecryptError,
            AlertDescription::ProtocolVersion,
            AlertDescription::InsufficientSecurity,
            AlertDescription::InternalError,
            AlertDescription::MissingExtension,
            AlertDescription::UnsupportedExtension,
            AlertDescription::NoApplicationProtocol,
        ];
        for code in codes {
            assert_eq!(AlertDescription::from_u8(code.to_u8()), Some(code));
        }
    }

    #[test]
    fn unknown_alert_code() {
        assert_eq!(AlertDescription::from_u8(255), None);
        assert_eq!(AlertDescription::from_u8(1), None);
    }
}
