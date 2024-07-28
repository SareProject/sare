use hkdf::InvalidLength;
use scrypt::errors::InvalidOutputLen;
use scrypt::errors::InvalidParams;

#[derive(Debug)]
pub enum KDFError {
    InvalidKeyLength,
    InvalidOutputLength,
    InvalidParams,
    Unexpected,
}

impl From<InvalidLength> for KDFError {
    fn from(_: InvalidLength) -> Self {
        KDFError::InvalidKeyLength
    }
}

impl From<InvalidOutputLen> for KDFError {
    fn from(_: InvalidOutputLen) -> Self {
        KDFError::InvalidOutputLength
    }
}

impl From<InvalidParams> for KDFError {
    fn from(_: InvalidParams) -> Self {
        KDFError::InvalidParams
    }
}