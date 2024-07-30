use std::fmt;

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

impl fmt::Display for KDFError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KDFError::InvalidKeyLength => write!(f, "Invalid key length"),
            KDFError::InvalidOutputLength => write!(f, "Invalid output length"),
            KDFError::InvalidParams => write!(f, "Invalid parameters"),
            KDFError::Unexpected => write!(f, "Unexpected error"),
        }
    }
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