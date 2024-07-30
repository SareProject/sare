pub mod certificate;
pub mod encryption;
pub mod keys;
pub mod signing;

use std::fmt;
use std::io::Error as IoError;

use sare_core::{
    encryption::error::EncryptionError, format::FormatError, hybrid_kem::error::HybridKEMError,
    kdf::error::KDFError, CoreErrorKind,
};

#[derive(Debug)]
pub enum SareError {
    IoError(String),
    CoreError(CoreErrorKind),
}

impl From<IoError> for SareError {
    fn from(err: IoError) -> Self {
        SareError::IoError(err.to_string())
    }
}

impl From<FormatError> for SareError {
    fn from(err: FormatError) -> Self {
        SareError::CoreError(CoreErrorKind::Format(err))
    }
}

impl From<EncryptionError> for SareError {
    fn from(err: EncryptionError) -> Self {
        SareError::CoreError(CoreErrorKind::Encryption(err))
    }
}

impl From<KDFError> for SareError {
    fn from(err: KDFError) -> Self {
        SareError::CoreError(CoreErrorKind::KDF(err))
    }
}

impl From<HybridKEMError> for SareError {
    fn from(err: HybridKEMError) -> Self {
        SareError::CoreError(CoreErrorKind::HybridKEM(err))
    }
}

impl fmt::Display for SareError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SareError::IoError(err) => write!(f, "IO Error: {}", err),
            SareError::CoreError(err) => write!(f, "Core Error: {}", err),
        }
    }
}
