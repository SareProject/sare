pub mod certificate;
pub mod encryption;
pub mod keys;
pub mod signing;

use std::io::Error as IoError;

use sare_core::{
    encryption::error::EncryptionError, format::FormatError, hybrid_kem::error::HybridKEMError,
    kdf::KDFError, CoreErrorKind,
};

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
