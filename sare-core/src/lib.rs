pub mod encryption;
pub mod format;
pub mod hybrid_kem;
pub mod hybrid_sign;
pub mod kdf;
pub mod seed;

use std::fmt;

use encryption::error::EncryptionError;
use format::FormatError;
use hybrid_kem::error::HybridKEMError;
use kdf::error::KDFError;
pub use pem;

#[derive(Debug)]
pub enum CoreErrorKind {
    Format(FormatError),
    Encryption(EncryptionError),
    KDF(KDFError),
    HybridKEM(HybridKEMError),
}

impl fmt::Display for CoreErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CoreErrorKind::Format(err) => write!(f, "Format Error: {}", err),
            CoreErrorKind::Encryption(err) => write!(f, "Encryption Error: {}", err),
            CoreErrorKind::KDF(err) => write!(f, "KDF Error: {}", err),
            CoreErrorKind::HybridKEM(err) => write!(f, "Hybrid KEM Error: {}", err),
        }
    }
}