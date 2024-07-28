pub mod encryption;
pub mod format;
pub mod hybrid_kem;
pub mod hybrid_sign;
pub mod kdf;
pub mod seed;

use encryption::error::EncryptionError;
use format::FormatError;
use hybrid_kem::error::HybridKEMError;
use kdf::error::KDFError;
pub use pem;

pub enum CoreErrorKind {
    Format(FormatError),
    Encryption(EncryptionError),
    KDF(KDFError),
    HybridKEM(HybridKEMError),
}
