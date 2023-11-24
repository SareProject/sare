use ed25519_compact::Error as X25519Error;
use pqc_kyber::KyberError;

#[derive(Debug)]
pub enum ErrSection {
    KEM,
    DH,
}

#[derive(Debug)]
pub enum HybridKEMError {
    InvalidInput(ErrSection),
    Decapsulation(ErrSection),
    RandomBytesGeneration(ErrSection),
    InvalidSeed(ErrSection),
    InvalidSecretKey(ErrSection),
    InvalidPublicKey(ErrSection),
    Unexpected,
}

impl From<KyberError> for HybridKEMError {
    fn from(err: KyberError) -> Self {
        match err {
            KyberError::RandomBytesGeneration => {
                HybridKEMError::RandomBytesGeneration(ErrSection::KEM)
            }
            KyberError::Decapsulation => HybridKEMError::Decapsulation(ErrSection::KEM),
            KyberError::InvalidInput => HybridKEMError::InvalidInput(ErrSection::KEM),
            _ => HybridKEMError::Unexpected,
        }
    }
}

impl From<X25519Error> for HybridKEMError {
    fn from(err: X25519Error) -> Self {
        match err {
            X25519Error::InvalidSeed => HybridKEMError::InvalidSeed(ErrSection::DH),
            X25519Error::InvalidSecretKey => HybridKEMError::InvalidSecretKey(ErrSection::DH),
            X25519Error::InvalidPublicKey => HybridKEMError::InvalidPublicKey(ErrSection::DH),
            _ => HybridKEMError::Unexpected,
        }
    }
}
