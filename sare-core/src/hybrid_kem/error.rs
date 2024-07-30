use std::fmt;

use ed25519_compact::Error as X25519Error;
use pqc_kyber::KyberError;

#[derive(Debug)]
pub enum ErrSection {
    KEM,
    DH,
}

impl fmt::Display for ErrSection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrSection::KEM => write!(f, "KEM"),
            ErrSection::DH => write!(f, "DH"),
        }
    }
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

impl fmt::Display for HybridKEMError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HybridKEMError::InvalidInput(section) => write!(f, "Invalid input in {}", section),
            HybridKEMError::Decapsulation(section) => write!(f, "Decapsulation error in {}", section),
            HybridKEMError::RandomBytesGeneration(section) => write!(f, "Random bytes generation error in {}", section),
            HybridKEMError::InvalidSeed(section) => write!(f, "Invalid seed in {}", section),
            HybridKEMError::InvalidSecretKey(section) => write!(f, "Invalid secret key in {}", section),
            HybridKEMError::InvalidPublicKey(section) => write!(f, "Invalid public key in {}", section),
            HybridKEMError::Unexpected => write!(f, "Unexpected error"),
        }
    }
}

impl From<KyberError> for HybridKEMError {
    fn from(err: KyberError) -> Self {
        match err {
            KyberError::RandomBytesGeneration => {
                HybridKEMError::RandomBytesGeneration(ErrSection::KEM)
            }
            KyberError::Decapsulation => HybridKEMError::Decapsulation(ErrSection::KEM),
            KyberError::InvalidInput => HybridKEMError::InvalidInput(ErrSection::KEM),
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
