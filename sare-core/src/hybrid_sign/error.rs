use std::fmt;

use ed25519_compact::Error as ED25519Error;

#[derive(Debug)]
pub enum ErrSection {
    EC,
    PQ,
}

impl fmt::Display for ErrSection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrSection::EC => write!(f, "EC"),
            ErrSection::PQ => write!(f, "PQ"),
        }
    }
}

#[derive(Debug)]
pub enum HybridSignError {
    InvalidSecretKey(ErrSection),
    InvalidPublicKey(ErrSection),
    Unexpected,
}

impl fmt::Display for HybridSignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HybridSignError::InvalidSecretKey(section) => write!(f, "Invalid secret key in {}", section),
            HybridSignError::InvalidPublicKey(section) => write!(f, "Invalid public key in {}", section),
            HybridSignError::Unexpected => write!(f, "Unexpected error"),
        }
    }
}

impl From<ED25519Error> for HybridSignError {
    fn from(err: ED25519Error) -> Self {
        match err {
            ED25519Error::InvalidSecretKey => HybridSignError::InvalidSecretKey(ErrSection::EC),
            ED25519Error::InvalidPublicKey => HybridSignError::InvalidPublicKey(ErrSection::EC),
            _ => HybridSignError::Unexpected,
        }
    }
}
