use ed25519_compact::Error as ED25519Error;

#[derive(Debug)]
pub enum ErrSection {
    EC,
    PQ,
}

#[derive(Debug)]
pub enum HybridSignError {
    InvalidSecretKey(ErrSection),
    InvalidPublicKey(ErrSection),
    Unexpected,
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
