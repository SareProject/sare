pub mod encryption;
pub mod format;
pub mod hybrid_kem;
pub mod hybrid_sign;
pub mod kdf;
pub mod seed;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PublicKey {
    X25519(Vec<u8>),
    Kyber768(Vec<u8>),
    Ed25519(Vec<u8>),
    Dilithium3(Vec<u8>),
}

impl PublicKey {
    pub fn get_algorithm(&self) -> String {
        match self {
            Self::Kyber768(_) => hybrid_kem::DHAlgorithm::X25519.to_string(),
            Self::X25519(_) => hybrid_kem::KEMAlgorithm::Kyber768.to_string(),
            Self::Ed25519(_) => hybrid_sign::ECAlgorithm::Ed25519.to_string(),
            Self::Dilithium3(_) => hybrid_sign::PQAlgorithm::Dilithium3.to_string(),
        }
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Kyber768(pk) => pk.as_ref(),
            Self::X25519(pk) => pk.as_ref(),
            Self::Ed25519(pk) => pk.as_ref(),
            Self::Dilithium3(pk) => pk.as_ref(),
        }
    }
}
