pub mod encryption;
pub mod format;
pub mod hybrid_kem;
pub mod hybrid_sign;
pub mod kdf;
pub mod seed;

#[derive(Copy, Clone, Debug)]
pub enum PublicKey {
    X25519([u8; 32]),
    Kyber768([u8; 1184]),
    Ed25519([u8; 32]),
    Dilithium3([u8; 1952]),
}

impl PublicKey {
    fn to_vec(&self) -> Vec<u8> {
        match self {
            Self::Kyber768(pk) => pk.to_vec(),
            Self::X25519(pk) => pk.to_vec(),
            Self::Ed25519(pk) => pk.to_vec(),
            Self::Dilithium3(pk) => pk.to_vec(),
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
