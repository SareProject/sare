use crate::keys::{MasterKey, HybridKEMAlgorithm};
use sare_core::hybrid_kem::{DHKeyPair, KEMKeyPair};
use sare_core::kdf::PKDF;

pub struct Recipient {
    dh_public_key: Vec<u8>,
    kem_public_key: Vec<u8>,
    algorithm: HybridKEMAlgorithm, // NOTE: To be able to check if recipient's algorithms are
                                   // compatible with ours
}

pub enum EncryptionType {
    Symmetric(PKDF),
    Asymmetric(MasterKey),
}

pub struct Encryptor(EncryptionType);

impl Encryptor {
    pub fn new() {}

    pub fn encrypt_with_recipient() {}
    pub fn encrypt_with_passphrase() {}
}
