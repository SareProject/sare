use crate::keys::{HybridKEMAlgorithm, MasterKey};
use sare_core::hybrid_kem::{DHKeyPair, KEMKeyPair};
use sare_core::kdf::PKDF;

pub struct Recipient {
    dh_public_key: Vec<u8>,
    kem_public_key: Vec<u8>,
    algorithm: HybridKEMAlgorithm, // NOTE: To be able to check if recipient's algorithms are
                                   // compatible with ours
}

pub struct Encryptor(MasterKey);

impl Encryptor {
    pub fn new(master_key: MasterKey) -> Self {
        Encryptor(master_key)
    }

    pub fn encrypt_with_passphrase() {}

    pub fn encrypt_with_recipient() {}
}
