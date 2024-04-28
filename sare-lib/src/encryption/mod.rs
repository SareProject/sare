use std::io::{Read, Write};

use sare_core::{
    encryption::{EncryptionAlgorithm, Encryptor as CoreEncryptor},
    kdf::PKDF,
};

use crate::keys::{HybridKEMAlgorithm, MasterKey};

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

    // TODO: Covert Errors to SareError and return
    pub fn encrypt_with_passphrase<R: Read, W: Write>(
        &self,
        mut data: R,
        mut output: W,
        pkdf: PKDF,
        algorithm: EncryptionAlgorithm,
    ) {
        let encryption_key = pkdf.derive_key(32).unwrap();

        // TODO: generate nonce in sare-core::encryption when calling `new` function
        let encryptor = CoreEncryptor::new(encryption_key, vec![0, 0, 0], algorithm);

        match algorithm {
            EncryptionAlgorithm::XCHACHA20POLY1305 => encryptor
                .encrypt_xchacha20poly1305(&mut data, &mut output)
                .unwrap(),
            _ => unimplemented!(),
        };
    }

    pub fn encrypt_with_recipient() {}
}
