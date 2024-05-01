use std::io::{Read, Write};

use sare_core::{
    encryption::{self, EncryptionAlgorithm, Encryptor as CoreEncryptor},
    hybrid_kem::{self, Encapsulation, HybridKEM},
    kdf::{HKDFAlgorithm, HKDF, KDF, PKDF},
};
use secrecy::{ExposeSecret, SecretVec};

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

    // TODO: needs error handling
    pub fn encrypt_with_recipient<R: Read, W: Write>(
        &self,
        mut data: R,
        mut output: W,
        recipient: &Recipient,
        algorithm: EncryptionAlgorithm,
    ) {
        let (dh_keypair, kem_keypair) = self.0.get_encryption_keypair();
        let kem = Encapsulation::new(&recipient.kem_public_key, recipient.algorithm.kem_algorithm);
        let kem_cipher_text = kem.encapsulate().unwrap().cipher_text;

        let hybrid_kem = HybridKEM::new(dh_keypair, kem_keypair);

        let shared_secret = hybrid_kem
            .calculate_raw_shared_key(&kem_cipher_text, &recipient.dh_public_key)
            .unwrap();

        let concated_shared_secrets = SecretVec::new(
            [
                shared_secret.0.expose_secret().as_slice(),
                &shared_secret.1.expose_secret().as_slice(),
            ]
            .concat(),
        );
        let encryption_key = HKDF::new(
            &concated_shared_secrets,
            &PKDF::generate_salt(),
            HKDFAlgorithm::SHA256,
        )
        .expand(None)
        .unwrap();
        // TODO: generate nonce in sare-core::encryption when calling `new` function
        let encryptor = CoreEncryptor::new(encryption_key, vec![0, 0, 0], algorithm);

        match algorithm {
            EncryptionAlgorithm::XCHACHA20POLY1305 => encryptor
                .encrypt_xchacha20poly1305(&mut data, &mut output)
                .unwrap(),
            _ => unimplemented!(),
        };
    }
}
