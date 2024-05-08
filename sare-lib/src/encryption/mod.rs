use std::io::{Read, Write};

use sare_core::{
    encryption::{EncryptionAlgorithm, Encryptor as CoreEncryptor},
    hybrid_kem::{Encapsulation, HybridKEM},
    kdf::{HKDFAlgorithm, HKDF, KDF, PKDF},
};
use secrecy::{ExposeSecret, SecretVec};

use crate::{
    keys::{HybridKEMAlgorithm, MasterKey},
    SareError,
};

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

    pub fn encrypt_with_passphrase<R: Read, W: Write>(
        &self,
        mut data: R,
        mut output: W,
        pkdf: PKDF,
        algorithm: EncryptionAlgorithm,
    ) -> Result<(), SareError> {
        let encryption_key = pkdf.derive_key(32)?;

        let encryptor = CoreEncryptor::new(encryption_key, algorithm);

        match algorithm {
            EncryptionAlgorithm::XCHACHA20POLY1305 => {
                encryptor.encrypt_xchacha20poly1305(&mut data, &mut output)?
            }
            _ => unimplemented!(),
        };

        Ok(())
    }

    // TODO: needs error handling
    pub fn encrypt_with_recipient<R: Read, W: Write>(
        &self,
        mut data: R,
        mut output: W,
        recipient: &Recipient,
        algorithm: EncryptionAlgorithm,
    ) -> Result<(), SareError> {
        let (dh_keypair, kem_keypair) = self.0.get_encryption_keypair();
        let kem = Encapsulation::new(&recipient.kem_public_key, recipient.algorithm.kem_algorithm);
        let kem_cipher_text = kem.encapsulate()?.cipher_text;

        let hybrid_kem = HybridKEM::new(dh_keypair, kem_keypair);

        let shared_secret =
            hybrid_kem.calculate_raw_shared_key(&kem_cipher_text, &recipient.dh_public_key)?;

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
        .expand(None)?;

        let encryptor = CoreEncryptor::new(encryption_key, algorithm);

        match algorithm {
            EncryptionAlgorithm::XCHACHA20POLY1305 => {
                encryptor.encrypt_xchacha20poly1305(&mut data, &mut output)?
            }
            _ => unimplemented!(),
        };
        Ok(())
    }
}
