use std::io::{Read, Write};

use sare_core::{
    encryption::{self, EncryptionAlgorithm, Encryptor as CoreEncryptor},
    format::{
        encryption::{EncryptionMetadataFormat, KEMMetadataFormat, PKDFMetadataFormat},
        header::{HeaderFormat, HeaderMetadataFormat},
        signature,
    },
    hybrid_kem::{Encapsulation, HybridKEM},
    kdf::{HKDFAlgorithm, HKDF, KDF, PKDF},
    sha3::{Digest, Sha3_256},
};
use secrecy::{ExposeSecret, SecretVec};

use crate::{
    keys::{HybridKEMAlgorithm, MasterKey, SharedPublicKey},
    signing, SareError,
};

pub struct Encryptor(MasterKey);

impl Encryptor {
    pub fn checksum<R: Read>(mut data: R) -> Result<[u8; 32], SareError> {
        let mut hasher = Sha3_256::new();
        let mut buf = vec![0u8; 2048 * 2048];
        loop {
            let n = data.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);

        Ok(out)
    }

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
        recipient: &SharedPublicKey,
        algorithm: EncryptionAlgorithm,
    ) -> Result<(), SareError> {
        let (dh_keypair, kem_keypair) = self.0.get_encryption_keypair();

        let encryption_public_key = recipient
            .fullchain_public_key
            .encryption_public_key
            .to_owned();

        let kem = Encapsulation::new(
            &encryption_public_key.kem_public_key,
            encryption_public_key.kem_algorithm,
        );
        let kem_cipher_text = kem.encapsulate()?.cipher_text;

        let hybrid_kem = HybridKEM::new(dh_keypair, kem_keypair);

        let shared_secret = hybrid_kem
            .calculate_raw_shared_key(&kem_cipher_text, &encryption_public_key.dh_public_key)?;

        let concated_shared_secrets = SecretVec::new(
            [
                shared_secret.0.expose_secret().as_slice(),
                &shared_secret.1.expose_secret().as_slice(),
            ]
            .concat(),
        );

        let kdf_salt = PKDF::generate_salt();
        let encryption_key =
            HKDF::new(&concated_shared_secrets, &kdf_salt, HKDFAlgorithm::SHA256).expand(None)?;

        let message_checksum = Self::checksum(&mut data)?;
        let signature = signing::Signing::new(self.0.clone()).sign_attached(&message_checksum);
        let signature_metadata = signature.signature_metadata.to_owned();

        let kem_metadata = KEMMetadataFormat {
            kem_algorithm: hybrid_kem.kem_keypair.algorithm,
            dh_algorithm: hybrid_kem.dh_keypair.algorithm,
            dh_sender_public_key: hybrid_kem.dh_keypair.public_key,
            hkdf_algorithm: HKDFAlgorithm::SHA256,
            kem_ciphertext: kem_cipher_text,
            kdf_salt: kdf_salt,
        };

        let signature_metadata = signature_metadata;

        let encryptor = CoreEncryptor::new(encryption_key, algorithm);

        let encryption_metadata = EncryptionMetadataFormat {
            encryption_algorithm: algorithm,
            nonce: Some(encryptor.nonce.to_owned()),
            kem_metadata: Some(kem_metadata.to_owned()),
            pkdf_metadata: None,
        };

        let header_metadata = HeaderMetadataFormat {
            encryption_metadata,
            kem_metadata: Some(kem_metadata),
            signature_metadata,
            comment: None,
        };

        let header = HeaderFormat {
            version: 1,
            metadata: header_metadata,
            signature: Some(signature),
        };

        let encoded_header = header.encode();

        output.write_all(&encoded_header)?;

        match algorithm {
            EncryptionAlgorithm::XCHACHA20POLY1305 => {
                encryptor.encrypt_xchacha20poly1305(&mut data, &mut output)?
            }
            _ => unimplemented!(),
        };
        Ok(())
    }
}
