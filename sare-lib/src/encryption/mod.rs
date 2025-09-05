use std::io::{Read, Seek, Write};

use sare_core::{
    encryption::{Decryptor as CoreDecryptor, EncryptionAlgorithm, Encryptor as CoreEncryptor},
    format::{
        encryption::{EncryptionMetadataFormat, KEMMetadataFormat, PKDFMetadataFormat},
        header::{HeaderFormat, HeaderMetadataFormat},
        signature::SignatureFormat,
    },
    hybrid_kem::{Encapsulation, HybridKEM},
    kdf::{HKDFAlgorithm, PKDFAlgorithm, HKDF, KDF, PKDF},
    sha3::{Digest, Sha3_256},
};
use secrecy::{ExposeSecret, SecretVec};

use super::SARE_VERSION;
use crate::{
    keys::{MasterKey, SharedPublicKey},
    signing, SareError,
};

pub struct Encryptor(MasterKey);

impl Encryptor {
    /// Create a new encryptor with a master key
    pub fn new(master_key: MasterKey) -> Self {
        Self(master_key)
    }

    /// Compute SHA3-256 checksum of a data stream
    pub fn checksum<R: Read>(mut data: R) -> Result<[u8; 32], SareError> {
        let mut hasher = Sha3_256::new();
        let mut buf = vec![0u8; 2_048 * 2_048];
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

    /// Generate a PKDF from a passphrase
    pub fn get_pkdf(
        passphrase: &SecretVec<u8>,
        algorithm: PKDFAlgorithm,
        _scaling_factor: u32,
    ) -> PKDF {
        let salt = PKDF::generate_salt();
        PKDF::new(passphrase, salt, algorithm)
    }

    /// Encrypt data symmetrically using a passphrase
    pub fn encrypt_with_passphrase<R: Read, W: Write>(
        mut data: R,
        mut output: W,
        pkdf: PKDF,
        algorithm: EncryptionAlgorithm,
    ) -> Result<(), SareError> {
        let encryption_key = pkdf.derive_key(32)?;
        let encryptor = CoreEncryptor::new(encryption_key, algorithm);

        let pkdf_metadata = PKDFMetadataFormat {
            pkdf_salt: pkdf.salt,
            pkdf_algorithm: pkdf.algorithm,
        };

        let encryption_metadata = EncryptionMetadataFormat {
            encryption_algorithm: algorithm,
            nonce: Some(encryptor.nonce.to_owned()),
            kem_metadata: None,
            pkdf_metadata: Some(pkdf_metadata),
        };

        let header_metadata = HeaderMetadataFormat {
            signature_metadata: None,
            encryption_metadata,
            comment: None,
        };

        let header = HeaderFormat {
            version: SARE_VERSION,
            metadata: header_metadata,
            signature: None,
        };

        output.write_all(&header.encode())?;

        encryptor.encrypt(&mut data, &mut output)?;

        Ok(())
    }

    /// Encrypt data asymmetrically for a recipient
    pub fn encrypt_with_recipient<R: Read, W: Write>(
        &self,
        mut data: R,
        mut output: W,
        recipient: &SharedPublicKey,
        algorithm: EncryptionAlgorithm,
    ) -> Result<(), SareError> {
        let (dh_keypair, kem_keypair) = self.0.get_encryption_keypair();
        let encryption_pub = &recipient.fullchain_public_key.encryption_public_key;

        let kem = Encapsulation::new(&encryption_pub.kem_public_key, encryption_pub.kem_algorithm);
        let kem_ciphertext = kem.encapsulate()?.cipher_text;

        let hybrid_kem = HybridKEM::new(dh_keypair, kem_keypair);
        let shared_secret =
            hybrid_kem.calculate_raw_shared_key(&kem_ciphertext, &encryption_pub.dh_public_key)?;
        let concated_shared_secrets = SecretVec::new(
            [
                shared_secret.0.expose_secret().as_slice(),
                &shared_secret.1.expose_secret().as_slice(),
            ]
            .concat(),
        );

        let kdf_salt = PKDF::generate_salt();
        let encryption_key = HKDF::new(
            &concated_shared_secrets,
            kdf_salt.to_owned(),
            HKDFAlgorithm::SHA256,
        )
        .expand(None)?;

        let message_checksum = Self::checksum(&mut data)?;
        let signature_header =
            signing::Signing::new(self.0.clone()).sign_attached(&message_checksum);
        let signature = signature_header.signature;

        let kem_metadata = KEMMetadataFormat {
            kem_algorithm: hybrid_kem.kem_keypair.algorithm,
            dh_algorithm: hybrid_kem.dh_keypair.algorithm,
            dh_sender_public_key: hybrid_kem.dh_keypair.public_key,
            hkdf_algorithm: HKDFAlgorithm::SHA256,
            kem_ciphertext,
            kdf_salt,
        };

        let encryptor = CoreEncryptor::new(encryption_key, algorithm);
        let encryption_metadata = EncryptionMetadataFormat {
            encryption_algorithm: algorithm,
            nonce: Some(encryptor.nonce.to_owned()),
            kem_metadata: Some(kem_metadata),
            pkdf_metadata: None,
        };

        let header_metadata = HeaderMetadataFormat {
            encryption_metadata,
            signature_metadata: signature.signature_metadata.clone(),
            comment: None,
        };

        let header = HeaderFormat {
            version: SARE_VERSION,
            metadata: header_metadata,
            signature: Some(signature),
        };

        output.write_all(&header.encode())?;

        encryptor.encrypt(&mut data, &mut output)?;

        Ok(())
    }
}

pub struct Decryptor(MasterKey);

impl Decryptor {
    pub fn new(master_key: MasterKey) -> Self {
        Self(master_key)
    }

    pub fn decode_file_header_and_rewind<R: Read + Seek>(
        encrypted_data: &mut R,
    ) -> Result<HeaderFormat, SareError> {
        let header_bytes = HeaderFormat::peek_header_seek(encrypted_data)?;
        Ok(HeaderFormat::decode(&header_bytes)?)
    }

    pub fn decode_file_header<R: Read>(encrypted_data: &mut R) -> Result<HeaderFormat, SareError> {
        let header_bytes = HeaderFormat::separate_header(encrypted_data)?;
        Ok(HeaderFormat::decode(&header_bytes)?)
    }

    pub fn decrypt_with_passphrase<R: Read, W: Write>(
        passphrase_bytes: SecretVec<u8>,
        mut encrypted_data: R,
        mut output: W,
    ) -> Result<(), SareError> {
        let header = Self::decode_file_header(&mut encrypted_data)?;

        if header.version > SARE_VERSION {
            return Err(SareError::Unexpected(format!(
                "sare version {} or higher is required, your version is {}",
                header.version, SARE_VERSION
            )));
        }

        let pkdf_metadata = header
            .metadata
            .encryption_metadata
            .pkdf_metadata
            .ok_or_else(|| SareError::Unexpected("Missing PKDF metadata".into()))?;

        let pkdf = PKDF::new(
            &passphrase_bytes,
            pkdf_metadata.pkdf_salt,
            pkdf_metadata.pkdf_algorithm,
        );
        let encryption_key = pkdf.derive_key(32)?;

        let algorithm = header.metadata.encryption_metadata.encryption_algorithm;
        let nonce = header
            .metadata
            .encryption_metadata
            .nonce
            .ok_or_else(|| SareError::Unexpected("Missing nonce".into()))?;

        CoreDecryptor::new(encryption_key, nonce, algorithm)
            .decrypt(&mut encrypted_data, &mut output)?;

        Ok(())
    }

    pub fn decrypt_with_recipient<R: Read, W: Write>(
        &self,
        mut encrypted_data: R,
        mut output: W,
    ) -> Result<Option<SignatureFormat>, SareError> {
        let header_bytes = HeaderFormat::separate_header(&mut encrypted_data)?;
        let header = HeaderFormat::decode(&header_bytes)?;
        let encryption_metadata = &header.metadata.encryption_metadata;

        let kem_metadata = encryption_metadata
            .kem_metadata
            .as_ref()
            .ok_or_else(|| SareError::Unexpected("Missing KEM metadata".into()))?;

        let (dh_keypair, kem_keypair) = self.0.get_encryption_keypair();
        let hybrid_kem = HybridKEM::new(dh_keypair, kem_keypair);

        let shared_secret = hybrid_kem.calculate_raw_shared_key(
            &kem_metadata.kem_ciphertext,
            &kem_metadata.dh_sender_public_key,
        )?;

        let concated_shared_secrets = SecretVec::new(
            [
                shared_secret.0.expose_secret().as_slice(),
                shared_secret.1.expose_secret().as_slice(),
            ]
            .concat(),
        );

        let encryption_key = HKDF::new(
            &concated_shared_secrets,
            kem_metadata.kdf_salt.to_owned(),
            HKDFAlgorithm::SHA256,
        )
        .expand(None)?;

        let nonce = encryption_metadata
            .nonce
            .as_ref()
            .ok_or_else(|| SareError::Unexpected("Missing nonce".into()))?;

        CoreDecryptor::new(
            encryption_key,
            nonce.to_owned(),
            encryption_metadata.encryption_algorithm,
        )
        .decrypt(&mut encrypted_data, &mut output)?;

        Ok(header.signature)
    }
}
