use std::io::{Read, Seek, SeekFrom, Write};

use sare_core::{
    encryption::{Decryptor as CoreDecryptor, EncryptionAlgorithm, Encryptor as CoreEncryptor},
    format::{
        encryption::{EncryptionMetadataFormat, KEMMetadataFormat, PKDFMetadataFormat},
        header::{HeaderFormat, HeaderMetadataFormat},
        signature::{SignatureFormat, SignatureHeaderFormat, SignatureMetadataFormat},
    },
    hybrid_kem::{DiffieHellman, Encapsulation, HybridKEM},
    kdf::{HKDF, HKDFAlgorithm, KDF, PKDF, PKDFAlgorithm},
    sha3::{Digest, Sha3_256},
};
use secrecy::{ExposeSecret, SecretVec};

use super::SARE_VERSION;
use crate::{
    SareError,
    keys::{MasterKey, SharedPublicKey},
    signing,
};

/// Domain separator so a file signature can never be replayed
/// as a certificate or a detached file signature
const CHECKSUM_CONTEXT: &[u8] = b"SARE ENCRYPTED FILE CHECKSUM";

/// Merge the unsigned header and the plaintext checksum into the message
/// covered by the signature of an encrypted file
fn merge_signed_message(unsigned_header: &[u8], plaintext_checksum: &[u8; 32]) -> Vec<u8> {
    [
        unsigned_header,
        plaintext_checksum.as_slice(),
        CHECKSUM_CONTEXT,
    ]
    .concat()
}

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
    pub fn get_pkdf<'a>(
        passphrase: &'a SecretVec<u8>,
        algorithm: PKDFAlgorithm,
        _scaling_factor: u32,
    ) -> PKDF<'a> {
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
    pub fn encrypt_with_recipient<R: Read + Seek, W: Write>(
        &self,
        mut data: R,
        mut output: W,
        recipient: &SharedPublicKey,
        algorithm: EncryptionAlgorithm,
    ) -> Result<(), SareError> {
        let (dh_keypair, _) = self.0.get_encryption_keypair();
        let encryption_pub = &recipient.fullchain_public_key.encryption_public_key;

        // The encapsulated secret is the shared secret of the sender,
        // only the recipient can decapsulate the cipher text back into it
        let kem = Encapsulation::new(&encryption_pub.kem_public_key, encryption_pub.kem_algorithm);
        let encapsulated_secret = kem.encapsulate()?;
        let kem_ciphertext = encapsulated_secret.cipher_text;

        let diffie_hellman = DiffieHellman::new(&dh_keypair, &encryption_pub.dh_public_key);
        let concated_shared_secrets = SecretVec::new(
            [
                diffie_hellman
                    .calculate_shared_key()?
                    .expose_secret()
                    .as_slice(),
                encapsulated_secret
                    .shared_secret
                    .expose_secret()
                    .as_slice(),
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

        let encryptor = CoreEncryptor::new(encryption_key, algorithm);

        let kem_metadata = KEMMetadataFormat {
            kem_algorithm: encryption_pub.kem_algorithm,
            dh_algorithm: encryption_pub.dh_algorithm,
            dh_sender_public_key: dh_keypair.public_key,
            hkdf_algorithm: HKDFAlgorithm::SHA256,
            kem_ciphertext,
            kdf_salt,
        };

        let (ec_keypair, pq_keypair) = self.0.get_signing_keypair();
        let signature_metadata = SignatureMetadataFormat {
            ec_algorithm: ec_keypair.algorithm,
            pq_algorithm: pq_keypair.algorithm,
        };

        let encryption_metadata = EncryptionMetadataFormat {
            encryption_algorithm: algorithm,
            nonce: Some(encryptor.nonce.to_owned()),
            kem_metadata: Some(kem_metadata),
            pkdf_metadata: None,
        };

        let header_metadata = HeaderMetadataFormat {
            encryption_metadata,
            signature_metadata: Some(signature_metadata),
            comment: None,
        };

        // The signature covers the header without the signature itself,
        // so the signed bytes are exactly the header the recipient rebuilds
        let unsigned_header = HeaderFormat {
            version: SARE_VERSION,
            metadata: header_metadata,
            signature: None,
        };

        // First pass: checksum of the plaintext, then rewind for the encryption pass
        let input_position = data.stream_position()?;
        let plaintext_checksum = Self::checksum(&mut data)?;
        data.seek(SeekFrom::Start(input_position))?;

        let unsigned_header_bytes = unsigned_header.encode();
        let signed_message = merge_signed_message(&unsigned_header_bytes, &plaintext_checksum);
        let signature = signing::Signing::new(self.0.clone())
            .sign_detached(&signed_message)
            .signature;

        let mut header = unsigned_header;
        header.signature = Some(signature);

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

        if header.version > SARE_VERSION {
            return Err(SareError::Unexpected(format!(
                "sare version {} or higher is required, your version is {}",
                header.version, SARE_VERSION
            )));
        }

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
                &shared_secret.1.expose_secret().as_slice(),
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

        // The checksum of the plaintext is computed while the payload is decrypted
        let mut checksum_writer = ChecksumWriter::new(&mut output);

        CoreDecryptor::new(
            encryption_key,
            nonce.to_owned(),
            encryption_metadata.encryption_algorithm,
        )
        .decrypt(&mut encrypted_data, &mut checksum_writer)?;

        if let Some(signature) = &header.signature {
            // The signature covers the unsigned header and the plaintext checksum,
            // both are rebuilt from the file and the decrypted payload
            let unsigned_header_bytes = HeaderFormat::rebuild_unsigned_header(&header_bytes)?;
            let signed_message =
                merge_signed_message(&unsigned_header_bytes, &checksum_writer.checksum());

            let signature_header = SignatureHeaderFormat {
                version: header.version,
                signature: signature.clone(),
            };

            if !signing::Signing::verify_detached(&signature_header, &signed_message)? {
                return Err(SareError::Unexpected(
                    "Signature of the file is invalid".into(),
                ));
            }
        }

        Ok(header.signature)
    }
}

/// A writer wrapper that hashes everything that passes through it,
/// so the decrypted payload and its checksum are produced in a single pass
struct ChecksumWriter<W: Write> {
    inner: W,
    hasher: Sha3_256,
}

impl<W: Write> ChecksumWriter<W> {
    fn new(inner: W) -> Self {
        ChecksumWriter {
            inner,
            hasher: Sha3_256::new(),
        }
    }

    fn checksum(&self) -> [u8; 32] {
        let digest = self.hasher.clone().finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }
}

impl<W: Write> Write for ChecksumWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let write_count = self.inner.write(buf)?;
        self.hasher.update(&buf[..write_count]);

        Ok(write_count)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}
