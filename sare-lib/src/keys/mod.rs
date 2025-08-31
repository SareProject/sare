use super::certificate::Certificate;
pub use sare_core::encryption::{EncryptionAlgorithm, KeyWrap};
use sare_core::format::certificate::CertificateFormat;
use sare_core::format::certificate::ValidationCertificateFormat;
pub use sare_core::format::encryption::*;
pub use sare_core::format::keys::*;
use sare_core::format::signature::SignatureFormat;
pub use sare_core::format::{EncodablePublic, EncodableSecret};
pub use sare_core::hybrid_kem::{DHAlgorithm, DHKeyPair, KEMAlgorithm, KEMKeyPair};
pub use sare_core::hybrid_sign::{ECAlgorithm, ECKeyPair, PQAlgorithm, PQKeyPair};
use sare_core::kdf::{PKDFAlgorithm, KDF, PKDF};
use sare_core::pem;
pub use sare_core::seed::Seed;
use secrecy::{ExposeSecret, SecretString, SecretVec};
use std::io::{BufReader, Read, Write};

use crate::SareError;

pub const RECOMENDED_PKDF_PARAMS: PKDFAlgorithm = PKDFAlgorithm::Scrypt(17, 8, 12);

#[derive(Clone, Copy)]
pub struct HybridSignAlgorithm {
    ec_algorithm: ECAlgorithm,
    pq_algorithm: PQAlgorithm,
}

impl Default for HybridSignAlgorithm {
    fn default() -> Self {
        HybridSignAlgorithm {
            ec_algorithm: ECAlgorithm::Ed25519,
            pq_algorithm: PQAlgorithm::Dilithium3,
        }
    }
}

impl HybridSignAlgorithm {
    pub fn from_string(algo: String) -> Self {
        match algo.as_str() {
            "ED25519_DILITHIUM3" => HybridSignAlgorithm {
                ec_algorithm: ECAlgorithm::Ed25519,
                pq_algorithm: PQAlgorithm::Dilithium3,
            },
            _ => HybridSignAlgorithm::default(),
        }
    }
}

#[derive(Clone, Copy)]
pub struct HybridKEMAlgorithm {
    pub dh_algorithm: DHAlgorithm,
    pub kem_algorithm: KEMAlgorithm,
}

impl Default for HybridKEMAlgorithm {
    fn default() -> Self {
        HybridKEMAlgorithm {
            dh_algorithm: DHAlgorithm::X25519,
            kem_algorithm: KEMAlgorithm::Kyber768,
        }
    }
}

impl HybridKEMAlgorithm {
    pub fn from_string(algo: String) -> Self {
        match algo.as_str() {
            "X25519_KYBER768" => HybridKEMAlgorithm {
                dh_algorithm: DHAlgorithm::X25519,
                kem_algorithm: KEMAlgorithm::Kyber768,
            },
            _ => HybridKEMAlgorithm::default(),
        }
    }
}

pub struct MasterKey {
    hybrid_kem_algorithm: HybridKEMAlgorithm,
    hybrid_sign_algorithm: HybridSignAlgorithm,
    master_seed: Seed,
}

impl MasterKey {
    pub fn generate(
        hybrid_kem_algorithm: HybridKEMAlgorithm,
        hybrid_sign_algorithm: HybridSignAlgorithm,
    ) -> Self {
        let master_seed = Seed::generate();

        MasterKey {
            hybrid_kem_algorithm,
            hybrid_sign_algorithm,
            master_seed,
        }
    }

    pub fn clone(&self) -> Self {
        MasterKey {
            hybrid_kem_algorithm: self.hybrid_kem_algorithm,
            hybrid_sign_algorithm: self.hybrid_sign_algorithm,
            master_seed: Seed::new(self.master_seed.clone_raw_seed()),
        }
    }

    pub fn export<W: Write>(
        &self,
        passphrase_bytes: Option<SecretVec<u8>>,
        mut output: W,
    ) -> Result<(), SareError> {
        match passphrase_bytes {
            Some(passphrase) => {
                let pkdf_salt = PKDF::generate_salt();

                let pkdf = PKDF::new(&passphrase, &pkdf_salt, RECOMENDED_PKDF_PARAMS);

                let pkdf_metadata = PKDFMetadataFormat {
                    pkdf_salt,
                    pkdf_algorithm: RECOMENDED_PKDF_PARAMS,
                };

                // NOTE: Because length is exactly 32bytes and parsable into [u8; 32] KeyWrap won't return an error
                let derived_key = pkdf.derive_key(32).unwrap();
                let keywrap = KeyWrap::new(derived_key).unwrap();

                let encrypted_seed = keywrap.wrap(self.master_seed.get_raw_seed()).unwrap();

                let encryption_metadata = EncryptionMetadataFormat {
                    kem_metadata: None,
                    nonce: None,
                    encryption_algorithm: EncryptionAlgorithm::AES256KW,
                    pkdf_metadata: Some(pkdf_metadata),
                };

                // TODO: impl `From` in sare_core::format::keys
                let secret_key_format = SecretKeyFormat {
                    ec_algorithm: self.hybrid_sign_algorithm.ec_algorithm,
                    pq_algorithm: self.hybrid_sign_algorithm.pq_algorithm,
                    dh_algorithm: self.hybrid_kem_algorithm.dh_algorithm,
                    kem_algorithm: self.hybrid_kem_algorithm.kem_algorithm,
                    master_seed: SecretVec::from(encrypted_seed),
                    encryption_metadata: Some(encryption_metadata),
                };

                output.write_all(secret_key_format.encode_pem().expose_secret().as_bytes())?;
            }
            None => {
                // TODO: impl `From` in sare_core::format::keys
                let secret_key_format = SecretKeyFormat {
                    ec_algorithm: self.hybrid_sign_algorithm.ec_algorithm,
                    pq_algorithm: self.hybrid_sign_algorithm.pq_algorithm,
                    dh_algorithm: self.hybrid_kem_algorithm.dh_algorithm,
                    kem_algorithm: self.hybrid_kem_algorithm.kem_algorithm,
                    master_seed: self.master_seed.clone_raw_seed(),
                    encryption_metadata: None,
                };

                output.write_all(secret_key_format.encode_pem().expose_secret().as_bytes())?;
            }
        }

        Ok(())
    }

    pub fn is_encrypted(secret_key_format: &SecretKeyFormat) -> bool {
        secret_key_format.encryption_metadata.is_some()
    }

    pub fn decode_pem<R: Read>(serialized_master_key: R) -> Result<SecretKeyFormat, SareError> {
        let mut reader = BufReader::new(serialized_master_key);

        let mut string_buf = String::new();
        reader.read_to_string(&mut string_buf)?;
        Ok(SecretKeyFormat::decode_pem(SecretString::from(string_buf))?)
    }

    pub fn import(
        decoded_master_key_format: SecretKeyFormat,
        passphrase_bytes: Option<SecretVec<u8>>,
    ) -> Result<Self, SareError> {
        let hybrid_sign_algorithm = HybridSignAlgorithm {
            ec_algorithm: decoded_master_key_format.ec_algorithm,
            pq_algorithm: decoded_master_key_format.pq_algorithm,
        };

        let hybrid_kem_algorithm = HybridKEMAlgorithm {
            dh_algorithm: decoded_master_key_format.dh_algorithm,
            kem_algorithm: decoded_master_key_format.kem_algorithm,
        };

        match passphrase_bytes {
            Some(passphrase) => {
                // NOTE: We'll check if it's encrypted first in CLI or other interfaces
                // TODO: Mention this on code docs later
                let encryption_metadata = decoded_master_key_format.encryption_metadata.unwrap();
                // NOTE: It will not be None if it's encrypted
                let pkdf_metadata = encryption_metadata.pkdf_metadata.unwrap();

                let pkdf = PKDF::new(
                    &passphrase,
                    &pkdf_metadata.pkdf_salt,
                    pkdf_metadata.pkdf_algorithm,
                );

                let derived_key = pkdf.derive_key(32)?;

                let keywrap = KeyWrap::new(derived_key)?;

                let decrypted_master_seed =
                    keywrap.dewrap(&decoded_master_key_format.master_seed)?;

                Ok(MasterKey {
                    hybrid_sign_algorithm,
                    hybrid_kem_algorithm,
                    master_seed: Seed::new(decrypted_master_seed),
                })
            }
            None => Ok(MasterKey {
                hybrid_sign_algorithm,
                hybrid_kem_algorithm,
                master_seed: Seed::new(decoded_master_key_format.master_seed),
            }),
        }
    }

    pub fn get_signing_keypair(&self) -> (ECKeyPair, PQKeyPair) {
        let ec_algorithm = self.hybrid_sign_algorithm.ec_algorithm;
        let pq_algorithm = self.hybrid_sign_algorithm.pq_algorithm;

        let ec_keypair = ECKeyPair::from_seed(&self.master_seed, ec_algorithm);
        let pq_keypair = PQKeyPair::from_seed(&self.master_seed, pq_algorithm);

        (ec_keypair, pq_keypair)
    }

    pub fn get_encryption_keypair(&self) -> (DHKeyPair, KEMKeyPair) {
        let dh_algorithm = self.hybrid_kem_algorithm.dh_algorithm;
        let kem_algorithm = self.hybrid_kem_algorithm.kem_algorithm;

        let dh_keypair = DHKeyPair::from_seed(&self.master_seed, dh_algorithm);
        let kem_keypair = KEMKeyPair::from_seed(&self.master_seed, kem_algorithm);

        (dh_keypair, kem_keypair)
    }

    pub fn get_signing_public_key(&self) -> SignaturePublicKeyFormat {
        let (ec_keypair, pq_keypair) = self.get_signing_keypair();

        SignaturePublicKeyFormat::from_keypairs(ec_keypair, pq_keypair)
    }

    pub fn get_encryption_public_key(&self) -> EncryptionPublicKeyFormat {
        let (dh_keypair, kem_keypair) = self.get_encryption_keypair();

        EncryptionPublicKeyFormat::from_keypairs(dh_keypair, kem_keypair)
    }

    pub fn export_signature_public<W: Write>(&self, mut output: W) -> Result<(), SareError> {
        let signature_public_key = self.get_signing_public_key();

        output.write_all(signature_public_key.encode_pem().as_bytes())?;
        Ok(())
    }

    pub fn export_encryption_public<W: Write>(&self, mut output: W) -> Result<(), SareError> {
        let encryption_public_key = self.get_signing_public_key();

        output.write_all(encryption_public_key.encode_pem().as_bytes())?;
        Ok(())
    }

    fn get_fullchain_public_key(&self) -> FullChainPublicKeyFormat {
        let signature_public_key = self.get_signing_public_key();
        let encryption_public_key = self.get_encryption_public_key();

        let fullchain_public_key = FullChainPublicKeyFormat {
            signature_public_key,
            encryption_public_key,
        };

        fullchain_public_key
    }

    pub fn export_public<W: Write>(&self, mut output: W) -> Result<[u8; 32], SareError> {
        let fullchain_public_key = self.get_fullchain_public_key();

        output.write_all(fullchain_public_key.encode_pem().as_bytes())?;
        Ok(fullchain_public_key.calculate_fingerprint())
    }

    pub fn get_fullchain_public_fingerprint(&self) -> [u8; 32] {
        self.get_fullchain_public_key().calculate_fingerprint()
    }

    pub fn get_fullchain_private_fingerprint(&self) -> Vec<u8> {
        SecretKeyFormat::calculate_fingerprint(self.master_seed.clone_raw_seed())
    }
}

#[derive(Clone)]
pub struct SharedPublicKey {
    pub fullchain_public_key: FullChainPublicKeyFormat,
    pub validation_certificate: Option<Certificate>,
}

impl SharedPublicKey {
    pub fn new(fullchain: FullChainPublicKeyFormat, validation: Option<Certificate>) -> Self {
        SharedPublicKey {
            fullchain_public_key: fullchain,
            validation_certificate: validation,
        }
    }

    pub fn from_pem(pem_data: String) -> Result<Self, SareError> {
        // Parse all PEM blocks at once
        let all_pems =
            pem::parse_many(&pem_data).map_err(|e| SareError::Unexpected(e.to_string()))?;

        let mut fullchain_public_key: Option<FullChainPublicKeyFormat> = None;
        let mut validation_certificate: Option<Certificate> = None;

        for block in all_pems {
            match block.tag() {
                sare_core::format::keys::FULLCHAIN_PUBLIC_KEY_PEM_TAG => {
                    fullchain_public_key =
                        Some(FullChainPublicKeyFormat::decode_bson(&block.contents())?);
                }
                sare_core::format::certificate::VALIDATION_PEM_TAG => {
                    validation_certificate = Some(Certificate::decode_bson(&block.contents())?)
                }
                _ => {}
            }
        }

        let fullchain_public_key = fullchain_public_key.ok_or(SareError::Unexpected(
            "Recipient's PublicKey is Missing".to_string(),
        ))?;

        Ok(SharedPublicKey {
            fullchain_public_key,
            validation_certificate,
        })
    }

    pub fn export<W: Write>(&self, mut output: W) -> Result<[u8; 32], SareError> {
        let fullchain_public_key = &self.fullchain_public_key;

        output.write_all(fullchain_public_key.encode_pem().as_bytes())?;

        if let Some(validation_certificate) = &self.validation_certificate {
            validation_certificate.export(output)?;
        }

        Ok(fullchain_public_key.calculate_fingerprint())
    }
}
