use serde::{Deserialize, Serialize};

use crate::encryption::EncryptionAlgorithm;
use crate::hybrid_kem::{DHAlgorithm, KEMAlgorithm};
use crate::kdf::{HKDFAlgorithm, PKDFAlgorithm};

#[derive(Clone, Serialize, Deserialize)]
pub struct KEMMetadataFormat {
    pub kem_algorithm: KEMAlgorithm,
    pub dh_algorithm: DHAlgorithm,
    pub dh_sender_public_key: Vec<u8>,
    pub hkdf_algorithm: HKDFAlgorithm,
    pub kem_ciphertext: Vec<u8>,
    pub kdf_salt: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct EncryptionMetadataFormat {
    pub encryption_algorithm: EncryptionAlgorithm,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none", flatten)]
    pub kem_metadata: Option<KEMMetadataFormat>,
    #[serde(skip_serializing_if = "Option::is_none", flatten)]
    pub pkdf_metadata: Option<PKDFMetadataFormat>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct PKDFMetadataFormat {
    pub pkdf_salt: Vec<u8>,
    pub pkdf_algorithm: PKDFAlgorithm,
}
