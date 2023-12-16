use serde::{Deserialize, Serialize};

use crate::encryption::EncryptionAlgorithm;
use crate::hybrid_kem::{DHAlgorithm, KEMAlgorithm};
use crate::kdf::{HKDFAlgorithm, PKDFAlgorithm};

#[derive(Serialize, Deserialize)]
pub struct KEMMetadataFormat {
    kem_algorithm: KEMAlgorithm,
    dh_algorithm: DHAlgorithm,
    dh_sender_public_key: Vec<u8>,
    hkdf_algorithm: HKDFAlgorithm,
    kem_ciphertext: Vec<u8>,
    kem_salt: [u8; 8],
}

#[derive(Serialize, Deserialize)]
pub struct EncryptionMetadataFormat {
    pub encryption_algorithm: EncryptionAlgorithm,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none", flatten)]
    pub kem_metadata: Option<KEMMetadataFormat>,
    #[serde(skip_serializing_if = "Option::is_none", flatten)]
    pub pkdf_metadata: Option<PKDFMetadataFormat>,
}

#[derive(Serialize, Deserialize)]
pub struct PKDFMetadataFormat {
    pub pkdf_salt: [u8; 8],
    pub pkdf_algorithm: PKDFAlgorithm,
}
