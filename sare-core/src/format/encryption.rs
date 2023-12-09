use serde::{Deserialize, Serialize};

use crate::hybrid_kem::{DHAlgorithm, KEMAlgorithm};
use crate::kdf::{HKDFAlgorithm, PKDFAlgorithm};

//TODO: Define in encryption module
#[derive(Serialize, Deserialize)]
pub enum EncryptionAlgorithm {
    AES256GCM,
}

#[derive(Serialize, Deserialize)]
pub struct KEMMetadataFormat {
    kem_algorithm: KEMAlgorithm,
    dh_algorithm: DHAlgorithm,
    hkdf_algorithm: HKDFAlgorithm,
    kem_ciphertext: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct EncryptionMetadataFormat {
    pub(crate) encryption_algorithm: EncryptionAlgorithm,
    #[serde(skip_serializing_if = "Option::is_none", flatten)]
    pub(crate) kem_metadata: Option<KEMMetadataFormat>,
    #[serde(skip_serializing_if = "Option::is_none", flatten)]
    pub(crate) pkdf_metadata: Option<PKDFMetadataFormat>,
}

#[derive(Serialize, Deserialize)]
pub struct PKDFMetadataFormat {
    pub(crate) pkdf_algorithm: PKDFAlgorithm,
    pub(crate) pkdf_workfactor_scale: u32,
}
