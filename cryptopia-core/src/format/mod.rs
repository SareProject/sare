use serde::{Deserialize, Serialize};

use crate::hybrid_kem::{DHAlgorithm, KEMAlgorithm};
use crate::hybrid_sign::{ECAlgorithm, PQAlgorithm};
use crate::kdf::{HKDFAlgorithm, PKDFAlgorithm};

//TODO: Define in encryption module
#[derive(Serialize, Deserialize)]
pub struct EncryptionAlgorithm();

const MAGIC_BYTES: &[u8; 9] = b"CRYPTOPIA";

#[derive(Serialize, Deserialize)]
pub struct SignatureMetadataFormat {
    ec_algorithm: ECAlgorithm,
    pq_algorithm: PQAlgorithm,
}

#[derive(Serialize, Deserialize)]
pub struct KEMMetadataFormat {
    kem_algorithm: KEMAlgorithm,
    dh_algorithm: DHAlgorithm,
    hkdf_algorithm: HKDFAlgorithm,
}

#[derive(Serialize, Deserialize)]
pub struct EncryptionMetadataFormat {
    encryption_algorithm: EncryptionAlgorithm,
}

#[derive(Serialize, Deserialize)]
pub struct MetadataFormat {
    kem_metadata: KEMMetadataFormat,
    signature_metadata: Option<SignatureMetadataFormat>,
    encryption_metadata: EncryptionMetadataFormat,
    pkdf_algorithm: Option<PKDFAlgorithm>,
    comment: Option<String>,
}

pub struct HeaderFormat {
    version: u32,
    metadata_length: u32,
    metadata: Vec<u8>,
    signature_length: u32,
    signature: Vec<u8>,
}
