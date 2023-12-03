use crate::hybrid_kem::{DHAlgorithm, KEMAlgorithm};
use crate::hybrid_sign::{ECAlgorithm, PQAlgorithm};
use crate::kdf::{HKDFAlgorithm, PKDFAlgorithm};

//TODO: Define in encryption module
pub struct EncryptionAlgorithm();

const MAGIC_BYTES: &[u8; 9] = b"CRYPTOPIA";

pub struct SignatureMetadataFormat {
    ec_algorithm: ECAlgorithm,
    pq_algorithm: PQAlgorithm,
}

pub struct KEMMetadataFormat {
    kem_algorithm: KEMAlgorithm,
    dh_algorithm: DHAlgorithm,
    hkdf_algorithm: HKDFAlgorithm,
}

pub struct EncryptionMetadataFormat {
    encryption_algorithm: EncryptionAlgorithm,
}

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
