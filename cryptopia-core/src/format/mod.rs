use bson::{bson, Bson};
use serde::{Deserialize, Serialize};

use crate::hybrid_kem::{DHAlgorithm, KEMAlgorithm};
use crate::hybrid_sign::{ECAlgorithm, PQAlgorithm};
use crate::kdf::{HKDFAlgorithm, PKDFAlgorithm};

//TODO: Define in encryption module
#[derive(Serialize, Deserialize)]
pub enum EncryptionAlgorithm {
    AES256GCM,
}

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
pub struct PKDFMetadataFormat {
    pkdf_algorithm: PKDFAlgorithm,
    pkdf_workfactor_scale: u32,
}

#[derive(Serialize, Deserialize)]
pub struct MetadataFormat {
    kem_metadata: Option<KEMMetadataFormat>,
    signature_metadata: Option<SignatureMetadataFormat>,
    encryption_metadata: EncryptionMetadataFormat,
    pkdf_metadata: Option<PKDFMetadataFormat>,
    comment: Option<String>,
}

impl MetadataFormat {
    pub fn encode(&self) -> Vec<u8> {
        bson::to_vec(&self).unwrap()
    }
}

pub struct HeaderFormat {
    version: u32,
    metadata_length: u32,
    metadata: Vec<u8>,
    signature_length: u32,
    signature: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENCODED_METADATA: &str = "zQAAAAprZW1fbWV0YWRhdGEACnNpZ25hdHVyZV9tZXRhZGF0YQADZW5jcnlwdGlvbl9tZXRhZGF0YQApAAAAAmVuY3J5cHRpb25fYWxnb3JpdGhtAAoAAABBRVMyNTZHQ00AAANwa2RmX21ldGFkYXRhAD8AAAACcGtkZl9hbGdvcml0aG0ABwAAAFNjcnlwdAAScGtkZl93b3JrZmFjdG9yX3NjYWxlADIAAAAAAAAAAAJjb21tZW50AA0AAABUZXN0IENvbW1lbnQAAA==";

    #[test]
    fn metadata_format_encode() {
        let encryption_metadata = EncryptionMetadataFormat {
            encryption_algorithm: EncryptionAlgorithm::AES256GCM,
        };

        let pkdf_metadata = PKDFMetadataFormat {
            pkdf_algorithm: PKDFAlgorithm::Scrypt,
            pkdf_workfactor_scale: 50,
        };

        let metadata = MetadataFormat {
            kem_metadata: None,
            signature_metadata: None,
            encryption_metadata,
            pkdf_metadata: Some(pkdf_metadata),
            comment: Some("Test Comment".to_string()),
        };

        assert_eq!(ENCODED_METADATA, &base64::encode(metadata.encode()));
    }
}
