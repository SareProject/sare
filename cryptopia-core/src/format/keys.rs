use bson::{bson, Bson};
use serde::{Deserialize, Serialize};

use crate::hybrid_kem::{DHAlgorithm, KEMAlgorithm};
use crate::hybrid_sign::{ECAlgorithm, PQAlgorithm};
use crate::format::encryption::EncryptionMetadataFormat;


#[derive(Serialize, Deserialize)]
pub struct SignaturePublicKeyFormat {
    ec_algorithm: ECAlgorithm,
    pq_algorithm: PQAlgorithm,
    ec_public_key: Vec<u8>,
    pq_public_key: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct EncryptionPublicKeyFormat {
    dh_algorithm: DHAlgorithm,
    kem_algorithm: KEMAlgorithm,
    dh_public_key: Vec<u8>,
    kem_public_key: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct FullChainPublicKeyFormat {
    signature_public_key: SignaturePublicKeyFormat,
    encryption_public_key: EncryptionPublicKeyFormat,
}

#[derive(Serialize, Deserialize)]
pub struct SecretKeyFormat {
    ec_algorithm: ECAlgorithm,
    pq_algorithm: PQAlgorithm,
    dh_algorithm: DHAlgorithm,
    kem_algorithm: KEMAlgorithm,
    #[serde(skip_serializing_if = "Option::is_none", flatten)]
    encryption_metadata: Option<EncryptionMetadataFormat>,
}

