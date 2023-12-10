use serde::{Deserialize, Serialize};

use crate::format::FormatError;
use crate::hybrid_sign::{ECAlgorithm, PQAlgorithm};

#[derive(Serialize, Deserialize)]
pub struct SignatureMetadataFormat {
    ec_algorithm: ECAlgorithm,
    pq_algorithm: PQAlgorithm,
}

#[derive(Serialize, Deserialize)]
pub struct SignatureFormat {
    #[serde(skip_serializing_if = "Option::is_none", flatten)]
    signature_metadata: Option<SignatureMetadataFormat>,
    ec_public_key: Vec<u8>,
    pq_public_key: Vec<u8>,
    message: Vec<u8>,
    ec_signature: Vec<u8>,
    pq_signature: Vec<u8>,
}

impl SignatureFormat {
    pub fn encode(&self) -> Vec<u8> {
        bson::to_vec(&self).unwrap()
    }

    pub fn decode(bson_signature: &[u8]) -> Result<Self, FormatError> {
        let metadata = bson::from_slice::<SignatureFormat>(bson_signature);

        // TODO: Needs Error Handling
        Ok(metadata.unwrap())
    }
}
