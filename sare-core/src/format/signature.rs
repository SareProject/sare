use serde::{Deserialize, Serialize};

use crate::format::error::FormatError;
use crate::format::EncodablePublic;
use crate::hybrid_sign::{ECAlgorithm, PQAlgorithm};

const SIGNATURE_TAG: &str = "SARE MESSAGE";

#[derive(Serialize, Deserialize)]
pub struct SignatureMetadataFormat {
    pub ec_algorithm: ECAlgorithm,
    pub pq_algorithm: PQAlgorithm,
}

#[derive(Serialize, Deserialize)]
pub struct SignatureFormat {
    #[serde(skip_serializing_if = "Option::is_none", flatten)]
    pub signature_metadata: Option<SignatureMetadataFormat>,
    pub ec_public_key: Vec<u8>,
    pub pq_public_key: Vec<u8>,
    pub message: Vec<u8>,
    pub ec_signature: Vec<u8>,
    pub pq_signature: Vec<u8>,
}

impl EncodablePublic for SignatureFormat {
    fn encode_bson(&self) -> Vec<u8> {
        bson::to_vec(&self).unwrap()
    }

    fn decode_bson(data: &[u8]) -> Result<Self, FormatError> {
        let metadata = bson::from_slice::<SignatureFormat>(data);

        Ok(metadata?)
    }

    fn encode_pem(&self) -> String {
        let pem = pem::Pem::new(SIGNATURE_TAG, self.encode_bson().as_slice());
        pem::encode(&pem)
    }

    fn decode_pem(pem_data: &str) -> Result<Self, FormatError> {
        let pem = pem::parse(pem_data)?;

        let bson_data = pem.contents();
        Self::decode_bson(bson_data)
    }
}
