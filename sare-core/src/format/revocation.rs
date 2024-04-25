use serde::{Deserialize, Serialize};
use sha2::Digest;

use super::{EncodablePublic, FormatError};

const REVOCATION_CERTIFICATE_PEM_TAG: &str = "SARE REVOCATION CERTIFICATE";

#[derive(Serialize, Deserialize)]
pub enum FingerprintAlgo {
    SHA2_256,
    SHA3_256,
}

#[derive(Serialize, Deserialize)]
pub struct Fingerprint {
    algorithm: FingerprintAlgo,
    fingerprint_hash: Vec<u8>,
}

impl Fingerprint {
    pub fn from_hash(fingerprint_hash: &[u8], algorithm: FingerprintAlgo) -> Self {
        Fingerprint {
            algorithm,
            fingerprint_hash: fingerprint_hash.to_vec(),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct RevocationCertificateFormat {
    pub name: Option<String>,
    pub email: Option<String>,
    pub expiry_date: Option<i64>,
    pub fingerprint: Fingerprint, // SHA Hash of public keys
}

impl EncodablePublic for RevocationCertificateFormat {
    fn encode_bson(&self) -> Vec<u8> {
        bson::to_vec(&self).unwrap()
    }

    fn decode_bson(bson_data: &[u8]) -> Result<Self, FormatError> {
        let public_key = bson::from_slice::<RevocationCertificateFormat>(bson_data).unwrap();
        Ok(public_key)
    }

    fn encode_pem(&self) -> String {
        let pem = pem::Pem::new(
            REVOCATION_CERTIFICATE_PEM_TAG,
            self.encode_bson().as_slice(),
        );
        pem::encode(&pem)
    }

    fn decode_pem(pem_public_key: &str) -> Result<Self, FormatError> {
        let pem = pem::parse(pem_public_key)?;

        let bson_data = pem.contents();
        Self::decode_bson(bson_data)
    }
}
