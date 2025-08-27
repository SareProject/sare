use super::{EncodablePublic, FormatError};
use serde::{Deserialize, Serialize};

const CERTIFICATE_PEM_TAG: &str = "SARE CERTIFICATE";

#[derive(Serialize, Deserialize)]
pub enum RevocationReason {
    Expired,
    Compromised,
}

#[derive(Serialize, Deserialize)]
pub struct RevocationCertificateFormat {
    pub revocation_date: Option<u64>,
    pub revocation_reason: RevocationReason,
}

#[derive(Serialize, Deserialize)]
pub enum CertificateType {
    Revocation(RevocationCertificateFormat),
}

#[derive(Serialize, Deserialize)]
pub struct CertificateFormat {
    pub issuer: String,
    pub expiry_date: Option<u64>,
    pub certificate_type: CertificateType,
}

impl CertificateFormat {
    pub fn get_revocation_timestamp(&self) -> Option<u64> {
        match &self.certificate_type {
            CertificateType::Revocation(revocation_format) => revocation_format.revocation_date,
            _ => None,
        }
    }
}

impl EncodablePublic for CertificateFormat {
    fn encode_bson(&self) -> Vec<u8> {
        bson::to_vec(&self).unwrap()
    }

    fn decode_bson(bson_data: &[u8]) -> Result<Self, FormatError> {
        let public_key = bson::from_slice::<CertificateFormat>(bson_data).unwrap();
        Ok(public_key)
    }

    fn encode_pem(&self) -> String {
        let pem = pem::Pem::new(CERTIFICATE_PEM_TAG, self.encode_bson().as_slice());
        pem::encode(&pem)
    }

    fn decode_pem(pem_public_key: &str) -> Result<Self, FormatError> {
        let pem = pem::parse(pem_public_key)?;

        let bson_data = pem.contents();
        Self::decode_bson(bson_data)
    }
}
