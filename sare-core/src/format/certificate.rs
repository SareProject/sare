use std::ops::Deref;

use crate::format::{keys::FullChainPublicKeyFormat, signature::SignatureFormat};

use super::{EncodablePublic, FormatError};
use serde::{Deserialize, Serialize};

pub const CERTIFICATE_PEM_TAG: &str = "SARE CERTIFICATE";
pub const REVOCATION_PEM_TAG: &str = "SARE REVOCATION CERTIFICATE";
pub const VALIDATION_PEM_TAG: &str = "SARE VALIDATION CERTIFICATE";

#[derive(Clone, Serialize, Deserialize)]
pub struct Issuer {
    pub name: String,
    pub email: String,
}

impl Issuer {
    pub fn new(name: String, email: String) -> Self {
        Issuer { name, email }
    }
    pub fn parse(input: &str) -> Option<Self> {
        let start = input.find('<')?;
        let end = input.find('>')?;

        if start >= end {
            return None;
        }

        Some(Self {
            name: input[..start].trim().to_string(),
            email: input[start + 1..end].trim().to_string(),
        })
    }

    pub fn to_string(&self) -> String {
        format!("{} <{}>", self.name, self.email)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub enum RevocationReason {
    Compromised,
    NoReasonSpecified,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RevocationCertificateFormat {
    pub revocation_date: u64,
    pub revocation_reason: RevocationReason,
    pub fullchain_fingerprint: [u8; 32],
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ValidationCertificateFormat {
    pub fullchain_public_key_fingerprint: [u8; 32],
}

#[derive(Clone, Serialize, Deserialize)]
pub enum CertificateType {
    Revocation(RevocationCertificateFormat),
    Validation(ValidationCertificateFormat),
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CertificateFormat {
    pub issuer: Issuer,
    pub expiry_date: Option<u64>,
    #[serde(flatten)]
    pub certificate_type: CertificateType,
}

impl CertificateFormat {
    pub fn get_revocation_data(&self) -> Option<&RevocationCertificateFormat> {
        match &self.certificate_type {
            CertificateType::Revocation(revocation_format) => Some(revocation_format),
            _ => None,
        }
    }

    pub fn get_validation_data(&self) -> Option<&ValidationCertificateFormat> {
        match &self.certificate_type {
            CertificateType::Validation(validation_format) => Some(validation_format),
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
        let tag = match self.certificate_type {
            CertificateType::Revocation(_) => REVOCATION_PEM_TAG,
            CertificateType::Validation(_) => VALIDATION_PEM_TAG,
            _ => CERTIFICATE_PEM_TAG,
        };

        let pem = pem::Pem::new(tag, self.encode_bson().as_slice());
        pem::encode(&pem)
    }

    fn decode_pem(pem_public_key: &str) -> Result<Self, FormatError> {
        let pem = pem::parse(pem_public_key)?;

        let bson_data = pem.contents();
        Self::decode_bson(bson_data)
    }
}
