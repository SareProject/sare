use std::io::{Read, Write};

pub use sare_core::format::{
    EncodablePublic, certificate::CertificateFormat, signature::SignatureFormat,
};
use sare_core::format::{
    certificate::{
        CertificateType, Issuer, RevocationCertificateFormat, RevocationReason,
        ValidationCertificateFormat,
    },
    signature::SignatureHeaderFormat,
};

use crate::{SareError, keys::MasterKey};

#[derive(Clone)]
pub struct Certificate {
    pub certificate: CertificateFormat,
    pub signature: SignatureHeaderFormat,
}

impl Certificate {
    /// Create a new attached-signed certificate from a master key and certificate format
    pub fn new(masterkey: MasterKey, certificate: CertificateFormat) -> Self {
        let encoded_certificate = certificate.encode_bson();
        let signed_certificate =
            super::signing::Signing::new(masterkey.clone()).sign_attached(&encoded_certificate);

        Self {
            certificate,
            signature: signed_certificate,
        }
    }

    /// Create a validation certificate
    pub fn new_validation(
        masterkey: MasterKey,
        expiry_timestamp: Option<u64>,
        issuer: &Issuer,
    ) -> Self {
        let validation = ValidationCertificateFormat {
            fullchain_public_key_fingerprint: masterkey.get_fullchain_public_fingerprint(),
        };

        let certificate = CertificateFormat {
            issuer: issuer.clone(),
            expiry_date: expiry_timestamp,
            certificate_type: CertificateType::Validation(validation),
        };

        Self::new(masterkey, certificate)
    }

    /// Create a revocation certificate
    pub fn new_revocation(
        masterkey: MasterKey,
        timestamp: u64,
        issuer: Issuer,
        reason: RevocationReason,
    ) -> Self {
        let revocation = RevocationCertificateFormat {
            revocation_date: timestamp,
            revocation_reason: reason,
            fullchain_fingerprint: masterkey.get_fullchain_public_fingerprint(),
        };

        let certificate = CertificateFormat {
            issuer,
            expiry_date: None,
            certificate_type: CertificateType::Revocation(revocation),
        };

        Self::new(masterkey, certificate)
    }

    /// Encode the certificate as PEM with proper tag
    fn encode_pem(&self) -> String {
        let tag = match self.certificate.certificate_type {
            CertificateType::Revocation(_) => sare_core::format::certificate::REVOCATION_PEM_TAG,
            CertificateType::Validation(_) => sare_core::format::certificate::VALIDATION_PEM_TAG,
        };

        let pem = sare_core::pem::Pem::new(tag, self.signature.encode_with_magic_byte().as_slice());
        sare_core::pem::encode(&pem)
    }

    /// Export certificate as PEM to a writer
    pub fn export<W: Write>(&self, mut output: W) -> Result<(), SareError> {
        let pem_encoded = self.encode_pem();
        output.write_all(pem_encoded.as_bytes())?;
        Ok(())
    }

    /// Decode a certificate from BSON bytes
    pub fn decode_bson(signature_data: &[u8]) -> Result<Self, SareError> {
        let signature_header = SignatureHeaderFormat::decode_with_magic_byte(signature_data)?;
        let signature = &signature_header.signature;

        let raw_message = signature.message.as_ref().ok_or_else(|| {
            SareError::IoError("Attached signature is missing the message".into())
        })?;

        let certificate = CertificateFormat::decode_bson(raw_message)?;

        Ok(Self {
            certificate,
            signature: signature_header,
        })
    }

    /// Verify the attached signature
    pub fn verify(&self) -> Result<bool, SareError> {
        super::signing::Signing::verify_attached(&self.signature)
    }

    /// Import a PEM-encoded certificate from a reader
    pub fn import<R: Read>(mut input: R) -> Result<Self, SareError> {
        let mut pem_string = String::new();
        input.read_to_string(&mut pem_string)?;

        let pem =
            sare_core::pem::parse(pem_string).map_err(|e| SareError::IoError(e.to_string()))?;

        Self::decode_bson(pem.contents())
    }
}
