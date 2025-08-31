use std::io::{Read, Write};

pub use sare_core::format::{
    certificate::CertificateFormat, signature::SignatureFormat, EncodablePublic,
};
use sare_core::format::{
    certificate::{
        self, CertificateType, Issuer, RevocationCertificateFormat, RevocationReason,
        ValidationCertificateFormat,
    },
    signature,
};

use crate::{keys::MasterKey, signing, SareError};

#[derive(Clone)]
pub struct Certificate {
    pub certificate: CertificateFormat,
    pub signature: SignatureFormat,
}

impl Certificate {
    pub fn new(masterkey: MasterKey, certificate: CertificateFormat) -> Self {
        let encoded_certificate = certificate.encode_bson();
        let signed_certificate =
            super::signing::Signing::new(masterkey).sign_attached(&encoded_certificate);

        Certificate {
            certificate,
            signature: signed_certificate,
        }
    }

    pub fn new_validation(masterkey: MasterKey, expiry_timestamp: u64, issuer: &Issuer) -> Self {
        let validation = ValidationCertificateFormat {
            fullchain_public_key_fingerprint: masterkey.get_fullchain_public_fingerprint(),
        };

        let certificate = CertificateFormat {
            issuer: issuer.clone(),
            expiry_date: Some(expiry_timestamp),
            certificate_type: CertificateType::Validation(validation),
        };

        Self::new(masterkey, certificate)
    }

    pub fn new_revocation_no_reason(masterkey: MasterKey, timestamp: u64, issuer: Issuer) -> Self {
        let reason = RevocationReason::NoReasonSpecified;
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

    fn encode_pem(&self) -> String {
        // TODO: implement get_tag() for CertificateType
        let tag = match self.certificate.certificate_type {
            CertificateType::Revocation(_) => sare_core::format::certificate::REVOCATION_PEM_TAG,
            CertificateType::Validation(_) => sare_core::format::certificate::VALIDATION_PEM_TAG,
            _ => sare_core::format::certificate::CERTIFICATE_PEM_TAG,
        };

        let pem = sare_core::pem::Pem::new(tag, self.signature.encode_bson().as_slice());
        sare_core::pem::encode(&pem)
    }

    pub fn export<W: Write>(&self, mut output: W) -> Result<(), SareError> {
        let pem_encoded_certificate = self.encode_pem();

        output.write_all(pem_encoded_certificate.as_bytes())?;
        Ok(())
    }

    pub fn decode_bson(bson_data: &[u8]) -> Result<Self, SareError> {
        let signature = SignatureFormat::decode_bson(bson_data)?;

        // Note: all certificates will be attached
        let raw_message = &signature.message;
        let signature_message = raw_message
            .as_ref()
            .expect("Attached signature is missing the message");
        let certificate = CertificateFormat::decode_bson(&signature_message)?;

        Ok(Certificate {
            certificate,
            signature,
        })
    }

    pub fn verify(&self) -> Result<bool, SareError> {
        super::signing::Signing::verify_attached(&self.signature)
    }

    pub fn import<R: Read>(mut input: R) -> Result<Self, SareError> {
        let mut pem_string = String::new();
        input.read_to_string(&mut pem_string)?;

        let pem =
            sare_core::pem::parse(pem_string).map_err(|e| SareError::IoError(e.to_string()))?;

        let bson_data = pem.contents();

        Self::decode_bson(bson_data)
    }
}
