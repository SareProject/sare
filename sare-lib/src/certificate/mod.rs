use std::io::{Read, Write};

pub use sare_core::format::{
    certificate::CertificateFormat, signature::SignatureFormat, EncodablePublic,
};
use sare_core::format::{
    certificate::{
        self, CertificateType, RevocationCertificateFormat, RevocationReason,
        ValidationCertificateFormat,
    },
    signature,
};

use crate::{keys::MasterKey, signing, SareError};

pub struct Certificate {
    pub certificate: CertificateFormat,
    pub signature: SignatureFormat,
}

impl Certificate {
    pub fn new(masterkey: MasterKey, certificate: CertificateFormat) -> Self {
        let encoded_certificate = certificate.encode_bson();
        let signed_certificate = super::signing::Signing::new(masterkey).sign(&encoded_certificate);

        Certificate {
            certificate,
            signature: signed_certificate,
        }
    }

    pub fn new_validation(masterkey: MasterKey, expiry_timestamp: u64, issuer: String) -> Self {
        let validation = ValidationCertificateFormat {
            fullchain_public_key_fingerprint: masterkey.get_fullchain_public_fingerprint(),
        };

        let certificate = CertificateFormat {
            issuer,
            expiry_date: Some(expiry_timestamp),
            certificate_type: CertificateType::Validation(validation),
        };

        Self::new(masterkey, certificate)
    }

    pub fn new_revocation_expiry(
        masterkey: MasterKey,
        expiry_timestamp: u64,
        issuer: String,
    ) -> Self {
        let reason = RevocationReason::Expired;
        let revocation = RevocationCertificateFormat {
            revocation_date: Some(expiry_timestamp),
            revocation_reason: reason,
        };

        let certificate = CertificateFormat {
            issuer,
            expiry_date: None,
            certificate_type: CertificateType::Revocation(revocation),
        };

        Self::new(masterkey, certificate)
    }

    fn encode_pem(&self) -> String {
        self.certificate.encode_pem()
    }

    pub fn export<W: Write>(&self, mut output: W) -> Result<(), SareError> {
        let pem_encoded_certificate = self.encode_pem();

        output.write_all(pem_encoded_certificate.as_bytes())?;
        Ok(())
    }

    pub fn decode_bson(bson_data: &[u8]) -> Result<Self, SareError> {
        let signature = SignatureFormat::decode_bson(bson_data)?;

        let signature_message = &signature.message;

        let certificate = CertificateFormat::decode_bson(&signature_message)?;

        Ok(Certificate {
            certificate,
            signature,
        })
    }

    pub fn verify(&self) -> Result<bool, SareError> {
        super::signing::Signing::verify(&self.signature)
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
