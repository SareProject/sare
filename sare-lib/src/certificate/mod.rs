use std::io::Write;

use sare_core::format::certificate::{self, CertificateType, RevocationCertificateFormat, RevocationReason};
pub use sare_core::format::{
    certificate::CertificateFormat, signature::SignatureFormat, EncodablePublic,
};

const CERTIFICATE_PEM_TAG: &str = "SARE CERTIFICATE";

use crate::{keys::MasterKey, SareError};

pub struct Cerificate(SignatureFormat);

impl Cerificate {
    pub fn new(masterkey: MasterKey, certificate: CertificateFormat) -> Self {
        let encoded_certificate = certificate.encode_bson();
        let signed_certificate = super::signing::Signing::new(masterkey).sign(&encoded_certificate);

        Cerificate(signed_certificate)
    }

    pub fn new_revocation_expiry(masterkey: MasterKey, expiry_timestamp: u64, issuer: String) -> Self {
        let reason = RevocationReason::Expired;
        let revocation = RevocationCertificateFormat {
            revocation_date: Some(expiry_timestamp),
            revocation_reason: reason
        };

        let certificate = CertificateFormat {
            issuer,
            expiry_date: None,
            certificate_type: CertificateType::Revocation(revocation)
        };

        Self::new(masterkey, certificate)
    }

    fn encode_pem(&self) -> String {
        let pem = sare_core::pem::Pem::new(CERTIFICATE_PEM_TAG, self.0.encode_bson().as_slice());
        sare_core::pem::encode(&pem)
    }

    pub fn export<W: Write>(&self, mut output: W) -> Result<(), SareError> {
        let pem_encoded_certificate = self.encode_pem();

        output.write_all(pem_encoded_certificate.as_bytes())?;
        Ok(())
    }
}
