use std::io::Write;

use sare_core::format::{
    certificate::CertificateFormat, signature::SignatureFormat, EncodablePublic,
};

const CERTIFICATE_PEM_TAG: &str = "SARE CERTIFICATE";

use crate::keys::MasterKey;

pub struct Cerificate(SignatureFormat);

impl Cerificate {
    pub fn new(masterkey: MasterKey, certificate: CertificateFormat) -> Self {
        let encoded_certificate = certificate.encode_bson();
        let signed_certificate = super::signing::Signing::new(masterkey).sign(&encoded_certificate);

        Cerificate(signed_certificate)
    }

    fn encode_pem(&self) -> String {
        let pem = sare_core::pem::Pem::new(CERTIFICATE_PEM_TAG, self.0.encode_bson().as_slice());
        sare_core::pem::encode(&pem)
    }

    pub fn export<W: Write>(&self, mut output: W) {
        let pem_encoded_certificate = self.encode_pem();

        output.write_all(pem_encoded_certificate.as_bytes());
    }
}
