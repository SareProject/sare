use sare_core::format::revocation::RevocationCertificateFormat;

enum CertificateType {
    Revocation(RevocationCertificateFormat),
}

impl CertificateType {
    pub fn new_revocation_certificate() -> Self{
        unimplemented!()
    }
}

pub struct Certificate{
    issuer: String,
    expiry_date: Option<i64>,
    certificate_type: CertificateType,
}
