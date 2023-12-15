use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct RevocationCertificateFormat {
    pub name: String,
    pub email: String,
    pub expiry_date: i64,
    pub fingerprint: [u8; 32], // SHA Hash of public keys
}
