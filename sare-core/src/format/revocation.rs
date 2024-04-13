use serde::{Deserialize, Serialize};

use super::PublicKeyFormat;

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
    pub fn calculate_fingerprint(public_key: impl PublicKeyFormat) -> Self {
        todo!()
    }
}

#[derive(Serialize, Deserialize)]
pub struct RevocationCertificateFormat {
    pub name: Option<String>,
    pub email: Option<String>,
    pub expiry_date: Option<i64>,
    pub fingerprint: Fingerprint, // SHA Hash of public keys
}
