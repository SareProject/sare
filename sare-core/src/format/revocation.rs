use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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
    pub fn from_hash(fingerprint_hash: &[u8], algorithm: FingerprintAlgo) -> Self {
        Fingerprint {
            algorithm,
            fingerprint_hash: fingerprint_hash.to_vec(),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct RevocationCertificateFormat {
    pub name: Option<String>,
    pub email: Option<String>,
    pub expiry_date: Option<i64>,
    pub fingerprint: Fingerprint, // SHA Hash of public keys
}
