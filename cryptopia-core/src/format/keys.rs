use secrecy::SecretVec;
use serde::{Deserialize, Serialize};

use crate::format::encryption::EncryptionMetadataFormat;
use crate::hybrid_kem::{DHAlgorithm, KEMAlgorithm};
use crate::hybrid_sign::{ECAlgorithm, PQAlgorithm};

#[derive(Serialize, Deserialize)]
pub struct SignaturePublicKeyFormat {
    ec_algorithm: ECAlgorithm,
    pq_algorithm: PQAlgorithm,
    ec_public_key: Vec<u8>,
    pq_public_key: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct EncryptionPublicKeyFormat {
    dh_algorithm: DHAlgorithm,
    kem_algorithm: KEMAlgorithm,
    dh_public_key: Vec<u8>,
    kem_public_key: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct FullChainPublicKeyFormat {
    signature_public_key: SignaturePublicKeyFormat,
    encryption_public_key: EncryptionPublicKeyFormat,
}

#[derive(Serialize, Deserialize)]
pub struct SecretKeyFormat {
    ec_algorithm: ECAlgorithm,
    pq_algorithm: PQAlgorithm,
    dh_algorithm: DHAlgorithm,
    kem_algorithm: KEMAlgorithm,
    #[serde(with = "secret_vec_serde")]
    master_seed: SecretVec<u8>,
    #[serde(skip_serializing_if = "Option::is_none", flatten)]
    encryption_metadata: Option<EncryptionMetadataFormat>,
}

mod secret_vec_serde {
    use secrecy::{ExposeSecret, SecretVec};
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(data: &SecretVec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&data.expose_secret())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<SecretVec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Vec::deserialize(deserializer)?;
        Ok(SecretVec::new(bytes))
    }
}
