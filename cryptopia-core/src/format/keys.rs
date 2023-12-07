use secrecy::{ExposeSecret, SecretVec};
use serde::{Deserialize, Serialize};

use crate::format::encryption::EncryptionMetadataFormat;
use crate::format::FormatError;
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
    pub ec_algorithm: ECAlgorithm,
    pub pq_algorithm: PQAlgorithm,
    pub dh_algorithm: DHAlgorithm,
    pub kem_algorithm: KEMAlgorithm,
    #[serde(with = "secret_vec_serde")]
    pub master_seed: SecretVec<u8>,
    #[serde(skip_serializing_if = "Option::is_none", flatten)]
    pub encryption_metadata: Option<EncryptionMetadataFormat>,
}

impl SecretKeyFormat {
    pub fn encode(&self) -> SecretVec<u8> {
        SecretVec::from(bson::to_vec(&self).unwrap())
    }

    pub fn decode(bson_secretkey: &SecretVec<u8>) -> Result<Self, FormatError> {
        let secret_key = bson::from_slice::<SecretKeyFormat>(bson_secretkey.expose_secret());

        // TODO: Needs Error Handling
        Ok(secret_key.unwrap())
    }
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
