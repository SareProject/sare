use secrecy::{ExposeSecret, SecretVec};
use serde::{Deserialize, Serialize};

use crate::format::encryption::EncryptionMetadataFormat;
use crate::format::FormatError;
use crate::hybrid_kem::{DHAlgorithm, DHKeyPair, KEMAlgorithm, KEMKeyPair};
use crate::hybrid_sign::{ECAlgorithm, ECKeyPair, PQAlgorithm, PQKeyPair};

#[derive(Serialize, Deserialize)]
pub struct SignaturePublicKeyFormat {
    ec_algorithm: ECAlgorithm,
    pq_algorithm: PQAlgorithm,
    ec_public_key: Vec<u8>,
    pq_public_key: Vec<u8>,
}

impl SignaturePublicKeyFormat {
    pub fn from_keypairs(ec_keypair: ECKeyPair, pq_keypair: PQKeyPair) -> Self {
        SignaturePublicKeyFormat {
            ec_algorithm: ec_keypair.algorithm,
            pq_algorithm: pq_keypair.algorithm,
            ec_public_key: ec_keypair.public_key,
            pq_public_key: pq_keypair.public_key,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct EncryptionPublicKeyFormat {
    dh_algorithm: DHAlgorithm,
    kem_algorithm: KEMAlgorithm,
    dh_public_key: Vec<u8>,
    kem_public_key: Vec<u8>,
}

impl EncryptionPublicKeyFormat {
    pub fn from_keypairs(dh_keypair: DHKeyPair, kem_keypair: KEMKeyPair) -> Self {
        EncryptionPublicKeyFormat {
            dh_algorithm: dh_keypair.algorithm,
            kem_algorithm: kem_keypair.algorithm,
            dh_public_key: dh_keypair.public_key,
            kem_public_key: kem_keypair.public_key,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct FullChainPublicKeyFormat {
    pub signature_public_key: SignaturePublicKeyFormat,
    pub encryption_public_key: EncryptionPublicKeyFormat,
}

impl FullChainPublicKeyFormat {
    pub fn encode(&self) -> Vec<u8> {
        bson::to_vec(&self).unwrap()
    }

    pub fn decode(bson_public_key: &Vec<u8>) -> Result<Self, FormatError> {
        let public_key = bson::from_slice::<FullChainPublicKeyFormat>(bson_public_key);

        // TODO: Needs Error Handling
        Ok(public_key.unwrap())
    }
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
