use secrecy::{ExposeSecret, SecretString, SecretVec};
use serde::{Deserialize, Serialize};

use super::{EncodablePublic, EncodableSecret};

use crate::format::encryption::EncryptionMetadataFormat;
use crate::format::FormatError;
use crate::hybrid_kem::{DHAlgorithm, DHKeyPair, KEMAlgorithm, KEMKeyPair};
use crate::hybrid_sign::{ECAlgorithm, ECKeyPair, PQAlgorithm, PQKeyPair};

use sha2::{Digest, Sha256};

pub const FULLCHAIN_PUBLIC_KEY_PEM_TAG: &str = "SARE FULLCHAIN PUBLIC KEY";
pub const SIGNATURE_PUBLIC_KEY_PEM_TAG: &str = "SARE SIGNATURE PUBLIC KEY";
pub const ENCRYPTION_PUBLIC_KEY_PEM_TAG: &str = "SARE ENCRYPTION PUBLIC KEY";
pub const MASTER_KEY_PEM_TAG: &str = "SARE MASTER KEY";

#[derive(Serialize, Deserialize, Clone)]
pub struct SignaturePublicKeyFormat {
    pub ec_algorithm: ECAlgorithm,
    pub pq_algorithm: PQAlgorithm,
    pub ec_public_key: Vec<u8>,
    pub pq_public_key: Vec<u8>,
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

impl EncodablePublic for SignaturePublicKeyFormat {
    fn encode_bson(&self) -> Vec<u8> {
        bson::to_vec(&self).unwrap()
    }

    fn decode_bson(bson_data: &[u8]) -> Result<Self, FormatError> {
        let public_key = bson::from_slice::<SignaturePublicKeyFormat>(bson_data).unwrap();
        Ok(public_key)
    }

    fn encode_pem(&self) -> String {
        let pem = pem::Pem::new(SIGNATURE_PUBLIC_KEY_PEM_TAG, self.encode_bson().as_slice());
        pem::encode(&pem)
    }

    fn decode_pem(pem_public_key: &str) -> Result<Self, FormatError> {
        let pem = pem::parse(pem_public_key)?;

        let bson_data = pem.contents();
        Self::decode_bson(bson_data)
    }
}

#[derive(Serialize, Deserialize, Clone)]
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

impl EncodablePublic for EncryptionPublicKeyFormat {
    fn encode_bson(&self) -> Vec<u8> {
        bson::to_vec(&self).unwrap()
    }

    fn decode_bson(bson_data: &[u8]) -> Result<Self, FormatError> {
        let public_key = bson::from_slice::<EncryptionPublicKeyFormat>(bson_data).unwrap();
        Ok(public_key)
    }

    fn encode_pem(&self) -> String {
        let pem = pem::Pem::new(ENCRYPTION_PUBLIC_KEY_PEM_TAG, self.encode_bson().as_slice());
        pem::encode(&pem)
    }

    fn decode_pem(pem_public_key: &str) -> Result<Self, FormatError> {
        let pem = pem::parse(pem_public_key)?;

        let bson_data = pem.contents();
        Self::decode_bson(bson_data)
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct FullChainPublicKeyFormat {
    pub signature_public_key: SignaturePublicKeyFormat,
    pub encryption_public_key: EncryptionPublicKeyFormat,
}

impl EncodablePublic for FullChainPublicKeyFormat {
    fn encode_bson(&self) -> Vec<u8> {
        bson::to_vec(&self).unwrap()
    }

    fn decode_bson(bson_data: &[u8]) -> Result<Self, FormatError> {
        let public_key = bson::from_slice::<FullChainPublicKeyFormat>(bson_data).unwrap();
        Ok(public_key)
    }

    fn encode_pem(&self) -> String {
        let pem = pem::Pem::new(FULLCHAIN_PUBLIC_KEY_PEM_TAG, self.encode_bson().as_slice());
        pem::encode(&pem)
    }

    fn decode_pem(pem_public_key: &str) -> Result<Self, FormatError> {
        let pem = pem::parse(pem_public_key)?;

        let bson_data = pem.contents();
        Self::decode_bson(bson_data)
    }
}

impl FullChainPublicKeyFormat {
    pub fn calculate_fingerprint(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        let ec_algorithm = &self.signature_public_key.ec_algorithm.to_string();
        hasher.update(ec_algorithm.as_bytes());
        let ec_public_key = &self.signature_public_key.ec_public_key;
        hasher.update(ec_public_key);

        let pq_algorithm = &self.signature_public_key.pq_algorithm.to_string();
        hasher.update(pq_algorithm.as_bytes());
        let pq_public_key = &self.signature_public_key.pq_public_key;
        hasher.update(pq_public_key);

        let dh_algorithm = &self.encryption_public_key.dh_algorithm.to_string();
        hasher.update(dh_algorithm.as_bytes());
        let dh_public_key = &self.encryption_public_key.dh_public_key;
        hasher.update(dh_public_key);

        let kem_algorithm = &self.encryption_public_key.kem_algorithm.to_string();
        hasher.update(kem_algorithm.as_bytes());
        let kem_public_key = &self.encryption_public_key.kem_public_key;
        hasher.update(kem_public_key);

        let fingerprint: [u8; 32] = hasher.finalize().into();

        fingerprint
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
    pub fn calculate_fingerprint(master_seed: SecretVec<u8>) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(master_seed.expose_secret());

        let fingerprint: [u8; 32] = hasher.finalize().into();

        fingerprint[..=16].to_vec()
    }
}

impl EncodableSecret for SecretKeyFormat {
    fn encode_bson(&self) -> SecretVec<u8> {
        SecretVec::from(bson::to_vec(&self).unwrap())
    }

    fn decode_bson(bson_secretkey: &SecretVec<u8>) -> Result<Self, FormatError> {
        let secret_key = bson::from_slice::<SecretKeyFormat>(bson_secretkey.expose_secret());

        Ok(secret_key?)
    }

    fn encode_pem(&self) -> SecretString {
        let pem = pem::Pem::new(
            MASTER_KEY_PEM_TAG,
            self.encode_bson().expose_secret().as_slice(),
        );

        SecretString::from(pem::encode(&pem))
    }

    fn decode_pem(pem_master_key: SecretString) -> Result<Self, FormatError> {
        let pem = pem::parse(pem_master_key.expose_secret())?;

        let bson_data = SecretVec::from(pem.into_contents());

        Self::decode_bson(&bson_data)
    }
}

mod secret_vec_serde {
    use secrecy::{ExposeSecret, SecretVec};
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(data: &SecretVec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(data.expose_secret())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<SecretVec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Vec::deserialize(deserializer)?;
        Ok(SecretVec::new(bytes))
    }
}
