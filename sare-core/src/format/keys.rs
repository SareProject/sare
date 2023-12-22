use secrecy::{ExposeSecret, SecretString, SecretVec};
use serde::{Deserialize, Serialize};

use crate::encryption::EncryptionAlgorithm;
use crate::format::encryption::EncryptionMetadataFormat;
use crate::format::FormatError;
use crate::hybrid_kem::{DHAlgorithm, DHKeyPair, KEMAlgorithm, KEMKeyPair};
use crate::hybrid_sign::{ECAlgorithm, ECKeyPair, PQAlgorithm, PQKeyPair};
use crate::PublicKey;

use sha2::{Digest, Sha256};

const FULLCHAIN_PUBLIC_KEY_PEM_TAG: &str = "SARE FULLCHAIN PUBLIC KEY";
const SIGNATURE_PUBLIC_KEY_PEM_TAG: &str = "SARE SIGNATURE PUBLIC KEY";
const ENCRYPTION_PUBLIC_KEY_PEM_TAG: &str = "SARE ENCRYPTION PUBLIC KEY";
const MASTER_KEY_PEM_TAG: &str = "SARE MASTER KEY";

#[derive(Serialize, Deserialize)]
pub struct SignaturePublicKeyFormat {
    ec_public_key: PublicKey,
    pq_public_key: PublicKey,
}

impl SignaturePublicKeyFormat {
    pub fn from_keypairs(ec_keypair: ECKeyPair, pq_keypair: PQKeyPair) -> Self {
        SignaturePublicKeyFormat {
            ec_public_key: ec_keypair.public_key,
            pq_public_key: pq_keypair.public_key,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct EncryptionPublicKeyFormat {
    dh_public_key: PublicKey,
    kem_public_key: PublicKey,
}

impl EncryptionPublicKeyFormat {
    pub fn from_keypairs(dh_keypair: DHKeyPair, kem_keypair: KEMKeyPair) -> Self {
        EncryptionPublicKeyFormat {
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
    pub fn encode_bson(&self) -> Vec<u8> {
        bson::to_vec(&self).unwrap()
    }

    pub fn decode_bson(bson_public_key: &[u8]) -> Result<Self, FormatError> {
        let public_key = bson::from_slice::<FullChainPublicKeyFormat>(bson_public_key);

        // TODO: Needs Error Handling
        Ok(public_key.unwrap())
    }

    pub fn encode_pem(&self) -> String {
        let pem = pem::Pem::new(FULLCHAIN_PUBLIC_KEY_PEM_TAG, self.encode_bson().as_slice());

        pem::encode(&pem)
    }

    pub fn decode_pem(pem_public_key: String) -> Result<Self, FormatError> {
        let pem = pem::parse(pem_public_key).unwrap();

        if pem.tag() != FULLCHAIN_PUBLIC_KEY_PEM_TAG {
            return Err(FormatError::FailedToDecode); //TODO: Replace with another error
        }

        let bson_data = pem.contents();

        Self::decode_bson(bson_data)
    }

    pub fn calculate_fingerprint(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        let ec_public_key = &self.signature_public_key.ec_public_key;
        hasher.update(ec_public_key.get_algorithm().as_bytes());
        hasher.update(ec_public_key);

        let pq_public_key = &self.signature_public_key.pq_public_key;
        hasher.update(pq_public_key.get_algorithm().as_bytes());
        hasher.update(pq_public_key);

        let dh_public_key = &self.encryption_public_key.dh_public_key;
        hasher.update(dh_public_key.get_algorithm().as_bytes());
        hasher.update(dh_public_key);

        let kem_public_key = &self.encryption_public_key.kem_public_key;
        hasher.update(kem_public_key.get_algorithm().as_bytes());
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
    pub fn encode_bson(&self) -> SecretVec<u8> {
        SecretVec::from(bson::to_vec(&self).unwrap())
    }

    pub fn decode_bson(bson_secretkey: &SecretVec<u8>) -> Result<Self, FormatError> {
        let secret_key = bson::from_slice::<SecretKeyFormat>(bson_secretkey.expose_secret());

        // TODO: Needs Error Handling
        Ok(secret_key.unwrap())
    }

    pub fn encode_pem(&self) -> SecretString {
        let pem = pem::Pem::new(
            MASTER_KEY_PEM_TAG,
            self.encode_bson().expose_secret().as_slice(),
        );

        SecretString::from(pem::encode(&pem))
    }

    pub fn decode_pem(pem_master_key: SecretString) -> Result<Self, FormatError> {
        let pem = pem::parse(pem_master_key.expose_secret()).unwrap();

        if pem.tag() != MASTER_KEY_PEM_TAG {
            return Err(FormatError::FailedToDecode); //TODO: Replace with another error
        }

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
