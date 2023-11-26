use cryptopia_seed::Seed;
use crystals_dilithium as dilithium;
use ed25519_compact as ed25519;

const ED25519_MAGIC_BYTES: [u8; 4] = [25, 85, 210, 14]; // 0xED25519 in LittleEndian
const DILITHIUM3_MAGIC_BYTES: [u8; 4] = [211, 12, 0, 0]; // 0xCD3 in LittleEndian

#[derive(Debug)]
pub enum HybridSignError {
    Unexpected,
}

pub enum ECAlgorithm {
    Ed25519,
}

pub struct ECKeyPair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
    pub algorithm: ECAlgorithm,
}

impl ECKeyPair {
    pub fn from_secret_key(
        secret_key: &[u8],
        ec_algorithm: ECAlgorithm,
    ) -> Result<Self, HybridSignError> {
        match ec_algorithm {
            ECAlgorithm::Ed25519 => {
                let secret_key = ed25519::SecretKey::from_slice(&secret_key).unwrap();
                let public_key = secret_key.public_key();

                Ok(ECKeyPair {
                    public_key: public_key.to_vec(),
                    secret_key: secret_key.to_vec(),
                    algorithm: ec_algorithm,
                })
            }
        }
    }

    pub fn from_seed(seed: &Seed, ec_algorithm: ECAlgorithm) -> Result<Self, HybridSignError> {
        match ec_algorithm {
            ECAlgorithm::Ed25519 => {
                let child_seed = seed.derive_32bytes_child_seed(Some(&[&ED25519_MAGIC_BYTES]));
                let keypair = ed25519::KeyPair::from_seed(child_seed.into());

                Ok(ECKeyPair {
                    public_key: keypair.pk.to_vec(),
                    secret_key: keypair.sk.to_vec(),
                    algorithm: ec_algorithm,
                })
            }
        }
    }
}

pub struct ECSignature {
    pub keypair: ECKeyPair,
}

impl ECSignature {
    pub fn new(keypair: ECKeyPair) -> Self {
        ECSignature { keypair }
    }

    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let signature_algorithm = &self.keypair.algorithm;

        match signature_algorithm {
            ECAlgorithm::Ed25519 => {
                let secret_key = ed25519::SecretKey::from_slice(&self.keypair.secret_key).unwrap();
                let signature = secret_key.sign(message, Some(ed25519::Noise::generate()));
                signature.to_vec()
            }
        }
    }

    pub fn verify(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, HybridSignError> {
        let signature_algorithm = &self.keypair.algorithm;

        match signature_algorithm {
            ECAlgorithm::Ed25519 => {
                let public_key = ed25519::PublicKey::from_slice(public_key).unwrap();
                let signature = ed25519::Signature::from_slice(signature).unwrap();
                let does_verify = public_key.verify(message, &signature);

                Ok(does_verify.is_ok())
            }
        }
    }
}

pub enum PQAlgorithm {
    Dilithium3,
}

pub struct PQKeyPair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
    pub algorithm: PQAlgorithm,
}

impl PQKeyPair {
    pub fn from_seed(seed: &Seed, pq_algorithm: PQAlgorithm) -> Result<Self, HybridSignError> {
        match pq_algorithm {
            PQAlgorithm::Dilithium3 => {
                let child_seed = seed.derive_64bytes_child_seed(Some(&[&DILITHIUM3_MAGIC_BYTES]));
                let keypair = dilithium::dilithium3::Keypair::generate(Some(&child_seed));
                Ok(PQKeyPair {
                    public_key: keypair.public.to_bytes().to_vec(),
                    secret_key: keypair.secret.to_bytes().to_vec(),
                    algorithm: pq_algorithm,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SEED: [u8; 128] = [
        198, 44, 204, 124, 44, 49, 54, 122, 236, 122, 174, 6, 50, 107, 65, 214, 47, 51, 12, 251,
        107, 231, 10, 176, 23, 212, 180, 156, 17, 59, 207, 193, 239, 137, 69, 61, 25, 4, 0, 233,
        97, 31, 94, 200, 222, 243, 222, 181, 63, 225, 246, 49, 233, 246, 206, 13, 147, 85, 137, 5,
        165, 80, 188, 150, 198, 44, 204, 124, 44, 49, 54, 122, 236, 122, 174, 6, 50, 107, 65, 214,
        47, 51, 12, 251, 107, 231, 10, 176, 23, 212, 180, 156, 17, 59, 207, 193, 239, 137, 69, 61,
        25, 4, 0, 233, 97, 31, 94, 200, 222, 243, 222, 181, 63, 225, 246, 49, 233, 246, 206, 13,
        147, 85, 137, 5, 165, 80, 188, 150,
    ];

    const ED25519_SECRET_KEY: &str =
        "9JEaadEpdYGWbEj9K4hWONQ7FxrD5bcAeZpfTMN85u3bf4hWtz+4nt6q6uqp6RU4h8BwFzRjWyMVwZDLC5BroQ==";

    const ED25519_PUBLIC_KEY: &str = "23+IVrc/uJ7equrqqekVOIfAcBc0Y1sjFcGQywuQa6E=";

    #[test]
    fn ed25519_keypair_from_seed() {
        let keypair = ECKeyPair::from_seed(&Seed::new(TEST_SEED), ECAlgorithm::Ed25519).unwrap();

        assert_eq!(base64::encode(keypair.secret_key), ED25519_SECRET_KEY,);
        assert_eq!(base64::encode(keypair.public_key), ED25519_PUBLIC_KEY,);
    }

    #[test]
    fn ed25519_keypair_from_secret_key() {
        let keypair = ECKeyPair::from_secret_key(
            &base64::decode(ED25519_SECRET_KEY).unwrap(),
            ECAlgorithm::Ed25519,
        )
        .unwrap();

        assert_eq!(base64::encode(keypair.public_key), ED25519_PUBLIC_KEY);
    }
}
