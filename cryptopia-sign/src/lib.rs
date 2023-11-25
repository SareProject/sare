use cryptopia_seed::Seed;
use ed25519_compact as ed25519;

const ED25519_MAGIC_BYTES: [u8; 4] = [25, 85, 210, 14]; // 0xED25519 in LittleEndian

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

pub enum PQAlgorithm {
    Falcon512,
}

pub struct PQKeyPair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
    pub algorithm: PQAlgorithm,
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
}
