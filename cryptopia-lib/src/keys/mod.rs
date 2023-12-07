pub use cryptopia_core::format::keys::*;
use cryptopia_core::format::FormatError;
pub use cryptopia_core::hybrid_kem::{DHAlgorithm, KEMAlgorithm};
pub use cryptopia_core::hybrid_sign::{ECAlgorithm, PQAlgorithm};
pub use cryptopia_core::seed::Seed;
use secrecy::{ExposeSecret, SecretVec};
use std::io::{BufReader, Read, Write};

pub struct HybridSignAlgorithm {
    ec_algorithm: ECAlgorithm,
    pq_algorithm: PQAlgorithm,
}

pub struct HybridKEMAlgorithm {
    dh_algorithm: DHAlgorithm,
    kem_algorithm: KEMAlgorithm,
}

pub struct MasterKey {
    hybrid_kem_algorithm: HybridKEMAlgorithm,
    hybrid_sign_algorithm: HybridSignAlgorithm,
    master_seed: Seed,
}

impl MasterKey {
    pub fn generate(
        hybrid_kem_algorithm: HybridKEMAlgorithm,
        hybrid_sign_algorithm: HybridSignAlgorithm,
    ) -> Self {
        let master_seed = Seed::generate();

        MasterKey {
            hybrid_kem_algorithm,
            hybrid_sign_algorithm,
            master_seed: master_seed,
        }
    }

    pub fn export<W: Write>(&self, passphrase_bytes: Option<SecretVec<u8>>, mut output: W) {
        //TODO: Encrypt with cryptopia_core::encryption if passphrase is provided

        match passphrase_bytes {
            Some(passphrase) => {
                todo!()
            }
            None => {
                // TODO: impl `From` in cryptopia_core::format::keys
                let secret_key_format = SecretKeyFormat {
                    ec_algorithm: self.hybrid_sign_algorithm.ec_algorithm,
                    pq_algorithm: self.hybrid_sign_algorithm.pq_algorithm,
                    dh_algorithm: self.hybrid_kem_algorithm.dh_algorithm,
                    kem_algorithm: self.hybrid_kem_algorithm.kem_algorithm,
                    master_seed: self.master_seed.clone_raw_seed(),
                    encryption_metadata: None,
                };

                output.write_all(secret_key_format.encode().expose_secret());
            }
        }
    }

    pub fn is_encrypted(secret_key_format: &SecretKeyFormat) -> bool {
        secret_key_format.encryption_metadata.is_some()
    }

    pub fn decode_bson<R: Read>(serialized_master_key: R) -> Result<SecretKeyFormat, FormatError> {
        let reader = BufReader::new(serialized_master_key);
        SecretKeyFormat::decode(&SecretVec::from(reader.buffer().to_vec()))
    }

    pub fn import<R: Read>(
        serialized_master_key: R,
        passphrase_bytes: Option<SecretVec<u8>>,
    ) -> Result<Self, FormatError> {
        let decoded_master_key_format = Self::decode_bson(serialized_master_key)?;

        let hybrid_sign_algorithm = HybridSignAlgorithm {
            ec_algorithm: decoded_master_key_format.ec_algorithm,
            pq_algorithm: decoded_master_key_format.pq_algorithm,
        };

        let hybrid_kem_algorithm = HybridKEMAlgorithm {
            dh_algorithm: decoded_master_key_format.dh_algorithm,
            kem_algorithm: decoded_master_key_format.kem_algorithm,
        };

        match passphrase_bytes {
            Some(passphrase) => {
                todo!()
            }
            None => Ok(MasterKey {
                hybrid_sign_algorithm,
                hybrid_kem_algorithm,
                master_seed: Seed::new(decoded_master_key_format.master_seed),
            }),
        }
    }
}
