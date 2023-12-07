pub use cryptopia_core::format::keys::*;
pub use cryptopia_core::hybrid_kem::{DHAlgorithm, KEMAlgorithm};
pub use cryptopia_core::hybrid_sign::{ECAlgorithm, PQAlgorithm};
pub use cryptopia_core::seed::Seed;
use secrecy::{ExposeSecret, SecretVec};
use std::io::Write;

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

    pub fn export<W: Write>(&self, passphrase_bytes: Option<SecretVec<u8>>, output: W) {
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
}
