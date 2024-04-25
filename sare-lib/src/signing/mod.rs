use sare_core::{
    format::signature::{SignatureFormat, SignatureMetadataFormat},
    hybrid_sign::{error::HybridSignError, ECSignature, PQSignature},
};

use crate::keys::MasterKey;

pub struct Signing(MasterKey);

impl Signing {
    pub fn new(master_key: MasterKey) -> Self {
        Signing(master_key)
    }

    // TODO: Copy and Clone needs to be implemented in sare-core::hybrid_sign
    // TODO: `new`/`from` methods needs to be implemented for Signature Formats
    pub fn sign(&self, message: &[u8]) -> SignatureFormat {
        let signing_keypair = self.0.get_signing_keypair();
        let ec_public_key = signing_keypair.0.public_key.to_owned();
        let pq_public_key = signing_keypair.1.public_key.to_owned();

        let ec_algorithm = signing_keypair.0.algorithm.to_owned();
        let pq_algorithm = signing_keypair.1.algorithm.to_owned();

        let ec_signature = ECSignature::new(signing_keypair.0).sign(message);
        let pq_signature = PQSignature::new(signing_keypair.1).sign(message);

        let signature_metadata = SignatureMetadataFormat {
            pq_algorithm: pq_algorithm,
            ec_algorithm: ec_algorithm,
        };

        let signature_format = SignatureFormat {
            signature_metadata: Some(signature_metadata),
            ec_public_key: ec_public_key,
            pq_public_key: pq_public_key,
            message: message.to_vec(),
            ec_signature: ec_signature,
            pq_signature: pq_signature,
        };

        signature_format
    }
}
