use sare_core::{
    format::signature::{SignatureFormat, SignatureMetadataFormat},
    hybrid_sign::{ECSignature, PQSignature},
};

use crate::{keys::MasterKey, SareError};

pub struct Signing(MasterKey);

impl Signing {
    pub fn new(master_key: MasterKey) -> Self {
        Signing(master_key)
    }

    // TODO: Copy and Clone needs to be implemented in sare-core::hybrid_sign
    // TODO: `new`/`from` methods needs to be implemented for Signature Formats
    pub fn sign(&self, message: &[u8]) -> SignatureFormat {
        let signing_keypair = self.0.get_signing_keypair();
        let ec_keypair = signing_keypair.0;
        let pq_keypair = signing_keypair.1;
        //let ec_public_key = signing_keypair.0.public_key.to_owned();
        //let pq_public_key = signing_keypair.1.public_key.to_owned();

        let ec_algorithm = ec_keypair.algorithm;
        let pq_algorithm = pq_keypair.algorithm;

        let ec_signature = ECSignature::new(&ec_keypair).sign(message);
        let pq_signature = PQSignature::new(&pq_keypair).sign(message);

        let signature_metadata = SignatureMetadataFormat {
            pq_algorithm,
            ec_algorithm,
        };

        SignatureFormat {
            signature_metadata: Some(signature_metadata),
            ec_public_key: ec_keypair.public_key,
            pq_public_key: pq_keypair.public_key,
            message: message.to_vec(),
            ec_signature,
            pq_signature,
        }
    }

    pub fn verify(signature: &SignatureFormat) -> Result<bool, SareError> {

        let ec_algorithm = signature.signature_metadata.as_ref().unwrap().ec_algorithm;
        let pq_algorithm = signature.signature_metadata.as_ref().unwrap().pq_algorithm;


        let ec_valid = ECSignature::verify(
            &ec_algorithm,
            &signature.ec_public_key,
            &signature.message,
            &signature.ec_signature
        )?;

        let pq_valid = PQSignature::verify(
            &pq_algorithm,
            &signature.pq_public_key,
            &signature.message,
            &signature.pq_signature
        )?;

        Ok(ec_valid && pq_valid)
    }

}
