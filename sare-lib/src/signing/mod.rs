use sare_core::{
    bson::raw,
    format::signature::{SignatureFormat, SignatureMetadataFormat},
    hybrid_sign::{ECSignature, PQSignature},
    sha3::Digest,
};

use crate::{keys::MasterKey, SareError};

pub struct Signing(MasterKey);

impl Signing {
    pub fn new(master_key: MasterKey) -> Self {
        Signing(master_key)
    }

    fn checksum_message(message: &[u8]) -> Vec<u8> {
        let mut hasher = sare_core::sha3::Sha3_256::new();

        hasher.update(message);

        let result = hasher.finalize();

        result.to_vec()
    }

    // TODO: Copy and Clone needs to be implemented in sare-core::hybrid_sign
    // TODO: `new`/`from` methods needs to be implemented for Signature Formats
    fn sign(&self, raw_message: &[u8], attached: bool) -> SignatureFormat {
        let message = &Self::checksum_message(raw_message);

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

        let raw_message = if attached {
            Some(raw_message.to_vec())
        } else {
            None
        };

        SignatureFormat {
            signature_metadata: Some(signature_metadata),
            ec_public_key: ec_keypair.public_key,
            pq_public_key: pq_keypair.public_key,
            message: raw_message,
            ec_signature,
            pq_signature,
        }
    }

    pub fn sign_attached(&self, raw_message: &[u8]) -> SignatureFormat {
        self.sign(raw_message, true)
    }

    pub fn sign_detached(&self, raw_message: &[u8]) -> SignatureFormat {
        self.sign(raw_message, false)
    }

    fn verify(signature: &SignatureFormat, raw_message: &[u8]) -> Result<bool, SareError> {
        let message = &Self::checksum_message(&raw_message);

        let ec_algorithm = signature.signature_metadata.as_ref().unwrap().ec_algorithm;
        let pq_algorithm = signature.signature_metadata.as_ref().unwrap().pq_algorithm;

        let ec_valid = ECSignature::verify(
            &ec_algorithm,
            &signature.ec_public_key,
            message,
            &signature.ec_signature,
        )?;

        let pq_valid = PQSignature::verify(
            &pq_algorithm,
            &signature.pq_public_key,
            message,
            &signature.pq_signature,
        )?;

        Ok(ec_valid && pq_valid)
    }

    pub fn verify_detached(
        signature: &SignatureFormat,
        raw_message: &[u8],
    ) -> Result<bool, SareError> {
        Self::verify(signature, raw_message)
    }

    pub fn verify_attached(signature: &SignatureFormat) -> Result<bool, SareError> {
        let raw_message = if let Some(message) = &signature.message {
            message
        } else {
            return Err(SareError::CoreError(sare_core::CoreErrorKind::HybridSign(
                sare_core::hybrid_sign::error::HybridSignError::Unexpected,
            )));
        };

        Self::verify(signature, &raw_message)
    }
}
