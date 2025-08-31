use sare_core::{
    bson::raw,
    format::{
        header::HeaderMetadataFormat,
        signature::{SignatureFormat, SignatureMetadataFormat},
    },
    hybrid_sign::{ECSignature, PQSignature},
    sha3::Digest,
};

use crate::{keys::MasterKey, signing, SareError};

pub struct Signing(MasterKey);

impl Signing {
    pub fn new(master_key: MasterKey) -> Self {
        Signing(master_key)
    }

    // TODO: Copy and Clone needs to be implemented in sare-core::hybrid_sign
    // TODO: `new`/`from` methods needs to be implemented for Signature Formats
    fn sign(&self, raw_message: &[u8], attached: bool) -> SignatureFormat {
        let fullchain_fingerprint = self.0.get_fullchain_public_fingerprint();
        let mut merged_message =
            Vec::with_capacity(raw_message.len() + fullchain_fingerprint.len());
        merged_message.extend_from_slice(raw_message);
        merged_message.extend_from_slice(&fullchain_fingerprint);

        let signing_keypair = self.0.get_signing_keypair();
        let ec_keypair = signing_keypair.0;
        let pq_keypair = signing_keypair.1;

        let message = if attached {
            Some(raw_message.to_vec())
        } else {
            None
        };

        let ec_algorithm = ec_keypair.algorithm;
        let pq_algorithm = pq_keypair.algorithm;

        let ec_signature = ECSignature::new(&ec_keypair).hash_and_sign(&merged_message);
        let pq_signature = PQSignature::new(&pq_keypair).hash_and_sign(&merged_message);

        let signature_metadata = SignatureMetadataFormat {
            pq_algorithm,
            ec_algorithm,
        };

        SignatureFormat {
            signature_metadata: Some(signature_metadata),
            ec_public_key: ec_keypair.public_key,
            pq_public_key: pq_keypair.public_key,
            message,
            ec_signature,
            pq_signature,
            fullchain_fingerprint,
        }
    }

    pub fn sign_attached(&self, raw_message: &[u8]) -> SignatureFormat {
        self.sign(raw_message, true)
    }

    pub fn sign_detached(&self, raw_message: &[u8]) -> SignatureFormat {
        self.sign(raw_message, false)
    }

    fn verify(signature: &SignatureFormat, message: &[u8]) -> Result<bool, SareError> {
        let fullchain_fingerprint = signature.fullchain_fingerprint;
        let mut merged_message = Vec::with_capacity(message.len() + fullchain_fingerprint.len());
        merged_message.extend_from_slice(message);
        merged_message.extend_from_slice(&fullchain_fingerprint);

        let ec_algorithm = signature.signature_metadata.as_ref().unwrap().ec_algorithm;
        let pq_algorithm = signature.signature_metadata.as_ref().unwrap().pq_algorithm;

        let ec_valid = ECSignature::hash_and_verify(
            &ec_algorithm,
            &signature.ec_public_key,
            &merged_message,
            &signature.ec_signature,
        )?;

        let pq_valid = PQSignature::hash_and_verify(
            &pq_algorithm,
            &signature.pq_public_key,
            &merged_message,
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
