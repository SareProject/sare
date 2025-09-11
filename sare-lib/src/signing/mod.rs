use sare_core::{
    format::signature::{SignatureFormat, SignatureHeaderFormat, SignatureMetadataFormat},
    hybrid_sign::{ECSignature, PQSignature},
};

use crate::{SARE_VERSION, SareError, keys::MasterKey};

pub struct Signing(MasterKey);

impl Signing {
    /// Create a new signing instance
    pub fn new(master_key: MasterKey) -> Self {
        Self(master_key)
    }

    /// Internal signing function
    fn sign(&self, raw_message: &[u8], attached: bool) -> SignatureHeaderFormat {
        let fullchain_fingerprint = self.0.get_fullchain_public_fingerprint();
        let merged_message =
            Self::merge_message_with_fingerprint(raw_message, &fullchain_fingerprint);

        let (ec_keypair, pq_keypair) = self.0.get_signing_keypair();

        let message_for_attached = if attached {
            Some(raw_message.to_vec())
        } else {
            None
        };

        let ec_signature = ECSignature::new(&ec_keypair).hash_and_sign(&merged_message);
        let pq_signature = PQSignature::new(&pq_keypair).hash_and_sign(&merged_message);

        let signature_metadata = SignatureMetadataFormat {
            ec_algorithm: ec_keypair.algorithm,
            pq_algorithm: pq_keypair.algorithm,
        };

        let signature = SignatureFormat {
            ec_public_key: ec_keypair.public_key,
            pq_public_key: pq_keypair.public_key,
            signature_metadata: Some(signature_metadata),
            message: message_for_attached,
            ec_signature,
            pq_signature,
            fullchain_fingerprint,
        };

        SignatureHeaderFormat {
            version: SARE_VERSION,
            signature,
        }
    }

    /// Sign with attached message
    pub fn sign_attached(&self, raw_message: &[u8]) -> SignatureHeaderFormat {
        self.sign(raw_message, true)
    }

    /// Sign with detached message
    pub fn sign_detached(&self, raw_message: &[u8]) -> SignatureHeaderFormat {
        self.sign(raw_message, false)
    }

    /// Verify a signature with a provided message
    fn verify(signature_header: &SignatureHeaderFormat, message: &[u8]) -> Result<bool, SareError> {
        if signature_header.version > SARE_VERSION {
            return Err(SareError::Unexpected(format!(
                "sare version {} or higher is required, your version is {}",
                signature_header.version, SARE_VERSION
            )));
        }

        let signature = &signature_header.signature;
        let merged_message =
            Self::merge_message_with_fingerprint(message, &signature.fullchain_fingerprint);

        let signature_metadata = signature.signature_metadata.as_ref().ok_or_else(|| {
            SareError::CoreError(sare_core::CoreErrorKind::HybridSign(
                sare_core::hybrid_sign::error::HybridSignError::Unexpected,
            ))
        })?;

        let ec_valid = ECSignature::hash_and_verify(
            &signature_metadata.ec_algorithm,
            &signature.ec_public_key,
            &merged_message,
            &signature.ec_signature,
        )?;

        let pq_valid = PQSignature::hash_and_verify(
            &signature_metadata.pq_algorithm,
            &signature.pq_public_key,
            &merged_message,
            &signature.pq_signature,
        )?;

        Ok(ec_valid && pq_valid)
    }

    /// Verify a detached signature
    pub fn verify_detached(
        signature_header: &SignatureHeaderFormat,
        raw_message: &[u8],
    ) -> Result<bool, SareError> {
        Self::verify(signature_header, raw_message)
    }

    /// Verify an attached signature
    pub fn verify_attached(signature_header: &SignatureHeaderFormat) -> Result<bool, SareError> {
        let signature = &signature_header.signature;
        let message = signature.message.as_ref().ok_or_else(|| {
            SareError::CoreError(sare_core::CoreErrorKind::HybridSign(
                sare_core::hybrid_sign::error::HybridSignError::Unexpected,
            ))
        })?;

        Self::verify(signature_header, message)
    }

    /// Helper to merge message with fullchain fingerprint
    fn merge_message_with_fingerprint(message: &[u8], fingerprint: &[u8]) -> Vec<u8> {
        let mut merged = Vec::with_capacity(message.len() + fingerprint.len());
        merged.extend_from_slice(message);
        merged.extend_from_slice(fingerprint);
        merged
    }
}
