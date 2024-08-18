use std::{borrow::Cow, fmt::Write, fs::File, sync::Arc, time};

use argh::FromArgs;
use sare_lib::{certificate::Cerificate, keys::MasterKey};

use crate::error::SareCLIError;

#[derive(FromArgs)]
/// Generates a SARE keypair
#[argh(subcommand, name = "keygen")]
pub struct RevocationCommand {}

impl RevocationCommand {
    pub fn revocate_expiry(
        masterkey: MasterKey,
        expiry_duration_humanreadable: String,
        issuer: String,
        output: File,
    ) -> Result<(), SareCLIError> {
        // TODO: Add comments to the revocation certificate file

        let expiry_duration_timestamp = duration_str::parse(expiry_duration_humanreadable)
            .map_err(|e| format!("Failed to parse duration {e}"))?
            .as_secs();

        let now_timestamp = std::time::Instant::now().elapsed().as_secs();
        let expiry_timestamp = now_timestamp + expiry_duration_timestamp;

        let revocation_certificate =
            Cerificate::new_revocation_expiry(masterkey, expiry_timestamp, issuer);

        revocation_certificate.export(output)?;

        Ok(())
    }
}
