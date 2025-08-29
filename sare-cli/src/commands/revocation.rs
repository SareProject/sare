use std::{
    borrow::Cow,
    fmt::Write,
    fs::File,
    sync::Arc,
    time::{self, SystemTime},
};

use argh::FromArgs;
use sare_lib::{certificate::Certificate, keys::MasterKey};

use crate::error::SareCLIError;

#[derive(FromArgs)]
/// Generates a SARE Revocation Certificate
#[argh(subcommand, name = "revcert")]
pub struct RevocationCommand {}

impl RevocationCommand {
    pub fn revocate_expiry(
        masterkey: MasterKey,
        expiry_duration_humanreadable: String,
        issuer: String,
        output: File,
    ) -> Result<(), SareCLIError> {
        let expiry_duration_timestamp = duration_str::parse(expiry_duration_humanreadable)
            .map_err(|e| format!("Failed to parse duration {e}"))?;

        let now_timestamp = SystemTime::now();
        let expiry_timestamp = now_timestamp + expiry_duration_timestamp;

        let target_time = expiry_timestamp
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .map_err(|e| e.to_string())?;

        let revocation_certificate =
            Certificate::new_revocation_expiry(masterkey, target_time, issuer);

        revocation_certificate.export(output)?;

        Ok(())
    }
}
