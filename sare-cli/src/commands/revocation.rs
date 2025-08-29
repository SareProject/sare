use std::{
    borrow::Cow,
    fmt::Write,
    fs::File,
    sync::Arc,
    time::{self, SystemTime},
};

use argh::FromArgs;
use sare_lib::{certificate::Certificate, keys::MasterKey};

use crate::{common, error::SareCLIError};

#[derive(FromArgs)]
/// Generates a SARE Revocation Certificate
#[argh(subcommand, name = "revcert")]
pub struct RevocationCommand {}

impl RevocationCommand {
    pub fn revocate_expiry(
        masterkey: MasterKey,
        expiry_timestamp: u64,
        issuer: String,
        output: File,
    ) -> Result<(), SareCLIError> {
        let revocation_certificate =
            Certificate::new_revocation_expiry(masterkey, expiry_timestamp, issuer);

        revocation_certificate.export(output)?;

        Ok(())
    }
}
