use std::{
    borrow::Cow,
    fmt::Write,
    fs::File,
    sync::Arc,
    time::{self, SystemTime},
};

use argh::FromArgs;
use sare_lib::{certificate::Certificate, keys::MasterKey, Issuer};

use crate::{
    common::{self, get_now_timestamp},
    error::SareCLIError,
};

#[derive(FromArgs)]
/// Generates a SARE Revocation Certificate
#[argh(subcommand, name = "revcert")]
pub struct RevocationCommand {}

impl RevocationCommand {
    pub fn revocate_no_reason(
        masterkey: MasterKey,
        issuer: Issuer,
        output: File,
    ) -> Result<(), SareCLIError> {
        let revocation_certificate =
            Certificate::new_revocation_no_reason(masterkey, get_now_timestamp(), issuer);

        revocation_certificate.export(output)?;

        Ok(())
    }
}
