use std::{
    borrow::Cow,
    fmt::Write,
    fs::File,
    process::Output,
    str::FromStr,
    sync::Arc,
    time::{self, SystemTime},
};

use sare_lib::format::certificate::RevocationReason;

use argh::FromArgs;
use sare_lib::{certificate::Certificate, keys::MasterKey, Issuer};

use crate::{
    common::{self, get_now_timestamp},
    db::SareDB,
    error::SareCLIError,
};

#[derive(FromArgs, Debug)]
#[argh(subcommand)]
enum RevocationSubCommand {
    Broadcast(BroadcastRevocation),
    New(NewRevocation),
    List(ListRevocation),
}

#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "broadcast")]
/// Broadcasts revocation to keyservers
struct BroadcastRevocation {}

#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "new")]
/// Generates a new revocation cert and replaces the old one
struct NewRevocation {
    /// reason for revocation (compromised | no-reason)
    #[argh(option, default = "RevocationReason::NoReasonSpecified")]
    reason: RevocationReason,
    /// masterkey id
    #[argh(option)]
    masterkey_id: Option<String>,
}

#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "list")]
/// Lists Revocations
pub struct ListRevocation {}

#[derive(FromArgs)]
/// Generates a SARE Revocation Certificate
#[argh(subcommand, name = "revocation")]
pub struct RevocationCommand {
    #[argh(subcommand)]
    sub: RevocationSubCommand,
}

impl RevocationCommand {
    pub fn execute(&self) -> Result<(), SareCLIError> {
        match &self.sub {
            RevocationSubCommand::Broadcast(_) => self.broadcast_revocation(),
            RevocationSubCommand::List(_) => self.list_revocation(),
            RevocationSubCommand::New(new) => self.new_revocation(&new),
        }
    }

    fn list_revocation(&self) -> Result<(), SareCLIError> {
        let sare_db = SareDB::import_from_json_file()?;

        let key_associations = sare_db.key_associations;

        for (masterkey_id, associated_key) in &key_associations {
            println!("MasterKey: {}", masterkey_id);
            println!("\tPublicKey fingerprint: {}", associated_key.public_key_id);
            println!(
                "\tRevocation Certificate ID: {}",
                associated_key.revocation_certificate_id
            );
        }

        Ok(())
    }

    fn new_revocation(&self, new: &NewRevocation) -> Result<(), SareCLIError> {
        let masterkey = common::get_master_key_from_cli(&new.masterkey_id)?;

        let issuer_name = common::get_confirmed_input("Issuer Name: ");
        let issuer_email = common::get_confirmed_input("Issuer Email: ");

        let issuer = Issuer {
            name: issuer_name,
            email: issuer_email,
        };

        let sare_directory = common::prepare_sare_directory()?;

        let fullchain_fingerprint = hex::encode_upper(masterkey.get_fullchain_public_fingerprint());

        let output = File::create(
            sare_directory
                .join("revocations")
                .join(format!("REVOC_{}.asc", fullchain_fingerprint)),
        )?;

        match new.reason {
            RevocationReason::Compromised => Self::revocate_compromised(masterkey, issuer, output),
            RevocationReason::NoReasonSpecified => {
                Self::revocate_no_reason(masterkey, issuer, output)
            }
        }
    }

    fn broadcast_revocation(&self) -> Result<(), SareCLIError> {
        print!("Not implemented yet!");
        Ok(())
    }

    pub fn revocate_no_reason(
        masterkey: MasterKey,
        issuer: Issuer,
        output: File,
    ) -> Result<(), SareCLIError> {
        let revocation_certificate = Certificate::new_revocation(
            masterkey,
            get_now_timestamp(),
            issuer,
            RevocationReason::NoReasonSpecified,
        );

        revocation_certificate.export(output)?;

        Ok(())
    }

    pub fn revocate_compromised(
        masterkey: MasterKey,
        issuer: Issuer,
        output: File,
    ) -> Result<(), SareCLIError> {
        let revocation_certificate = Certificate::new_revocation(
            masterkey,
            get_now_timestamp(),
            issuer,
            RevocationReason::Compromised,
        );

        revocation_certificate.export(output)?;

        Ok(())
    }
}
