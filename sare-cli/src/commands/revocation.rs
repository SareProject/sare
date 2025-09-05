use std::fs::File;

use argh::FromArgs;
use colored::*;
use sare_lib::{
    certificate::Certificate, format::certificate::Issuer, format::certificate::RevocationReason,
    keys::MasterKey,
};

use crate::{common, db::SareDB, error::SareCLIError};

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
/// Generates a new revocation certificate and replaces the old one
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
/// Lists revocations
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
            RevocationSubCommand::New(new) => self.new_revocation(new),
        }
    }

    fn list_revocation(&self) -> Result<(), SareCLIError> {
        let sare_db = SareDB::import_from_json_file()?;
        let key_associations = sare_db.key_associations;

        if key_associations.is_empty() {
            println!("{} No revocation certificates found.", "⚠️".yellow());
            return Ok(());
        }

        println!("{} Revocation Certificates:", "📜".cyan());
        for (masterkey_id, associated_key) in &key_associations {
            println!("🔑 MasterKey: {}", masterkey_id);
            println!(
                "  📄 PublicKey fingerprint: {}",
                associated_key.public_key_id
            );
            println!(
                "  🗑️ Revocation Certificate ID: {}\n",
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

        let output_file = sare_directory
            .join("revocations")
            .join(format!("REVOC_{}.asc", fullchain_fingerprint));
        let output = File::create(&output_file)?;

        println!(
            "{} Generating revocation certificate for MasterKey: {}",
            "🗑️".blue(),
            fullchain_fingerprint
        );

        match new.reason {
            RevocationReason::Compromised => Self::revocate_compromised(masterkey, issuer, output)?,
            RevocationReason::NoReasonSpecified => {
                Self::revocate_no_reason(masterkey, issuer, output)?
            }
        }

        println!(
            "{} Revocation certificate saved at {:?}",
            "✅".green(),
            output_file
        );

        Ok(())
    }

    fn broadcast_revocation(&self) -> Result<(), SareCLIError> {
        println!("{} Feature not implemented yet!", "⚠️".yellow());
        Ok(())
    }

    pub fn revocate_no_reason(
        masterkey: MasterKey,
        issuer: Issuer,
        output: File,
    ) -> Result<(), SareCLIError> {
        let revocation_certificate = Certificate::new_revocation(
            masterkey,
            common::get_now_timestamp(),
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
            common::get_now_timestamp(),
            issuer,
            RevocationReason::Compromised,
        );
        revocation_certificate.export(output)?;
        Ok(())
    }
}
