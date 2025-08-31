use std::{
    fs::{self, File},
    io::Cursor,
    path::{Path, PathBuf},
    time::Duration,
};

use argh::FromArgs;

use indicatif::ProgressBar;
use sare_lib::keys::{
    FullChainPublicKeyFormat, HybridKEMAlgorithm, HybridSignAlgorithm, MasterKey, SharedPublicKey,
};
use secrecy::{ExposeSecret, SecretVec};

use crate::{
    commands::{recipient, revocation::RevocationCommand},
    common::{self, prepare_sare_directory},
    db::{self, SareDB, SareDBRecipient},
    SareCLIError,
};

#[derive(FromArgs, Debug)]
#[argh(subcommand)]
enum RecipientSubCommand {
    Add(AddRecipient),
    Remove(RemoveRecipient),
    List(ListRecipients),
}

#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "add")]
/// Add a new recipient
struct AddRecipient {
    #[argh(positional)]
    key: PathBuf,
}

#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "remove")]
/// Remove a recipient
struct RemoveRecipient {
    /// identifier (id or fingerprint)
    #[argh(positional)]
    id: String,
}

#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "list")]
/// List all recipients
struct ListRecipients {}

#[derive(FromArgs)]
/// Generates a SARE keypair
#[argh(subcommand, name = "recipient")]
pub struct RecipientCommand {
    /// generates key files without encryption (Not recommended)
    #[argh(subcommand)]
    sub: RecipientSubCommand,
}

impl RecipientCommand {
    pub fn execute(&self) -> Result<(), SareCLIError> {
        match &self.sub {
            RecipientSubCommand::Add(add) => self.add_recipient(add)?,
            RecipientSubCommand::Remove(remove) => self.remove_recipient(remove)?,
            RecipientSubCommand::List(_) => Self::list_recipients()?,
        }
        Ok(())
    }

    fn add_recipient(&self, add: &AddRecipient) -> Result<(), SareCLIError> {
        let pem_content = fs::read_to_string(&add.key)?;
        let recipient_key = SharedPublicKey::from_pem(pem_content)?;
        let fullchain_fingerprint = recipient_key.fullchain_public_key.calculate_fingerprint();

        let sare_directory = common::prepare_sare_directory()?;
        let temp_dir = sare_directory.join(".temp");

        let fullchain_fingerprint = hex::encode_upper(fullchain_fingerprint);

        let mut recipient_buffer = Cursor::new(Vec::new());
        recipient_key.export(recipient_buffer.get_mut())?;

        // Export to temp dirs
        let recipient_path_temp = temp_dir
            .join("recipients")
            .join(format!("RECIPIENT_{}.pem", &fullchain_fingerprint.as_str()));
        fs::write(&recipient_path_temp, &recipient_buffer.into_inner())?;

        let is_key_verified =
            if let Some(verification_certificate) = recipient_key.validation_certificate {
                verification_certificate.verify()?
            } else {
                false
            };

        let recipient_final = sare_directory
            .join("recipients")
            .join(format!("RECIPIENT_{}.pem", &fullchain_fingerprint));

        fs::rename(recipient_path_temp, recipient_final)?;

        let comment = common::get_confirmed_input(
            "Add any comment or aditional information for this recipient: ",
        );

        let recipient = SareDBRecipient::new(&fullchain_fingerprint, Some(comment));

        let mut sare_db = SareDB::import_from_json_file()?;
        sare_db.add_recipient(fullchain_fingerprint[0..10].to_string(), recipient);
        sare_db.save_to_json_file()?;

        println!(
            "\nPublicKey added as recipient
        \n\tLOCATION: {:?},
        \n\tPUB: {}\n\tVERIFIED: {}",
            sare_directory.join("recipients"),
            fullchain_fingerprint,
            is_key_verified
        );

        Ok(())
    }

    fn remove_recipient(&self, remove: &RemoveRecipient) -> Result<(), SareCLIError> {
        let mut sare_db = SareDB::import_from_json_file()?;

        if sare_db.recipients.remove(&remove.id).is_some() {
            println!("Recipient {} removed successfully.", remove.id);
        } else {
            println!("No recipient found with id: {}", remove.id);
        }

        sare_db.save_to_json_file()?;

        let sare_directory = prepare_sare_directory()?;
        let recipient_file = sare_directory
            .join("recipients")
            .join(format!("RECIPIENT_{}.pem", remove.id));

        if recipient_file.exists() {
            fs::remove_file(recipient_file)?;
        }

        Ok(())
    }

    fn list_recipients() -> Result<(), SareCLIError> {
        let sare_db = SareDB::import_from_json_file()?;

        if sare_db.recipients.is_empty() {
            println!("No recipients found.");
            return Ok(());
        }

        println!("Recipients:");
        for (idx, (id, r)) in sare_db.recipients.iter().enumerate() {
            println!(
                "{}. {}\n\tFingerprint: {}\n\tComment: {}\n\tAdded: {}\n",
                idx + 1,
                id,
                r.fullchain_fingerprint,
                r.comment.as_deref().unwrap_or("None"),
                common::format_expiry_date(Some(r.date_added))
            );
        }

        Ok(())
    }
}
