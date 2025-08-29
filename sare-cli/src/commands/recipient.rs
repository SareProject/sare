use std::{
    fs::{self, File},
    io::Cursor,
    path::Path,
    time::Duration,
};

use argh::FromArgs;

use indicatif::ProgressBar;
use sare_lib::keys::{
    FullChainPublicKeyFormat, HybridKEMAlgorithm, HybridSignAlgorithm, MasterKey,
    RecipientPublicKey,
};
use secrecy::{ExposeSecret, SecretVec};

use crate::{
    commands::revocation::RevocationCommand,
    common,
    db::{self, SareDB},
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
    key: String,
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
        Ok(())
    }

    fn add_recipient(&self, add: &AddRecipient) -> Result<(), SareCLIError> {
        let pem_content = fs::read_to_string(&add.key)?;
        let recipient_key = RecipientPublicKey::from_pem(pem_content)?;

        todo!();
    }

    fn remove_recipient(&self, remove: &RemoveRecipient) -> Result<(), SareCLIError> {
        todo!();
    }

    fn list_recipients() -> Result<(), SareCLIError> {
        todo!();
    }
}
