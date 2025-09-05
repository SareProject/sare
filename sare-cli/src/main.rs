use argh::FromArgs;

mod commands;
pub mod common;
pub mod db;
pub mod error;

use crate::commands::{
    decrypt::DecryptCommand, encrypt::EncryptCommand, masterkey::MasterkeyCommand,
    recipient::RecipientCommand, revocation::RevocationCommand, signature::SignatureCommand,
};
use error::SareCLIError;

#[derive(FromArgs)]
/// Safe At Rest Encryption. A tool to stay Safe in the Quantum Age
struct SareCli {
    #[argh(subcommand)]
    cmd: SubCommand,
}

#[derive(FromArgs)]
#[argh(subcommand)]
enum SubCommand {
    MasterKey(MasterkeyCommand),
    Recipient(RecipientCommand),
    Signature(SignatureCommand),
    Encrypt(EncryptCommand),
    Decrypt(DecryptCommand),
    Revocation(RevocationCommand),
}

fn main() -> () {
    pretty_env_logger::init();
    // Parse command-line arguments
    let args: SareCli = argh::from_env();

    let result = match args.cmd {
        SubCommand::MasterKey(masterkey_command) => masterkey_command.execute(),
        SubCommand::Recipient(recipient_command) => recipient_command.execute(),
        SubCommand::Signature(signature_command) => signature_command.execute(),
        SubCommand::Encrypt(encrypt_command) => encrypt_command.execute(),
        SubCommand::Decrypt(decrypt_command) => decrypt_command.execute(),
        SubCommand::Revocation(revocation_command) => revocation_command.execute(),
    };

    match result {
        Ok(()) => (),
        Err(e) => e.pretty(),
    }
}
