use argh::FromArgs;

mod commands;
pub mod common;
pub mod db;
pub mod error;

use crate::commands::{
    decrypt::DecryptCommand, encrypt::EncryptCommand, keygen::KeyGenCommand,
    listkeys::ListKeysCommand, recipient::RecipientCommand, revocation::RevocationCommand,
    signature::SignatureCommand,
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
    KeyGen(KeyGenCommand),
    ListKeys(ListKeysCommand),
    Recipient(RecipientCommand),
    Signature(SignatureCommand),
    Encrypt(EncryptCommand),
    Decrypt(DecryptCommand),
    Revocation(RevocationCommand),
}

fn main() -> Result<(), SareCLIError> {
    pretty_env_logger::init();
    // Parse command-line arguments
    let args: SareCli = argh::from_env();

    match args.cmd {
        SubCommand::KeyGen(keygen_command) => keygen_command.execute(),
        SubCommand::ListKeys(listkeys_command) => listkeys_command.execute(),
        SubCommand::Recipient(recipient_command) => recipient_command.execute(),
        SubCommand::Signature(signature_command) => signature_command.execute(),
        SubCommand::Encrypt(encrypt_command) => encrypt_command.execute(),
        SubCommand::Decrypt(decrypt_command) => decrypt_command.execute(),
        SubCommand::Revocation(revocation_command) => revocation_command.execute(),
    }
}
