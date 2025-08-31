use std::{
    fs::{self, File},
    path::PathBuf,
};

use argh::FromArgs;
use sare_lib::{
    certificate::SignatureFormat,
    encryption::Encryptor,
    keys::{EncodablePublic, MasterKey},
};
use sare_lib::{keys::SharedPublicKey, signing::Signing};
use secrecy::ExposeSecret;

use crate::{
    commands::{recipient, signature},
    common,
    db::SareDB,
    error::SareCLIError,
};

#[derive(FromArgs)]
/// Generates/Verifies Signatures
#[argh(subcommand, name = "encrypt")]
pub struct EncryptCommand {
    #[argh(positional)]
    input_file: PathBuf,
    #[argh(positional)]
    output_file: PathBuf,
    /// recipient id
    #[argh(option)]
    recipient: Option<String>,
    /// masterkey id
    #[argh(option)]
    masterkey_id: Option<String>,
}

impl EncryptCommand {
    pub fn execute(&self) -> Result<(), SareCLIError> {
        let mut input_file = File::open(&self.input_file)?;
        let mut output_file = File::create(&self.output_file)?;

        let recipient = common::get_recipient_from_cli(&self.recipient)?;

        let masterkey = common::get_master_key_from_cli(&self.masterkey_id)?;

        let encryptor = Encryptor::new(masterkey);

        println!("Starting the encryption!");

        encryptor.encrypt_with_recipient(
            &mut input_file,
            &mut output_file,
            &recipient,
            sare_lib::keys::EncryptionAlgorithm::XCHACHA20POLY1305,
        )?;

        Ok(())
    }
}
