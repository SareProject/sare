use std::{
    fs::{self, File},
    io::{BufReader, Cursor, Read, Write},
    path::PathBuf,
    process::Output,
    time::Duration,
};

use argh::FromArgs;

use indicatif::ProgressBar;
use sare_lib::{
    certificate::Certificate,
    encryption::Decryptor,
    keys::{HybridKEMAlgorithm, HybridSignAlgorithm, MasterKey},
    Issuer,
};
use secrecy::{ExposeSecret, SecretVec};

use crate::{
    commands::{decrypt, revocation::RevocationCommand, signature},
    common,
    db::{self, SareDB},
    SareCLIError,
};

#[derive(FromArgs)]
/// Generates a SARE keypair
#[argh(subcommand, name = "decrypt")]
pub struct DecryptCommand {
    #[argh(positional)]
    input_file: PathBuf,
    #[argh(positional)]
    output_file: PathBuf,
    /// masterkey id
    #[argh(option)]
    masterkey_id: Option<String>,
}

impl DecryptCommand {
    pub fn execute(&self) -> Result<(), SareCLIError> {
        let mut input_file = File::open(&self.input_file)?;
        let mut output_file = File::create(&self.output_file)?;

        let file_header = Decryptor::decode_file_header_and_rewind(&mut input_file)?;

        if file_header.is_asymmetric() {
            let masterkey = common::get_master_key_from_cli(&self.masterkey_id)?;
            let decryptor = Decryptor::new(masterkey);

            let signature = decryptor.decrypt_with_recipient(&mut input_file, &mut output_file)?;

            println!("File Successfully decrypted!");

            if let Some(signature) = signature {
                if signature.fullchain_fingerprint
                    == file_header.signature.unwrap().fullchain_fingerprint
                {
                    println!("Signature attached to the file was valid! ");
                } else {
                    println!("Signature attached to the file was NOT valid!");
                }
            } else {
                println!("No signature was attached to the file");
            }
        } else {
            let passphrase = common::read_cli_secret("Please enter passphrase for the file: ")?;
            let passphrase_bytes =
                SecretVec::new(passphrase.expose_secret().to_owned().into_bytes());
            Decryptor::decrypt_with_passphrase(
                passphrase_bytes,
                &mut input_file,
                &mut output_file,
            )?;

            println!("File successfully decrypted");
        }

        Ok(())
    }
}
