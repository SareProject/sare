use std::{fs::File, path::PathBuf};

use argh::FromArgs;
use colored::*;
use sare_lib::encryption::Decryptor;
use secrecy::{ExposeSecret, SecretVec};

use crate::{SareCLIError, common};

#[derive(FromArgs)]
/// Decrypt a SARE-encrypted file
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

            println!("{} Starting asymmetric decryption...", "🔒".blue());
            let signature = decryptor.decrypt_with_recipient(&mut input_file, &mut output_file)?;

            println!(
                "{} File successfully decrypted!\n  📄 Input: {:?}\n  📂 Output: {:?}",
                "✅".green(),
                self.input_file,
                self.output_file
            );

            if let Some(signature) = signature {
                if signature.fullchain_fingerprint
                    == file_header.signature.unwrap().fullchain_fingerprint
                {
                    println!("  {} Signature attached to the file is VALID", "✅".green());
                } else {
                    println!("  {} Signature attached to the file is INVALID", "❌".red());
                }
            } else {
                println!("  {} No signature was attached to the file", "⚠️".yellow());
            }
        } else {
            let passphrase = common::read_cli_secret("Please enter passphrase for the file: ")?;
            let passphrase_bytes =
                SecretVec::new(passphrase.expose_secret().to_owned().into_bytes());

            println!("{} Starting symmetric decryption...", "🔐".blue());
            Decryptor::decrypt_with_passphrase(
                passphrase_bytes,
                &mut input_file,
                &mut output_file,
            )?;

            println!(
                "{} File successfully decrypted\n  📄 Input: {:?}\n  📂 Output: {:?}",
                "✅".green(),
                self.input_file,
                self.output_file
            );
        }

        Ok(())
    }
}
