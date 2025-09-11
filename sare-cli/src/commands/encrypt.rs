use std::{fs::File, path::PathBuf};

use argh::FromArgs;
use colored::*;
use sare_lib::{
    encryption::Encryptor,
    keys::{self, MasterKey, SharedPublicKey},
};
use secrecy::{ExposeSecret, SecretVec};

use crate::{SareCLIError, common};

#[derive(FromArgs, Debug)]
#[argh(subcommand)]
enum EncryptionSubCommand {
    Symmetric(SymmetricEncryption),
    Asymmetric(AsymmetricEncryption),
}

#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "symmetric")]
/// Symmetric encryption of a file
struct SymmetricEncryption {
    #[argh(positional)]
    input_file: PathBuf,
    #[argh(positional)]
    output_file: PathBuf,
    /// kdf algorithm
    #[argh(option)]
    kdf_algorithm: Option<String>,
    /// kdf scaling factor
    #[argh(option)]
    kdf_scaling_factor: Option<u32>,
}

#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "asymmetric")]
/// Asymmetric encryption of a file
struct AsymmetricEncryption {
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

#[derive(FromArgs)]
/// Encrypt files symmetrically or asymmetrically
#[argh(subcommand, name = "encrypt")]
pub struct EncryptCommand {
    #[argh(subcommand)]
    sub: EncryptionSubCommand,
}

impl EncryptCommand {
    pub fn execute(&self) -> Result<(), SareCLIError> {
        match &self.sub {
            EncryptionSubCommand::Asymmetric(asym) => self.asymmetric(asym),
            EncryptionSubCommand::Symmetric(sym) => self.symmetric(sym),
        }
    }

    fn asymmetric(&self, asym: &AsymmetricEncryption) -> Result<(), SareCLIError> {
        let mut input_file = File::open(&asym.input_file)?;
        let mut output_file = File::create(&asym.output_file)?;

        let recipient: SharedPublicKey = common::get_recipient_from_cli(&asym.recipient)?;
        let masterkey: MasterKey = common::get_master_key_from_cli(&asym.masterkey_id)?;
        let encryptor = Encryptor::new(masterkey);

        println!("{} Starting asymmetric encryption...", "🔒".blue());

        encryptor.encrypt_with_recipient(
            &mut input_file,
            &mut output_file,
            &recipient,
            keys::EncryptionAlgorithm::XCHACHA20POLY1305,
        )?;

        println!(
            "{} File successfully encrypted asymmetrically:\n  📄 Input: {:?}\n  🔏 Output: {:?}",
            "✅".green(),
            asym.input_file,
            asym.output_file
        );

        Ok(())
    }

    fn symmetric(&self, sym: &SymmetricEncryption) -> Result<(), SareCLIError> {
        let mut input_file = File::open(&sym.input_file)?;
        let mut output_file = File::create(&sym.output_file)?;

        let passphrase = common::read_cli_secret("Enter passphrase for symmetric encryption: ")?;
        let passphrase_bytes: SecretVec<u8> =
            SecretVec::new(passphrase.expose_secret().to_string().into_bytes());

        let scaling_factor = sym.kdf_scaling_factor.unwrap_or(1);
        let kdf_algo = sym.kdf_algorithm.as_deref().unwrap_or("argon2");

        let pkdf = Encryptor::get_pkdf(
            &passphrase_bytes,
            keys::RECOMMENDED_PKDF_PARAMS,
            scaling_factor,
        );

        println!(
            "{} Starting symmetric encryption with AEAD ({} KDF)...",
            "🔐".blue(),
            kdf_algo
        );

        Encryptor::encrypt_with_passphrase(
            &mut input_file,
            &mut output_file,
            pkdf,
            keys::EncryptionAlgorithm::XCHACHA20POLY1305,
        )?;

        println!(
            "{} File successfully encrypted symmetrically:\n  📄 Input: {:?}\n  🔏 Output: {:?}",
            "✅".green(),
            sym.input_file,
            sym.output_file
        );

        Ok(())
    }
}
