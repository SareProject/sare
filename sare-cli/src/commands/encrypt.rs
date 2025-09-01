use std::{
    fs::{self, File},
    path::PathBuf,
};

use argh::FromArgs;
use sare_lib::{
    certificate::SignatureFormat,
    encryption::{self, Encryptor},
    keys::{self, EncodablePublic, MasterKey},
};
use sare_lib::{keys::SharedPublicKey, signing::Signing};
use secrecy::{ExposeSecret, SecretVec};

use crate::{
    commands::{recipient, signature},
    common,
    db::SareDB,
    error::SareCLIError,
};

#[derive(FromArgs, Debug)]
#[argh(subcommand)]
enum EncryptionSubCommand {
    Symmetric(SymmetricEncryption),
    Asymmetric(AsymmetricEncryption),
}

#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "symmetric")]
/// Add a new recipient
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
/// Remove a recipient
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
/// Generates/Verifies Signatures
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

        let recipient = common::get_recipient_from_cli(&asym.recipient)?;

        let masterkey = common::get_master_key_from_cli(&asym.masterkey_id)?;

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

    fn symmetric(&self, sym: &SymmetricEncryption) -> Result<(), SareCLIError> {
        let mut input_file = File::open(&sym.input_file)?;
        let mut output_file = File::create(&sym.output_file)?;

        // Ask the user for a passphrase
        let passphrase = common::read_cli_secret("Enter passphrase for symmetric encryption: ")?;
        let passphrase_bytes: SecretVec<u8> =
            SecretVec::new(passphrase.expose_secret().to_string().into_bytes());

        // Derive master key from the passphrase using the KDF
        let scaling_factor = sym.kdf_scaling_factor.unwrap_or(1);
        let _kdf_algo = sym.kdf_algorithm.as_deref().unwrap_or("argon2"); // TODO: fix this too

        // TODO: will ask the pkdf params from user

        let pkdf = Encryptor::get_pkdf(
            &passphrase_bytes,
            keys::RECOMENDED_PKDF_PARAMS,
            scaling_factor,
        );

        println!("Starting symmetric encryption with AEAD...");

        Encryptor::encrypt_with_passphrase(
            &mut input_file,
            &mut output_file,
            pkdf,
            keys::EncryptionAlgorithm::XCHACHA20POLY1305,
        )?;

        Ok(())
    }
}
