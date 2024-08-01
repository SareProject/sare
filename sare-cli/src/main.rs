use lib::{common, SareCLIError};
use std::{error::Error, fs::File};

use argh::{FromArgValue, FromArgs};

use sare_lib::{
    keys::{HybridKEMAlgorithm, HybridSignAlgorithm, MasterKey},
    SareError,
};
use secrecy::{ExposeSecret, SecretString, SecretVec};

// TODO: Use a crate to create and check if the directory exists, this is for testing purposes only
const DEFAULT_KEY_PATH: &str = ".sare";

#[derive(FromArgs)]
/// Safe At Rest Encryption. A tool to stay Safe in the Quantum Age
struct SareCli {
    #[argh(subcommand)]
    cmd: SubCommand,
}

#[derive(FromArgs)]
#[argh(subcommand)]
enum SubCommand {
    KeyGen(KeyGen),
}

#[derive(FromArgs)]
/// Generates a SARE keypair
#[argh(subcommand, name = "keygen")]
struct KeyGen {
    /// generates key files without encryption (Not recommended)
    #[argh(switch)]
    unencrypted_keyfiles: Option<bool>,

    /// hybrid KEM algorithm
    #[argh(option)]
    hybrid_kem_algorithm: Option<String>,

    /// hybrid Sign algorithm
    #[argh(option)]
    hybrid_sign_algorithm: Option<String>,
}

fn generate_key_pair(options: &KeyGen) -> Result<(), SareCLIError> {
    let masterkey = MasterKey::generate(
        HybridKEMAlgorithm::from_string(
            options
                .hybrid_kem_algorithm
                .clone()
                .unwrap_or("".to_string()),
        ),
        HybridSignAlgorithm::from_string(
            options
                .hybrid_sign_algorithm
                .clone()
                .unwrap_or("".to_string()),
        ),
    );

    let mut masterkey_file = File::create("sare_masterkey.pem")?;
    let mut publickey_file = File::create("sare_publickey.pem")?;

    match options.unencrypted_keyfiles {
        None => {
            let passphrase = common::read_cli_secret("Enter your passphrase: ")?;

            masterkey.export(
                Some(SecretVec::<u8>::from(
                    passphrase.expose_secret().as_bytes().to_vec(),
                )),
                &mut masterkey_file,
            )
        }
        Some(_) => masterkey.export(None, &mut masterkey_file),
    }?;

    masterkey.export_public(&mut publickey_file)?;

    // TODO: create and return fingerprint as well
    eprintln!("Your Keypair has been generated!");
    Ok(())
}

fn main() -> Result<(), SareCLIError> {
    // Parse command-line arguments
    let args: SareCli = argh::from_env();

    match args.cmd {
        SubCommand::KeyGen(options) => generate_key_pair(&options),
    }
}
