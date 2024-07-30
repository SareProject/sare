use lib::{common, SareCLIError};
use std::{error::Error, fs::File};

use argh::FromArgs;

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
    #[argh(option)]
    unencrypted_keyfiles: Option<bool>,
}

// TODO: Implement Display to SareError so it can be returned here and shown to the user
fn generate_key_pair(options: &KeyGen) -> Result<(), SareCLIError> {
    // TODO: Take algorithms as input and if they're None use default
    let masterkey = MasterKey::generate(
        HybridKEMAlgorithm::default(),
        HybridSignAlgorithm::default(),
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
        Some(_) => {
            masterkey.export(
                None,
                &mut masterkey_file,
            )
        }
    }?;

    masterkey.export_public(&mut publickey_file)?;
    todo!();
    //let output_file = File::create(output_path);
}

fn main() {
    // Parse command-line arguments
    let args: SareCli = argh::from_env();

    match args.cmd {
        SubCommand::KeyGen(options) => {
            if let Err(err) = generate_key_pair(&options) {
                eprintln!("Error: {}", err);
            } else {
                println!("Key pair generated!");
            }
        }
    }
}
