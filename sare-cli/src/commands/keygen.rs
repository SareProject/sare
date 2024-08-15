use std::{fs::File, path::PathBuf};

use argh::FromArgs;

use sare_lib::keys::{HybridKEMAlgorithm, HybridSignAlgorithm, MasterKey};
use secrecy::{ExposeSecret, SecretVec};

use crate::{common, SareCLIError};

#[derive(FromArgs)]
/// Generates a SARE keypair
#[argh(subcommand, name = "keygen")]
pub struct KeyGenCommand {
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

impl KeyGenCommand {
    pub fn execute(&self) -> Result<(), SareCLIError> {
        let masterkey = MasterKey::generate(
            HybridKEMAlgorithm::from_string(
                self.hybrid_kem_algorithm.clone().unwrap_or("".to_string()),
            ),
            HybridSignAlgorithm::from_string(
                self.hybrid_sign_algorithm.clone().unwrap_or("".to_string()),
            ),
        );

        let fullchain_fingerprint = hex::encode_upper(masterkey.get_fullchain_public_fingerprint());

        let sare_directory = common::prepare_sare_directory()?;

        // TODO: generate fingerprint or keyid and name the file with that
        let mut masterkey_file = File::create(sare_directory.join("private_keys/sare_masterkey.pem"))?;
        let mut publickey_file = File::create(sare_directory.join(format!("public_keys/PUB_{fullchain_fingerprint}.pem")))?;

        match self.unencrypted_keyfiles {
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

        log::info!("Your Keypair has been generated!");
        Ok(())
    }
}
