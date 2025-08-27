use std::fs::File;

use argh::FromArgs;

use sare_lib::keys::{HybridKEMAlgorithm, HybridSignAlgorithm, MasterKey};
use secrecy::{ExposeSecret, SecretVec};

use crate::{
    commands::revocation::RevocationCommand,
    common,
    db::{self, SareDB},
    SareCLIError,
};

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

        let keyid = hex::encode_upper(masterkey.get_fullchain_private_fingerprint());

        let mut masterkey_file =
            File::create(sare_directory.join(format!("private_keys/MASTER_{keyid}.pem")))?;
        let mut publickey_file = File::create(
            sare_directory.join(format!("public_keys/PUB_{fullchain_fingerprint}.pem")),
        )?;
        let revocation_file = File::create(
            sare_directory.join(format!("revocations/REVOC_{fullchain_fingerprint}.asc")),
        )?;

        let issuer_name = common::get_confirmed_input("Full Name: ");
        let issuer_email = common::get_confirmed_input("Email: ");

        let issuer = format!("{issuer_name} <{issuer_email}>");

        let expiry_duration = common::get_confirmed_input("Key is valid for?");

        // NOTE: Really unefficient way of cloning masterkey, should be sorted out later
        RevocationCommand::revocate_expiry(
            masterkey.clone(),
            expiry_duration,
            issuer,
            revocation_file,
        )?;

        let associated_key =
            db::SareDBAssociatedKey::new(&fullchain_fingerprint, &fullchain_fingerprint);
        let sare_db = SareDB::new(&keyid, associated_key);

        sare_db.insert_to_json_file()?;

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
