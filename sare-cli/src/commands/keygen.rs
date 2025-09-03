use std::{
    fs::{self, File},
    io::{Cursor, Write},
    time::Duration,
};

use argh::FromArgs;

use indicatif::ProgressBar;
use sare_lib::{
    certificate::Certificate,
    keys::{HybridKEMAlgorithm, HybridSignAlgorithm, MasterKey},
    Issuer,
};
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

    /// generates public keys without validation certificate (Not recommended)
    #[argh(switch)]
    no_validation_cert: Option<bool>,

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
        let keyid = hex::encode_upper(masterkey.get_fullchain_private_fingerprint());

        let issuer_name = common::get_confirmed_input("Full Name: ");
        let issuer_email = common::get_confirmed_input("Email: ");
        let issuer = Issuer::new(issuer_name, issuer_email);
        let expiry_duration = common::human_readable_duration_to_timestamp(
            &common::get_confirmed_input("Key is valid for? "),
        )?;

        let sare_directory = common::prepare_sare_directory()?;
        let temp_dir = sare_directory.join(".temp");

        // Export master key to memory
        let mut master_buffer = Cursor::new(Vec::new());
        if self.unencrypted_keyfiles.unwrap_or(false) {
            masterkey.export(None, &mut master_buffer)?;
        } else {
            let passphrase = common::read_cli_secret("Enter your passphrase: ")?;

            let progress_bar = ProgressBar::new_spinner();
            progress_bar.set_message("Encrypting Masterkey...");
            progress_bar.enable_steady_tick(Duration::from_millis(100));

            masterkey.export(
                Some(SecretVec::<u8>::from(
                    passphrase.expose_secret().as_bytes().to_vec(),
                )),
                &mut master_buffer,
            )?;

            progress_bar.finish_with_message("Masterkey encrypted!");
        }

        // Export public key
        let mut public_buffer = Cursor::new(Vec::new());
        masterkey.export_public(&mut public_buffer)?;
        if !self.no_validation_cert.unwrap_or(false) {
            let validation_certificate =
                Certificate::new_validation(masterkey.clone(), expiry_duration, &issuer);
            validation_certificate.export(&mut public_buffer)?;
        }

        // Export revocation file
        let revocation_path_temp = temp_dir
            .join("revocations")
            .join(format!("REVOC_{fullchain_fingerprint}.asc"));
        let revocation_file_temp = fs::File::create(&revocation_path_temp)?;
        RevocationCommand::revocate_no_reason(masterkey.clone(), issuer, revocation_file_temp)?;

        // write files to temp dir
        let master_path_temp = temp_dir
            .join("private_keys")
            .join(format!("MASTER_{keyid}.pem"));
        fs::write(&master_path_temp, master_buffer.into_inner())?;

        let public_path_temp = temp_dir
            .join("public_keys")
            .join(format!("PUB_{fullchain_fingerprint}.pem"));
        fs::write(&public_path_temp, public_buffer.into_inner())?;

        // Move files to actual directories since everything went ok

        let master_final = sare_directory
            .join("private_keys")
            .join(format!("MASTER_{keyid}.pem"));
        let public_final = sare_directory
            .join("public_keys")
            .join(format!("PUB_{fullchain_fingerprint}.pem"));
        let revocation_final = sare_directory
            .join("revocations")
            .join(format!("REVOC_{fullchain_fingerprint}.asc"));

        fs::rename(master_path_temp, master_final)?;
        fs::rename(public_path_temp, public_final)?;
        fs::rename(revocation_path_temp, revocation_final)?;

        // Insert to DB
        let associated_key = db::SareDBAssociatedKey::new(
            &fullchain_fingerprint,
            &format!("{fullchain_fingerprint}"),
        );
        let mut sare_db = SareDB::import_from_json_file()?;
        sare_db.add_key_association(&keyid, associated_key);
        sare_db.save_to_json_file()?;

        println!(
            "\nYour Keypair has been generated!
        \n\tLOCATION: {:?},
        \n\tPUB: {}\n\tMASTER: {}",
            sare_directory, fullchain_fingerprint, keyid
        );

        Ok(())
    }
}
