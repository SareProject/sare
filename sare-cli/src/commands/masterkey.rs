use std::{
    fs::{self, File},
    io::{Cursor, Read},
    time::Duration,
};

use argh::FromArgs;
use colored::*;
use indicatif::ProgressBar;
use sare_lib::{
    certificate::Certificate,
    format::certificate::Issuer,
    keys::{HybridKEMAlgorithm, HybridSignAlgorithm, MasterKey, SharedPublicKey},
};
use secrecy::{ExposeSecret, SecretVec};

use crate::{
    commands::revocation::RevocationCommand,
    common,
    db::{self, SareDB},
    SareCLIError,
};

#[derive(FromArgs, Debug)]
#[argh(subcommand)]
enum MasterkeySubCommand {
    Generate(GenerateMasterkey),
    List(ListMasterkeys),
    Remove(RemoveMasterkey),
    Info(ExportMasterkey),
}

#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "generate")]
/// Generate a new master key
struct GenerateMasterkey {
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

#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "remove")]
/// Remove an existing master key
struct RemoveMasterkey {
    /// masterkey id
    #[argh(positional)]
    masterkey_id: Option<String>,
    /// keep the key files
    #[argh(option)]
    keep_key_files: Option<bool>,
}

#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "export")]
/// Show information about a master key
struct ExportMasterkey {
    /// masterkey id
    #[argh(positional)]
    masterkey_id: Option<String>,
}

#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "list")]
/// List all available master keys
struct ListMasterkeys {}

#[derive(FromArgs)]
/// Manage SARE master keys
#[argh(subcommand, name = "masterkey")]
pub struct MasterkeyCommand {
    #[argh(subcommand)]
    sub: MasterkeySubCommand,
}

impl MasterkeyCommand {
    pub fn execute(&self) -> Result<(), SareCLIError> {
        match &self.sub {
            MasterkeySubCommand::Generate(gen) => self.generate_masterkey(gen),
            MasterkeySubCommand::List(_) => self.list_masterkeys(),
            MasterkeySubCommand::Remove(rem) => self.remove_masterkey(rem),
            MasterkeySubCommand::Info(info) => self.masterkey_info(info),
        }
    }

    pub fn list_masterkeys(&self) -> Result<(), SareCLIError> {
        let sare_db = SareDB::import_from_json_file()?;
        let sare_directory = common::prepare_sare_directory()?;

        println!(
            "\n{}",
            "=== 🔑 Available Master Keys ===".bold().underline()
        );

        for (master_key_id, key) in sare_db.key_associations {
            println!(
                "{} {}",
                "Master Key ID:".bright_blue().bold(),
                master_key_id
            );
            println!(
                "   {} {}",
                "Public Key ID:".bright_green(),
                key.public_key_id
            );

            let mut public_key_file = File::open(
                sare_directory
                    .join("public_keys")
                    .join(format!("PUB_{}.pem", key.public_key_id)),
            )?;

            let mut public_key_pem_content = String::new();
            public_key_file.read_to_string(&mut public_key_pem_content)?;

            let shared_public_key = SharedPublicKey::from_pem(public_key_pem_content)?;
            let validation_cert = shared_public_key.validation_certificate;

            if let Some(validation_data) = validation_cert {
                let expiry_date =
                    common::format_expiry_date(validation_data.certificate.expiry_date);
                println!(
                    "   {} {} (expires: {})",
                    "✔ Validation:".bright_green(),
                    validation_data.certificate.issuer.to_string(),
                    expiry_date
                );
            } else {
                println!("   {} Validation Certificate Not Found!", "⚠".yellow());
            }
            println!();
        }

        Ok(())
    }

    fn remove_masterkey(&self, rem: &RemoveMasterkey) -> Result<(), SareCLIError> {
        let masterkey = common::get_master_key_from_cli(&rem.masterkey_id)?;
        let confirmation_string = common::random_confirmaton_string(6);

        println!(
            "{} {}",
            "Confirmation Code:".bright_yellow().bold(),
            confirmation_string
        );
        let confirmed_input =
            common::get_confirmed_input("Type the confirmation code (case sensitive): ");

        if confirmation_string == confirmed_input {
            let sare_directory = common::prepare_sare_directory()?;
            let mut sare_db = SareDB::import_from_json_file()?;

            let key_id = hex::encode_upper(masterkey.get_fullchain_private_fingerprint());
            let fullchain_fingerprint =
                hex::encode_upper(masterkey.get_fullchain_public_fingerprint());

            sare_db.key_associations.remove(&key_id);
            sare_db.save_to_json_file()?;

            if !rem.keep_key_files.unwrap_or(false) {
                let masterkey_file = sare_directory
                    .join("private_keys")
                    .join(format!("MASTER_{key_id}.pem"));
                let publickey_file = sare_directory
                    .join("public_keys")
                    .join(format!("PUB_{fullchain_fingerprint}.pem"));
                let revoc_file = sare_directory
                    .join("revocations")
                    .join(format!("REVOC_{fullchain_fingerprint}.asc"));

                let progress = ProgressBar::new_spinner();
                progress.set_message("Removing key files...");
                progress.enable_steady_tick(Duration::from_millis(100));

                fs::remove_file(masterkey_file)?;
                fs::remove_file(publickey_file)?;
                fs::remove_file(revoc_file)?;

                progress.finish_with_message("✅ Key files removed");
            }

            println!("{}", "✅ Masterkey successfully removed".green().bold());
        } else {
            println!(
                "{}",
                "❌ Operation canceled: confirmation code mismatch"
                    .red()
                    .bold()
            );
        }

        Ok(())
    }

    fn masterkey_info(&self, info: &ExportMasterkey) -> Result<(), SareCLIError> {
        let masterkey = common::get_master_key_from_cli(&info.masterkey_id)?;

        let key_id = hex::encode_upper(masterkey.get_fullchain_private_fingerprint());
        let fullchain_fingerprint = hex::encode_upper(masterkey.get_fullchain_public_fingerprint());

        println!(
            "\n{}",
            "=== ℹ Master Key Information ===".bold().underline()
        );
        println!("{} {}", "Key ID:".bright_blue(), key_id);
        println!(
            "{} {}",
            "Public Key Fingerprint:".bright_green(),
            fullchain_fingerprint
        );

        let sare_directory = common::prepare_sare_directory()?;
        let publickey_file = sare_directory
            .join("public_keys")
            .join(format!("PUB_{fullchain_fingerprint}.pem"));

        let publickey_pem_content = fs::read_to_string(publickey_file)?;
        let shared_public_key = SharedPublicKey::from_pem(publickey_pem_content)?;

        if let Some(validation_cert) = shared_public_key.validation_certificate {
            println!(
                "{} {} (expires: {})",
                "✔ Validation:".bright_green(),
                validation_cert.certificate.issuer.to_string(),
                common::format_expiry_date(validation_cert.certificate.expiry_date)
            );
        }

        println!("{}", "Mnemonic Seed:".bright_yellow().bold());
        println!("{}", masterkey.to_mnemonic().expose_secret());

        Ok(())
    }

    fn generate_masterkey(&self, gen: &GenerateMasterkey) -> Result<(), SareCLIError> {
        let masterkey = MasterKey::generate(
            HybridKEMAlgorithm::from_string(
                gen.hybrid_kem_algorithm.clone().unwrap_or("".to_string()),
            ),
            HybridSignAlgorithm::from_string(
                gen.hybrid_sign_algorithm.clone().unwrap_or("".to_string()),
            ),
        );

        let fullchain_fingerprint = hex::encode_upper(masterkey.get_fullchain_public_fingerprint());
        let keyid = hex::encode_upper(masterkey.get_fullchain_private_fingerprint());

        let issuer_name = common::get_confirmed_input("Full Name: ");
        let issuer_email = common::get_confirmed_input("Email: ");
        let issuer = Issuer::new(issuer_name, issuer_email);
        let expiry_duration = common::human_readable_duration_to_timestamp(
            &common::get_confirmed_input("Key is valid for? (e.g. 1y, 6m, 30d): "),
        )?;

        let sare_directory = common::prepare_sare_directory()?;
        let temp_dir = sare_directory.join(".temp");

        // Export master key to memory
        let mut master_buffer = Cursor::new(Vec::new());
        if gen.unencrypted_keyfiles.unwrap_or(false) {
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

            progress_bar.finish_with_message("✅ Masterkey encrypted");
        }

        // Export public key
        let mut public_buffer = Cursor::new(Vec::new());
        masterkey.export_public(&mut public_buffer)?;
        if !gen.no_validation_cert.unwrap_or(false) {
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

        // Move files to actual directories
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
            &fullchain_fingerprint.to_string(),
        );
        let mut sare_db = SareDB::import_from_json_file()?;
        sare_db.add_key_association(&keyid, associated_key);
        sare_db.save_to_json_file()?;

        println!("\n{}", "✅ Keypair generated successfully!".green().bold());
        println!("   {} {:?}", "Location:".cyan(), sare_directory);
        println!(
            "   {} {}",
            "Public Fingerprint:".cyan(),
            fullchain_fingerprint
        );
        println!("   {} {}", "Master Key ID:".cyan(), keyid);
        println!(
            "   {} {}",
            "Expires:".cyan(),
            common::format_expiry_date(expiry_duration)
        );

        Ok(())
    }
}
