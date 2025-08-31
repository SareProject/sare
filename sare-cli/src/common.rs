use std::{
    fs::{self, File},
    io::{self, Write},
    path::PathBuf,
    time::{Duration, SystemTime},
};

use chrono::DateTime;
use indicatif::ProgressBar;
use rpassword;
use sare_lib::keys::{MasterKey, SharedPublicKey};
use secrecy::{ExposeSecret, SecretString};

use crate::{commands::recipient, db::SareDB, error::SareCLIError};

pub const DEFAULT_SARE_DIRECTORY: &str = ".sare";
pub const DB_FILE: &str = "saredb.json";

pub fn get_recipient_from_cli(
    recipient_id: &Option<String>,
) -> Result<SharedPublicKey, SareCLIError> {
    let sare_db = SareDB::import_from_json_file()?;

    let recipients = sare_db.recipients;

    if recipients.is_empty() {
        println!("You don't have any recipients. use recipient add command to add one!");
        return Err(SareCLIError::Unexpected(String::new()));
    }

    let recipient_id = if let Some(recipient_id) = recipient_id {
        &recipient_id.to_owned()
    } else {
        println!("You haven't specified any recipients, choose one from the list below:");

        let mut entries: Vec<_> = recipients.iter().collect();
        entries.sort_by_key(|(k, _)| *k); // sort by key

        for (idx, key_id) in entries.iter().enumerate() {
            println!("{}. {}", idx + 1, key_id.1.fullchain_fingerprint);
        }

        let index_input = get_confirmed_input("Please enter the number of the recipient: ");

        let index: usize = index_input
            .parse()
            .map_err(|e: std::num::ParseIntError| SareCLIError::Unexpected(e.to_string()))?;

        if let Some((key, value)) = entries.get(index - 1) {
            &value.fullchain_fingerprint
        } else {
            println!("Invalid index {}", index);
            return Err(SareCLIError::Unexpected(String::new()));
        }
    };

    let sare_directory = prepare_sare_directory()?;

    let recipient_file = sare_directory
        .join("recipients")
        .join(format!("RECIPIENT_{recipient_id}.pem"));

    let recipient_pem = fs::read_to_string(recipient_file)?;

    let recipient = SharedPublicKey::from_pem(recipient_pem)?;

    Ok(recipient)
}

pub fn get_master_key_from_cli(masterkey_id: &Option<String>) -> Result<MasterKey, SareCLIError> {
    let sare_db = SareDB::import_from_json_file()?;

    let associated_keys = sare_db.key_associations;

    if associated_keys.is_empty() {
        println!("You don't have any master keys right now, use keygen command to generate one!");
        return Err(SareCLIError::Unexpected(String::new()));
    }

    let masterkey_id = if let Some(masterkey_id) = masterkey_id {
        &masterkey_id.to_owned()
    } else {
        println!("You haven't specified any master keys, choose one from below");

        let mut entries: Vec<_> = associated_keys.iter().collect();
        entries.sort_by_key(|(k, _)| *k); // sort by key

        for (idx, key_id) in entries.iter().enumerate() {
            println!("{}. {}", idx + 1, key_id.0);
        }

        let index_input = get_confirmed_input("Please enter the number of the key: ");

        let index: usize = index_input
            .parse()
            .map_err(|e: std::num::ParseIntError| SareCLIError::Unexpected(e.to_string()))?;

        if let Some((key, _value)) = entries.get(index - 1) {
            key.to_owned()
        } else {
            println!("Invalid index {}", index);
            return Err(SareCLIError::Unexpected(String::new()));
        }
    };

    let sare_directory = prepare_sare_directory()?;

    let masterkey_file =
        File::open(sare_directory.join(format!("private_keys/MASTER_{masterkey_id}.pem")))?;

    let secret_key_format = MasterKey::decode_pem(masterkey_file)?;

    let passphrase = if secret_key_format.encryption_metadata.is_some() {
        let input_passphrase = read_cli_secret("Please enter your passphrase: ")?;
        let passphrase_bytes =
            secrecy::Secret::new(input_passphrase.expose_secret().clone().into_bytes());

        Some(passphrase_bytes)
    } else {
        None
    };

    let masterkey = MasterKey::import(secret_key_format, passphrase)?;

    Ok(masterkey)
}

pub fn get_now_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("System time is before UNIX EPOCH")
        .as_secs()
}

pub fn human_readable_duration_to_timestamp(duration: &str) -> Result<u64, SareCLIError> {
    let duration_in_second =
        duration_str::parse(duration).map_err(|e| format!("Failed to parse duration {e}"))?;

    let now_timestamp = SystemTime::now();
    let expiry_timestamp = now_timestamp + duration_in_second;

    let target_time = expiry_timestamp
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| e.to_string())?;

    Ok(target_time)
}

pub fn format_expiry_date(expiry_timestamp: Option<u64>) -> String {
    match expiry_timestamp {
        Some(timestamp) => {
            let datetime = DateTime::from_timestamp(timestamp as i64, 0)
                .unwrap_or_else(|| DateTime::from_timestamp(0, 0).unwrap());
            datetime.format("%Y-%m-%d").to_string()
        }
        None => "Never".to_string(),
    }
}

// TODO: Return SareCLIError Instead Of String
pub fn read_cli_secret(prompt: impl ToString) -> Result<SecretString, String> {
    let secret: SecretString = rpassword::prompt_password(prompt)
        .map_err(|e| e.to_string())?
        .into();

    Ok(secret)
}

pub fn create_directory(path: &PathBuf) -> Result<PathBuf, SareCLIError> {
    log::debug!("Directory {} exists, Skipping!", path.to_string_lossy());
    if !path.exists() {
        fs::create_dir(path)?;
        log::debug!("Directory {} Initialized!", path.to_string_lossy())
    }
    Ok(path.to_owned())
}

pub fn prepare_sare_directory() -> Result<PathBuf, SareCLIError> {
    let home_directory = dirs::home_dir().unwrap_or(PathBuf::new());
    let sare_directory = create_directory(&home_directory.join(DEFAULT_SARE_DIRECTORY))?;

    create_directory(&sare_directory.join("private_keys"))?;
    create_directory(&sare_directory.join("public_keys"))?;
    create_directory(&sare_directory.join("revocations"))?;
    create_directory(&sare_directory.join("recipients"))?;

    let temp_dir = create_directory(&sare_directory.join(".temp"))?;

    create_directory(&temp_dir.join("private_keys"))?;
    create_directory(&temp_dir.join("public_keys"))?;
    create_directory(&temp_dir.join("revocations"))?;
    create_directory(&temp_dir.join("recipients"))?;

    Ok(sare_directory)
}

pub fn get_confirmed_input(prompt: &str) -> String {
    loop {
        print!("{}", prompt);
        io::stdout().flush().unwrap();

        let mut input = String::new();
        match io::stdin().read_line(&mut input) {
            Ok(_) => {
                input = input.trim().to_string();
                print!("You entered '{}'. Confirm (y/N): ", input);
                io::stdout().flush().unwrap();

                let mut confirmation = String::new();
                match io::stdin().read_line(&mut confirmation) {
                    Ok(_) => {
                        let confirmation = confirmation.trim().to_lowercase();
                        if confirmation == "y" {
                            return input;
                        } else if confirmation == "n" {
                            println!("Let's try again.");
                        } else {
                            println!("Invalid response. Please enter 'y' or 'N'.");
                        }
                    }
                    Err(_) => {
                        println!("Error reading confirmation. Please try again.");
                    }
                }
            }
            Err(_) => {
                println!("Error reading input. Please try again.");
            }
        }
    }
}
