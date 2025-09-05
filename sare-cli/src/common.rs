use std::{
    fs::{self, File},
    io::{self, Write},
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use chrono::DateTime;
use colored::*;
use rpassword;
use sare_lib::keys::{MasterKey, SharedPublicKey};
use secrecy::{ExposeSecret, SecretString};

use crate::{db::SareDB, error::SareCLIError};

pub const DEFAULT_SARE_DIRECTORY: &str = ".sare";
pub const DB_FILE: &str = "saredb.json";

pub fn random_confirmaton_string(len: usize) -> String {
    let mut seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;

    let charset = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut s = String::with_capacity(len);

    for _ in 0..len {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        let idx = (seed % charset.len() as u64) as usize;
        s.push(charset[idx] as char);
    }

    s
}

pub fn get_recipient_from_cli(
    recipient_id: &Option<String>,
) -> Result<SharedPublicKey, SareCLIError> {
    let sare_db = SareDB::import_from_json_file()?;
    let recipients = sare_db.recipients;

    if recipients.is_empty() {
        println!(
            "{}",
            "⚠ No recipients found. Use `recipient add` command first.".yellow()
        );
        return Err(SareCLIError::Unexpected("no recipients found".into()));
    }

    let recipient_id = if let Some(recipient_id) = recipient_id {
        recipient_id.to_owned()
    } else {
        println!("{}", "No recipient specified. Choose from the list:".cyan());

        let mut entries: Vec<_> = recipients.iter().collect();
        entries.sort_by_key(|(k, _)| *k);

        for (idx, (_key, rec)) in entries.iter().enumerate() {
            println!("{}. {}", idx + 1, rec.fullchain_fingerprint);
        }

        let index_input = get_confirmed_input("Enter recipient number: ");
        let index: usize = index_input
            .parse()
            .map_err(|e: std::num::ParseIntError| SareCLIError::Unexpected(e.to_string()))?;

        if let Some((_key, value)) = entries.get(index - 1) {
            value.fullchain_fingerprint.clone()
        } else {
            println!("{} {}", "❌ Invalid index:".red(), index);
            return Err(SareCLIError::Unexpected("invalid recipient index".into()));
        }
    };

    let sare_directory = prepare_sare_directory()?;
    let recipient_file = sare_directory
        .join("recipients")
        .join(format!("RECIPIENT_{recipient_id}.pem"));

    let recipient_pem = fs::read_to_string(recipient_file)?;
    Ok(SharedPublicKey::from_pem(recipient_pem)?)
}

pub fn get_master_key_from_cli(masterkey_id: &Option<String>) -> Result<MasterKey, SareCLIError> {
    let sare_db = SareDB::import_from_json_file()?;
    let associated_keys = sare_db.key_associations;

    if associated_keys.is_empty() {
        println!(
            "{}",
            "⚠ No master keys found. Use `masterkey generate` first.".yellow()
        );
        return Err(SareCLIError::Unexpected("no master keys found".into()));
    }

    let masterkey_id = if let Some(masterkey_id) = masterkey_id {
        masterkey_id.to_owned()
    } else {
        println!(
            "{}",
            "No master key specified. Choose from the list:".cyan()
        );

        let mut entries: Vec<_> = associated_keys.iter().collect();
        entries.sort_by_key(|(k, _)| *k);

        for (idx, (id, _)) in entries.iter().enumerate() {
            println!("{}. {}", idx + 1, id);
        }

        let index_input = get_confirmed_input("Enter master key number: ");
        let index: usize = index_input
            .parse()
            .map_err(|e: std::num::ParseIntError| SareCLIError::Unexpected(e.to_string()))?;

        if let Some((id, _)) = entries.get(index - 1) {
            id.to_owned().to_string()
        } else {
            println!("{} {}", "❌ Invalid index:".red(), index);
            return Err(SareCLIError::Unexpected("invalid master key index".into()));
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

    Ok(MasterKey::import(secret_key_format, passphrase)?)
}

pub fn get_now_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("System time is before UNIX EPOCH")
        .as_secs()
}

pub fn human_readable_duration_to_timestamp(duration: &str) -> Result<Option<u64>, SareCLIError> {
    let duration_in_second = duration_str::parse(duration)
        .map_err(|e| SareCLIError::Unexpected(format!("Failed to parse duration: {e}")))?;

    let expiry_timestamp = SystemTime::now() + duration_in_second;
    let target_time = expiry_timestamp
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| SareCLIError::Unexpected(e.to_string()))?;

    Ok(Some(target_time))
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

pub fn read_cli_secret(prompt: impl ToString) -> Result<SecretString, String> {
    rpassword::prompt_password(prompt)
        .map_err(|e| e.to_string())
        .map(Into::into)
}

pub fn create_directory(path: &PathBuf) -> Result<PathBuf, SareCLIError> {
    if !path.exists() {
        fs::create_dir(path)?;
        log::debug!("Directory {} created", path.to_string_lossy());
    } else {
        log::debug!("Directory {} exists, skipping", path.to_string_lossy());
    }
    Ok(path.to_owned())
}

pub fn prepare_sare_directory() -> Result<PathBuf, SareCLIError> {
    let home_directory = dirs::home_dir().unwrap_or(PathBuf::new());
    let sare_directory = create_directory(&home_directory.join(DEFAULT_SARE_DIRECTORY))?;

    for sub in ["private_keys", "public_keys", "revocations", "recipients"] {
        create_directory(&sare_directory.join(sub))?;
    }

    let temp_dir = create_directory(&sare_directory.join(".temp"))?;
    for sub in ["private_keys", "public_keys", "revocations", "recipients"] {
        create_directory(&temp_dir.join(sub))?;
    }

    Ok(sare_directory)
}

pub fn get_confirmed_input(prompt: &str) -> String {
    loop {
        print!("{} ", prompt.cyan().bold());
        io::stdout().flush().unwrap();

        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            println!("{}", "❌ Error reading input. Try again.".red());
            continue;
        }

        let input = input.trim().to_string();
        print!("You entered '{}'. Confirm (y/N): ", input);
        io::stdout().flush().unwrap();

        let mut confirmation = String::new();
        if io::stdin().read_line(&mut confirmation).is_err() {
            println!("{}", "❌ Error reading confirmation.".red());
            continue;
        }

        match confirmation.trim().to_lowercase().as_str() {
            "y" => return input,
            "n" => println!("{}", "Let's try again.".yellow()),
            _ => println!("{}", "Invalid response. Enter 'y' or 'N'.".yellow()),
        }
    }
}
