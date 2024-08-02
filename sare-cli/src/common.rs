use std::{fs, path::{Path, PathBuf}};

use rpassword;
use secrecy::SecretString;

use crate::error::SareCLIError;

// TODO: Return SareCLIError Instead Of String
pub fn read_cli_secret(prompt: impl ToString) -> Result<SecretString, String> {
    let secret: SecretString = rpassword::prompt_password(prompt)
        .map_err(|e| e.to_string())?
        .into();

    Ok(secret)
}

pub fn create_directory(path: &PathBuf) -> Result<PathBuf, SareCLIError> {
    if !path.exists() {
        fs::create_dir(path)?;
    }
    Ok(path.to_owned())
}