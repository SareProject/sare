use rpassword;
use secrecy::SecretString;

// TODO: Return SareCLIError Instead Of String
pub fn read_cli_secret(prompt: impl ToString) -> Result<SecretString, String> {
    let secret: SecretString = rpassword::prompt_password(prompt)
        .map_err(|e| e.to_string())?
        .into();

    Ok(secret)
}
