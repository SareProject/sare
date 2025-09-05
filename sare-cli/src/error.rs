use colored::*;
use sare_lib::{format::error::FormatError, SareError};
use serde_json::Error as JsonError;
use std::fmt;
use std::io::Error as IoError;

#[derive(Debug)]
pub enum SareCLIError {
    IoError(String),
    Unexpected(String),
    SareLibError(SareError),
    JsonError(String),
}

impl From<String> for SareCLIError {
    fn from(err: String) -> Self {
        SareCLIError::Unexpected(err)
    }
}

impl From<IoError> for SareCLIError {
    fn from(err: IoError) -> Self {
        SareCLIError::IoError(err.to_string())
    }
}

impl From<SareError> for SareCLIError {
    fn from(err: SareError) -> Self {
        SareCLIError::SareLibError(err)
    }
}

impl From<JsonError> for SareCLIError {
    fn from(err: JsonError) -> Self {
        SareCLIError::JsonError(err.to_string())
    }
}

impl From<FormatError> for SareCLIError {
    fn from(err: FormatError) -> Self {
        SareCLIError::SareLibError(SareError::CoreError(sare_lib::CoreErrorKind::Format(err)))
    }
}

impl fmt::Display for SareCLIError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SareCLIError::IoError(err) => {
                write!(f, "💾 {} {}", "IO Error:".red().bold(), err.red())
            }
            SareCLIError::Unexpected(err) => {
                let clean = err
                    .lines()
                    .map(|line| line.trim())
                    .filter(|line| !line.is_empty())
                    .collect::<Vec<_>>()
                    .join("\n\t• ");

                write!(
                    f,
                    "{}\n\t• {}",
                    "❌ Unexpected Error:".bright_red().bold(),
                    clean.bright_red()
                )
            }
            SareCLIError::SareLibError(err) => {
                write!(
                    f,
                    "🛠 {} {}",
                    "SareLib Error:".yellow().bold(),
                    err.to_string().yellow()
                )
            }
            SareCLIError::JsonError(err) => {
                write!(f, "📝 {} {}", "JSON Error:".blue().bold(), err.blue())
            }
        }
    }
}

impl SareCLIError {
    /// Print the error in a pretty format
    pub fn pretty(&self) {
        eprintln!("{}", self);
    }
}
