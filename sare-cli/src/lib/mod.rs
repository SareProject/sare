pub mod common;
use sare_lib::SareError;
use std::fmt;
use std::io::Error as IoError;

#[derive(Debug)]
pub enum SareCLIError {
    IoError(String),
    Unexpected(String),
    SareLibError(SareError),
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

impl fmt::Display for SareCLIError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SareCLIError::IoError(err) => write!(f, "IO Error: {}", err),
            SareCLIError::Unexpected(err) => write!(f, "Unexpected Error: {}", err),
            SareCLIError::SareLibError(err) => write!(f, "SareLib Error: {}", err),
        }
    }
}
