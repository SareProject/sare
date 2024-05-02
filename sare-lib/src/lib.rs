pub mod certificate;
pub mod encryption;
pub mod keys;
pub mod signing;

use std::io::Error as IoError;

use sare_core::{format::FormatError, CoreErrorKind};

pub enum SareError {
    IoError(String),
    CoreError(CoreErrorKind)
}

impl From<IoError> for SareError {
    fn from(err: IoError) -> Self {
        SareError::IoError(err.to_string())
    }
}

impl From<FormatError> for SareError {
    fn from(err: FormatError) -> Self {
        SareError::CoreError(CoreErrorKind::FormatError(err))
    }
}