use std::fmt;

use bson::error::Error as BsonError;
use pem::PemError;

#[derive(Debug)]
pub enum ErrSection {
    PEM(PemError),
    BSON(BsonError),
    HEADER,
}

impl fmt::Display for ErrSection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrSection::PEM(err) => write!(f, "PEM Error: {}", err),
            ErrSection::BSON(err) => write!(f, "BSON Error: {}", err),
            ErrSection::HEADER => write!(f, "Header Error"),
        }
    }
}

#[derive(Debug)]
pub enum FormatError {
    FailedToDecode(ErrSection),
    InvalidHeader(String),
    InvalidPKDFParameters(String),
}

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FormatError::FailedToDecode(err) => write!(f, "Failed to decode: {}", err),
            FormatError::InvalidHeader(err) => write!(f, "Invalid header: {}", err),
            FormatError::InvalidPKDFParameters(err) => {
                write!(f, "Invalid PKDF parameters: {}", err)
            }
        }
    }
}

impl From<BsonError> for FormatError {
    fn from(err: BsonError) -> Self {
        FormatError::FailedToDecode(ErrSection::BSON(err))
    }
}

impl From<PemError> for FormatError {
    fn from(err: PemError) -> Self {
        FormatError::FailedToDecode(ErrSection::PEM(err))
    }
}
