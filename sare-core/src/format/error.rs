use std::fmt;

use bson::de::Error as BsonError;
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
}

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FormatError::FailedToDecode(err) => write!(f, "Failed to decode: {}", err),
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
