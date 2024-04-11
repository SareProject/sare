use bson::de::Error as BsonError;
use pem::{Pem, PemError};
use secrecy::{SecretString, SecretVec};

pub mod encryption;
pub mod header;
pub mod keys;
pub mod revocation;
pub mod signature;

#[derive(Debug)]
pub enum ErrSection {
    PEM(PemError),
    BSON(BsonError),
    HEADER,
}

#[derive(Debug)]
pub enum FormatError {
    FailedToDecode(ErrSection),
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

pub trait EncodablePublic {
    fn encode_bson(&self) -> Vec<u8>;
    fn decode_bson(bson_data: &[u8]) -> Result<Self, FormatError>
    where
        Self: Sized;
    fn encode_pem(&self) -> String;
    fn decode_pem(pem_data: &str) -> Result<Self, FormatError>
    where
        Self: Sized;
}

pub trait EncodableSecret {
    fn encode_bson(&self) -> SecretVec<u8>;
    fn decode_bson(bson_data: &SecretVec<u8>) -> Result<Self, FormatError>
    where
        Self: Sized;
    fn encode_pem(&self) -> SecretString;
    fn decode_pem(pem_data: SecretString) -> Result<Self, FormatError>
    where
        Self: Sized;
}
