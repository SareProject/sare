use aead::Error as AeadError;
use aes_kw::Error as KekError;
use std::{fmt, io::Error as IOError};

#[derive(Debug)]
pub enum ErrSection {
    IO(IOError),
    Aead(AeadError),
    Kek(KekError),
}

impl fmt::Display for ErrSection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrSection::IO(err) => write!(f, "IO Error: {}", err),
            ErrSection::Aead(err) => write!(f, "AEAD Error: {}", err),
            ErrSection::Kek(err) => write!(f, "KEK Error: {}", err),
        }
    }
}

#[derive(Debug)]
pub enum EncryptionError {
    FailedToReadOrWrite(ErrSection),
    InvalidKeyLength,
    FailedToEncryptOrDecrypt(ErrSection),
    Unexpected,
}

impl From<IOError> for EncryptionError {
    fn from(err: IOError) -> Self {
        EncryptionError::FailedToReadOrWrite(ErrSection::IO(err))
    }
}

impl From<AeadError> for EncryptionError {
    fn from(err: AeadError) -> Self {
        EncryptionError::FailedToEncryptOrDecrypt(ErrSection::Aead(err))
    }
}

impl From<KekError> for EncryptionError {
    fn from(err: KekError) -> Self {
        EncryptionError::FailedToEncryptOrDecrypt(ErrSection::Kek(err))
    }
}

impl fmt::Display for EncryptionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncryptionError::FailedToReadOrWrite(err) => {
                write!(f, "Failed to read or write: {}", err)
            }
            EncryptionError::InvalidKeyLength => write!(f, "Invalid key length"),
            EncryptionError::FailedToEncryptOrDecrypt(err) => {
                write!(f, "Failed to encrypt or decrypt: {}", err)
            }
            EncryptionError::Unexpected => write!(f, "Unexpected error"),
        }
    }
}
