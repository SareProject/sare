use aead::Error as AeadError;
use aes_kw::Error as KekError;
use std::io::Error as IOError;

#[derive(Debug)]
pub enum ErrSection {
    IO(IOError),
    Aead(AeadError),
    Kek(KekError),
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
