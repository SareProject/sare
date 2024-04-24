use std::io::Error as IOError;

#[derive(Debug)]
pub enum ErrSection {
    IO(IOError),
    Encryption,
}

#[derive(Debug)]
pub enum EncryptionError {
    FailedToReadOrWrite(ErrSection),
    InvalidKeyLength,
    FailedToDecrypt,
    Unexpected,
}


impl From<IOError> for EncryptionError {
    fn from(err: IOError) -> Self {
        EncryptionError::FailedToReadOrWrite(ErrSection::IO(err))
    }
}
