use std::array::TryFromSliceError;
use bip39::ErrorKind;

#[derive(Debug)]
pub enum SeedError {
    InvalidMnemonicPhrase,
    InvalidSeedLength
}

impl From<TryFromSliceError> for SeedError {
    fn from(_: TryFromSliceError) -> Self {
        SeedError::InvalidSeedLength
    }
}
