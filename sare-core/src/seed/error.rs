use std::{array::TryFromSliceError, fmt};

#[derive(Debug)]
pub enum SeedError {
    InvalidMnemonicPhrase,
    InvalidSeedLength,
}

impl fmt::Display for SeedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SeedError::InvalidMnemonicPhrase => write!(f, "Invalid mnemonic phrase"),
            SeedError::InvalidSeedLength => write!(f, "Invalid seed length"),
        }
    }
}

impl From<TryFromSliceError> for SeedError {
    fn from(_: TryFromSliceError) -> Self {
        SeedError::InvalidSeedLength
    }
}
