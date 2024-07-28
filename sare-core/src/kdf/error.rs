use hkdf::InvalidLength;

#[derive(Debug)]
pub enum KDFError {
    InvalidKeyLength,
    InvalidOutputLength,
    InvalidParams,
    Unexpected,
}

impl From<InvalidLength> for KDFError {
    fn from(_: InvalidLength) -> Self {
        KDFError::InvalidKeyLength
    }
}
