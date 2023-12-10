use serde::{Deserialize, Serialize};

use aes_kw::KekAes256;
use secrecy::{ExposeSecret, SecretVec};

#[derive(Serialize, Deserialize)]
pub enum EncryptionAlgorithm {
    AES256GCM,
    AES256KW,
}

#[derive(Debug)]
pub enum EncryptionError {
    InvalidKeyLength,
    Unexpected,
}

pub struct KeyWrap {
    input_key: SecretVec<u8>,
}

impl KeyWrap {
    pub fn new(input_key: SecretVec<u8>) -> Result<Self, EncryptionError> {
        if input_key.expose_secret().len() != 32 {
            return Err(EncryptionError::InvalidKeyLength);
        }

        Ok(KeyWrap { input_key })
    }

    pub fn encrypt(&self, data: &SecretVec<u8>) -> Vec<u8> {
        let mut output: Vec<u8> = Vec::with_capacity(data.expose_secret().len() + 8);

        let input_key = <[u8; 32]>::try_from(self.input_key.expose_secret().as_slice()).unwrap();

        let kek = KekAes256::from(input_key);

        kek.wrap(data.expose_secret(), &mut output);

        output
    }
}
