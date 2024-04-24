pub mod error;

use serde::{Deserialize, Serialize};
use crate::encryption::error::*;

use aead::stream;
use aes_kw::KekAes256;
use chacha20poly1305::KeyInit;
use chacha20poly1305::XChaCha20Poly1305;
use secrecy::{ExposeSecret, SecretVec};
use std::io::{Read, Write};

const AEAD_BUFFER_LEN: usize = 2048;

#[derive(Serialize, Deserialize)]
pub enum EncryptionAlgorithm {
    AES256GCM,
    AES256KW,
    XCHACHA20POLY1305,
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

    pub fn wrap(&self, data: &SecretVec<u8>) -> Vec<u8> {
        let mut output: Vec<u8> = Vec::with_capacity(data.expose_secret().len() + 8);

        let input_key = <[u8; 32]>::try_from(self.input_key.expose_secret().as_slice()).unwrap();

        let kek = KekAes256::from(input_key);

        kek.wrap(data.expose_secret(), &mut output);

        output
    }

    pub fn dewrap(&self, wrapped_data: &SecretVec<u8>) -> Result<SecretVec<u8>, EncryptionError> {
        let mut output: Vec<u8> = Vec::with_capacity(wrapped_data.expose_secret().len() - 8);

        let input_key = <[u8; 32]>::try_from(self.input_key.expose_secret().as_slice()).unwrap();

        let kek = KekAes256::from(input_key);

        kek.unwrap(wrapped_data.expose_secret(), &mut output)
            .map_err(|_| EncryptionError::FailedToDecrypt)?;

        Ok(SecretVec::from(output))
    }
}

pub struct Encryptor {
    input_key: SecretVec<u8>,
    nonce: Vec<u8>,
    algorithm: EncryptionAlgorithm,
}

impl Encryptor {
    pub fn new(input_key: SecretVec<u8>, nonce: Vec<u8>, algorithm: EncryptionAlgorithm) -> Self {
        Encryptor {
            input_key,
            nonce,
            algorithm,
        }
    }

    pub fn encrypt<R: Read, W: Write>(&self, data: R, output: W) -> Result<(), EncryptionError> {
        todo!();
    }

    // TODO: Needs Error Handling
    pub fn encrypt_xchacha20poly1305<R: Read, W: Write>(
        &self,
        mut data: R,
        mut output: W,
    ) -> Result<(), EncryptionError> {
        let input_key = <[u8; 32]>::try_from(self.input_key.expose_secret().as_slice()).unwrap();
        let nonce = <[u8; 19]>::try_from(self.nonce.as_slice()).unwrap();

        let aead = XChaCha20Poly1305::new(input_key.as_ref().into());
        let mut stream_aead = stream::EncryptorBE32::from_aead(aead, nonce.as_ref().into());
        let mut data_buffer = [0u8; AEAD_BUFFER_LEN];

        loop {
            let read_count = data.read(&mut data_buffer)?;

            if read_count == AEAD_BUFFER_LEN {
                let encrypted_data = stream_aead.encrypt_next(data_buffer.as_slice()).unwrap();

                output.write(&encrypted_data)?;
            } else {
                let encrypted_data = stream_aead
                    .encrypt_last(&data_buffer[..read_count])
                    .unwrap();

                output.write(&encrypted_data)?;
                break;
            }
        }
        Ok(())
    }
}

pub struct Decryptor {
    input_key: SecretVec<u8>,
    nonce: Vec<u8>,
    algorithm: EncryptionAlgorithm,
}

impl Decryptor {
    pub fn new(input_key: SecretVec<u8>, nonce: Vec<u8>, algorithm: EncryptionAlgorithm) -> Self {
        Decryptor {
            input_key,
            nonce,
            algorithm,
        }
    }

    pub fn decrypt<R: Read, W: Write>(
        &self,
        encrypted_data: R,
        output: W,
    ) -> Result<(), EncryptionError> {
        todo!();
    }

    // TODO: Needs Error Handling
    pub fn decrypt_xchacha20poly1305<R: Read, W: Write>(
        &self,
        mut encrypted_data: R,
        mut output: W,
    ) -> Result<(), EncryptionError> {
        let input_key = <[u8; 32]>::try_from(self.input_key.expose_secret().as_slice()).unwrap();
        let nonce = <[u8; 19]>::try_from(self.nonce.as_slice()).unwrap();

        let aead = XChaCha20Poly1305::new(input_key.as_ref().into());
        let mut stream_aead = stream::DecryptorBE32::from_aead(aead, nonce.as_ref().into());
        let mut encrypted_buffer = [0u8; AEAD_BUFFER_LEN + 16]; // 16bytes for AEAD tag

        loop {
            let read_count = encrypted_data.read(&mut encrypted_buffer)?;

            if read_count == AEAD_BUFFER_LEN {
                let decrypted_data = stream_aead
                    .decrypt_next(encrypted_buffer.as_slice())
                    .unwrap();

                output.write(&decrypted_data)?;
            } else {
                let decrypted_data = stream_aead
                    .decrypt_last(&encrypted_buffer[..read_count])
                    .unwrap();

                output.write(&decrypted_data)?;
                break;
            }
        }

        Ok(())
    }
}
