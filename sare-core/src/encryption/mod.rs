pub mod error;

use crate::encryption::error::*;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use aead::stream;
use aes_kw::KekAes256;
use chacha20poly1305::KeyInit;
use chacha20poly1305::XChaCha20Poly1305;
use secrecy::{ExposeSecret, SecretVec};
use std::io::{Read, Write};
use std::vec;

const AEAD_BUFFER_LEN: usize = 2048;
const AEAD_TAG_LEN: usize = 16;
const XCHACHA20POLY1305_NONCE_LEN: usize = 19;

// A STREAM frame must be filled completely before it can be processed,
// a short read is only ever the last chunk of the stream
fn read_chunk<R: Read>(data: &mut R, buffer: &mut [u8]) -> Result<usize, EncryptionError> {
    let mut read_count = 0;

    while read_count < buffer.len() {
        let n = data.read(&mut buffer[read_count..])?;
        if n == 0 {
            break;
        }
        read_count += n;
    }

    Ok(read_count)
}

fn convert_input_key(input_key: &SecretVec<u8>) -> Result<[u8; 32], EncryptionError> {
    <[u8; 32]>::try_from(input_key.expose_secret().as_slice())
        .map_err(|_| EncryptionError::InvalidKeyLength)
}

#[derive(Copy, Debug, Clone, Serialize, Deserialize)]
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

    pub fn wrap(&self, data: &SecretVec<u8>) -> Result<Vec<u8>, EncryptionError> {
        let mut output: Vec<u8> = vec![0; data.expose_secret().len() + 8];

        let input_key = <[u8; 32]>::try_from(self.input_key.expose_secret().as_slice()).unwrap();

        let kek = KekAes256::from(input_key);

        kek.wrap_with_padding(data.expose_secret(), &mut output)?;

        Ok(output)
    }

    pub fn dewrap(&self, wrapped_data: &SecretVec<u8>) -> Result<SecretVec<u8>, EncryptionError> {
        let mut output: Vec<u8> = vec![0; wrapped_data.expose_secret().len().saturating_sub(8)];

        let input_key = <[u8; 32]>::try_from(self.input_key.expose_secret().as_slice()).unwrap();

        let kek = KekAes256::from(input_key);

        kek.unwrap_with_padding(wrapped_data.expose_secret(), &mut output)?;

        Ok(SecretVec::from(output))
    }
}

pub struct Encryptor {
    input_key: SecretVec<u8>,
    pub nonce: Vec<u8>,
    algorithm: EncryptionAlgorithm,
}

impl Encryptor {
    pub fn new(input_key: SecretVec<u8>, algorithm: EncryptionAlgorithm) -> Self {
        // TODO: Implement get_nonce_length() function for EncryptionAlgorithm enum
        let mut nonce = vec![0; 19];
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut nonce);

        Encryptor {
            input_key,
            nonce,
            algorithm,
        }
    }

    pub fn encrypt<R: Read, W: Write>(
        &self,
        mut data: R,
        mut output: W,
    ) -> Result<(), EncryptionError> {
        match self.algorithm {
            EncryptionAlgorithm::XCHACHA20POLY1305 => {
                self.encrypt_xchacha20poly1305(&mut data, &mut output)
            }
            _ => Err(EncryptionError::UnsupportedAlgorithm),
        }
    }

    pub fn encrypt_xchacha20poly1305<R: Read, W: Write>(
        &self,
        mut data: R,
        mut output: W,
    ) -> Result<(), EncryptionError> {
        let input_key = convert_input_key(&self.input_key)?;
        let nonce = self.nonce.as_slice();

        let aead = XChaCha20Poly1305::new(input_key.as_ref().into());
        let mut stream_aead = stream::EncryptorBE32::from_aead(aead, nonce.as_ref().into());
        let mut data_buffer = [0u8; AEAD_BUFFER_LEN];

        loop {
            let read_count = read_chunk(&mut data, &mut data_buffer)?;

            if read_count == AEAD_BUFFER_LEN {
                let encrypted_data = stream_aead.encrypt_next(data_buffer.as_slice())?;

                output.write_all(&encrypted_data)?;
            } else {
                let encrypted_data = stream_aead.encrypt_last(&data_buffer[..read_count])?;

                output.write_all(&encrypted_data)?;
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
        mut encrypted_data: R,
        mut output: W,
    ) -> Result<(), EncryptionError> {
        match self.algorithm {
            EncryptionAlgorithm::XCHACHA20POLY1305 => {
                self.decrypt_xchacha20poly1305(&mut encrypted_data, &mut output)
            }
            _ => Err(EncryptionError::UnsupportedAlgorithm),
        }
    }

    pub fn decrypt_xchacha20poly1305<R: Read, W: Write>(
        &self,
        mut encrypted_data: R,
        mut output: W,
    ) -> Result<(), EncryptionError> {
        if self.nonce.len() != XCHACHA20POLY1305_NONCE_LEN {
            return Err(EncryptionError::InvalidNonceLength);
        }

        let input_key = convert_input_key(&self.input_key)?;
        let nonce = self.nonce.as_slice();

        let aead = XChaCha20Poly1305::new(input_key.as_ref().into());
        let mut stream_aead = stream::DecryptorBE32::from_aead(aead, nonce.as_ref().into());
        let mut encrypted_buffer = [0u8; AEAD_BUFFER_LEN + AEAD_TAG_LEN]; // 16bytes for AEAD tag

        loop {
            let read_count = read_chunk(&mut encrypted_data, &mut encrypted_buffer)?;

            // A full frame is 2048bytes of ciphertext + 16bytes of AEAD tag,
            // only a short frame can ever be the last chunk of the stream
            if read_count == AEAD_BUFFER_LEN + AEAD_TAG_LEN {
                let decrypted_data = stream_aead.decrypt_next(encrypted_buffer.as_slice())?;

                output.write_all(&decrypted_data)?;
            } else {
                let decrypted_data =
                    stream_aead.decrypt_last(&encrypted_buffer[..read_count])?;

                output.write_all(&decrypted_data)?;
                break;
            }
        }

        Ok(())
    }
}
