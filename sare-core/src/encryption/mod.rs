pub mod error;

use crate::encryption::error::*;
use rand::Rng;
use serde::{Deserialize, Serialize};

use aes_kw::{aes::Aes256, InnerInit, KwpAes256};
use chacha20poly1305::KeyInit;
use chacha20poly1305::XChaCha20Poly1305;
use secrecy::{ExposeSecret, SecretBox};
use std::io::{Read, Write};
use std::vec;

const AEAD_BUFFER_LEN: usize = 2048;
const AEAD_TAG_LEN: usize = 16;
const XCHACHA20POLY1305_NONCE_LEN: usize = 19;

/// STREAM construction with a 32-bit big endian counter and a 1-byte
/// "last block" flag stored as the last 5 bytes of the AEAD nonce, as
/// described in "Online Authenticated-Encryption and its Nonce-Reuse
/// Misuse-Resistance" (Hoang, Reyhanitabar, Rogaway, Vizár)
///
/// The aead crate removed its stream module in 0.6, the construction is
/// small enough to be kept here instead
mod stream {
    use super::XCHACHA20POLY1305_NONCE_LEN;
    use aead::Aead;
    use chacha20poly1305::{XChaCha20Poly1305, XNonce};

    const STREAM_NONCE_LEN: usize = XCHACHA20POLY1305_NONCE_LEN + 5;

    fn aead_nonce(prefix: &[u8], position: u32, last_block: bool) -> XNonce {
        debug_assert_eq!(prefix.len(), XCHACHA20POLY1305_NONCE_LEN);

        let mut nonce = [0u8; STREAM_NONCE_LEN];
        nonce[..prefix.len()].copy_from_slice(prefix);
        nonce[prefix.len() + 1..].copy_from_slice(&position.to_be_bytes());
        nonce[prefix.len()] = last_block as u8;

        XNonce::from(nonce)
    }

    pub fn encrypt_next(
        aead: &XChaCha20Poly1305,
        prefix: &[u8],
        position: u32,
        chunk: &[u8],
    ) -> Result<Vec<u8>, aead::Error> {
        aead.encrypt(&aead_nonce(prefix, position, false), chunk)
    }

    pub fn encrypt_last(
        aead: &XChaCha20Poly1305,
        prefix: &[u8],
        position: u32,
        chunk: &[u8],
    ) -> Result<Vec<u8>, aead::Error> {
        aead.encrypt(&aead_nonce(prefix, position, true), chunk)
    }

    pub fn decrypt_next(
        aead: &XChaCha20Poly1305,
        prefix: &[u8],
        position: u32,
        chunk: &[u8],
    ) -> Result<Vec<u8>, aead::Error> {
        aead.decrypt(&aead_nonce(prefix, position, false), chunk)
    }

    pub fn decrypt_last(
        aead: &XChaCha20Poly1305,
        prefix: &[u8],
        position: u32,
        chunk: &[u8],
    ) -> Result<Vec<u8>, aead::Error> {
        aead.decrypt(&aead_nonce(prefix, position, true), chunk)
    }
}

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

fn convert_input_key(input_key: &SecretBox<[u8]>) -> Result<[u8; 32], EncryptionError> {
    <[u8; 32]>::try_from(input_key.expose_secret())
        .map_err(|_| EncryptionError::InvalidKeyLength)
}

#[derive(Copy, Debug, Clone, Serialize, Deserialize)]
pub enum EncryptionAlgorithm {
    AES256GCM,
    AES256KW,
    XCHACHA20POLY1305,
}

pub struct KeyWrap {
    input_key: SecretBox<[u8]>,
}

impl KeyWrap {
    pub fn new(input_key: SecretBox<[u8]>) -> Result<Self, EncryptionError> {
        if input_key.expose_secret().len() != 32 {
            return Err(EncryptionError::InvalidKeyLength);
        }

        Ok(KeyWrap { input_key })
    }

    pub fn wrap(&self, data: &SecretBox<[u8]>) -> Result<Vec<u8>, EncryptionError> {
        let mut output: Vec<u8> = vec![0; data.expose_secret().len() + 8];

        let input_key = <[u8; 32]>::try_from(self.input_key.expose_secret()).unwrap();

        let kek = KwpAes256::inner_init(Aes256::new(&input_key.into()));

        kek.wrap_key(data.expose_secret(), &mut output)?;

        Ok(output)
    }

    pub fn dewrap(&self, wrapped_data: &SecretBox<[u8]>) -> Result<SecretBox<[u8]>, EncryptionError> {
        let mut output: Vec<u8> = vec![0; wrapped_data.expose_secret().len().saturating_sub(8)];

        let input_key = <[u8; 32]>::try_from(self.input_key.expose_secret()).unwrap();

        let kek = KwpAes256::inner_init(Aes256::new(&input_key.into()));

        let unwrapped = kek.unwrap_key(wrapped_data.expose_secret(), &mut output)?;

        Ok(SecretBox::new(unwrapped.to_vec().into()))
    }
}

pub struct Encryptor {
    input_key: SecretBox<[u8]>,
    pub nonce: Vec<u8>,
    algorithm: EncryptionAlgorithm,
}

impl Encryptor {
    pub fn new(input_key: SecretBox<[u8]>, algorithm: EncryptionAlgorithm) -> Self {
        // TODO: Implement get_nonce_length() function for EncryptionAlgorithm enum
        let mut nonce = vec![0; 19];
        let mut rng = rand::rng();
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

        let aead = XChaCha20Poly1305::new(&input_key.into());
        let mut data_buffer = [0u8; AEAD_BUFFER_LEN];
        let mut position = 0u32;

        loop {
            let read_count = read_chunk(&mut data, &mut data_buffer)?;

            let encrypted_data = if read_count == AEAD_BUFFER_LEN {
                stream::encrypt_next(&aead, nonce, position, &data_buffer)?
            } else {
                stream::encrypt_last(&aead, nonce, position, &data_buffer[..read_count])?
            };

            output.write_all(&encrypted_data)?;

            if read_count != AEAD_BUFFER_LEN {
                break;
            }

            position += 1;
        }
        Ok(())
    }
}

pub struct Decryptor {
    input_key: SecretBox<[u8]>,
    nonce: Vec<u8>,
    algorithm: EncryptionAlgorithm,
}

impl Decryptor {
    pub fn new(input_key: SecretBox<[u8]>, nonce: Vec<u8>, algorithm: EncryptionAlgorithm) -> Self {
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

        let aead = XChaCha20Poly1305::new(&input_key.into());
        let mut encrypted_buffer = [0u8; AEAD_BUFFER_LEN + AEAD_TAG_LEN]; // 16bytes for AEAD tag
        let mut position = 0u32;

        loop {
            let read_count = read_chunk(&mut encrypted_data, &mut encrypted_buffer)?;

            // A full frame is 2048bytes of ciphertext + 16bytes of AEAD tag,
            // only a short frame can ever be the last chunk of the stream
            let decrypted_data = if read_count == AEAD_BUFFER_LEN + AEAD_TAG_LEN {
                stream::decrypt_next(&aead, nonce, position, &encrypted_buffer)?
            } else {
                stream::decrypt_last(&aead, nonce, position, &encrypted_buffer[..read_count])?
            };

            output.write_all(&decrypted_data)?;

            if read_count != AEAD_BUFFER_LEN + AEAD_TAG_LEN {
                break;
            }

            position += 1;
        }

        Ok(())
    }
}
