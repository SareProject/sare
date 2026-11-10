pub mod error;

use crate::encryption::error::*;
use rand::Rng;
use serde::{Deserialize, Serialize};

use aes_kw::{aes::Aes256, InnerInit, KwpAes256};
use chacha20poly1305::KeyInit;
use chacha20poly1305::XChaCha20Poly1305;
use secrecy::{ExposeSecret, SecretBox};
use std::io::{BufWriter, Read, Write};
use std::thread;
use std::vec;

const AEAD_BUFFER_LEN: usize = 2048;
const AEAD_TAG_LEN: usize = 16;
const XCHACHA20POLY1305_NONCE_LEN: usize = 19;

/// A full STREAM frame carries the encrypted chunk plus the AEAD tag
const FULL_FRAME_LEN: usize = AEAD_BUFFER_LEN + AEAD_TAG_LEN;

/// Frames processed per batch, a batch of full frames is 2 MiB of plaintext.
/// The frames of a batch are independent because every STREAM frame carries
/// its own counter in the nonce, so a batch can be spread over threads
const BATCH_FRAMES: usize = 1024;

/// Below this many frames in a batch the worker spawn overhead outweighs
/// the parallel gain, so the batch is processed on the calling thread
const PARALLEL_MIN_FRAMES: usize = 64;

/// Capacity of the buffered writer in front of the output stream, so the
/// per frame writes do not turn into one syscall per frame
const OUTPUT_BUFFER_LEN: usize = 1024 * 1024;

/// STREAM construction with a 32-bit big endian counter and a 1-byte
/// "last block" flag stored as the last 5 bytes of the AEAD nonce, as
/// described in "Online Authenticated-Encryption and its Nonce-Reuse
/// Misuse-Resistance" (Hoang, Reyhanitabar, Rogaway, Vizár)
///
/// The aead crate removed its stream module in 0.6, the construction is
/// small enough to be kept here instead
mod stream {
    use super::XCHACHA20POLY1305_NONCE_LEN;
    use aead::{AeadInOut, Tag};
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

    // Every function works in place on the frame it is given, the caller
    // reuses its frame buffers across the whole stream

    pub fn encrypt_next_detached(
        aead: &XChaCha20Poly1305,
        prefix: &[u8],
        position: u32,
        chunk: &mut [u8],
    ) -> Result<Tag<XChaCha20Poly1305>, aead::Error> {
        aead.encrypt_inout_detached(&aead_nonce(prefix, position, false), &[], chunk.into())
    }

    pub fn encrypt_last_detached(
        aead: &XChaCha20Poly1305,
        prefix: &[u8],
        position: u32,
        chunk: &mut [u8],
    ) -> Result<Tag<XChaCha20Poly1305>, aead::Error> {
        aead.encrypt_inout_detached(&aead_nonce(prefix, position, true), &[], chunk.into())
    }

    pub fn decrypt_next_detached(
        aead: &XChaCha20Poly1305,
        prefix: &[u8],
        position: u32,
        chunk: &mut [u8],
        tag: &[u8],
    ) -> Result<(), aead::Error> {
        let mut tag_array = Tag::<XChaCha20Poly1305>::default();
        tag_array.copy_from_slice(tag);

        aead.decrypt_inout_detached(
            &aead_nonce(prefix, position, false),
            &[],
            chunk.into(),
            &tag_array,
        )
    }

    pub fn decrypt_last_detached(
        aead: &XChaCha20Poly1305,
        prefix: &[u8],
        position: u32,
        chunk: &mut [u8],
        tag: &[u8],
    ) -> Result<(), aead::Error> {
        let mut tag_array = Tag::<XChaCha20Poly1305>::default();
        tag_array.copy_from_slice(tag);

        aead.decrypt_inout_detached(
            &aead_nonce(prefix, position, true),
            &[],
            chunk.into(),
            &tag_array,
        )
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

/// Number of worker threads the frames of a batch can be spread over
fn available_thread_count() -> usize {
    thread::available_parallelism().map_or(1, |count| count.get())
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
        output: W,
    ) -> Result<(), EncryptionError> {
        let input_key = convert_input_key(&self.input_key)?;
        let nonce = self.nonce.as_slice();
        let thread_count = available_thread_count();

        let aead = XChaCha20Poly1305::new(&input_key.into());
        let mut batch = vec![0u8; BATCH_FRAMES * AEAD_BUFFER_LEN];
        let mut tags = vec![[0u8; AEAD_TAG_LEN]; BATCH_FRAMES];
        let mut position = 0u32;
        let mut output = BufWriter::with_capacity(OUTPUT_BUFFER_LEN, output);

        loop {
            let read_count = read_chunk(&mut data, &mut batch)?;
            let full_frames = read_count / AEAD_BUFFER_LEN;

            encrypt_frames(
                &aead,
                nonce,
                position,
                &mut batch[..full_frames * AEAD_BUFFER_LEN],
                &mut tags[..full_frames],
                thread_count,
            )?;

            for (frame, tag) in batch[..full_frames * AEAD_BUFFER_LEN]
                .chunks_exact(AEAD_BUFFER_LEN)
                .zip(tags.iter())
            {
                output.write_all(frame)?;
                output.write_all(tag)?;
            }

            // The frame counter is 32 bits, a stream that exhausts it can not
            // be represented in this format
            position = position
                .checked_add(full_frames as u32)
                .ok_or(EncryptionError::Unexpected)?;

            if read_count == batch.len() {
                continue;
            }

            // A short read is only ever the last chunk of the stream, a stream
            // that ends on a frame boundary still carries the tag of an empty
            // last block
            let tail = &mut batch[full_frames * AEAD_BUFFER_LEN..read_count];
            let tag = stream::encrypt_last_detached(&aead, nonce, position, tail)?;
            output.write_all(tail)?;
            output.write_all(&tag)?;

            break;
        }

        output.flush()?;

        Ok(())
    }
}

/// Encrypt the full frames of a batch in place, every frame carries its own
/// STREAM counter so the frames are independent and can be spread over the
/// worker threads, the tags are written to `tags` in frame order
fn encrypt_frames(
    aead: &XChaCha20Poly1305,
    nonce: &[u8],
    first_position: u32,
    batch: &mut [u8],
    tags: &mut [[u8; AEAD_TAG_LEN]],
    thread_count: usize,
) -> Result<(), EncryptionError> {
    let frame_count = batch.len() / AEAD_BUFFER_LEN;
    if frame_count == 0 {
        return Ok(());
    }

    // A single thread skips the spawn overhead for small batches
    let thread_count = if frame_count >= PARALLEL_MIN_FRAMES {
        thread_count.min(frame_count)
    } else {
        1
    };
    if thread_count == 1 {
        for (index, frame) in batch.chunks_exact_mut(AEAD_BUFFER_LEN).enumerate() {
            let frame_position = frame_position(first_position, index)?;
            tags[index] = stream::encrypt_next_detached(aead, nonce, frame_position, frame)?.into();
        }

        return Ok(());
    }

    let frames_per_thread = frame_count.div_ceil(thread_count);
    let chunk_len = frames_per_thread * AEAD_BUFFER_LEN;
    let mut position = first_position;

    let result = thread::scope(|scope| -> Result<(), EncryptionError> {
        let mut workers = Vec::new();

        for (chunk, tags) in batch
            .chunks_mut(chunk_len)
            .zip(tags.chunks_mut(frames_per_thread))
        {
            let chunk_frames = chunk.len() as u32 / AEAD_BUFFER_LEN as u32;

            workers.push(scope.spawn(move || -> Result<(), EncryptionError> {
                for (index, frame) in chunk.chunks_exact_mut(AEAD_BUFFER_LEN).enumerate() {
                    let frame_position = frame_position(position, index)?;
                    tags[index] =
                        stream::encrypt_next_detached(aead, nonce, frame_position, frame)?.into();
                }

                Ok(())
            }));

            position += chunk_frames;
        }

        for worker in workers {
            worker.join().map_err(|_| EncryptionError::Unexpected)??;
        }

        Ok(())
    });

    result
}

/// The STREAM position of frame `index` inside a batch that starts at
/// `first_position`, the format can not address more than 2^32 frames
fn frame_position(first_position: u32, index: usize) -> Result<u32, EncryptionError> {
    first_position
        .checked_add(index as u32)
        .ok_or(EncryptionError::Unexpected)
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
        output: W,
    ) -> Result<(), EncryptionError> {
        if self.nonce.len() != XCHACHA20POLY1305_NONCE_LEN {
            return Err(EncryptionError::InvalidNonceLength);
        }

        let input_key = convert_input_key(&self.input_key)?;
        let nonce = self.nonce.as_slice();
        let thread_count = available_thread_count();

        let aead = XChaCha20Poly1305::new(&input_key.into());
        let mut encrypted_batch = vec![0u8; BATCH_FRAMES * FULL_FRAME_LEN];
        let mut plain_batch = vec![0u8; BATCH_FRAMES * AEAD_BUFFER_LEN];
        let mut position = 0u32;
        let mut output = BufWriter::with_capacity(OUTPUT_BUFFER_LEN, output);

        loop {
            let read_count = read_chunk(&mut encrypted_data, &mut encrypted_batch)?;
            let full_frames = read_count / FULL_FRAME_LEN;

            decrypt_frames(
                &aead,
                nonce,
                position,
                &mut encrypted_batch[..full_frames * FULL_FRAME_LEN],
                &mut plain_batch[..full_frames * AEAD_BUFFER_LEN],
                thread_count,
            )?;

            output.write_all(&plain_batch[..full_frames * AEAD_BUFFER_LEN])?;

            // The frame counter is 32 bits, a stream that exhausts it can not
            // be represented in this format
            position = position
                .checked_add(full_frames as u32)
                .ok_or(EncryptionError::Unexpected)?;

            if read_count == encrypted_batch.len() {
                continue;
            }

            // A full frame is 2048 bytes of cipher text plus the 16 byte tag,
            // only a short frame can ever be the last chunk of the stream, a
            // stream that ends on a frame boundary is missing its last block
            let tail =
                &mut encrypted_batch[full_frames * FULL_FRAME_LEN..read_count];
            if tail.len() < AEAD_TAG_LEN {
                return Err(aead::Error.into());
            }

            let (chunk, tag) = tail.split_at_mut(tail.len() - AEAD_TAG_LEN);
            stream::decrypt_last_detached(&aead, nonce, position, chunk, tag)?;
            output.write_all(chunk)?;

            break;
        }

        output.flush()?;

        Ok(())
    }
}

/// Decrypt the full frames of a batch, the cipher text bytes are replaced
/// with the plaintext in place and copied over to the plain batch, every
/// frame carries its own STREAM counter so the frames are independent and
/// can be spread over the worker threads
fn decrypt_frames(
    aead: &XChaCha20Poly1305,
    nonce: &[u8],
    first_position: u32,
    encrypted_batch: &mut [u8],
    plain_batch: &mut [u8],
    thread_count: usize,
) -> Result<(), EncryptionError> {
    let frame_count = encrypted_batch.len() / FULL_FRAME_LEN;
    if frame_count == 0 {
        return Ok(());
    }

    // A single thread skips the spawn overhead for small batches
    let thread_count = if frame_count >= PARALLEL_MIN_FRAMES {
        thread_count.min(frame_count)
    } else {
        1
    };
    if thread_count == 1 {
        for index in 0..frame_count {
            let frame_position = frame_position(first_position, index)?;
            decrypt_frame(aead, nonce, frame_position, encrypted_batch, plain_batch, index)?;
        }

        return Ok(());
    }

    let frames_per_thread = frame_count.div_ceil(thread_count);
    let encrypted_chunk_len = frames_per_thread * FULL_FRAME_LEN;
    let plain_chunk_len = frames_per_thread * AEAD_BUFFER_LEN;
    let mut position = first_position;

    let result = thread::scope(|scope| -> Result<(), EncryptionError> {
        let mut workers = Vec::new();

        for (encrypted_chunk, plain_chunk) in encrypted_batch
            .chunks_mut(encrypted_chunk_len)
            .zip(plain_batch.chunks_mut(plain_chunk_len))
        {
            let chunk_frames = encrypted_chunk.len() as u32 / FULL_FRAME_LEN as u32;

            workers.push(scope.spawn(move || -> Result<(), EncryptionError> {
                for index in 0..(encrypted_chunk.len() / FULL_FRAME_LEN) {
                    let frame_position = frame_position(position, index)?;
                    decrypt_frame(aead, nonce, frame_position, encrypted_chunk, plain_chunk, index)?;
                }

                Ok(())
            }));

            position += chunk_frames;
        }

        for worker in workers {
            worker.join().map_err(|_| EncryptionError::Unexpected)??;
        }

        Ok(())
    });

    result
}

/// Decrypt the frame at `index` inside the batches, the cipher text bytes of
/// the frame are replaced with the plaintext and copied over to the plain
/// batch, the frame is authenticated against its tag before any plaintext is
/// released by the caller
fn decrypt_frame(
    aead: &XChaCha20Poly1305,
    nonce: &[u8],
    position: u32,
    encrypted_batch: &mut [u8],
    plain_batch: &mut [u8],
    index: usize,
) -> Result<(), EncryptionError> {
    let frame = &mut encrypted_batch[index * FULL_FRAME_LEN..(index + 1) * FULL_FRAME_LEN];
    let (chunk, tag) = frame.split_at_mut(AEAD_BUFFER_LEN);

    stream::decrypt_next_detached(aead, nonce, position, chunk, tag)?;

    plain_batch[index * AEAD_BUFFER_LEN..(index + 1) * AEAD_BUFFER_LEN].copy_from_slice(chunk);

    Ok(())
}
