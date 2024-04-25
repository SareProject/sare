use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use secrecy::{ExposeSecret, SecretVec};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Sha512};

#[derive(Debug)]
pub enum KDFError {
    InvalidKeyLength,
    InvalidOutputLength,
    InvalidParams,
    Unexpected,
}

#[derive(Serialize, Deserialize)]
pub enum HKDFAlgorithm {
    SHA256,
    SHA512,
}

impl HKDFAlgorithm {
    pub fn get_output_size(&self) -> usize {
        match &self {
            HKDFAlgorithm::SHA256 => 32,
            HKDFAlgorithm::SHA512 => 64,
        }
    }
}

pub trait KDF {
    fn generate_salt() -> [u8; 8] {
        let mut salt_buffer = [0u8; 8];

        OsRng.fill_bytes(&mut salt_buffer);

        salt_buffer
    }
}

pub struct HKDF<'a> {
    input_data: &'a SecretVec<u8>,
    salt: &'a [u8],
    algorithm: HKDFAlgorithm,
}

impl<'a> HKDF<'a> {
    pub fn new(input_data: &'a SecretVec<u8>, salt: &'a [u8], algorithm: HKDFAlgorithm) -> Self {
        HKDF {
            input_data,
            salt,
            algorithm,
        }
    }

    fn expand_sha256(
        &self,
        additional_context: Option<&[u8]>,
        okm: &mut [u8],
    ) -> Result<(), KDFError> {
        let hkdf = Hkdf::<Sha256>::new(Some(self.salt), self.input_data.expose_secret());
        hkdf.expand(additional_context.unwrap_or(&[0]), okm)
            .map_err(|_| KDFError::InvalidKeyLength)?;

        Ok(())
    }

    fn expand_sha512(
        &self,
        additional_context: Option<&[u8]>,
        okm: &mut [u8],
    ) -> Result<(), KDFError> {
        let hkdf = Hkdf::<Sha512>::new(Some(self.salt), self.input_data.expose_secret());
        hkdf.expand(additional_context.unwrap_or(&[0]), okm)
            .map_err(|_| KDFError::InvalidKeyLength)?;

        Ok(())
    }

    pub fn expand(&self, additional_context: Option<&[u8]>) -> Result<SecretVec<u8>, KDFError> {
        let mut okm = vec![0u8; self.algorithm.get_output_size()];

        match &self.algorithm {
            HKDFAlgorithm::SHA256 => {
                self.expand_sha256(additional_context, &mut okm)?;
            }
            HKDFAlgorithm::SHA512 => {
                self.expand_sha512(additional_context, &mut okm)?;
            }
        }

        Ok(SecretVec::from(okm))
    }
}

#[derive(Serialize, Deserialize)]
pub enum PKDFAlgorithm {
    Scrypt(u8, u32, u32),
}

pub struct PKDF<'a> {
    input_data: &'a SecretVec<u8>,
    salt: &'a [u8],
    algorithm: PKDFAlgorithm,
}

impl KDF for PKDF<'_> {}

impl<'a> PKDF<'a> {
    pub fn new(input_data: &'a SecretVec<u8>, salt: &'a [u8], algorithm: PKDFAlgorithm) -> Self {
        PKDF {
            input_data,
            salt,
            algorithm,
        }
    }

    // NOTE: To be used later
    /*
    pub fn calculate_scrypt_workfactor(&self) -> (usize, usize, usize) {
        let n: usize = (self.workfactor_scale / 4).max(2);
        let r = 8usize;
        let p: u64 = ((2i64.pow(n as u32) / 20).max(1).ilog2()).max(1).into();
        (n, r, p as usize)
    }
    */

    pub fn derive_key(&self, key_length: usize) -> Result<SecretVec<u8>, KDFError> {
        match &self.algorithm {
            PKDFAlgorithm::Scrypt(n, r, p) => {
                let params = scrypt::Params::new(*n, *r, *p, key_length)
                    .map_err(|_| KDFError::InvalidParams)?;

                let mut output = vec![0u8; key_length];
                scrypt::scrypt(
                    self.input_data.expose_secret(),
                    self.salt,
                    &params,
                    &mut output,
                )
                .map_err(|_| KDFError::InvalidOutputLength)?;

                Ok(SecretVec::from(output))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SALT: [u8; 9] = [1, 1, 1, 1, 1, 1, 1, 1, 1];
    const TEST_INPUT_DATA: [u8; 6] = [6, 6, 6, 6, 6, 6];

    const HKDF_SHA512_OUTPUT: [u8; 64] = [
        46, 30, 33, 140, 17, 103, 238, 164, 144, 144, 87, 205, 161, 83, 5, 128, 209, 210, 128, 15,
        170, 178, 211, 157, 130, 12, 111, 198, 100, 233, 90, 81, 165, 143, 136, 207, 139, 106, 43,
        238, 207, 132, 156, 252, 170, 83, 253, 239, 179, 216, 72, 37, 218, 57, 122, 202, 198, 175,
        44, 42, 8, 192, 18, 167,
    ];

    const SCRYPT_OUTPUT: [u8; 10] = [172, 240, 153, 61, 124, 223, 14, 128, 130, 37];

    #[test]
    fn hkdf() {
        let binding = SecretVec::from(TEST_INPUT_DATA.to_vec());
        let hkdf = HKDF::new(&binding, &TEST_SALT, HKDFAlgorithm::SHA512);

        let output = hkdf.expand(None).unwrap();

        assert_eq!(HKDF_SHA512_OUTPUT, output.expose_secret().as_slice());
    }

    /*
    #[test]
    fn scrypt_workfactor_scale() {
        let input_data = SecretVec::from(TEST_INPUT_DATA.to_vec());
        let pkdf = PKDF::new(&input_data, &TEST_SALT, 60, PKDFAlgorithm::Scrypt);

        let workfactor = pkdf.calculate_scrypt_workfactor();

        assert_eq!((15, 8, 10), workfactor);
    }
    */

    #[test]
    fn scrypt_key_derive() {
        let input_data = SecretVec::from(TEST_INPUT_DATA.to_vec());
        let pkdf = PKDF::new(&input_data, &TEST_SALT, PKDFAlgorithm::Scrypt(5, 8, 1));

        let output = pkdf.derive_key(10).unwrap();

        assert_eq!(SCRYPT_OUTPUT, output.expose_secret().as_slice());
    }
}
