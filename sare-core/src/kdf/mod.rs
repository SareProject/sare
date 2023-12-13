use ring::hkdf;
use ring::rand::{SecureRandom, SystemRandom};
use secrecy::{ExposeSecret, SecretVec};
use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub enum KDFError {
    Unexpected,
}

#[derive(Serialize, Deserialize)]
pub enum HKDFAlgorithm {
    SHA256,
    SHA512,
}

pub trait KDF {
    fn generate_salt() -> [u8; 8] {
        let rng = SystemRandom::new();
        let mut salt_buffer = [0u8; 8];

        rng.fill(&mut salt_buffer).unwrap();

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

    pub fn expand(&self, additional_context: Option<&[&[u8]]>) -> Result<SecretVec<u8>, KDFError> {
        let (hash_algorithm, output_key_length) = match &self.algorithm {
            HKDFAlgorithm::SHA256 => (hkdf::HKDF_SHA256, 32),
            HKDFAlgorithm::SHA512 => (hkdf::HKDF_SHA512, 64),
        };

        let salt = hkdf::Salt::new(hash_algorithm, self.salt);
        let hkdf_prk = salt.extract(self.input_data.expose_secret());

        let hkdf_okm = hkdf_prk
            .expand(additional_context.unwrap_or(&[&[0]]), hash_algorithm)
            .unwrap();

        let mut output = vec![0u8; output_key_length];
        //TODO: convert ther errors later
        hkdf_okm.fill(&mut output).unwrap();

        Ok(SecretVec::from(output))
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
                let params = scrypt::Params::new(*n, *r, *p, key_length).unwrap(); // TODO: Convert errors

                // TODO: convert errors
                let mut output = vec![0u8; key_length];
                scrypt::scrypt(
                    self.input_data.expose_secret(),
                    self.salt,
                    &params,
                    &mut output,
                )
                .unwrap();

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
