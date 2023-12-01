use ring::hkdf;

#[derive(Debug)]
pub enum KDFError {
    Unexpected,
}

pub enum HKDFAlgorithm {
    SHA256,
    SHA512,
}

pub struct HKDF<'a> {
    input_data: &'a [u8],
    salt: &'a [u8],
    algorithm: HKDFAlgorithm,
}

impl<'a> HKDF<'a> {
    pub fn new(input_data: &'a [u8], salt: &'a [u8], algorithm: HKDFAlgorithm) -> Self {
        HKDF {
            input_data,
            salt,
            algorithm,
        }
    }

    pub fn expand(
        &self,
        additional_context: Option<&[&[u8]]>,
        output: &mut [u8],
    ) -> Result<(), KDFError> {
        let hash_algorithm = match &self.algorithm {
            HKDFAlgorithm::SHA256 => hkdf::HKDF_SHA256,
            HKDFAlgorithm::SHA512 => hkdf::HKDF_SHA512,
        };

        let salt = hkdf::Salt::new(hash_algorithm, self.salt);
        let hkdf_prk = salt.extract(&self.input_data);

        let hkdf_okm = hkdf_prk
            .expand(additional_context.unwrap_or(&[&[0]]), hash_algorithm)
            .unwrap();

        //TODO: convert ther errors later
        hkdf_okm.fill(output).unwrap();
        Ok(())
    }
}

pub enum PKDFAlgorithm {
    Scrypt,
}

pub struct PKDF<'a> {
    input_data: &'a [u8],
    salt: &'a [u8],
    workfactor_scale: usize,
    algorithm: PKDFAlgorithm,
}

impl<'a> PKDF<'a> {
    pub fn new(
        input_data: &'a [u8],
        salt: &'a [u8],
        workfactor_scale: usize,
        algorithm: PKDFAlgorithm,
    ) -> Self {
        PKDF {
            input_data,
            salt,
            workfactor_scale,
            algorithm,
        }
    }

    pub fn calculate_scrypt_workfactor(&self) -> (usize, usize, usize) {
        let n: usize = (self.workfactor_scale / 4).max(2);
        let r = 8usize;
        let p: u64 = ((2i64.pow(n as u32) / 20).max(1).ilog2()).max(1).into();
        (n, r, p as usize)
    }

    pub fn derive_key(&self, output: &mut [u8]) -> Result<(), KDFError> {
        match &self.algorithm {
            PKDFAlgorithm::Scrypt => {
                let workfactor = self.calculate_scrypt_workfactor();

                let params = scrypt::Params::new(
                    workfactor.0.try_into().unwrap_or(255),
                    workfactor.1 as u32,
                    workfactor.2 as u32,
                    output.len(),
                )
                .unwrap(); // TODO: Convert errors

                // TODO: convert errors
                scrypt::scrypt(&self.input_data, &self.salt, &params, output).unwrap();

                Ok(())
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
        let hkdf = HKDF::new(&TEST_INPUT_DATA, &TEST_SALT, HKDFAlgorithm::SHA512);

        let mut output = [0u8; 64];

        hkdf.expand(None, &mut output).unwrap();

        assert_eq!(HKDF_SHA512_OUTPUT, output);
    }

    #[test]
    fn scrypt_workfactor_scale() {
        let pkdf = PKDF::new(&TEST_INPUT_DATA, &TEST_SALT, 60, PKDFAlgorithm::Scrypt);

        let workfactor = pkdf.calculate_scrypt_workfactor();

        assert_eq!((15, 8, 10), workfactor);
    }

    #[test]
    fn scrypt_key_derive() {
        let pkdf = PKDF::new(&TEST_INPUT_DATA, &TEST_SALT, 20, PKDFAlgorithm::Scrypt);

        let mut output = [0u8; 10];
        pkdf.derive_key(&mut output).unwrap();

        assert_eq!(SCRYPT_OUTPUT, output);
    }
}
