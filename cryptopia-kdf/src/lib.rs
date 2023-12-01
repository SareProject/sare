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

    #[test]
    fn hkdf() {
        let hkdf = HKDF::new(&TEST_INPUT_DATA, &TEST_SALT, HKDFAlgorithm::SHA512);

        let mut output = [0u8; 64];

        hkdf.expand(None, &mut output).unwrap();

        assert_eq!(HKDF_SHA512_OUTPUT, output);
    }
}
