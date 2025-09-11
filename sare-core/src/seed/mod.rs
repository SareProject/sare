pub mod error;

use bip39::{Language, Mnemonic};
use rand::RngCore;
use rand::rngs::OsRng;
use secrecy::{ExposeSecret, SecretString, SecretVec};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

use crate::kdf::{HKDF, HKDFAlgorithm};

use crate::seed::error::*;

pub struct Seed {
    raw_seed: SecretVec<u8>,
}

impl Seed {
    pub fn new(raw_seed: SecretVec<u8>) -> Self {
        Seed { raw_seed }
    }

    pub fn generate() -> Self {
        let mut raw_seed_buffer = vec![0u8; 128];

        OsRng.fill_bytes(&mut raw_seed_buffer);

        Seed {
            raw_seed: SecretVec::from(raw_seed_buffer),
        }
    }

    pub fn to_mnemonic(&self) -> SecretString {
        let seed_chunks: Vec<&[u8]> = self.raw_seed.expose_secret().chunks_exact(32).collect();

        let mut mnemonic_phrase: String = String::new();

        for chunk in seed_chunks {
            // NOTE: Because the chunck sizes are known and in the valid range there will be no errors here
            // and it can be unwraped without having to handle errors
            let mnemonic = Mnemonic::from_entropy(chunk, Language::English).unwrap();
            mnemonic_phrase.push_str(mnemonic.phrase());
            mnemonic_phrase.push(' ');
        }

        SecretString::from(mnemonic_phrase.trim_end().to_string())
    }

    pub fn from_mnemonic(seed_phrase: &SecretString) -> Result<Self, SeedError> {
        let phrase_seperated: Vec<&str> = seed_phrase.expose_secret().split_whitespace().collect();

        let mut raw_seed_buffer: Vec<u8> = Vec::new();

        for phrase in phrase_seperated.chunks_exact(24) {
            let mnemonic = Mnemonic::from_phrase(&phrase.join(" "), Language::English);

            if let Ok(mnemonic_parsed) = mnemonic {
                let entropy = mnemonic_parsed.entropy();
                raw_seed_buffer.extend(entropy);
            } else {
                return Err(SeedError::InvalidMnemonicPhrase);
            }
        }

        let raw_seed = <[u8; 128]>::try_from(raw_seed_buffer.as_slice())?;

        Ok(Seed {
            raw_seed: SecretVec::from(raw_seed.to_vec()),
        })
    }

    pub fn get_raw_seed(&self) -> &SecretVec<u8> {
        &self.raw_seed
    }

    pub fn clone_raw_seed(&self) -> SecretVec<u8> {
        SecretVec::from(self.raw_seed.expose_secret().clone())
    }

    pub fn derive_64bytes_child_seed(&self, additional_context: Option<&[u8]>) -> SecretVec<u8> {
        let hkdf = HKDF::new(&self.raw_seed, vec![], HKDFAlgorithm::SHA512);
        hkdf.expand(additional_context).unwrap()
    }

    pub fn derive_32bytes_child_seed(&self, additional_context: Option<&[u8]>) -> SecretVec<u8> {
        let hkdf = HKDF::new(&self.raw_seed, vec![], HKDFAlgorithm::SHA256);

        hkdf.expand(additional_context).unwrap()
    }

    pub fn derive_extended_child_key(
        &self,
        length: usize,
        additional_context: Option<&[u8]>,
    ) -> SecretVec<u8> {
        let child_seed = &self.derive_64bytes_child_seed(additional_context);

        let mut xof = Shake256::default();
        xof.update(child_seed.expose_secret());
        let mut xof_reader = xof.finalize_xof();

        let mut child_key = vec![0u8; length];
        xof_reader.read(&mut child_key);

        SecretVec::from(child_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_RAW_SEED: [u8; 128] = [
        107, 77, 197, 228, 108, 243, 219, 99, 78, 6, 163, 49, 167, 215, 3, 169, 28, 225, 74, 229,
        73, 142, 237, 44, 255, 42, 149, 31, 19, 188, 90, 149, 19, 3, 211, 176, 24, 229, 12, 40, 56,
        181, 125, 236, 17, 75, 78, 186, 184, 87, 223, 0, 22, 191, 56, 252, 146, 123, 162, 130, 153,
        100, 84, 12, 121, 96, 192, 255, 68, 161, 170, 4, 151, 183, 68, 143, 22, 140, 68, 157, 95,
        97, 93, 92, 201, 154, 221, 86, 124, 141, 233, 52, 9, 125, 216, 221, 143, 138, 19, 193, 231,
        220, 61, 154, 49, 92, 145, 167, 33, 168, 71, 156, 228, 247, 106, 74, 130, 191, 185, 185,
        118, 141, 70, 127, 85, 252, 241, 113,
    ];

    const TEST_32BYTES_CHILD_SEED: [u8; 32] = [
        106, 137, 246, 68, 110, 39, 182, 234, 60, 243, 135, 137, 167, 244, 248, 126, 41, 208, 235,
        107, 32, 28, 184, 60, 200, 190, 32, 129, 158, 163, 166, 236,
    ];

    const TEST_64BYTES_CHILD_SEED: [u8; 64] = [
        87, 50, 246, 51, 43, 11, 34, 202, 167, 240, 188, 167, 254, 136, 161, 214, 144, 235, 6, 136,
        38, 39, 148, 139, 161, 176, 171, 75, 119, 36, 232, 42, 65, 123, 155, 69, 106, 94, 37, 179,
        71, 135, 196, 93, 18, 24, 237, 111, 81, 122, 84, 1, 135, 36, 74, 77, 142, 207, 245, 94,
        223, 170, 164, 155,
    ];

    const TEST_EXTENDED_CHILD_KEY: [u8; 96] = [
        66, 77, 213, 45, 109, 239, 140, 74, 253, 233, 246, 97, 182, 102, 112, 208, 187, 129, 108,
        251, 125, 149, 192, 191, 222, 56, 116, 221, 217, 102, 76, 119, 63, 120, 108, 143, 169, 64,
        15, 220, 217, 176, 29, 81, 158, 0, 23, 82, 57, 208, 164, 177, 89, 197, 99, 252, 84, 253,
        56, 110, 16, 75, 76, 147, 112, 123, 41, 230, 148, 25, 21, 235, 250, 43, 233, 71, 191, 212,
        175, 145, 78, 198, 51, 82, 157, 188, 117, 201, 21, 66, 134, 77, 179, 68, 223, 37,
    ];

    const TEST_MNEMONIC_PHRASE: &str = "hero hotel jungle supreme diet random day stamp coyote dirt science fall sock pistol news crack unfold gun skirt clay van taste heart process basic burden ugly crack express beef tissue quick ugly medal squirrel install lyrics usage able subject decline tonight page eagle civil rate expand never just alcohol divert matter boy across gain trigger monitor refuse bachelor deny voyage push industry crew tail recycle casino sponsor dog same gloom phone moon explain vacant soul sense snack shell mutual poet ask ball degree exhaust release claw fitness rifle slight person mind vocal wrist shift clock";

    #[test]
    fn derive_child_seed() {
        let master_seed = Seed::new(SecretVec::from(TEST_RAW_SEED.to_vec()));

        let child_seed_32bytes = master_seed.derive_32bytes_child_seed(None);
        let child_seed_64bytes = master_seed.derive_64bytes_child_seed(None);
        let child_key = master_seed.derive_extended_child_key(96, None);

        assert_eq!(
            child_seed_32bytes.expose_secret().as_slice(),
            TEST_32BYTES_CHILD_SEED
        );
        assert_eq!(
            child_seed_64bytes.expose_secret().as_slice(),
            TEST_64BYTES_CHILD_SEED
        );
        assert_eq!(
            child_key.expose_secret().as_slice(),
            TEST_EXTENDED_CHILD_KEY
        );
    }

    #[test]
    fn menmonic_seed_encode() {
        let master_seed = Seed::new(SecretVec::from(TEST_RAW_SEED.to_vec()));

        let phrase = master_seed.to_mnemonic();

        assert_eq!(phrase.expose_secret().as_str(), TEST_MNEMONIC_PHRASE);
    }

    #[test]
    fn menmonic_seed_decode() {
        let master_seed =
            Seed::from_mnemonic(&SecretString::from(TEST_MNEMONIC_PHRASE.to_string())).unwrap();

        assert_eq!(
            master_seed.get_raw_seed().expose_secret().as_slice(),
            TEST_RAW_SEED
        );
    }
}
