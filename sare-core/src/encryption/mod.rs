use aes_kw::KekAes256;
use secrecy::{ExposeSecret, Secret, SecretVec};

pub struct KeyWrap {
    input_key: Secret<[u8; 32]>,
}

impl KeyWrap {
    pub fn new(input_key: Secret<[u8; 32]>) -> Self {
        KeyWrap { input_key }
    }

    pub fn encrypt(&self, data: &SecretVec<u8>) -> Vec<u8> {
        let mut output: Vec<u8> = Vec::with_capacity(data.expose_secret().len() + 8);

        let kek = KekAes256::from(*self.input_key.expose_secret());

        kek.wrap(data.expose_secret(), &mut output);

        output
    }
}
