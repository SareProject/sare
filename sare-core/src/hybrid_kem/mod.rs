pub mod error;

use crate::seed::Seed;

use ed25519_compact::x25519;
use secrecy::{ExposeSecret, SecretVec};

use serde::{Deserialize, Serialize};
use std::string::ToString;

use crate::hybrid_kem::error::*;

use crate::PublicKey;

const X25519_MAGIC_BYTES: [u8; 4] = [25, 85, 2, 0]; // 0x25519 in LittleEndian
const KYBER768_MAGIC_BYTES: [u8; 4] = [104, 7, 0, 0]; // 0x768 in LittleEndian

#[derive(Clone, Copy, Serialize, Deserialize)]
pub enum DHAlgorithm {
    X25519,
}

impl ToString for DHAlgorithm {
    fn to_string(&self) -> String {
        match self {
            Self::X25519 => String::from("X25519"),
        }
    }
}

pub struct DHKeyPair {
    pub public_key: PublicKey,
    pub secret_key: SecretVec<u8>,
    pub algorithm: DHAlgorithm,
}

impl DHKeyPair {
    pub fn from_secret_key(
        secret_key: &SecretVec<u8>,
        dh_algorithm: DHAlgorithm,
    ) -> Result<Self, HybridKEMError> {
        match dh_algorithm {
            DHAlgorithm::X25519 => {
                let secret_key = x25519::SecretKey::from_slice(secret_key.expose_secret())?;
                let public_key = secret_key.recover_public_key()?;

                Ok(DHKeyPair {
                    public_key: PublicKey::X25519(public_key.to_vec()),
                    secret_key: SecretVec::from(secret_key.to_vec()),
                    algorithm: dh_algorithm,
                })
            }
        }
    }

    pub fn from_seed(seed: &Seed, dh_algorithm: DHAlgorithm) -> Self {
        match dh_algorithm {
            DHAlgorithm::X25519 => {
                let child_seed = &seed.derive_32bytes_child_seed(Some(&X25519_MAGIC_BYTES));

                // Because we make sure the key is 32bytes it won't return errors
                let secret_key =
                    x25519::SecretKey::from_slice(child_seed.expose_secret().as_slice()).unwrap();
                let public_key = secret_key.recover_public_key().unwrap();

                DHKeyPair {
                    public_key: PublicKey::X25519(public_key.to_vec()),
                    secret_key: SecretVec::from(secret_key.to_vec()),
                    algorithm: dh_algorithm,
                }
            }
        }
    }
}

pub struct DiffieHellman<'a> {
    pub sender_keypair: &'a DHKeyPair,
    pub reciever_public_key: &'a Vec<u8>,
}

impl<'a> DiffieHellman<'a> {
    pub fn new(sender_keypair: &'a DHKeyPair, reciever_public_key: &'a Vec<u8>) -> Self {
        DiffieHellman {
            sender_keypair,
            reciever_public_key,
        }
    }

    pub fn calculate_shared_key(&self) -> Result<SecretVec<u8>, HybridKEMError> {
        let dh_algorithm = &self.sender_keypair.algorithm;

        match dh_algorithm {
            DHAlgorithm::X25519 => {
                let sender_key =
                    x25519::SecretKey::from_slice(self.sender_keypair.secret_key.expose_secret())?;
                let reciever_key = x25519::PublicKey::from_slice(self.reciever_public_key)?;

                Ok(reciever_key.dh(&sender_key)?.as_slice().to_vec().into())
            }
        }
    }
}

#[derive(Clone, Copy, Serialize, Deserialize)]
pub enum KEMAlgorithm {
    Kyber768,
}

impl ToString for KEMAlgorithm {
    fn to_string(&self) -> String {
        match self {
            Self::Kyber768 => String::from("Kyber768"),
        }
    }
}

pub struct KEMKeyPair {
    pub public_key: PublicKey,
    pub secret_key: SecretVec<u8>,
    pub algorithm: KEMAlgorithm,
}

impl KEMKeyPair {
    pub fn from_seed(seed: &Seed, kem_algorithm: KEMAlgorithm) -> Self {
        match kem_algorithm {
            KEMAlgorithm::Kyber768 => {
                let child_seed = seed.derive_64bytes_child_seed(Some(&KYBER768_MAGIC_BYTES));
                // Because the size of the child_seed is fixed it won't return errors
                let keypair = pqc_kyber::derive(child_seed.expose_secret()).unwrap();

                KEMKeyPair {
                    public_key: PublicKey::Kyber768(keypair.public.to_vec()),
                    secret_key: SecretVec::from(keypair.secret.to_vec()),
                    algorithm: kem_algorithm,
                }
            }
        }
    }
}

pub struct EncapsulatedSecret {
    pub shared_secret: SecretVec<u8>,
    pub cipher_text: Vec<u8>,
}

pub struct Encapsulation {
    public_key: PublicKey,
    algorithm: KEMAlgorithm,
}

impl Encapsulation {
    pub fn new(public_key: PublicKey, algorithm: KEMAlgorithm) -> Self {
        Encapsulation {
            public_key: public_key,
            algorithm,
        }
    }

    pub fn encapsulate(&self) -> Result<EncapsulatedSecret, HybridKEMError> {
        let mut random_generator = rand::thread_rng();

        let (cipher_text, shared_secret) = match self.algorithm {
            KEMAlgorithm::Kyber768 => {
                pqc_kyber::encapsulate(self.public_key.as_ref(), &mut random_generator).unwrap()
            }
        };

        Ok(EncapsulatedSecret {
            shared_secret: SecretVec::from(shared_secret.to_vec()),
            cipher_text: cipher_text.to_vec(),
        })
    }
}

pub struct DecapsulatedSecret {
    shared_secret: SecretVec<u8>,
}

pub struct Decapsulation<'a> {
    secret_key: &'a SecretVec<u8>,
    algorithm: &'a KEMAlgorithm,
}

impl<'a> Decapsulation<'a> {
    pub fn new(secret_key: &'a SecretVec<u8>, algorithm: &'a KEMAlgorithm) -> Self {
        Decapsulation {
            secret_key,
            algorithm,
        }
    }

    pub fn decapsulate(&self, cipher_text: &[u8]) -> Result<DecapsulatedSecret, HybridKEMError> {
        let shared_secret = match self.algorithm {
            KEMAlgorithm::Kyber768 => {
                pqc_kyber::decapsulate(cipher_text, self.secret_key.expose_secret()).unwrap()
            }
        };

        Ok(DecapsulatedSecret {
            shared_secret: SecretVec::from(shared_secret.to_vec()),
        })
    }
}

pub struct HybridKEM {
    pub dh_keypair: DHKeyPair,
    pub kem_keypair: KEMKeyPair,
}

impl HybridKEM {
    pub fn new(dh_keypair: DHKeyPair, kem_keypair: KEMKeyPair) -> Self {
        HybridKEM {
            dh_keypair,
            kem_keypair,
        }
    }

    pub fn calculate_raw_shared_key(
        &self,
        kem_cipher_text: &[u8],
        dh_sender_public_key: PublicKey,
    ) -> Result<(SecretVec<u8>, SecretVec<u8>), HybridKEMError> {
        let binding = dh_sender_public_key.as_ref().to_vec();
        let diffie_hellman = DiffieHellman::new(&self.dh_keypair, &binding);
        let kem_decapsulation =
            Decapsulation::new(&self.kem_keypair.secret_key, &self.kem_keypair.algorithm);

        let dh_shared_secret = diffie_hellman.calculate_shared_key()?;
        let kem_shared_secret = kem_decapsulation.decapsulate(kem_cipher_text)?;

        Ok((dh_shared_secret, kem_shared_secret.shared_secret))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SEED: [u8; 128] = [
        198, 44, 204, 124, 44, 49, 54, 122, 236, 122, 174, 6, 50, 107, 65, 214, 47, 51, 12, 251,
        107, 231, 10, 176, 23, 212, 180, 156, 17, 59, 207, 193, 239, 137, 69, 61, 25, 4, 0, 233,
        97, 31, 94, 200, 222, 243, 222, 181, 63, 225, 246, 49, 233, 246, 206, 13, 147, 85, 137, 5,
        165, 80, 188, 150, 198, 44, 204, 124, 44, 49, 54, 122, 236, 122, 174, 6, 50, 107, 65, 214,
        47, 51, 12, 251, 107, 231, 10, 176, 23, 212, 180, 156, 17, 59, 207, 193, 239, 137, 69, 61,
        25, 4, 0, 233, 97, 31, 94, 200, 222, 243, 222, 181, 63, 225, 246, 49, 233, 246, 206, 13,
        147, 85, 137, 5, 165, 80, 188, 150,
    ];

    const KYBER_SECRET_KEY: &str ="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";

    const KYBER_PUBLIC_KEY: &str ="eoMnONCcnYSjbkNQ1oO6KJYfNwsj3LaX+keuMEGz05COI8oqzAVEQFVmtzY/sgJrg9sIG9RylBfLicnCzEet2WStYPyoTPwIyYBg6vyYTnCZfuYr/uO40FQCqXop7ihdTMe5Q+ltmQzM61wpX4t/oRK6+kG9KtBueOCerhdAJhKpo1yUgNiQAehJuesXCqdko1amBEMHq/gCDPGVNUmO5zE+NlNP0RaJT5qpdNcGh7AcFriTezAsj4QJboZ4kfB6HZl0z3OWkuzGR3ekBYdEOcC8JopoHayvcje6CYA0F5NpBSe5vSSErUwoOEEaX7By6rzIVBBMrjtVUPalICsp32W7pyBC9fOk6IVCVXlRTRu+BqEoQeVJmCtET9wTguo1hCgHNPiCpQEdcbjGJJnPeqQlN0Su8eXNzyODA5pDAYi+MqC7tFtD7SCJ71xgHCI4FuZAn6BIS1ykBnpai0tzd5xiexuf1/w5i6SjV2sQbRGEpQzIJlzHyFa/5vArfSh6xnCTg3QvkOxraGBH3zV2KilnHJOM2lFLJSc+Zkl7tmPCEblC0SAD4gdyYto+yxYD3yN3klGKhtCtrvROpdwu97yQ9jmYveZ8hhxFSHhcT3dxs4pSX5kGmLutsmsASGSqw1i+9JhOSkFx71ViM8sLUNStPSwKjkPAhqghIyAYffZ7wwKVUkwoZacxw2h8myEbdux14rt70pzDrhY2S6gRbDYVKwiwnSVtDoECcaATjjPL3mO9Y/IdTCSmi4gno9Gx4BVoMNcM92xE1HC4IagZ0RhwA7ZVZFBfpDyObnugEYDJEVscpsKZKjdbhWRWucwdGbOjsXkq8Uk+J5Eb42mrvZMEoFspSwJrN8ayWBMh8VdNzMA+UAttPyoh0aOJqPdlZWZyIEcnJ8cBWJACdFmHO4XPq9p5+kmPUPAVJcKq+lQB+2NZ79JpZXm248auAqVebAadWzJ1WiJ4rgKR7qZzCvxJHpQuprs0npoM8wJ/FrSfqLuRpzxSVmzLh6E5x/Q3huRjxSQXCAw0Csud5zuBEKLMimyrq2nH5Xi0alSkzbFBLwlWLlnDiGcKYzuQm3PDnsLFbZFi9HeF02uhWjO80RGG6jolZjpd95VgAZB5oMBW2WcM8leYvHYM/IMQODlyfmGZU2Q6igtylYt4mMQQlRAUAYWM4fopdSe/7huWK0iEUtEXO6qUVTEA4Ywv8wJMwFhYn1U/VXN/+qOtMIR65bgFzCitSsE542Eg4Xm1ZJbLF3USobtAi5CXaRaLRrNWALWTO+gNu1wFb7eZMySoHyU+03u/Lzux2ZfGPEVA/IhVJ/Qr27x4hrqY66agtno0QfUB4oxsp+IMBpS7TjieeTwdhoPFynkd93CfTEIOfJi6A1W2UsqUWUKsB5sHXuhK8kjHZxl/haa9lxMvAMO2dAp6P0gTi6qNF5JCsjvM8aNrQEiNodmeO3SPfRS3D7tTx3HBOTObmPwuEegI6IRUoAiiMsuxPLEMOpV2bihNHpRKXGtihatuo9opj3ekqxlglF/TNc/qSn3cGowhuUiBum8kK0lqA9jonDRuuUaCG1A=";

    const KYBER_CIPHER_TEXT: &str = "dcZCy2qBW9KURkV2YmYvg3v35MAX2TsNMEA5m8GHws7D+m7IfOw6NWskDojrglG0s1j3pC4HGoOp7urS5SDqvsZlmW0vae//ZHMqIHStG14vRM23lIl1ElZejtkm0AWfGhYs4ZkAzeRfdPjuaYbm3UzbEm8bng0yTyifMigqEc9whQp2WKu0z6bArcFftrQsxkR2wLaK8qN+w7ARuL4infcRHSeexzyt3NvP65KK7/8lRqjMvp4rbjcyucSKr6UPaIwgIQntuRn3y90QOXbuijWduGulCK4z2eS1dFsrYnuc66JZZPz7OJTDdHyFpYMxdulNv0KFFgbC6yef7zXu984iGmdNPdRQRK5tmqdQld4eKKxQ9MZFOVB0R0xJ6FLRcImsiIMSDbjBo+C2aGyZir156XeFcIeXbSz/APxucTtciFE5sNLOYVBAz3ci7t1gnZvWr9Blw8Ew7kb0Mk1l1sh4ZONSrmpG/qQeOfyBGMiUgiszqPuMAQNwB/8I64t3QO72JMzW9jQMUIa/q4isfc3wScPFHW4Hbnmk5HpTsqbjogdxTsDYa7orcKCTkRz80+Fa0bf2n2sQW0mieph0gntlEgw6Mk/wNOZPUwljj7t+B3qy1MS2RYCALvLFCBQ06cMdyE6EJrgPUqjFh0npmFV6sdAigVYhEStWNdKftVw8A4jfHKQhR+fGcyZm3zY7ZjQailZbOGBDmZDhWnyzKajYKovvYkyNDI/6H4qtMKEmBXJ/QIOu2VvaJAeyVGFtv1kmPzfgag/Y0obOZfVyarkfwUqRsK/fi2DWURwrAVwDI+k+4+e/6Bpe4ERf5crxaYVE/THfwLh0cj8ShLR8h59FjrWYutHFqHwzE8WY6JaV01kebROK9tbbvtZn79GNuwfxrCOiB8LEM1usSbj8bdBLFgTrbsujB8XhOnSn5RJmg6BoE4Bb7wPQUujrjuF3G4x74miChX/LUjc34nJDERng2kUT0vqC2+A7uDxDqjoc48LP/muCuKqD5xJZAjXE8FH9hN2WMEdrvcj986WefCGLJCWHLkMvCzUq3WPpTcH6xwQorgR4ZoLuR+wwWRMlIJfzVsbkxQedJONGBvjKRI8jf50dldQUGVN52eV5dRW6X0hUQkhTToWSFCxw22WQF18s9iun4BMWW3pp0AjuhtptjcSnQGAW+YBw1WDtRv1OT8VFAY5O0rFUJ1rtaMEE1bd0g0NrZ1WK+F68d60xP+sGmYyEGxyx1A2Yc5lOccG5mEZRnxPOsEgGygyWM9KePFN/MO5fu09jJUSTSUuelI7UbM1r0v44ns+Wm1wWpsNfXthkLmvbdVHjXPjvTZnWp6Nr0J5pYZKdZEleLxLjuUzQRHt7obhpQX+kBlAHFrEzDCdeYrlL1HFAFYP5n5WdVDYZn0rgypan3KpCx5YS+bhSYkqYAekUub+CzW46Xek=";

    const KYBER_SHARED_SECRET: [u8; 32] = [
        185, 127, 166, 22, 6, 250, 76, 23, 7, 18, 145, 156, 212, 31, 147, 145, 238, 220, 219, 29,
        89, 115, 86, 138, 173, 153, 147, 40, 206, 131, 51, 127,
    ];

    const X25519_SECRET_KEY: &str = "Hce1WL1kC3XHHSH+5EyDzoyraj9+bWZTX1R4A7ZougM=";
    const X25519_PUBLIC_KEY: &str = "P07nNmiMAgt4hSh8YMwQ58yRBxErKp9VXrh74RHz7Sw=";

    const X25519_RECV_SECRET_KEY: &str = "OCsYVt7xwPf11E8chbtRa+IRYgYsoEpbfRY8+R0hcEc=";
    const X25519_RECV_PUBLIC_KEY: &str = "3Yic3lphqfixI+rSbOiB91SCpEh0vPCrWu6n2YxzMn0=";

    const X25519_SHARED_SECRET: [u8; 32] = [
        71, 141, 13, 166, 215, 13, 144, 138, 183, 233, 237, 240, 88, 255, 7, 135, 238, 98, 67, 21,
        233, 9, 99, 125, 193, 122, 201, 224, 41, 51, 100, 25,
    ];

    #[test]
    fn kyber_keypair_from_seed() {
        let keypair = KEMKeyPair::from_seed(
            &Seed::new(SecretVec::from(TEST_SEED.to_vec())),
            KEMAlgorithm::Kyber768,
        );

        assert_eq!(
            KYBER_SECRET_KEY,
            base64::encode(keypair.secret_key.expose_secret())
        );

        assert_eq!(KYBER_PUBLIC_KEY, base64::encode(keypair.public_key));
    }

    #[test]
    fn x25519_keypair_from_seed() {
        let keypair = DHKeyPair::from_seed(
            &Seed::new(SecretVec::from(TEST_SEED.to_vec())),
            DHAlgorithm::X25519,
        );

        assert_eq!(
            X25519_SECRET_KEY,
            base64::encode(keypair.secret_key.expose_secret())
        );

        assert_eq!(X25519_PUBLIC_KEY, base64::encode(keypair.public_key));
    }

    #[test]
    fn kyber_encapsulate() {
        let kem = Encapsulation::new(
            PublicKey::Kyber768(vec![0x6u8; 1184]),
            KEMAlgorithm::Kyber768,
        );

        assert!(kem.encapsulate().is_ok());
    }

    #[test]
    fn kyber_decapsulate() {
        let binding = SecretVec::from(base64::decode(KYBER_SECRET_KEY).unwrap());
        let kem = Decapsulation::new(&binding, &KEMAlgorithm::Kyber768);

        let decapsulated_secret = kem
            .decapsulate(&base64::decode(KYBER_CIPHER_TEXT).unwrap())
            .unwrap();

        assert_eq!(
            decapsulated_secret.shared_secret.expose_secret().as_slice(),
            KYBER_SHARED_SECRET
        );
    }

    #[test]
    fn diffie_hellman_x25519() {
        let sender_keypair = DHKeyPair::from_seed(
            &Seed::new(SecretVec::from(TEST_SEED.to_vec())),
            DHAlgorithm::X25519,
        );

        let binding = base64::decode(X25519_RECV_PUBLIC_KEY).unwrap();

        let sender_dh = DiffieHellman::new(&sender_keypair, &binding);

        let sender_shared_secret = sender_dh.calculate_shared_key().unwrap();

        let reciever_keypair = DHKeyPair::from_secret_key(
            &SecretVec::from(base64::decode(X25519_RECV_SECRET_KEY).unwrap()),
            DHAlgorithm::X25519,
        )
        .unwrap();

        let binding = base64::decode(X25519_PUBLIC_KEY).unwrap();
        let reciever_dh = DiffieHellman::new(&reciever_keypair, &binding);

        let reciever_shared_secret = reciever_dh.calculate_shared_key().unwrap();

        assert_eq!(
            reciever_shared_secret.expose_secret(),
            sender_shared_secret.expose_secret()
        );
    }
}
