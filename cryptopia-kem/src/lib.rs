pub mod error;

use cryptopia_seed::Seed;
use ed25519_compact as ed25519;
use ed25519_compact::x25519;

use crate::error::*;

const X25519_MAGIC_BYTES: [u8; 4] = [25, 85, 2, 0]; // 0x25519 in LittleEndian
const KYBER768_MAGIC_BYTES: [u8; 4] = [104, 7, 0, 0]; // 0x768 in LittleEndian

#[derive(Clone)]
pub enum DHAlgorithm {
    X25519,
}

#[derive(Clone)]
pub struct DHKeyPair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
    pub algorithm: DHAlgorithm,
}

impl DHKeyPair {
    pub fn from_secret_key(
        secret_key: &[u8],
        dh_algorithm: DHAlgorithm,
    ) -> Result<Self, HybridKEMError> {
        match dh_algorithm {
            DHAlgorithm::X25519 => {
                let secret_key = x25519::SecretKey::from_slice(&secret_key)?;
                let public_key = secret_key.recover_public_key()?;

                Ok(DHKeyPair {
                    public_key: public_key.to_vec(),
                    secret_key: secret_key.to_vec(),
                    algorithm: dh_algorithm,
                })
            }
        }
    }

    pub fn from_seed(seed: &Seed, dh_algorithm: DHAlgorithm) -> Result<Self, HybridKEMError> {
        match dh_algorithm {
            DHAlgorithm::X25519 => {
                let child_seed = &seed.derive_32bytes_child_seed(Some(&[&X25519_MAGIC_BYTES]));

                let secret_key = x25519::SecretKey::from_slice(&child_seed.as_slice())?;
                let public_key = secret_key.recover_public_key()?;

                Ok(DHKeyPair {
                    public_key: public_key.to_vec(),
                    secret_key: secret_key.to_vec(),
                    algorithm: dh_algorithm,
                })
            }
        }
    }
}

pub struct DiffieHellman {
    pub sender_keypair: DHKeyPair,
    pub reciever_public_key: Vec<u8>,
}

impl DiffieHellman {
    pub fn new(sender_keypair: DHKeyPair, reciever_public_key: Vec<u8>) -> Self {
        DiffieHellman {
            sender_keypair,
            reciever_public_key,
        }
    }

    pub fn calculate_shared_key(&self) -> Result<Vec<u8>, HybridKEMError> {
        let dh_algorithm = &self.sender_keypair.algorithm;

        match dh_algorithm {
            DHAlgorithm::X25519 => {
                let sender_key = x25519::SecretKey::from_slice(&self.sender_keypair.secret_key)?;
                let reciever_key = x25519::PublicKey::from_slice(&self.reciever_public_key)?;

                Ok(reciever_key.dh(&sender_key)?.as_slice().to_vec())
            }
        }
    }
}

#[derive(Clone)]
pub enum KEMAlgorithm {
    Kyber,
}

#[derive(Clone)]
pub struct KEMKeyPair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
    pub algorithm: KEMAlgorithm,
}

impl KEMKeyPair {
    pub fn from_seed(seed: &Seed, kem_algorithm: KEMAlgorithm) -> Result<Self, HybridKEMError> {
        match kem_algorithm {
            KEMAlgorithm::Kyber => {
                let child_seed = seed.derive_64bytes_child_seed(Some(&[&KYBER768_MAGIC_BYTES]));
                let keypair = pqc_kyber::derive(&child_seed)?;

                Ok(KEMKeyPair {
                    public_key: keypair.public.to_vec(),
                    secret_key: keypair.secret.to_vec(),
                    algorithm: kem_algorithm,
                })
            }
        }
    }
}

pub struct EncapsulatedSecret {
    pub shared_secret: Vec<u8>,
    pub cipher_text: Vec<u8>,
}

pub struct Encapsulation {
    public_key: Vec<u8>,
    algorithm: KEMAlgorithm,
}

impl Encapsulation {
    pub fn new(public_key: &[u8], algorithm: KEMAlgorithm) -> Self {
        Encapsulation {
            public_key: public_key.to_vec(),
            algorithm,
        }
    }

    pub fn encapsulate(&self) -> Result<EncapsulatedSecret, HybridKEMError> {
        let mut random_generator = rand::thread_rng();

        let (cipher_text, shared_secret) = match self.algorithm {
            KEMAlgorithm::Kyber => {
                pqc_kyber::encapsulate(&self.public_key, &mut random_generator).unwrap()
            }
        };

        Ok(EncapsulatedSecret {
            shared_secret: shared_secret.to_vec(),
            cipher_text: cipher_text.to_vec(),
        })
    }
}

pub struct DecapsulatedSecret {
    shared_secret: Vec<u8>,
}

pub struct Decapsulation {
    secret_key: Vec<u8>,
    algorithm: KEMAlgorithm,
}

impl Decapsulation {
    pub fn new(secret_key: &[u8], algorithm: KEMAlgorithm) -> Self {
        Decapsulation {
            secret_key: secret_key.to_vec(),
            algorithm,
        }
    }

    pub fn decapsulate(&self, cipher_text: &[u8]) -> Result<DecapsulatedSecret, HybridKEMError> {
        let shared_secret = match self.algorithm {
            KEMAlgorithm::Kyber => {
                pqc_kyber::decapsulate(cipher_text, &self.secret_key).unwrap()
            }
        };

        Ok(DecapsulatedSecret {
            shared_secret: shared_secret.to_vec(),
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
        dh_sender_public_key: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), HybridKEMError> {
        // TODO: Reduce Copy/Clone
        let diffie_hellman =
            DiffieHellman::new(self.dh_keypair.clone(), dh_sender_public_key.to_vec());
        let kem_decapsulation = Decapsulation::new(
            &self.kem_keypair.secret_key,
            self.kem_keypair.algorithm.clone(),
        );

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

    const KYBER_PUBLIC_KEY: &str ="ZRVtBUpdwmtIKzPB00Js+iNvRkGgW2wmN3dzTRWnt7Q3tgYdM7vLACMb8XsVFfJop2yzXaIXGFa8PTa/y+I6PXRxbzgJocpjAhOjOopltSlsx+acKCyJ/3InxHAgNpxnEzGaLotATwao/mR9GRqx4vszvEO8poSnKAGgMqgCafQzgkQV7GEEetOEVzWgcPF7nPMddhkqggnFZ5UJynykq8GQ2uuawXIULLMwlQTOhZKHPIm7IOYwwqp1z+BalskDliNTSRLEp3h2PcJfC5Mhr4UecBqhmYU6OrRvclGlKCQlqMSheiMZriJrB1ykUaUrWSh7uvFL0Ba6yvTNMUWZS6Uo5EkePHScrvkusmEuZRQ489ALH1Ao8OpiHWYGK5ak/na2KNN3yFufpvCuWBKWhIpF32i5r3KktYmrBGWRP1pJp4Ja6ktOlHV+yuEs/UiE/es5skiIQGk65AZh71Z1LXu1i0hRFVuBFyWE0+aUzwEwlEMT7BQWoSp/gLZgSiEnKFx0CYLIJlltyNYu6FixBVXImWEpKJQtFWAxn9WYfMsJvYfNGDkGqVujgoNvXiWR+6Sf3gJQdIi6mUiLKGORIzF4VSeAy2UaSkZI5gc3SvQl42iGfIBNmaVWp/HNpqSiwcsfEioOAgMLkQpFW/KB+laj7OfOAtd18PU1b3ErrMug5URgPgY/b6UZHYS9NvoOkck431RmzJHIrFSZ3gQnvdg5W9mvNSkCOPU9D6tSo2R0OKpLNKGIBTFp5Txx0Ry+PRgPQVHBoMk++CekOcyAINbIwcgLWkEGdSlhQQMPnfUXlqMKcxzFQ9Sok8cjM9CeQnJjTVJoL5hK0BN/JzQNCOVqFfI1BDBWRSJ+pfsXrvF7qagjAYdD9QRbnABKdjU88zma+/mV4ilFRHkeS0M3dueUXbpvdOouzFMWEdmD5dlqlQqRKMNaWzx+WgCcn1ZFoOGNSdtL9yRe1cNGZba6AioBOjKgsODMKdRqDoOobIEVYHzJ7FI4AYWb+dvNh7kmuoedIRhHxrjCgSsj/0ynzChUCrMTREguavKZYWylB1vHO5B+9iRslaA31NBBukYQ85UPNxETFuqteBC27MmfPPYEujFdqeu36/N9KhS2pNaoAhu0tZCbYuS3oQxwpHOODQSowyGNEIKnQUOke1UhXfRkHysERCtEsdgPsPKAqUWC3gwa6HshwSQKbvVzsAUvZIgOczqPLKOMg+lMKExkulcJmLVdzHoFLjaf/HmmSbM+kQgyHLUd9TtoSzCpZGSBdaUOLmEYNcyAE3SBffJLmHm433aa33DKengtfIiPOVExOPFixpYoi8pyF3Is9eLP9dh+2LIumYEzrBlhJ0qZtxfKM/xj2Bm/AbNC5kGd1QWAO3FR+LtjWExZP4VkSnMp67bMeyI/OuBgaZQwrzgR2tenvxOnAhldsaEp88Z/BsC2fMowD8BAyxeSkSuR6YFgrPcOxgVlbPefyLyXL8AEREhVcIyNSAM4R3THiOcVjPEzq0J+B2yKUcxvYSaYFPeNBONZsVEmeYIqwD9nDitrlMaZqpptfrbxusX4xQNo6Ug=";

    const KYBER_CIPHER_TEXT: &str = "dcZCy2qBW9KURkV2YmYvg3v35MAX2TsNMEA5m8GHws7D+m7IfOw6NWskDojrglG0s1j3pC4HGoOp7urS5SDqvsZlmW0vae//ZHMqIHStG14vRM23lIl1ElZejtkm0AWfGhYs4ZkAzeRfdPjuaYbm3UzbEm8bng0yTyifMigqEc9whQp2WKu0z6bArcFftrQsxkR2wLaK8qN+w7ARuL4infcRHSeexzyt3NvP65KK7/8lRqjMvp4rbjcyucSKr6UPaIwgIQntuRn3y90QOXbuijWduGulCK4z2eS1dFsrYnuc66JZZPz7OJTDdHyFpYMxdulNv0KFFgbC6yef7zXu984iGmdNPdRQRK5tmqdQld4eKKxQ9MZFOVB0R0xJ6FLRcImsiIMSDbjBo+C2aGyZir156XeFcIeXbSz/APxucTtciFE5sNLOYVBAz3ci7t1gnZvWr9Blw8Ew7kb0Mk1l1sh4ZONSrmpG/qQeOfyBGMiUgiszqPuMAQNwB/8I64t3QO72JMzW9jQMUIa/q4isfc3wScPFHW4Hbnmk5HpTsqbjogdxTsDYa7orcKCTkRz80+Fa0bf2n2sQW0mieph0gntlEgw6Mk/wNOZPUwljj7t+B3qy1MS2RYCALvLFCBQ06cMdyE6EJrgPUqjFh0npmFV6sdAigVYhEStWNdKftVw8A4jfHKQhR+fGcyZm3zY7ZjQailZbOGBDmZDhWnyzKajYKovvYkyNDI/6H4qtMKEmBXJ/QIOu2VvaJAeyVGFtv1kmPzfgag/Y0obOZfVyarkfwUqRsK/fi2DWURwrAVwDI+k+4+e/6Bpe4ERf5crxaYVE/THfwLh0cj8ShLR8h59FjrWYutHFqHwzE8WY6JaV01kebROK9tbbvtZn79GNuwfxrCOiB8LEM1usSbj8bdBLFgTrbsujB8XhOnSn5RJmg6BoE4Bb7wPQUujrjuF3G4x74miChX/LUjc34nJDERng2kUT0vqC2+A7uDxDqjoc48LP/muCuKqD5xJZAjXE8FH9hN2WMEdrvcj986WefCGLJCWHLkMvCzUq3WPpTcH6xwQorgR4ZoLuR+wwWRMlIJfzVsbkxQedJONGBvjKRI8jf50dldQUGVN52eV5dRW6X0hUQkhTToWSFCxw22WQF18s9iun4BMWW3pp0AjuhtptjcSnQGAW+YBw1WDtRv1OT8VFAY5O0rFUJ1rtaMEE1bd0g0NrZ1WK+F68d60xP+sGmYyEGxyx1A2Yc5lOccG5mEZRnxPOsEgGygyWM9KePFN/MO5fu09jJUSTSUuelI7UbM1r0v44ns+Wm1wWpsNfXthkLmvbdVHjXPjvTZnWp6Nr0J5pYZKdZEleLxLjuUzQRHt7obhpQX+kBlAHFrEzDCdeYrlL1HFAFYP5n5WdVDYZn0rgypan3KpCx5YS+bhSYkqYAekUub+CzW46Xek=";

    const KYBER_SHARED_SECRET: [u8; 32] = [
        183, 102, 43, 102, 46, 239, 20, 187, 142, 62, 179, 2, 196, 137, 94, 110, 126, 158, 191, 34,
        16, 52, 7, 121, 116, 131, 130, 141, 192, 44, 252, 175,
    ];

    const X25519_SECRET_KEY: &str = "0iJufJMGpxJoS6VHCyMycjhv8zJrc1jTImiEYl5h39I=";
    const X25519_PUBLIC_KEY: &str = "S86ZB5XJxcQRr3AReEJqXrtF5xnqSxnzWcS0woOy1iw=";

    const X25519_RECV_SECRET_KEY: &str = "OCsYVt7xwPf11E8chbtRa+IRYgYsoEpbfRY8+R0hcEc=";
    const X25519_RECV_PUBLIC_KEY: &str = "3Yic3lphqfixI+rSbOiB91SCpEh0vPCrWu6n2YxzMn0=";

    const X25519_SHARED_SECRET: [u8; 32] = [
        71, 141, 13, 166, 215, 13, 144, 138, 183, 233, 237, 240, 88, 255, 7, 135, 238, 98, 67, 21,
        233, 9, 99, 125, 193, 122, 201, 224, 41, 51, 100, 25,
    ];

    #[test]
    fn kyber_keypair_from_seed() {
        let keypair = KEMKeyPair::from_seed(&Seed::new(TEST_SEED), KEMAlgorithm::Kyber).unwrap();

        assert_eq!(KYBER_SECRET_KEY, base64::encode(keypair.secret_key));

        assert_eq!(KYBER_PUBLIC_KEY, base64::encode(keypair.public_key));
    }

    #[test]
    fn x25519_keypair_from_seed() {
        let keypair = DHKeyPair::from_seed(&Seed::new(TEST_SEED), DHAlgorithm::X25519).unwrap();

        assert_eq!(X25519_SECRET_KEY, base64::encode(keypair.secret_key));

        assert_eq!(X25519_PUBLIC_KEY, base64::encode(keypair.public_key));
    }

    #[test]
    fn kyber_encapsulate() {
        let kem = Encapsulation::new(
            &base64::decode(KYBER_PUBLIC_KEY).unwrap(),
            KEMAlgorithm::Kyber,
        );

        assert!(kem.encapsulate().is_ok());
    }

    #[test]
    fn kyber_decapsulate() {
        let kem = Decapsulation::new(
            &base64::decode(KYBER_SECRET_KEY).unwrap(),
            KEMAlgorithm::Kyber,
        );

        let decapsulated_secret = kem
            .decapsulate(&base64::decode(KYBER_CIPHER_TEXT).unwrap())
            .unwrap();

        assert_eq!(decapsulated_secret.shared_secret, KYBER_SHARED_SECRET);
    }

    #[test]
    fn diffie_hellman_x25519() {
        let sender_keypair =
            DHKeyPair::from_seed(&Seed::new(TEST_SEED), DHAlgorithm::X25519).unwrap();

        let sender_dh = DiffieHellman::new(
            sender_keypair,
            base64::decode(X25519_RECV_PUBLIC_KEY).unwrap(),
        );

        let sender_shared_secret = sender_dh.calculate_shared_key().unwrap();

        let reciever_keypair = DHKeyPair::from_secret_key(
            &base64::decode(X25519_RECV_SECRET_KEY).unwrap(),
            DHAlgorithm::X25519,
        )
        .unwrap();

        let reciever_dh =
            DiffieHellman::new(reciever_keypair, base64::decode(X25519_PUBLIC_KEY).unwrap());

        let reciever_shared_secret = reciever_dh.calculate_shared_key().unwrap();

        assert_eq!(reciever_shared_secret, sender_shared_secret);
    }
}
