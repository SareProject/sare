use cryptopia_seed::Seed;
use ed25519_compact as ed25519;
use ed25519_compact::x25519;
use rand::RngCore;

#[derive(Debug)]
pub enum KEMError {
    InvalidInput,
    Decapsulation,
    RandomBytesGeneration,
}

#[derive(Debug)]
pub enum DHError {
    InvalidSecretKey,
}

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
    pub fn from_secret_key(secret_key: &[u8], dh_algorithm: DHAlgorithm) -> Result<Self, DHError> {
        match dh_algorithm {
            DHAlgorithm::X25519 => {
                //TODO: Needs error handling
                let secret_key = x25519::SecretKey::from_slice(&secret_key).unwrap();
                let public_key = secret_key.recover_public_key().unwrap();

                Ok(DHKeyPair {
                    public_key: public_key.to_vec(),
                    secret_key: secret_key.to_vec(),
                    algorithm: dh_algorithm,
                })
            }
        }
    }

    pub fn from_seed(seed: &Seed, dh_algorithm: DHAlgorithm) -> Self {
        match dh_algorithm {
            DHAlgorithm::X25519 => {
                let child_seed = &seed.derive_32bytes_child_seed(None);
                let ed25519_seed = ed25519::Seed::from_slice(child_seed).unwrap();

                let ed25519_keypair = ed25519::KeyPair::from_seed(ed25519_seed);

                let keypair = x25519::KeyPair::from_ed25519(&ed25519_keypair).unwrap();

                DHKeyPair {
                    public_key: keypair.pk.to_vec(),
                    secret_key: keypair.sk.to_vec(),
                    algorithm: dh_algorithm,
                }
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

    pub fn calculate_shared_key(&self) -> Vec<u8> {
        let dh_algorithm = &self.sender_keypair.algorithm;

        match dh_algorithm {
            DHAlgorithm::X25519 => {
                // TODO: Needs error handling
                let sender_key =
                    x25519::SecretKey::from_slice(&self.sender_keypair.secret_key).unwrap();
                let reciever_key =
                    x25519::PublicKey::from_slice(&self.reciever_public_key).unwrap();
                reciever_key.dh(&sender_key).unwrap().as_slice().to_vec()
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
    pub fn from_seed(seed: &Seed, kem_algorithm: KEMAlgorithm) -> Result<Self, KEMError> {
        match kem_algorithm {
            KEMAlgorithm::Kyber => {
                let child_seed = seed.derive_64bytes_child_seed(None);
                // TODO: Convert to KEMError or handle the Error
                let keypair = pqc_kyber::derive(&child_seed).unwrap();

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

    pub fn encapsulate(&self) -> Result<EncapsulatedSecret, KEMError> {
        let mut random_generator = rand::thread_rng();

        // NOTE: pass the shared secret through a KDF/XOF later
        let (cipher_text, shared_secret) = match self.algorithm {
            KEMAlgorithm::Kyber => {
                //TODO: Error Handle or Convert to KEMError
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

    pub fn decapsulate(&self, cipher_text: &[u8]) -> Result<DecapsulatedSecret, KEMError> {
        let shared_secret = match self.algorithm {
            KEMAlgorithm::Kyber => {
                //TODO: Error Handle or Convert to KEMError
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
    ) -> (Vec<u8>, Vec<u8>) {
        // TODO: Reduce Copy/Clone
        let diffie_hellman =
            DiffieHellman::new(self.dh_keypair.clone(), dh_sender_public_key.to_vec());
        let kem_decapsulation = Decapsulation::new(
            &self.kem_keypair.secret_key,
            self.kem_keypair.algorithm.clone(),
        );

        // TODO: Needs Error Handling
        let dh_shared_secret = diffie_hellman.calculate_shared_key();
        let kem_shared_secret = kem_decapsulation.decapsulate(kem_cipher_text).unwrap();

        (dh_shared_secret, kem_shared_secret.shared_secret)
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

    const KYBER_PUBLIC_KEY: &str ="mrowiRhcZJYQ0tenlXYbNxIP4WyoD0iu6xBB+CpVK+dRSPUIzcEVhbOiJziDrFx1xzMwH2K1lLeWtLIrZRc+MzK+7WVJfwFkwTEYX+y62Bl1EKiiPVUk5TSdioiLHPm/+SQVSXxjr1gO9gxO7DiCAVB6v8EMNMlqpDIjfZo/4mxlzypQUAbHMprIjWaoncS7PGUgOVVmDKNpSmhw4xpB6PhYAFWQbWSWfCdF++o5oJQWXOtNMiqF9GorZtsO4zqrkJcm9behjVA6fObBrAdxFcx1z3k+rkGksGwIbtUR5pO2wRIXYivMpVp34+wtPYEeW9UcqPApFKtTjkJ+6MAgVZNGu+ke2jOpPUCXXzWbutJ0r6WptcI282yLe8pH8LE5hELEpNsqzVRVT2V1bOjKsYSDb3ucHaSO5ypoIZNGIOrM/gamldlwikGR7gUwKNiB4EuFYAlTbitpMusE8QPIxHsusieMUbMJD6MfA5tWbWB9tIGMkTyzqbA2M7aM/rESmvtCsXME9VW7kdLOYtYLWHqBRItIuSzBD9sryYbCvpCQ9PCJcQWeRKG3iod1o5DJ7weu4ywWFJeITdQyQ0yfgyTBpgYGysYtgny6JKlf9aZKEghQFRuklCdzCOcRKyQ0n8se32Y8+FG7RbOcspt2DYpDscdTLYU0BaVmgVugTOyflvaYBpAXABYW6PCShhI8AEiDJXtJhJJCoBps+YehULYFoWEWhURpD3IsLAWeNhBxKBiSf0kZgnhvBtvOOltIekizBVhJhdpk1QuOwtU6lqQUuEatoxwXLrIXsryulLBJz8cFDmg4Med5Iui7XHZwd6Ml0cM5jwpgWeWCxvaZd4iS0hUbBSxnL1ucINU3GwEa0wHEB9GH/+JrLwPM2VC2KvlWTGSAirK24gpZJpBkIwkSduXEONYMLgGnklrJJ1RQssZjidQikmmWNfcRYvoMIkZQp2q32aQcYDloCMU5kPYKPNbIHmibgac2+zu2qkqr8KiRnOVnbZGA8VzD7jlTvdVn/LIgZRmr2sawjoQ/4YCNNow2CudXm5sMT4a1nvxGBVEzT4JWa7R5V9w5X9ljBSBNjuAtwdSa2pCgXJqpWQkPI7hQS7l/vLpOOTt690Ncd7uZAuYGlJiI35uWBiF+JDwzPlIcZ5WYUFR9a6ZiSRlocDenpDOnn/wGh2FT+5OEemusOiuhfCMtrPJufHaMaOiS+TKRxys+LetASaEalTa81ixH1cc4QAqQE0Js2cst25sl5IijMdiO7JY77Me5ZYYsGHTKypjKKFUV/UsMYcJ6joY22oUTfwuk6yhCq1J3xQLMexlGqkPEevtrHMd7kLwvIqSbymNWfqky+qyqKjwtDXrDcvDDpTNnKakRHlViKNRN4kfOtjYAzqlzpmmjRxkjFVqMS6h8XHYRs5e1Z0nPFWRtsbZfSBJrETR9QqVWC2Y+Lri2YEIUiWWV9MKzWmLLE0h5y6tGDxwjppFMaBpZE6hpChuN7rtBtGm7XTYlFcl6/VsNd+dCUqmwoFaCyY7oMQWQ2QLr6N3U5oWJZDAP1JWi2VjZUj2Yr/B58H4=";

    const KYBER_CIPHER_TEXT: &str = "ZAhuT1oPh0okhWOt/+45f1cmJvHAHZE2zK8+GhlyJrmjnfZf5jDoEUV7h8vbXiXQP1BiBjyn2WuZHva3gHUV0G8EKEedhYDlYtOk6lcyHq1LtD9JZwZYnCz5cfkWiaEKGc6p6ehQxKNvWkw/+wcgDLIH8n6VAD9GIgxs3Gd6/OXifQJ8uczAUTkYbN4XT6YPMAm5MOCsSM62mjwswVhvJfdyCDaJhAOUppuTGWVNoS5yzr/8bDGFEOemMWprw3RaU7DmlvxPqdiSum8jPsB7SUPvGdWAjTnJvx4ZicsHKE9hMgY97KPh6/zQb+BVlzLMimXDZb6+UZbLDeZQanmWiVRDl8VCuJdROGmY/6bPipmSjEuvuvZaU0gz6WLHWLi2QecbA+Mej8IL522tLbkga7mMFiwqqlnUur7mkhhRSLX5DKp2NXz/OjtXwF4JmezoorYKMvsTH+FB/UXHhzlgIj4wPvYcK83x/ti9eC3B+b8MJT3vX8CxbSBuCqCLSUSlUgGJfMADo7fiGaIhGFYUoSxCzl9Yg6oiV7GBioTLKNRFG5gUuP+6oy8VC+OJcIcoDpMnt/MJuUYgvs1XgLq8pDaqyOblvK2w23+8Fkc6PLeIPSv8XVJl1B4LkxTZtQFb7FZmByS8v1jPeHPRGdPaiWDI7DphtS7+aj8THCFkjmo29gOiL29vPY1jhmG4vqPeHUsn30qQzCw91fyPtqN+sJiJ2k9axOrILixyxYRcth5J8X32xJ1clL0oRnjIWP3gXVcgEdVYfcrfetCzbKI/PuiaPQjeS1+c6rvBFvoR69GWo014ZaZ1CvfmYiW6lU1x/DIj4HES0sF0E60r+9i1ZFg63t8AOXbO+RVBCfm0ZjsnSB43fTxnO1Kdx73PlAws7bbAVcS6YVpt0QhuQdBvaAbGKR+Nmdq30NrCDKpKwYbPnsJc7L8Tl9HPVQPMSrLBrwNJOatOUOx9OKpEifqdnH15cvYd8lNJeMxEXGA+M25xtGifA/3vF49xZkx/Tu6IAV2Ega6EX4sOL0R+yD5uNlVPhW1MOOtllEs5hzptH/1neeVKHTCzAMQj1VToayt9zXt5UPApRuqKQ86gHqagl56bWFWg7MozD7ZUrGhfdll7q7xeSyfm0GePDpzHSC+F/7FTKuxNkAo2yiqNsfEud3pR/ORAQLpcrvhX5kGa0EpK23sW2pteW5So6SCC6S6GUTmN1cf7miUuFZMsYsCL9PIv8d6QAGT2XwaLkbgV6h5mTq8IS+wnv0ZS0lMnRbN/+oMxlzbXcRcOf+K4Bt2WUwi1IZELTugqJiLo5ERtNHljhPwYF1IeENwMtdMTDwX/ue4f7CNPM1/L6V5PE+LRC2J/k72I1rMc/k0DvI99Nk5Vn68WR3bnPpJCog4EDLM6kDWjDf6hixgZ/4g+qHprh7CIIK/8xuSM8lgVuVLDlCg=";

    const KYBER_SHARED_SECRET: [u8; 32] = [
        183, 108, 33, 83, 98, 32, 135, 6, 239, 95, 144, 138, 139, 162, 121, 209, 156, 238, 77, 117,
        45, 193, 21, 215, 1, 212, 15, 171, 171, 112, 236, 85,
    ];

    const X25519_SECRET_KEY: &str = "iLV+OgCjIYzJ7lFpSaJI8MqwsZFxdW1mXnwV6SyTo1w=";
    const X25519_PUBLIC_KEY: &str = "LQ3mPmbYuqO4FfxprjvOKs13HLsP2VtnlJHMkdxDzkc=";

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
        let keypair = DHKeyPair::from_seed(&Seed::new(TEST_SEED), DHAlgorithm::X25519);

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
        let sender_keypair = DHKeyPair::from_seed(&Seed::new(TEST_SEED), DHAlgorithm::X25519);

        let sender_dh = DiffieHellman::new(
            sender_keypair,
            base64::decode(X25519_RECV_PUBLIC_KEY).unwrap(),
        );

        let sender_shared_secret = sender_dh.calculate_shared_key();

        let reciever_keypair = DHKeyPair::from_secret_key(
            &base64::decode(X25519_RECV_SECRET_KEY).unwrap(),
            DHAlgorithm::X25519,
        )
        .unwrap();

        let reciever_dh =
            DiffieHellman::new(reciever_keypair, base64::decode(X25519_PUBLIC_KEY).unwrap());

        let reciever_shared_secret = reciever_dh.calculate_shared_key();

        assert_eq!(reciever_shared_secret, sender_shared_secret);
    }
}
