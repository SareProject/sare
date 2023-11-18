use ed25519_compact as ed25519;
use ed25519_compact::x25519;
use rand::RngCore;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

pub fn shake256(input_data: &[u8], output_length: usize) -> Vec<u8> {
    let mut xof = Shake256::default();
    xof.update(input_data);

    let mut xof_reader = xof.finalize_xof();
    let mut xof_buffer = vec![0u8; output_length];

    xof_reader.read(&mut xof_buffer);

    xof_buffer
}

#[derive(Debug)]
pub enum KEMError {
    InvalidInput,
    Decapsulation,
    RandomBytesGeneration,
}

#[derive(Debug)]
pub enum ECError {
    InvalidSecretKey,
}

pub enum ECAlgorithm {
    Ed25519,
}

pub struct ECKeyPair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
    pub seed: Option<Vec<u8>>,
    pub algorithm: ECAlgorithm,
}

impl ECKeyPair {
    pub fn from_secret_key(secret_key: &[u8], ec_algorithm: ECAlgorithm) -> Result<Self, ECError> {
        match ec_algorithm {
            ECAlgorithm::Ed25519 => {
                //TODO: Needs error handling
                let keypair = ed25519::KeyPair::from_slice(secret_key).unwrap();

                Ok(ECKeyPair {
                    public_key: keypair.pk.to_vec(),
                    secret_key: keypair.sk.to_vec(),
                    seed: None,
                    algorithm: ec_algorithm,
                })
            }
        }
    }

    pub fn from_seed(seed: &[u8], ec_algorithm: ECAlgorithm) -> Self {
        match ec_algorithm {
            ECAlgorithm::Ed25519 => {
                let xof_seed = shake256(seed, ed25519::Seed::BYTES);
                let ed25519_seed = ed25519::Seed::from_slice(&xof_seed).unwrap();

                let keypair = ed25519::KeyPair::from_seed(ed25519_seed);

                ECKeyPair {
                    public_key: keypair.pk.to_vec(),
                    secret_key: keypair.sk.to_vec(),
                    seed: Some(seed.to_vec()),
                    algorithm: ec_algorithm,
                }
            }
        }
    }
}

pub struct DiffieHellman {
    pub sender_keypair: ECKeyPair,
    pub reciever_public_key: Vec<u8>,
}

impl DiffieHellman {
    pub fn new(sender_keypair: ECKeyPair, reciever_public_key: Vec<u8>) -> Self {
        DiffieHellman {
            sender_keypair,
            reciever_public_key,
        }
    }

    pub fn calculate_shared_key(&self) -> Vec<u8> {
        let ec_algorithm = &self.sender_keypair.algorithm;

        match ec_algorithm {
            ECAlgorithm::Ed25519 => {
                // TODO: Needs error handling
                let ed25519_secret_key =
                    ed25519::SecretKey::from_slice(&self.sender_keypair.secret_key).unwrap();
                let sender_key = x25519::SecretKey::from_ed25519(&ed25519_secret_key).unwrap();

                let reciever_ed25519_public_key =
                    ed25519::PublicKey::from_slice(&self.reciever_public_key).unwrap();
                let reciever_key =
                    x25519::PublicKey::from_ed25519(&reciever_ed25519_public_key).unwrap();
                reciever_key.dh(&sender_key).unwrap().as_slice().to_vec()
            }
        }
    }
}

pub enum KEMAlgorithm {
    Kyber,
}

pub struct KEMKeyPair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
    pub seed: Option<Vec<u8>>,
    pub algorithm: KEMAlgorithm,
}

impl KEMKeyPair {
    pub fn from_seed(seed: &[u8], kem_algorithm: KEMAlgorithm) -> Result<Self, KEMError> {
        match kem_algorithm {
            KEMAlgorithm::Kyber => {
                let xof_seed = shake256(seed, 64);

                // TODO: Convert to KEMError or handle the Error
                let keypair = pqc_kyber::derive(&xof_seed).unwrap();

                Ok(KEMKeyPair {
                    public_key: keypair.public.to_vec(),
                    secret_key: keypair.secret.to_vec(),
                    seed: Some(seed.to_vec()),
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

// TODO: Implement Decapsulation

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

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SEED: [u8; 64] = [
        198, 44, 204, 124, 44, 49, 54, 122, 236, 122, 174, 6, 50, 107, 65, 214, 47, 51, 12, 251,
        107, 231, 10, 176, 23, 212, 180, 156, 17, 59, 207, 193, 239, 137, 69, 61, 25, 4, 0, 233,
        97, 31, 94, 200, 222, 243, 222, 181, 63, 225, 246, 49, 233, 246, 206, 13, 147, 85, 137, 5,
        165, 80, 188, 150,
    ];

    const KYBER_SECRET_KEY: &str ="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";

    const KYBER_PUBLIC_KEY: &str ="xKa9VZivdwuIMRdxntMvrsKf0GJR6lRwXUyLfCqZ4ftBt9lmbLWA1QmrAtwGO0JDosouh+BpudIEwzPKtUSAnLdOAEmi6uSgK1EPc7qcUHU0wtRynMqEMhxbhFqEtIYyaPMTfpsP/ZYlR5t6xGG1bBhZy1iNeqOx5HEIBgggcPKluVZZsOioCcTB2JAz20eBjWljXyI8o1nP4WxUXEh9gVVknDxjGBPPhgd2z0sO1ZSuPCMUQfxt5oQj8hlm6gFU5MdfG2O71ii3dBPK6NSAU2tBP3SI9PAgDRrMF8DBdVMKE+mfo+m0dcC6GIhUvLh4sOIBelSsSUBOs8otgUPIUdqcjbqCZSxB1huNf0J/AbCNKmi2gzDJXOt2PlQauBgvH2tweOwXZMu3n0mJ1xY8NugCzcgB2EQ11zJRBxB/eKQVbYAGFesdUYQEAhvMKJIN9ZISe8iSG4dg2Lg6y+yexLKwwaskPysWxnU9YMolZZdiVxvDbANr8phivvGeVVKDWXUhjSMF89p9YfhjMKC3qShFIxqNPaAWF9qRslWB7tc1ddEv41lLeRZ+nVKFBwUBPSiyWjWNFqcxUEFfSDRpb9QBrIrJbCFgNrZZCuJ3OIF2mBCvFAq81UBWoOOx5tuKrpqXhbK5LIxf6MOTiSivzWKej7S2K8HKqDcxrNyeR1LAarU4AUR9F9mq84mYeYM0mFzF9OgkrPa/l1A0bGNfKNcd/yeVxGC449WHJxiUqFaI1BXNefJ+gbhrpvvKG0wuNpW8orw+cFA9ghhO2tx+oHiJ8oohjmS1zeUih9gSjrDHoyOwc4mg2xUHGiu8BYbDbDWDuuhH91scmsVji4y/hWhsX+VevLwK+2kTRaZeULwnHnET7dFFJta+4qN/L9ITpnwsoIu2vMjDyZxUkBmKR7Zt/GEfK/xk4sViLCBVHHVdyIsqQqpr+wYS+VkIGPqZH3AqgZB+eJEE2jSWMEN8HaGA9zhrhsGOETmK/xQyx2hXTgyT7elxiUy/Q+POLDAehOiKIJWGiGVXmPB7BQsbadtv12OpmDVlTmWnbAO9o6nOapi7MYY0kdxkrZMaemE6BcNqc8RThJC5kMUoSEt0o4u78PSSQBg+A5J8/ENjwxEVHmgYWUyBGhCKvtC3Svu7ePaVJDyIFXBpUIIAIOi+Cop3FKB9hDgKL1pAW3CQEoJVjqdyMOxuQxSEkumynXplWjQjzrIGzkIQU1DES/XGOzCYSxMtNSOD3ql0BOVMJDqvdMo9k5QGitQP7LNN2EIt+3e7m8u5uWqc3iNq06hV8JppWox5HZhGUyGTzwcaI5LHg5UEnjZ59MkP5TfEl/mklMRuOuldfxwZtvGomWiDfwB0haN3iFSQvVtpxek6zOd2KcqoziOZYzZNgNsX52utGFVTj3Zxu1F8M7JdkKuxgeAD5TWQZIWoRswQVBMSFQe3WwYiaQB3GmuIwQm73oNN/Dp9V1l3+dK6mZYgiFZBYGfCEMGfUKXDuUFQcceKejdBsHDNcAm5eeSfL/q5n9sQn85HtidID+hgYrzhoo4jZR/rvNIE1hMA7HgTbIt/YHI=";

    const KYBER_CIPHER_TEXT: &str = "ZAhuT1oPh0okhWOt/+45f1cmJvHAHZE2zK8+GhlyJrmjnfZf5jDoEUV7h8vbXiXQP1BiBjyn2WuZHva3gHUV0G8EKEedhYDlYtOk6lcyHq1LtD9JZwZYnCz5cfkWiaEKGc6p6ehQxKNvWkw/+wcgDLIH8n6VAD9GIgxs3Gd6/OXifQJ8uczAUTkYbN4XT6YPMAm5MOCsSM62mjwswVhvJfdyCDaJhAOUppuTGWVNoS5yzr/8bDGFEOemMWprw3RaU7DmlvxPqdiSum8jPsB7SUPvGdWAjTnJvx4ZicsHKE9hMgY97KPh6/zQb+BVlzLMimXDZb6+UZbLDeZQanmWiVRDl8VCuJdROGmY/6bPipmSjEuvuvZaU0gz6WLHWLi2QecbA+Mej8IL522tLbkga7mMFiwqqlnUur7mkhhRSLX5DKp2NXz/OjtXwF4JmezoorYKMvsTH+FB/UXHhzlgIj4wPvYcK83x/ti9eC3B+b8MJT3vX8CxbSBuCqCLSUSlUgGJfMADo7fiGaIhGFYUoSxCzl9Yg6oiV7GBioTLKNRFG5gUuP+6oy8VC+OJcIcoDpMnt/MJuUYgvs1XgLq8pDaqyOblvK2w23+8Fkc6PLeIPSv8XVJl1B4LkxTZtQFb7FZmByS8v1jPeHPRGdPaiWDI7DphtS7+aj8THCFkjmo29gOiL29vPY1jhmG4vqPeHUsn30qQzCw91fyPtqN+sJiJ2k9axOrILixyxYRcth5J8X32xJ1clL0oRnjIWP3gXVcgEdVYfcrfetCzbKI/PuiaPQjeS1+c6rvBFvoR69GWo014ZaZ1CvfmYiW6lU1x/DIj4HES0sF0E60r+9i1ZFg63t8AOXbO+RVBCfm0ZjsnSB43fTxnO1Kdx73PlAws7bbAVcS6YVpt0QhuQdBvaAbGKR+Nmdq30NrCDKpKwYbPnsJc7L8Tl9HPVQPMSrLBrwNJOatOUOx9OKpEifqdnH15cvYd8lNJeMxEXGA+M25xtGifA/3vF49xZkx/Tu6IAV2Ega6EX4sOL0R+yD5uNlVPhW1MOOtllEs5hzptH/1neeVKHTCzAMQj1VToayt9zXt5UPApRuqKQ86gHqagl56bWFWg7MozD7ZUrGhfdll7q7xeSyfm0GePDpzHSC+F/7FTKuxNkAo2yiqNsfEud3pR/ORAQLpcrvhX5kGa0EpK23sW2pteW5So6SCC6S6GUTmN1cf7miUuFZMsYsCL9PIv8d6QAGT2XwaLkbgV6h5mTq8IS+wnv0ZS0lMnRbN/+oMxlzbXcRcOf+K4Bt2WUwi1IZELTugqJiLo5ERtNHljhPwYF1IeENwMtdMTDwX/ue4f7CNPM1/L6V5PE+LRC2J/k72I1rMc/k0DvI99Nk5Vn68WR3bnPpJCog4EDLM6kDWjDf6hixgZ/4g+qHprh7CIIK/8xuSM8lgVuVLDlCg=";

    const KYBER_SHARED_SECRET: [u8; 32] = [
        33, 131, 45, 165, 89, 124, 75, 12, 207, 80, 131, 73, 209, 140, 107, 57, 219, 207, 249, 68,
        7, 112, 30, 168, 239, 125, 154, 176, 168, 214, 115, 9,
    ];

    const ED25519_SECRET_KEY: &str =
        "EFO3S65/0uFvEVIw50nLGSmofqIy3PajIuS7ecdm3z5kFcVvrK6Mfsl/2UNSbVsemFSx6CW+3mtDazkVDXzyWQ==";
    const ED25519_PUBLIC_KEY: &str = "ZBXFb6yujH7Jf9lDUm1bHphUseglvt5rQ2s5FQ188lk=";

    const ED25519_RECV_SECRET_KEY: &str =
        "k3GP/VzyJHFLai/KvsTRZIKtil3JJXU14GO+DmnDKru/YVd6U0CbMOKbtTMxktKbQ58WvyyazjJLaNudQ23cJA==";
    const ED25519_RECV_PUBLIC_KEY: &str = "v2FXelNAmzDim7UzMZLSm0OfFr8sms4yS2jbnUNt3CQ=";

    const X25519_SHARED_SECRET: [u8; 32] = [
        138, 84, 169, 209, 181, 91, 22, 19, 179, 104, 197, 174, 49, 126, 27, 34, 94, 52, 31, 70,
        217, 101, 97, 144, 128, 5, 191, 4, 183, 71, 30, 55,
    ];
    #[test]
    fn kyber_keypair_from_seed() {
        let keypair = KEMKeyPair::from_seed(&TEST_SEED, KEMAlgorithm::Kyber).unwrap();

        assert_eq!(KYBER_SECRET_KEY, base64::encode(keypair.secret_key));

        assert_eq!(KYBER_PUBLIC_KEY, base64::encode(keypair.public_key));
    }

    #[test]
    fn ed25519_keypair_from_seed() {
        let keypair = ECKeyPair::from_seed(&TEST_SEED, ECAlgorithm::Ed25519);

        assert_eq!(ED25519_SECRET_KEY, base64::encode(keypair.secret_key));

        assert_eq!(ED25519_PUBLIC_KEY, base64::encode(keypair.public_key));
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
    fn ed25519_x25519() {
        let sender_keypair = ECKeyPair::from_seed(&TEST_SEED, ECAlgorithm::Ed25519);

        let sender_dh = DiffieHellman::new(
            sender_keypair,
            base64::decode(ED25519_RECV_PUBLIC_KEY).unwrap(),
        );

        let sender_shared_secret = sender_dh.calculate_shared_key();

        let reciever_keypair = ECKeyPair::from_secret_key(
            &base64::decode(ED25519_RECV_SECRET_KEY).unwrap(),
            ECAlgorithm::Ed25519,
        )
        .unwrap();

        let reciever_dh = DiffieHellman::new(
            reciever_keypair,
            base64::decode(ED25519_PUBLIC_KEY).unwrap(),
        );

        let reciever_shared_secret = reciever_dh.calculate_shared_key();

        assert_eq!(reciever_shared_secret, sender_shared_secret);
    }
}
