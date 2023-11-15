use rand::RngCore;

#[derive(Debug)]
pub enum KEMError {
    InvalidInput,
    Decapsulation,
    RandomBytesGeneration,
}

pub enum KEMAlgorithm {
    Kyber,
}

pub struct KeyPair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
    pub seed: Option<Vec<u8>>,
}

impl KeyPair {
    pub fn generate(kem_algorithm: KEMAlgorithm) -> Result<Self, KEMError> {
        let mut random_generator = rand::thread_rng();

        let mut seed = vec![0; 64];

        random_generator.fill_bytes(&mut seed);

        let keypair = match kem_algorithm {
            // TODO: Convert to KEMError or handle the Error
            KEMAlgorithm::Kyber => pqc_kyber::derive(&seed).unwrap(),
        };

        Ok(KeyPair {
            public_key: keypair.public.to_vec(),
            secret_key: keypair.secret.to_vec(),
            seed: Some(seed),
        })
    }

    pub fn from_seed(seed: &[u8], kem_algorithm: KEMAlgorithm) -> Result<Self, KEMError> {
        let keypair = match kem_algorithm {
            // TODO: Convert to KEMError or handle the Error
            KEMAlgorithm::Kyber => pqc_kyber::derive(seed).unwrap(),
        };

        Ok(KeyPair {
            public_key: keypair.public.to_vec(),
            secret_key: keypair.secret.to_vec(),
            seed: Some(seed.to_vec()),
        })
    }
}

pub struct EncapsulatedSecret {
    pub shared_secret: Vec<u8>,
    pub cipher_text: Vec<u8>,
}

pub struct Encapsulation {
    public_key: Vec<u8>,
    algorithm: KEMAlgorithm
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

#[cfg(test)]
mod tests {
    use super::*;

    const KYBER_TEST_SEED: [u8; 64] = [
        198, 44, 204, 124, 44, 49, 54, 122, 236, 122, 174, 6, 50, 107, 65, 214, 47, 51, 12, 251,
        107, 231, 10, 176, 23, 212, 180, 156, 17, 59, 207, 193, 239, 137, 69, 61, 25, 4, 0, 233,
        97, 31, 94, 200, 222, 243, 222, 181, 63, 225, 246, 49, 233, 246, 206, 13, 147, 85, 137, 5,
        165, 80, 188, 150,
    ];

    const KYBER_SECRET_KEY: &str = "9tGgljUSWbtzCisnzyi5IKsvgbZSa1MYJHeeNaxxmVu+bNgugLMy8hUtAtIQFUkjdfydQ0svtCdzLupholC762LNr1c85EJAkjK2dqYIyRBOttaCjiXE75AKRufAndQ6PhSjs6tMyLtWMrNjDwmOiflFsZaynmMLNkM9w0ljosgkZcAubtyJUBWQa/cxAQBABMIWX+aqJHOpFyIesuBGAvBeJzROl5sS80oCaNADznUlvTZVF+mroPbLvgoCh7JH3aW5uSwhPySPE9k9U3HLAMYumjaw/nB3C1w9kvkl1CaiTqzLg1oD1BLFCFm66KFriCxvDObMYyhtZGF5yhbHUUpSYywaA1qSk3spZrWcc4AuPoRB7GYD8GRUYanLPfZ8kCMjF1QKgrS+X0ZY8orBDOxNfIktqUiJ9xFVa/scdoAxvoMf7UsJNPPMbNcV46iW0vqkNPS/pPgBNOo6mSJvTWV8YRSAEQEnAKLK8rAxCmQRuZYAv3yR0yB3CQdhb1C+ReZdOVuo/qG49woNKZNW2bxTCtPKEDjF0Lm7m6EzC1hJxnszH8YRBqBrdSuqGfohGYI4HtbM68ydvAdu4UGrMGttswtYkUwGJutmGqaNsBu0b5om6+c75NuARIkx8TM1ejC0cTErziFH2Yc9HUJHxAbFBxvHt3g4oJS7jRW4B/N3CWOQyTI9HtPCC8i1u9a0u2gj1Gurguxaf4oHPlwZGFOCAoSBXPmmi6AN65azaZGsdYeA37BtNiwxNbgKEeDCWWNaHPCH8BcFKVHJtqQwxPwUlcChiqUKsNNYYMhNfgtK8Sy5ekW81WfBoZQbZENoA1oYXkYxiHPGxLe4VQeVAfVpA9Nw6YV631Rg75aa2EQH1eY0c7KwYvB1marMpKzPn2WjnQOyHcZ9pvIgOKXDREk7SrGpBpVIktY0ZTBWaoEzHaautqWgq0RvidqUfeVpIyyTkrGPluIE96fNj0yYBrCpBqs8FcqfMjpRUQcREJWGXLYcMFUKE8aeqpsWKhhE5ePKBfuvTirNvoFSs7A5EGRsoeFasjCrDUtFcAVMwuszuEh5AnmmP1qc69e2dJdBdZqKz0gsoykLzvt+jbSNnnydUYZ3tyQwGnFTXvOAaCYJegtmmYm1IqyoUUtaIYSEpqV9ntVFN5IkqMFXM5RYXAxznGcEgdS10ZhvH1AVGXK+NMYiQyqukWWrVwyY8WAcb1GQcECIlyK7EWF6KbA/8rkheezBszazqspZDaV1taxneWm7eisb4aunviV8G+PEW+Mr6ZJoUjwWeJG2/5i/kdRyKXevjYe/7md818llltwntDppLSOhyFXFvGMMqoNdA+zKEMYIsite57l0gWl7dgSY3OKQ7zeHPmAGF9lNvio2hOUhcGIPEQxKddbBWORyYAUNRLaLLLk6hgpzcsVkvopIzUt6JYNrStUvOVQR+GSCvLVqTiRsKgVmXvgBI8d0JAkEn3lqxXoVIQadCPhor8SX+rad2hm69AUwqAol2weNODtDLdwHyBoSpraL7XhNTEWgR4Nwy/x+SEW7pgouVOp4ttehbxQgS5OhczML+5Azv6xotKl2dAcFyaOkjGwMuzFprLB+SCCP0fNV6eN0UZRfmChwoUUzXNcRDRFsryF2/+ESB3zLeMyCLbLALlXMQ2kG+ea8EtZtTAqaompvkShJcsIa+AVMXTcGB6pp53weTBPC3fRCHAofeMqDxXYTJxzFTdiA0HYe1KZpaut9FIXH7bRJzZWrsJVKwQxJmzcDE/UAIAu/gFtWdxht41kC+xCjlUw00TbPZjabvwZFsWirbQpt9mNDa4sOldGrINSK9iRWPkwEUYx/mhmOQqCgncCXPIh1VHp6qglC0WWEMLi86NBnf1uDLJqA29Nzt4MZWTOxANC0t8hCF2ovlLFqo1cNDDilU6BNhyyBUXWAD0FUoDZ29jyQdTNwUDPPSCgpxkpGJqiIOIcjYcVlYFiWcokaEPs1EBROGGRPVDR/0VUzMZmfCkJIiMYU2SqFglka5qfJ6DQljUR2w5hauCSbRSYXs4RQQnWz36EffriOQcl97bQyWSWN3SliEOQ3PFSR8OMigFQt8TKRyUcPBgAD3bU8T6Ig4+dgsbbLUwg8EnOOCNA7mwGtIMU+/MOHwLjEjGRo0lMSSKinMyoKjKG2nFyAh7tuZGhPDLCgI/pSomSDCrIp5YnIfbrG1zQSTkuteJUDs9kqsKgg1bsoeuUehqYPzWUvjxVgF3JS2GNK7LyOBiUqDWdCmntT9ltPM/W2eMipDUNo9ERqqLClIhi9H8NjT7fMWEOdHrzIxfRT7TJrOYelEGHOo2uQOMoMGiu4MxBXwjgqrmASSSZ6kdIy6Qwz54FipcgU4deQBGdXsvs7VtVyp2s5uvVbRiVf0Wp6YMSErseFHHczk4wWcXC2keZvFIGpMlFE3nlhb4jDitdEhahQmGcPSjYW9Yu6nMceExQBehCW6RuM6EAYtOyxk8YKRnt+P9xrGguMfQJmI1UbdhyRVrMhYbXKa4PLeQUwAZepBiiL8Hx/jhDBExesjSYacgqFcgaRsOwMDAFgGdmEM8oBMXk2rAJcLoufctJ7qhKofAq/XOwjIkw4ystXpqwlKlEQAMdmn0cPaLxH1rOFwJNeRfGrmshBcmOj5dsP5jPOuUhDYWcjTddn5It+u8R3LWg86BIBxzaMsSG10PeG8rmhPhS+SzMJKyATFVCBJkE4MfuLNBol0Eu6fJE5MQiWCXxySOlJC+J9udew29J1eYrOMtKUcadcwQd5GBoAC6ggXyNNwtMJurZcvxWOOne4HaOTEQEAT8eLbPNFoQePuvCLMRDNtJiGXsxS8uUyOjsg8yUPnLWbmYNDiJV2tnOX3jGRDnqPSRCAyKJa93MfEBUqLJwwAHBdJ8uVRSt3fvqUMFtwpCWoZgJbrCdC5sUeVYu0d1UXRXN28WeqTLxwLalYrAEVe/Vm1gp2IWVPmttdhPkTfqtNx1aQjlhOggu5L4fLKqOWoiQCVkK/WBSBo5NbceUr9gvMLCW5decQ2jLHl2k7pWa+DNYWf6IKALrB1LeaQgzKzI/vJhuqjAOr28ZpE2fY23dnWT0SAwgtWjE8ohEax5pLdv6nX1u27dqf0q8cJbnAPCdMrxBVGu+JRT0ZBADpYR9eyN7z3rU/4fYx6fbODZNViQWlULyW";

    const KYBER_PUBLIC_KEY: &str = "TEWgR4Nwy/x+SEW7pgouVOp4ttehbxQgS5OhczML+5Azv6xotKl2dAcFyaOkjGwMuzFprLB+SCCP0fNV6eN0UZRfmChwoUUzXNcRDRFsryF2/+ESB3zLeMyCLbLALlXMQ2kG+ea8EtZtTAqaompvkShJcsIa+AVMXTcGB6pp53weTBPC3fRCHAofeMqDxXYTJxzFTdiA0HYe1KZpaut9FIXH7bRJzZWrsJVKwQxJmzcDE/UAIAu/gFtWdxht41kC+xCjlUw00TbPZjabvwZFsWirbQpt9mNDa4sOldGrINSK9iRWPkwEUYx/mhmOQqCgncCXPIh1VHp6qglC0WWEMLi86NBnf1uDLJqA29Nzt4MZWTOxANC0t8hCF2ovlLFqo1cNDDilU6BNhyyBUXWAD0FUoDZ29jyQdTNwUDPPSCgpxkpGJqiIOIcjYcVlYFiWcokaEPs1EBROGGRPVDR/0VUzMZmfCkJIiMYU2SqFglka5qfJ6DQljUR2w5hauCSbRSYXs4RQQnWz36EffriOQcl97bQyWSWN3SliEOQ3PFSR8OMigFQt8TKRyUcPBgAD3bU8T6Ig4+dgsbbLUwg8EnOOCNA7mwGtIMU+/MOHwLjEjGRo0lMSSKinMyoKjKG2nFyAh7tuZGhPDLCgI/pSomSDCrIp5YnIfbrG1zQSTkuteJUDs9kqsKgg1bsoeuUehqYPzWUvjxVgF3JS2GNK7LyOBiUqDWdCmntT9ltPM/W2eMipDUNo9ERqqLClIhi9H8NjT7fMWEOdHrzIxfRT7TJrOYelEGHOo2uQOMoMGiu4MxBXwjgqrmASSSZ6kdIy6Qwz54FipcgU4deQBGdXsvs7VtVyp2s5uvVbRiVf0Wp6YMSErseFHHczk4wWcXC2keZvFIGpMlFE3nlhb4jDitdEhahQmGcPSjYW9Yu6nMceExQBehCW6RuM6EAYtOyxk8YKRnt+P9xrGguMfQJmI1UbdhyRVrMhYbXKa4PLeQUwAZepBiiL8Hx/jhDBExesjSYacgqFcgaRsOwMDAFgGdmEM8oBMXk2rAJcLoufctJ7qhKofAq/XOwjIkw4ystXpqwlKlEQAMdmn0cPaLxH1rOFwJNeRfGrmshBcmOj5dsP5jPOuUhDYWcjTddn5It+u8R3LWg86BIBxzaMsSG10PeG8rmhPhS+SzMJKyATFVCBJkE4MfuLNBol0Eu6fJE5MQiWCXxySOlJC+J9udew29J1eYrOMtKUcadcwQd5GBoAC6ggXyNNwtMJurZcvxWOOne4HaOTEQEAT8eLbPNFoQePuvCLMRDNtJiGXsxS8uUyOjsg8yUPnLWbmYNDiJV2tnOX3jGRDnqPSRCAyKJa93MfEBUqLJwwAHBdJ8uVRSt3fvqUMFtwpCWoZgJbrCdC5sUeVYu0d1UXRXN28WeqTLxwLalYrAEVe/Vm1gp2IWVPmttdhPkTfqtNx1aQjlhOggu5L4fLKqOWoiQCVkK/WBSBo5NbceUr9gvMLCW5decQ2jLHl2k7pWa+DNYWf6IKALrB1LeaQgzKzI/vJhuqjAOr28ZpE2fY23dnWT0SAwg=";


    const KYBER_CIPHER_TEXT: &str = "ZAhuT1oPh0okhWOt/+45f1cmJvHAHZE2zK8+GhlyJrmjnfZf5jDoEUV7h8vbXiXQP1BiBjyn2WuZHva3gHUV0G8EKEedhYDlYtOk6lcyHq1LtD9JZwZYnCz5cfkWiaEKGc6p6ehQxKNvWkw/+wcgDLIH8n6VAD9GIgxs3Gd6/OXifQJ8uczAUTkYbN4XT6YPMAm5MOCsSM62mjwswVhvJfdyCDaJhAOUppuTGWVNoS5yzr/8bDGFEOemMWprw3RaU7DmlvxPqdiSum8jPsB7SUPvGdWAjTnJvx4ZicsHKE9hMgY97KPh6/zQb+BVlzLMimXDZb6+UZbLDeZQanmWiVRDl8VCuJdROGmY/6bPipmSjEuvuvZaU0gz6WLHWLi2QecbA+Mej8IL522tLbkga7mMFiwqqlnUur7mkhhRSLX5DKp2NXz/OjtXwF4JmezoorYKMvsTH+FB/UXHhzlgIj4wPvYcK83x/ti9eC3B+b8MJT3vX8CxbSBuCqCLSUSlUgGJfMADo7fiGaIhGFYUoSxCzl9Yg6oiV7GBioTLKNRFG5gUuP+6oy8VC+OJcIcoDpMnt/MJuUYgvs1XgLq8pDaqyOblvK2w23+8Fkc6PLeIPSv8XVJl1B4LkxTZtQFb7FZmByS8v1jPeHPRGdPaiWDI7DphtS7+aj8THCFkjmo29gOiL29vPY1jhmG4vqPeHUsn30qQzCw91fyPtqN+sJiJ2k9axOrILixyxYRcth5J8X32xJ1clL0oRnjIWP3gXVcgEdVYfcrfetCzbKI/PuiaPQjeS1+c6rvBFvoR69GWo014ZaZ1CvfmYiW6lU1x/DIj4HES0sF0E60r+9i1ZFg63t8AOXbO+RVBCfm0ZjsnSB43fTxnO1Kdx73PlAws7bbAVcS6YVpt0QhuQdBvaAbGKR+Nmdq30NrCDKpKwYbPnsJc7L8Tl9HPVQPMSrLBrwNJOatOUOx9OKpEifqdnH15cvYd8lNJeMxEXGA+M25xtGifA/3vF49xZkx/Tu6IAV2Ega6EX4sOL0R+yD5uNlVPhW1MOOtllEs5hzptH/1neeVKHTCzAMQj1VToayt9zXt5UPApRuqKQ86gHqagl56bWFWg7MozD7ZUrGhfdll7q7xeSyfm0GePDpzHSC+F/7FTKuxNkAo2yiqNsfEud3pR/ORAQLpcrvhX5kGa0EpK23sW2pteW5So6SCC6S6GUTmN1cf7miUuFZMsYsCL9PIv8d6QAGT2XwaLkbgV6h5mTq8IS+wnv0ZS0lMnRbN/+oMxlzbXcRcOf+K4Bt2WUwi1IZELTugqJiLo5ERtNHljhPwYF1IeENwMtdMTDwX/ue4f7CNPM1/L6V5PE+LRC2J/k72I1rMc/k0DvI99Nk5Vn68WR3bnPpJCog4EDLM6kDWjDf6hixgZ/4g+qHprh7CIIK/8xuSM8lgVuVLDlCg=";


    #[test]
    fn keypair_generate() {
        let keypair = KeyPair::generate(KEMAlgorithm::Kyber);

        assert!(keypair.is_ok())
    }

    #[test]
    fn keypair_from_seed() {
        let keypair = KeyPair::from_seed(&KYBER_TEST_SEED, KEMAlgorithm::Kyber).unwrap();

        let byte_string: String = keypair
            .secret_key
            .iter()
            .map(|&byte| format!("\\{:03o}", byte))
            .collect();

        // Create a byte string
        let result = format!("b'{}'", byte_string);

        // Print the resulting byte string
        println!("{}", result);

        assert_eq!(KYBER_SECRET_KEY, base64::encode(keypair.secret_key));

        assert_eq!(KYBER_PUBLIC_KEY, base64::encode(keypair.public_key));
    }

    #[test]
    fn encapsulate() {
        let kem = Encapsulation::new(&base64::decode(KYBER_PUBLIC_KEY).unwrap(), KEMAlgorithm::Kyber);

        assert!(kem.encapsulate().is_ok());

    }
}
