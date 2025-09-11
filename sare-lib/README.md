# SARE Lib

**SARE LIB IS IN BETA. IT IS QUICKLY EVOLVING AND NOT YET AUDITED FOR SECURITY. USE WITH CAUTION.**

SARE Lib is the high-level library for building applications using the SARE cryptographic standard. It provides safe, modular, and user-friendly interfaces for encryption, decryption, signing, key management, and certificate handling, while relying on **sare-core** under the hood for low-level cryptography.

---

## Core Principles

- **Hybrid Security**: SARE Lib is secure against both classical and quantum attacks.
    
- **Modular Design**: Easily integrate new algorithms for encryption, signing, or key derivation.
    
- **Human Rights Focused**: Privacy and security are foundational rights. SARE empowers users to protect these rights online. Even when quantum-computers emerge.
    

> This is **not a roll-your-own-crypto project**. Only audited, standard, and proven algorithms are used for all encryption, signing, and key encapsulation operations.

---

## Installation

### Using SARE Lib in a Rust Project

Add it to your dependencies in `Cargo.toml`:

```toml
[dependencies]
sare-lib = "0.1"
```

### Using Cargo

Install via Cargo:

```bash
cargo add sare-lib
```

---

## Example Usage

### Encrypting and Decrypting Files

#### Symmetric Encryption

```rust
use sare_lib::{encryption::Encryptor, keys::{EncryptionAlgorithm, RECOMENDED_PKDF_PARAMS}};
use secrecy::SecretVec;
use std::fs::File;

let input_file = File::open("message.txt")?;
let mut output_file = File::create("message.enc")?;
let passphrase = SecretVec::new(b"supersecret".to_vec());

// Generate key derivation function (KDF) using recommended parameters
let pkdf = Encryptor::get_pkdf(&passphrase, RECOMENDED_PKDF_PARAMS, 1);

// Encrypt the file symmetrically using XChaCha20-Poly1305 AEAD
Encryptor::encrypt_with_passphrase(&mut input_file, &mut output_file, pkdf, EncryptionAlgorithm::XCHACHA20POLY1305)?;
```

#### Symmetric Decryption

```rust
use sare_lib::encryption::Decryptor;
use secrecy::SecretVec;
use std::fs::File;

let mut input_file = File::open("message.enc")?;
let mut output_file = File::create("message_decrypted.txt")?;
let passphrase = SecretVec::new(b"supersecret".to_vec());

Decryptor::decrypt_with_passphrase(passphrase, &mut input_file, &mut output_file)?;
```

---

#### Asymmetric Encryption

```rust
use sare_lib::{encryption::Encryptor, keys::{MasterKey, SharedPublicKey, EncryptionAlgorithm}};
use std::fs::File;

let input_file = File::open("document.txt")?;
let mut output_file = File::create("document.enc")?;

// Load master key and recipient public key
let master_key = MasterKey::load("MASTER_KEY.pem")?;
let recipient_key = SharedPublicKey::from_pem(std::fs::read_to_string("recipient.pem")?)?;

let encryptor = Encryptor::new(master_key);
encryptor.encrypt_with_recipient(&mut input_file, &mut output_file, &recipient_key, EncryptionAlgorithm::XCHACHA20POLY1305)?;
```

#### Asymmetric Decryption

```rust
use sare_lib::encryption::Decryptor;
use std::fs::File;

// Load your master key
let master_key = MasterKey::load("MASTER_KEY.pem")?;
let decryptor = Decryptor::new(master_key);

let mut input_file = File::open("document.enc")?;
let mut output_file = File::create("document_decrypted.txt")?;

// Decrypt the file
let signature = decryptor.decrypt_with_recipient(&mut input_file, &mut output_file)?;

if let Some(sig) = signature {
    println!("Signature attached: {:?}", sig.fullchain_fingerprint);
}
```

---

### Signing and Verifying

#### Detached Signature

```rust
use sare_lib::signing::Signing;
use std::fs;

let master_key = MasterKey::load("MASTER_KEY.pem")?;
let signer = Signing::new(master_key);

let message = fs::read("report.txt")?;
let signature = signer.sign_detached(&message);
fs::write("report.sig", signature.encode_with_magic_byte())?;
```

#### Verifying a Detached Signature

```rust
use sare_lib::signing::Signing;
use sare_lib::format::signature::SignatureHeaderFormat;
use std::fs;

let signed_file = fs::read("report.sig")?;
let original_file = fs::read("report.txt")?;

let signature_header = SignatureHeaderFormat::decode_with_magic_byte(&signed_file)?;
let is_valid = Signing::verify_detached(&signature_header, &original_file)?;

println!("Signature valid: {}", is_valid);
```

---

### Master Key Management

#### Generate a Master Key

```rust
use sare_lib::keys::{MasterKey, HybridKEMAlgorithm, HybridSignAlgorithm};

let master_key = MasterKey::generate(
    HybridKEMAlgorithm::default(),
    HybridSignAlgorithm::default()
);

// Export the master key (optionally encrypted with a passphrase)
master_key.export(Some("supersecret".as_bytes().to_vec().into()), &mut std::fs::File::create("MASTER_KEY.pem")?)?;

// Export public key
master_key.export_public(&mut std::fs::File::create("PUB_KEY.pem")?)?;
```

#### Inspect a Master Key

```rust
let master_key = MasterKey::load("MASTER_KEY.pem")?;
println!("Master Key Fingerprint: {:?}", master_key.get_fullchain_public_fingerprint());
println!("Mnemonic Seed: {}", master_key.to_mnemonic().expose_secret());
```

#### Revoke a Master Key

```rust
use sare_lib::{certificate::Certificate, format::certificate::Issuer, format::certificate::RevocationReason};

let master_key = MasterKey::load("MASTER_KEY.pem")?;
let issuer = Issuer::new("Your Name", "your@email.com");

let revocation_cert = Certificate::new_revocation(master_key, 1682611200, issuer, RevocationReason::NoReasonSpecified);
revocation_cert.export(std::fs::File::create("REVOC_KEY.asc")?)?;
```

---

### Recipient Management

```rust
use sare_lib::keys::SharedPublicKey;

// Add a recipient
let recipient_key = SharedPublicKey::from_pem(std::fs::read_to_string("recipient.pem")?)?;
recipient_key.export(std::fs::File::create("RECIPIENT.pem")?)?;

// Load and list recipients
let recipient_key = SharedPublicKey::from_pem(std::fs::read_to_string("RECIPIENT.pem")?)?;
println!("Recipient fingerprint: {:?}", recipient_key.fullchain_public_key.calculate_fingerprint());
```


> For more detailed documentation on the underlying processes and formatting happening behind the scenes, please read our documentation book at [https://sareproject.github.io/docs](https://sareproject.github.io/docs)

---
## Core Components

- **Keys**: Generate master keys, export/import keys, derive subkeys for encryption/signing
    
- **Encryption & Decryption**: Symmetric (password-based) and asymmetric (recipient-based) encryption engines
    
- **Signing**: Hybrid post-quantum + classical signatures with attached or detached message support
    
- **Certificates**: Validation and revocation certificates
    
- **Modular Cryptography**: Easily extendable to new algorithms
    

SARE Lib is designed to make application development straightforward while letting **sare-core** handle the complexity of cryptography in the background.

---

## Security Notice

SARE is built to use **audited and standard cryptographic algorithms** at the low-level encryption, signing, and encapsulation layers.

However, SARE itself still needs to be audited to be considered secure. Please use it at your own risk and do not use it for critical use cases.

If you've found security vulnerabilities, please follow our security policy for reporting. Do not report them in the GitHub issues or announce them publicly until we have released a fix for the issue: [https://github.com/SareProject/sare/security/policy](https://github.com/SareProject/sare/security/policy)

---

## Support

If you want to help SARE grow, the best way is financially. Please check out our donation page: [https://sareproject.github.com/docs/support](https://sareproject.github.com/docs/support)

But a share on social media, a star on our GitHub repo, or even a simple supporting message is enough motivation for us to keep going.

---
## License

SARE Lib is released under a combination of the [MIT License](/LICENSE-MIT) and the [Apache License](/LICENSE-APACHE).
