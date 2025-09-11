# SARE CLI

![Crates.io Version](https://img.shields.io/crates/v/sare-cli)
![Crates.io License](https://img.shields.io/crates/l/sare-cli)
![Crates.io Size](https://img.shields.io/crates/size/sare-cli)
![Crates.io Total Downloads](https://img.shields.io/crates/d/sare-cli)

**THIS TOOL IS IN BETA. IT IS QUICKLY EVOLVING AND HAS NOT BEEN FULLY AUDITED FOR SECURITY.**

A command-line tool to stay safe in the quantum age. Built on top of [sare-lib](https://github.com/SareProject/sare/tree/main/sare-lib), SARE CLI allows users to encrypt, decrypt, sign, and manage cryptographic keys and recipients using a standardized and quantum-safe hybrid approach.

---

## Table of Contents

- [Overview](#overview)
    
- [Installation](#installation)
    
- [Usage](#usage)
    
- [Commands](#commands)
    
- [Security Notice](#security-notice)
    
- [License](#license)
    

---

## Overview

SARE CLI is built on top of of **sare-lib** with some additions like recipients/keys management database. It currently supports:

- Hybrid encryption and decryption (symmetric and asymmetric)
    
- Detached digital signatures and verification
    
- Master key generation, inspection, and revocation
    
- Recipient management
    
- KDF-based symmetric encryption options

---

## Installation

### Installation from source:

You can build from source:

```bash
git clone https://github.com/SareProject/sare
cd sare
cargo build --release
```

The resulting binary will be located at:

```bash
target/release/sare-cli
```

### Installation using cargo

You can simply install using `cargo install`:

```
cargo install sare-cli
```

---

## Usage

The CLI follows this structure:

```bash
sare-cli <command> [subcommand] [options]
```

### Core Commands

- `masterkey` – Generate, list, remove, or inspect master keys
    
- `recipient` – Add, remove, or list recipients
    
- `signature` – Generate or verify digital signatures
    
- `encrypt` – Symmetric or asymmetric file encryption
    
- `decrypt` – Symmetric or asymmetric file decryption
    
- `revocation` – Generate, list, or broadcast revocation certificates
    

Use `sare-cli <command> -h` to see available subcommands and options.

---

## Examples

### Generate a Master Key

```bash
sare-cli masterkey generate --hybrid-kem-algorithm X25519_KYBER768 --hybrid-sign-algorithm ED25519_DILITHIUM3
```

If you don't provide the HybridKEM and HybridSign algorithms, the defaults will be used.

Also, on key generation, two certificates will be generated for you: one **revocation certificate**, which you can share to prove that your key is not being used either because it’s compromised or you lost access to it for any reason; and the **validation certificate**, attached to your public key. The validation certificate is used to prove that you own all the keys since signing and encryption keys are separate, and it contains your issuer ID (like your name and email address) and an expiry date so users won't accidentally encrypt messages with your expired key.

---

### Encrypt a File Asymmetrically

Before encrypting to someone, you should add them as a recipient:

```bash
sare-cli recipient add recipient.pem
```

Then:

```bash
sare-cli encrypt asymmetric input.txt output.enc --recipient RECIPIENT_ID --masterkey-id MASTER_KEY_ID
```

If you don't provide `MASTER_KEY_ID` and/or `RECIPIENT_ID`, it will show you the list of recipients / master keys.

---

### Encrypt a File Symmetrically

```bash
sare-cli encrypt symmetric input.txt output.enc
```

---

### Decrypt a File

```bash
sare-cli decrypt input.enc output.txt
```

`sare-cli` will detect whether the file is encrypted using your public key (asymmetrically) or using a password (symmetrically) and will either ask for your master key for decryption or a password based on that.

---

### Generate a Signature

```bash
sare-cli signature generate input.txt input.sig --masterkey-id MASTER_KEY_ID
```

Signatures will be **detached**, meaning the signature file does not include the content of the file. For verification, you'll need both the original file and the signature.

---

### Verify a Signature

```bash
sare-cli signature verify input.sig input.txt
```

---

### Add a Recipient

```bash
sare-cli recipient add recipient.pem
```

---

### List Recipients

```bash
sare-cli recipient list
```

---

### Generate a Revocation Certificate

```bash
sare-cli revocation new --masterkey-id MASTER_KEY_ID
```

Note: broadcasting revocations is not implemented yet since it requires the implementation of a keyserver first.

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

SARE CLI is released under a combination of the [MIT License](LICENSE-MIT) and the [Apache License](LICENSE-APACHE).
