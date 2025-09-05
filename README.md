# SARE (Safe At Rest Encryption)

SARE is a hybrid post-quantum encryption system designed to protect files against both classical and future quantum attacks. It combines classical algorithms (e.g., X25519 or Ed25519) with post-quantum schemes (e.g., Kyber768) to provide strong security even if one scheme is compromised.

The repository contains three Rust components:

- [**sare-core**](sare-core) – Core cryptographic library.
- [**sare-lib**](sare-lib) – High-level file encryption library.
- [**sare-cli**](sare-cli) – Command-line interface.

SARE uses a custom file format: a header starting with the ASCII magic `SARECRYPT`, followed by length fields, version, BSON metadata, and optional BSON signatures. Metadata contains all parameters needed to decrypt, including encryption algorithm, KDF, salt, nonce, and optional KEM/signature information.

## Quick Example Using `sare-cli`

You can use the `--help` flag with any command to see detailed options and switches:

```bash
sare-cli <command> --help
```

### 1. Key Management

#### Generate Master Key

```bash
sare-cli masterkey generate
```

This command generates:

* **Validation Certificate** – Confirms that all your public keys are valid for a specified duration.
* **Revocation Certificate** – Acts as a kill switch. Publishing this certificate tells others not to use your public key anymore.

#### Add a Recipient

```bash
sare-cli recipient add <path-to-recipient-public-key.pem>
```

Adds a new recipient’s public key so that you can encrypt files for them.

---

### 2. File Encryption & Decryption

#### Encrypt a File

```bash
sare-cli encrypt asymmetric <input-file> <output-file>
```

Encrypts the input file for one or more recipients using asymmetric encryption.

#### Decrypt a File

```bash
sare-cli decrypt <input-file> <output-file>
```

Decrypts a file that was previously encrypted with `sare-cli`.

---

### 3. File Signing & Verification

#### Generate a Signature

```bash
sare-cli signature generate <input-file> <output-file>
```

Generates a digital signature for a file. The signature can be attached to or stored alongside the file.

#### Verify a Signature

```bash
sare-cli signature verify <input-file> <output-file>
```

Verifies that a file’s signature is valid and matches the expected signer.

