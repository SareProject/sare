# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),  
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- 

### Changed
- 

### Fixed
- 

### Security
- 

---

## [0.2.0] - 2026-11-07 - Cryptographic Fixes and Dependency Updates

### Added
- Regression test suite covering symmetric and asymmetric roundtrips, STREAM chunk boundaries, and every tampering path (wrong passphrase, modified header, modified payload, forged validation certificates).

### Changed
- Updated every dependency to its latest version: `secrecy` 0.10, `rand` 0.10, `aead` 0.6, `chacha20poly1305` 0.11, `sha2` 0.11, `sha3` 0.12 (SHAKE256 now comes from the new `shake` crate), `bson` 3, `pem` 4, `crystals-dilithium` 2, `aes-kw` 0.3, `hkdf` 0.13, `scrypt` 0.12, `ed25519-compact` 2.6 and the `sare-cli` dependencies (`argh`, `chrono`, `colored`, `dirs`, `duration-str`, `indicatif`, `log`, `rpassword`, `serde`, `serde_json`).
- The STREAM-BE32 construction is implemented in `sare-core` because the `aead` crate removed its `stream` module in 0.6; it is byte-for-byte compatible with the files written by previous versions.
- Removed the unused `generic-array` dependency.
- Workspace crates are patched to the local paths so `sare-lib` and `sare-cli` always build against the `sare-core` of this repository.

### Fixed
- Hybrid KEM: the sender decapsulated the recipient's Kyber cipher text with the sender's own secret key, so no recipient could ever decrypt a file. The sender now uses the shared secret returned by `encapsulate()` and only the recipient decapsulates.
- Asymmetric encryption silently encrypted nothing: the checksum pass consumed the whole input and the payload was always empty. The plaintext is now seeked back and encrypted for real.
- Symmetric decryption panicked for any plaintext of 2048 bytes or more because a full STREAM frame is 2048 + 16 bytes. The framing now reads complete frames and only a short frame falls into the last chunk.
- Every AEAD failure (wrong passphrase, tampered data) unwrapped into a panic. All unwraps on the decrypt paths are typed errors now.
- `export_encryption_public` exported the signing public key instead of the encryption public key.

### Security
- The CLI reported a tampered signature as VALID by comparing the header fingerprint with itself. Decryption now verifies the signature against the unsigned header and the checksum of the decrypted plaintext.
- Validation certificates were self-signed, so any attacker key shipped with `Verified: Yes`. They are now issued by a separate issuer master key and verified against the trusted keys of the local wallet.
- Headers are validated before parsing: bounded lengths, checked slice indexes and a 4MiB header cap instead of panics.
- scrypt parameters read from a file are capped (log_n <= 20, r <= 1024, p <= 16) so a crafted file can not amplify the KDF cost without bound.
- The confirmation code comes from `OsRng` with rejection sampling instead of a timestamp seeded LCG.

---

## [0.1.0] - 2025-09-11 - Initial Release
### Added
- Core post-quantum hybrid encryption and signing algorithms.
- `sare-core` library handling encryption/decryption engines, KDFs, hybrid KEM/Sign, seed management, and formatting.
- `sare-lib` library providing user-friendly high-level API.
- CLI tool `sare-cli` built on top of `sare-lib`.
- Security policy, contribution guidelines, and manifesto.
- File encryption/decryption with symmetric and asymmetric support.
- Master key management, recipient management, revocation, and digital signatures.

---

## [0.1.1] - 2025-09-11 - Kyber Fix

### Security
- Replaced `pqc_kyber` with `safe_pqc_kyber` because of known security issues
