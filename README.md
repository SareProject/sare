# SARE (Safe At Rest Encryption)

**THIS SOFTWARE IS IN BETA, QUICKLY EVOLVING, AND HAS NOT BEEN AUDITED FOR SECURITY.**
**USE AT YOUR OWN RISK. DO NOT USE FOR HIGHLY SENSITIVE DATA UNTIL IT UNDERGOES A FORMAL SECURITY REVIEW.**

SARE(**S**afe **At** **R**est **E**ncryption) is a hybrid post-quantum encryption system designed to protect files against both classical and future quantum attacks. Its modular architecture allows easy integration of new encryption, signing, and KDF algorithms, ensuring the system can evolve alongside emerging cryptographic standards.

The repository contains three Rust components:

- [**sare-core**](https://github.com/SareProject/sare/blob/main/sare-core) – Core cryptographic library.
    
- [**sare-lib**](https://github.com/SareProject/sare/blob/main/sare-lib) – High-level file encryption library.
    
- [**sare-cli**](https://github.com/SareProject/sare/blob/main/sare-cli) – Command-line interface.
    

**NOTE:** SARE is **not a "roll your own crypto" project**—all core cryptographic operations (encryption, signing, key encapsulation, key derivations, etc) rely on well-vetted, standard, and widely audited algorithms and implementations.

## Documentations

Documentation for SARE, including use of CLI, libraries, formatting standards, and implementations exists at:

[https://sareproject.github.io/docs](https://sareproject.github.io/docs)

## Features

- **Post-Quantum Hybrid Security**: Combines classical and post-quantum algorithms to protect against both present and future threats.

- **Modular and Extensible**: Easily add or swap encryption, signing, and KDF algorithms without rewriting core logic.

- **Symmetric and Asymmetric Encryption**: Secure files with either passphrases or public/private key pairs.

- **Master Key Management**: Generate, export, and manage master keys with **validation certificates** to prove ownership and authenticity.

- **Recipient Management**: Add, remove, and list recipients for secure asymmetric file sharing.

- **Digital Signatures**: Sign and verify files to guarantee authenticity and integrity.

- **Revocation Certificates**: Create and manage revocations for compromised or obsolete keys.

- **High-Level API via `sare-lib`**: Simplifies building secure applications on top of SARE.

- **CLI Tool (`sare-cli`)**: Command-line interface for encryption, decryption, key management, and signing.

- **Security-Focused**: Uses audited, standard, proven algorithms at the low-level; security and safety are foundational.

## Installation and usage

SARE can be used as a CLI tool or integrated into your Rust projects via the libraries.

* For **quick examples and installation instructions**, see the individual component READMEs:

* [`sare-lib`](https://github.com/SareProject/sare/tree/main/sare-lib) – library usage examples and high-level API.

* [`sare-cli`](https://github.com/SareProject/sare/tree/main/sare-cli) – CLI usage examples.


For detailed guidance and full documentation, including API reference and advanced usage, please check out [Getting Started with SARE](https://sareproject.github.io/docs/getting-started/installation.html)

> Note: `sare-core` currently does not include usage examples as it is a low-level library intended to be used through `sare-lib`. Developers working directly with `sare-core` should be extremely cautious.

----
## Contributions

All contributions to SARE, either in documents, code, security improvements, audits, or practically anything, are super welcome and really appreciated.

To start contributing, please have a quick look at our contribution guide at [CONTRIBUTING.md](CONTRIBUTING.md)

## Security Bug Reporting

To report security vulnerabilities, please refer to our [Security Policy](https://github.com/SareProject/sare/security/policy) or email them directly to [zolagonano@protonmail.com](mailto:zolagonano@protonmail.com).

You can also encrypt your report using the following PGP key:  
`F22EB734505C76E59AFC95C4B4A4AEFDAFF48132`

Or simply use SARE's security advisory reporting tool provided by Github: [https://github.com/SareProject/sare/security/advisories](https://github.com/SareProject/sare/security/advisories)

For non-security bugs or feature requests, please use the repository's issue tracker or submit a pull request.

---
## Release Notes

SARE is actively developed, and new releases are regularly published. Each release includes updates, bug fixes, and security improvements.

You can view all releases on GitHub: [SARE Releases](https://github.com/SareProject/sare/releases)

All notable changes are documented in the [CHANGELOG.md](CHANGELOG.md) file, which follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) conventions.

---
## Support / Donations

Security and privacy aren’t just nice-to-haves—they’re the foundation for a lot of other rights. Protect them, and you’re protecting the **right to life**, stopping arbitrary detention, and defending the **right to liberty and security**. That, in turn, makes room for **freedom of thought, conscience, and religion**—even the freedom to change your beliefs—and **freedom of assembly and association**, the right to gather and organize. All of it feeds into having a **fair trial** and real access to justice.

SARE is my attempt to protect privacy and security online, with the hope that it helps protect these other civil and political rights too—especially in a world where privacy is basically invisible to governments and corporations.

If you want to help SARE grow, the best way is financially—check out our donation page: [https://sareproject.github.com/docs/support](https://sareproject.github.com/docs/support)

---
## License

All executable code and libraries of SARE are released under a combination of the [MIT License](LICENSE-MIT) and the [Apache License](LICENSE-APACHE).

The books, documents, wikis, and user guides of SARE are released under the Creative Commons Attribution 4.0 International (CC BY 4.0).
