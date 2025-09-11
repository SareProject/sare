# SARE Core

![Crates.io Version](https://img.shields.io/crates/v/sare-core)
![Crates.io License](https://img.shields.io/crates/l/sare-core)
![Crates.io Size](https://img.shields.io/crates/size/sare-core)
![Crates.io Total Downloads](https://img.shields.io/crates/d/sare-core)


**SARE CORE IS A LOW-LEVEL CRYPTOGRAPHIC ENGINE. USE WITH CAUTION.**  
This library forms the backbone of the SARE ecosystem. It provides the essential cryptographic primitives, engines, and formats upon which the high-level library, **sare-lib**, is built.

SARE Core is **not intended for direct use in applications** unless you are building specialized extensions or experimenting with alternative implementations. Most developers will interact exclusively with **sare-lib**, which exposes the functionality in a safe, modular, and user-friendly manner.

---

## Purpose

SARE Core exists to:

- Provide low-level cryptographic engines for **encryption, decryption, and signing**
    
- Implement **file and key format standards** that are tightly integrated into all SARE components
    
- Support **hybrid post-quantum algorithms** for both KEM and signature systems
    
- Handle **seed generation and subkey derivation** for HybridKEM and HybridSign
    
- Expose **KDF engines** for password-based symmetric encryption and other derivations
    

The separation between **core** and **lib** allows SARE to evolve. Underlying engines or algorithms can be swapped, upgraded, or replaced without breaking high-level usage in **sare-lib**, ensuring longevity and adaptability of the ecosystem.

---

## Who Should Use SARE Core

SARE Core is primarily for:

- Library developers creating **new versions or custom forks of SARE**
    
- Advanced users who need **direct access to cryptographic engines**
    
- Researchers or implementers experimenting with **alternative or future-proof algorithms**
    

> **Warning:** SARE Core is a low-level library. Misuse can compromise security. Only use it if you understand cryptography deeply and the potential risks of modifying or bypassing high-level abstractions.

---

## Relationship with SARE Lib

- **sare-lib**: High-level library for building applications and tools using the SARE standard. It relies heavily on SARE Core but abstracts away the complexity. Most developers only interact with this.
    
- **sare-core**: Provides the engines and formats underneath. It's fully modular, enabling algorithm swaps and upgrades without requiring changes in **sare-lib**.
    

File formatting, key management, hybrid algorithms, and KDF engines exist in SARE Core but are **publicly exported in sare-lib** for developers, so building applications using SARE is straightforward.

Essentially, if you’re building apps, you mostly deal with **sare-lib**. If you’re innovating or extending the cryptography itself, you dig into **sare-core**.

---

## Modularity & Adaptability

SARE Core is designed with **modularity** in mind:

- Swap out encryption or signing implementations if a library is abandoned or replaced
    
- Integrate new KDFs, hybrid KEMs, or signature schemes with minimal changes to high-level code
    
- Experiment safely without breaking the SARE standard or applications built on top of it
    

---

## Security

- SARE Core uses **audited and standardized algorithms** at the lowest level
    
- It is intended to be a **cryptographic engine**, not a finished application interface
    
- Direct use requires **extreme caution**, as errors can compromise security

---

## Support

If you want to help SARE grow, the best way is financially. Please check out our donation page: [https://sareproject.github.com/docs/support](https://sareproject.github.com/docs/support)

But a share on social media, a star on our GitHub repo, or even a simple supporting message is enough motivation for us to keep going.

---
## License

SARE CLI is released under a combination of the [MIT License](LICENSE-MIT) and the [Apache License](LICENSE-APACHE).
