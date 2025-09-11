# Contributing to SARE

Thank you for your interest in contributing to **SARE**! We welcome contributions of all kinds: bug reports, feature requests, documentation improvements, and code contributions. To keep the project organized and maintain high quality, please follow these guidelines.

---

## Table of Contents

1. [Reporting Issues](#reporting-issues)
    
2. [Feature Requests](#feature-requests)
    
3. [Code Contributions](#code-contributions)
    
4. [Branching and Pull Requests](#branching-and-pull-requests)
    
5. [Code Style](#code-style)
    
6. [Testing](#testing)
    
7. [Documentation](#documentation)
    
8. [Security](#security)
    

---

## Reporting Issues

- Use the **Issues** tab on GitHub to report bugs or unexpected behavior.
    
- Provide detailed steps to reproduce the issue, including OS, Rust version, and SARE version.
    
- Include logs or error messages where applicable.
    

---

## Feature Requests

- Use Issues to propose new features.
    
- Clearly describe the problem you want to solve and your proposed solution.
    
- Label your issue as `enhancement` if applicable.
    

---

## Code Contributions

- Fork the repository and create your feature branch:
    
    ```bash
    git checkout -b feature/my-feature
    ```
    
- Make your changes on the branch.
    
- Ensure your code builds and passes existing tests.
    

---

## Branching and Pull Requests

- Keep your branch focused on a single feature or fix.
    
- When ready, submit a **Pull Request (PR)** against `main`.
    
- In the PR description, explain the motivation and provide examples if relevant.
    
- Reviewers may request changes — this is normal and part of maintaining quality.
    

---

## Code Style

- SARE follows standard **Rust coding conventions** (use `rustfmt`).
    
- Write **clear, readable code** and avoid overly complex implementations.
    
- Document your functions and modules with Rust doc comments (`///`).
    

---

## Testing

- All new features must include **unit tests** where possible.
    
- Run tests before submitting a PR:
    
    ```bash
    cargo test
    ```
    
- Ensure that existing tests pass with your changes.
    

---

## Documentation

- Keep documentation up to date.
    
- Include examples in doc comments where relevant.
    
- Update README or mdBook documentation if your change affects usage.
	
- Document/User Guide repository is at https://github.com/SareProject/docs 

---

## Security

- Do **not** include sensitive information (keys, passwords, secrets) in commits or PRs.
    
- If you discover a security issue, report it privately by emailing the maintainers before making it public.
    

---

### Thank You!

We appreciate your contributions and support. Your help keeps SARE secure and reliable for everyone!
