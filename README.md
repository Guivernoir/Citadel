## Citadel

Citadel is a **production-grade cryptographic library written in Rust**, designed to be embedded into larger systems that require **CNSA 2.0–aligned post-quantum cryptography**, while maintaining **hybrid compatibility with established classical algorithms**.

Its primary objective is to enable **incremental migration to post-quantum cryptography** without forcing disruptive architectural changes in existing systems.

Citadel prioritizes **correctness, explicit security guarantees, and controlled exposure of cryptographic primitives**, making it suitable for security-sensitive environments where transparency and control are required.

---

## Design Goals

- **Production-grade**: Designed for real systems, not demonstrations.
- **Embeddable**: Single-crate architecture with minimal assumptions about the host system.
- **Post-quantum ready**: Implements CNSA 2.0–approved post-quantum algorithms.
- **Hybrid migration support**: Enables coexistence of post-quantum and classical cryptography.
- **Explicit safety boundaries**: Low-level APIs are exposed with clear warnings and documentation.
- **Platform-agnostic**: Portable Rust with no platform-specific dependencies.

---

## Non-Goals

Citadel explicitly does **not** aim to:

- Provide a full TLS, VPN, or application-layer security protocol.
- Abstract cryptography behind opaque, “magic” APIs.
- Replace well-established protocol stacks.
- Hide cryptographic complexity from engineers who need control.

Citadel is a **cryptographic building block**, not a turnkey security solution.

---

## Implemented Algorithms

Citadel implements the following **CNSA 2.0–aligned algorithms**, using well-defined external implementations wrapped behind a unified, consistent API:

### Post-Quantum Cryptography

- **ML-KEM-1024** — Key encapsulation mechanism (FIPS 203)
- **ML-DSA-87** — Digital signature algorithm (FIPS 204)
- **LMS** — Leighton–Micali Signature scheme
- **XMSS** — eXtended Merkle Signature Scheme

### Classical Cryptography

- **AES-256**
- **SHA-384**
- **SHA-512**

Hybrid constructions are supported to allow **gradual migration** from classical cryptography to post-quantum alternatives.

---

## Hybrid Cryptography Support

Citadel is designed for environments where **immediate, full replacement of classical cryptography is impractical**.

It provides native support for **hybrid cryptographic strategies**, allowing systems to:

- Combine post-quantum and classical key exchanges.
- Combine post-quantum and classical signatures.
- Gradually phase out classical primitives as operational confidence increases.

This approach aligns with real-world migration requirements in long-lived systems.

---

## Architecture Overview

- **Single-crate design** for ease of integration.
- Modular internal structure separating:

  - Key encapsulation
  - Digital signatures
  - Hashing
  - Symmetric cryptography

- Clear separation between:

  - Algorithm implementations
  - Memory handling
  - API exposure

Low-level primitives are exposed intentionally, with explicit documentation regarding correct and incorrect usage.

---

## Safety & Memory Handling

Citadel places strong emphasis on **secure memory practices**:

- Explicit **zeroization** of sensitive material.
- Controlled use of `unsafe` code where required for performance or correctness.
- Unsafe blocks are:

  - Minimized
  - Documented
  - Isolated

No implicit guarantees are made beyond what is explicitly documented.

---

## Threat Model

Citadel is designed to defend against:

- Passive and active network adversaries.
- Cryptographic attacks addressed by the implemented algorithms.
- Memory disclosure risks mitigated through explicit zeroization.

Out of scope:

- Physical attacks.
- Fault injection.
- Microarchitectural side-channel attacks beyond best-effort mitigations.

These boundaries are intentional and documented.

---

## API Philosophy

Citadel exposes both:

- **High-level APIs** for standard use cases.
- **Low-level primitives** for systems requiring fine-grained control.

Low-level APIs are marked accordingly and require cryptographic expertise to use safely.

If you misuse them, Citadel will not save you — by design.

---

## Testing & Verification

Citadel employs:

- Comprehensive unit tests.
- Algorithm-specific test suites.
- Validation against known test vectors where applicable.

Additional verification strategies may be introduced over time, but correctness and clarity take precedence over unchecked complexity.

---

## Usage Examples

Examples demonstrating correct usage are available in the `/examples` directory.

The README intentionally avoids inline usage snippets to keep the focus on design and guarantees rather than quick starts.

---

## License

Licensed under the **Apache License, Version 2.0**.

---

## Project Status

Citadel is under active development.

While designed with production use in mind, users are expected to **review, audit, and evaluate** the library according to their security requirements before deployment.
