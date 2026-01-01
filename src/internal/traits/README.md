# Internal Traits Module

## Overview

The `internal/traits` module provides foundational trait abstractions for cryptographic operations in Citadel. These traits establish type-safe interfaces with compile-time guarantees while maintaining the flexibility required for hybrid post-quantum constructions.

**⚠️ INTERNAL API NOTICE**

This module is strictly internal to Citadel. The traits defined here are implementation details and are not exposed in the public API. Breaking changes may occur without notice.

---

## Architecture

```
internal/traits/
├── mod.rs          # Module organization and exports
├── kem.rs          # Key encapsulation mechanisms
├── signature.rs    # Digital signature schemes
├── symmetric.rs    # Authenticated encryption (AEAD)
├── hash.rs         # Cryptographic hash functions
├── memory.rs       # Secure memory management
└── validation.rs   # Parameter validation utilities
```

---

## Design Philosophy

### Type-Safe Cryptography

All cryptographic parameters are enforced through Rust's type system:

```rust
// Compile-time guarantees via const generics
trait KeyEncapsulation<
    const PUBLIC_KEY_SIZE: usize,
    const SECRET_KEY_SIZE: usize,
    const CIPHERTEXT_SIZE: usize,
    const SHARED_SECRET_SIZE: usize,
>
```

This approach prevents:

- Runtime size mismatches
- Buffer overflow vulnerabilities
- Implicit type coercions
- Silent truncation or padding

### Security by Design

Every trait is designed with side-channel resistance as a primary concern:

- **Constant-time operations** where feasible
- **Complete validation** before returning errors
- **Generic error types** that prevent information leakage
- **Explicit zeroization** of sensitive material

### Unified Error Handling

All operations return `Result<T>` from the error module:

```rust
use crate::errors::Result;

fn encapsulate(&self, public_key: &[u8; PUBLIC_KEY_SIZE])
    -> Result<([u8; CIPHERTEXT_SIZE], [u8; SHARED_SECRET_SIZE])>;
```

The error system distinguishes:

- **Cryptographic failures** (verification failed, decryption failed)
- **API misuse** (invalid buffer size, wrong key length)

See `src/errors/README.md` for complete details.

---

## Trait Descriptions

### KeyEncapsulation

Post-quantum key encapsulation mechanisms and hybrid constructions.

**Operations:**

- `generate_keypair()` — Generate new cryptographic keypair
- `encapsulate()` — Encapsulate shared secret for public key
- `decapsulate()` — Recover shared secret from ciphertext

**Algorithm:** ML-KEM-1024

**Example:**

```rust
impl KeyEncapsulation<1568, 3168, 1568, 32> for MlKem1024 {
    fn encapsulate(&self, pk: &[u8; 1568])
        -> Result<([u8; 1568], [u8; 32])>
    {
        // Implementation ensures:
        // - Fresh randomness per invocation
        // - Constant-time operations
        // - Complete validation before errors
    }
}
```

---

### SignatureScheme

Digital signature algorithms with deterministic or randomized signing.

**Operations:**

- `generate_keypair()` — Generate signing keypair
- `sign()` — Create signature over message
- `verify()` — Verify signature authenticity

**Algorithms:** ML-DSA-87, LMS, XMSS

**Example:**

```rust
impl SignatureScheme<2592, 4032, 4627> for MlDsa87 {
    fn verify(&self, pk: &[u8; 2592], msg: &[u8], sig: &[u8; 4627])
        -> Result<()>
    {
        // Implementation must:
        // - Complete all checks before returning
        // - Return same error for all failures
        // - Use constant-time comparisons
    }
}
```

---

### AeadCipher

Authenticated encryption with associated data.

**Operations:**

- `encrypt()` — Encrypt and authenticate plaintext
- `decrypt()` — Decrypt and verify ciphertext

**Algorithms:** AES-256-GCM

**Critical:** Callers must ensure nonce uniqueness. Each (key, nonce) pair may be used only once.

**Example:**

```rust
impl AeadCipher<32, 12, 16> for Aes256Gcm {
    fn decrypt(&self, key: &[u8; 32], nonce: &[u8; 12],
               ct: &[u8], ad: &[u8], out: &mut [u8])
        -> Result<()>
    {
        // Implementation must:
        // - Verify authentication before decrypting
        // - Never output plaintext on failure
        // - Use constant-time tag comparison
    }
}
```

---

### HashFunction

Cryptographic hash functions for integrity and key derivation.

**Operations:**

- `hash()` — One-shot hashing operation
- `new_context()` — Create incremental hasher

**Algorithms:** SHA-384, SHA-512

**Example:**

```rust
impl HashFunction<48> for Sha384 {
    fn hash(&self, input: &[u8]) -> Result<[u8; 48]> {
        // Implementation guarantees:
        // - Deterministic output
        // - No key material involved
        // - Complete processing
    }
}
```

---

### SecureMemory

Explicit zeroization of sensitive cryptographic material.

**Philosophy:** Security operations must be visible in code, not hidden behind automatic mechanisms.

**Operations:**

- `zeroize()` — Overwrite memory with zeros using volatile writes

**Usage:**

```rust
let mut secret_key = [0u8; 32];
// ... use key ...
secret_key.zeroize(); // Explicit, visible cleanup
```

---

## Hybrid Constructions

Hybrid post-quantum cryptography is implemented through composition, not inheritance.

### Hybrid KEM Pattern

```rust
struct KemHybrid<PQ, Classical>
where
    PQ: KeyEncapsulation<PQ_PK, PQ_SK, PQ_CT, 32>,
    Classical: KeyEncapsulation<C_PK, C_SK, C_CT, 32>,
{
    pq: PQ,
    classical: Classical,
}

impl<PQ, C> KeyEncapsulation<...> for KemHybrid<PQ, C> {
    fn encapsulate(&self, pk: &[u8; ...]) -> Result<...> {
        // Split public key
        let (pq_pk, c_pk) = split_key(pk);

        // Encapsulate with both
        let (ct1, ss1) = self.pq.encapsulate(pq_pk)?;
        let (ct2, ss2) = self.classical.encapsulate(c_pk)?;

        // Combine using KDF
        let combined = kdf(&[&ss1, &ss2]);

        Ok((concat(ct1, ct2), combined))
    }
}
```

### Hybrid Signature Pattern

```rust
impl<PQ, C> SignatureScheme<...> for SignatureHybrid<PQ, C> {
    fn verify(&self, pk: &[u8; ...], msg: &[u8], sig: &[u8; ...])
        -> Result<()>
    {
        let (pq_pk, c_pk) = split_key(pk);
        let (pq_sig, c_sig) = split_sig(sig);

        // Both must verify (AND logic)
        self.pq.verify(pq_pk, msg, pq_sig)?;
        self.classical.verify(c_pk, msg, c_sig)?;

        Ok(())
    }
}
```

**Security:** Hybrid security is the minimum of both components. If either component is broken, the hybrid is broken.

---

## Parameter Validation

The `validation` module provides reusable validation functions that return descriptive errors:

```rust
use crate::internal::traits::validation::*;

pub fn encrypt(key: &[u8], nonce: &[u8], plaintext: &[u8])
    -> Result<Vec<u8>>
{
    validate_key_size::<32>(key)?;
    validate_nonce_size::<12>(nonce)?;

    // Validation passed, proceed with operation
    // ...
}
```

**Available Validators:**

- `validate_key_size::<N>()`
- `validate_nonce_size::<N>()`
- `validate_public_key_size::<N>()`
- `validate_secret_key_size::<N>()`
- `validate_signature_size::<N>()`
- `validate_ciphertext_min_size()`
- `validate_output_size()`
- `validate_not_empty()`

---

## Implementation Guidelines

### Security Requirements

When implementing these traits:

1. **Use `validation.rs` functions** for all parameter checks
2. **Return generic errors** for cryptographic failures
3. **Complete all validation** before returning errors (no early exit)
4. **Use constant-time operations** in critical paths
5. **Zeroize sensitive data** explicitly via `SecureMemory`
6. **Document const generic values** and their security properties

### Testing Requirements

Every implementation must include:

- **Test vectors** from standards (where available)
- **Negative tests** for invalid inputs
- **Size verification** that const generics are correct
- **Error consistency** that all failures map to correct error types

Example test structure:

```rust
#[test]
fn verify_rejects_invalid_signature() {
    let result = scheme.verify(&pk, &msg, &bad_sig);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err().crypto(),
        Some(CryptoError::VerificationFailed)
    ));
}
```

---

## Integration with Citadel

```
┌─────────────────────────────────┐
│   Public API (concrete types)   │
├─────────────────────────────────┤
│  Internal traits (this module)  │
├─────────────────────────────────┤
│   Algorithm implementations     │
├─────────────────────────────────┤
│  External crates (ml-kem, etc)  │
└─────────────────────────────────┘
```

Public APIs use concrete types that implement these traits internally. The traits are never exposed in public interfaces.

---

## What This Module Does NOT Provide

- ❌ Public trait-based APIs
- ❌ Automatic trait derivation
- ❌ Dynamic dispatch in hot paths
- ❌ Lifetime parameters
- ❌ Async operations
- ❌ Blanket implementations

---

## Stability

**Internal traits have no stability guarantees.** They may change at any time as Citadel evolves.

Only the public API (not defined in this module) has stability commitments.

---

## Additional Resources

- **Error Handling:** See `src/errors/README.md`
- **Security Properties:** See `SECURITY.md` in this directory
- **Project Overview:** See root `README.md`

---

## Summary

The traits module provides the foundation for Citadel's cryptographic implementations. Through careful use of Rust's type system and const generics, it enforces security properties at compile time while maintaining the flexibility needed for hybrid post-quantum constructions.

**Key principle:** Make incorrect usage impossible, make misuse visible, make correct usage natural.
