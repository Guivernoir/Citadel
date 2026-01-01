# Citadel Error Module

## Overview

The error module implements a two-tier error system that separates **cryptographic failures** from **API misuse**. This design prevents information leakage while providing actionable feedback during development.

## Structure

```
src/errors/
├── mod.rs       # Public API and unified Error type
├── crypto.rs    # Cryptographic operation errors
└── misuse.rs    # Developer misuse errors
```

## Design Principles

### 1. Security Over Diagnostics

Cryptographic errors are intentionally opaque. If detailed error information could aid an attacker (e.g., distinguishing padding failures from MAC failures), it's deliberately omitted.

**Example:**

```rust
// ❌ BAD: Leaks information
Err("MAC verification failed at byte 16")

// ✅ GOOD: Opaque
Err(CryptoError::VerificationFailed)
```

### 2. Two Error Classes

#### Cryptographic Errors (`CryptoError`)

- **What**: Valid operations that failed securely
- **Examples**: Verification failed, decryption failed, invalid ciphertext
- **Properties**: Expected, non-fatal, coarse-grained
- **Logging**: Minimal (avoid exposing details)

#### Misuse Errors (`MisuseError`)

- **What**: Developer mistakes
- **Examples**: Invalid buffer size, unsupported algorithm, wrong parameter set
- **Properties**: Deterministic, actionable, should never happen in production
- **Logging**: Safe to log with full details

### 3. Side-Channel Safety

Error behavior must be deterministic and timing-consistent:

- No data-dependent error selection
- No dynamic string formatting in hot paths
- No conditional allocations
- Constant-cost with respect to error variants

### 4. Stability

The public error API is designed for long-term stability:

- Minimal variants (can always add, hard to remove)
- No algorithm-specific details in public types
- Feature flags for std-dependent functionality

## Usage Examples

### Basic Error Handling

```rust
use citadel::errors::{Error, CryptoError, MisuseError};

fn process_ciphertext(ct: &[u8]) -> Result<Vec<u8>, Error> {
    // Check buffer size (misuse error)
    if ct.len() < MIN_CIPHERTEXT_LEN {
        return Err(MisuseError::InvalidCiphertextLength.into());
    }

    // Attempt decryption (crypto error)
    decrypt(ct).map_err(|_| CryptoError::DecryptionFailed.into())
}

match process_ciphertext(&data) {
    Ok(plaintext) => { /* ... */ },
    Err(Error::Crypto(_)) => {
        // Crypto failure - log minimally, don't expose details
        log::warn!("decryption failed");
    },
    Err(Error::Misuse(e)) => {
        // Misuse - log details, this is a bug
        log::error!("API misuse: {}", e);
        panic!("invalid API usage");
    }
}
```

### Pattern Matching

```rust
match result {
    Ok(data) => process(data),

    // Handle specific crypto failures if needed
    Err(Error::Crypto(CryptoError::VerificationFailed)) => {
        // Signature didn't verify - this is expected in adversarial contexts
        return Err(ResponseError::Unauthenticated);
    },

    // Catch-all for other crypto errors
    Err(Error::Crypto(_)) => {
        return Err(ResponseError::InvalidRequest);
    },

    // Misuse errors indicate bugs
    Err(Error::Misuse(e)) => {
        log::error!("BUG: {}", e);
        return Err(ResponseError::InternalError);
    }
}
```

### Type-Specific Results

```rust
use citadel::errors::{CryptoResult, MisuseResult};

// Functions can return specific error types
fn validate_params(key_len: usize) -> MisuseResult<()> {
    if key_len != 32 {
        return Err(MisuseError::InvalidKeyLength);
    }
    Ok(())
}

fn verify_tag(tag: &[u8]) -> CryptoResult<()> {
    if !constant_time_eq(tag, expected) {
        return Err(CryptoError::VerificationFailed);
    }
    Ok(())
}
```

## What This Module Does NOT Do

❌ **No `thiserror` or `anyhow`**: Explicit control over error representation  
❌ **No algorithm names in errors**: Prevents fingerprinting  
❌ **No automatic dependency error conversion**: Maintain control  
❌ **No verbose Display messages**: Keep information minimal  
❌ **No stringly-typed errors**: Type-safe, pattern-matchable

## Testing Considerations

```rust
#[test]
fn errors_are_deterministic() {
    let err = CryptoError::VerificationFailed;
    let msg1 = format!("{}", err);
    let msg2 = format!("{}", err);
    assert_eq!(msg1, msg2);
}

#[test]
fn errors_are_compact() {
    assert!(size_of::<Error>() <= 8);
}
```

## Feature Flags

```toml
[features]
default = ["std"]
std = []  # Enables std::error::Error trait implementation
```

The `std` feature is required for `std::error::Error` trait implementation. The module works in `no_std` environments without it.

## Integration Notes

- Cryptographic operations must complete all verification steps before mapping failures to a crypto error, to avoid early-exit timing leakage.

### For Library Authors

When wrapping Citadel errors in your own types:

```rust
pub enum MyError {
    Citadel(citadel::errors::Error),
    Network(NetworkError),
    // ...
}

// Preserve the crypto/misuse distinction
impl MyError {
    pub fn is_recoverable(&self) -> bool {
        match self {
            MyError::Citadel(Error::Crypto(_)) => true,
            MyError::Citadel(Error::Misuse(_)) => false,
            // ...
        }
    }
}
```

### For Application Authors

In production, consider:

- Treating all crypto errors uniformly in responses
- Logging crypto errors minimally (just occurrence, not details)
- Crash or panic on misuse errors in debug builds
- Convert misuse errors to generic "internal error" in release

## Philosophy

> "If an error helps debugging but hurts security, it loses."

This module prioritizes security over convenience. Diagnostic information that could aid an attacker is intentionally omitted. Rich diagnostics can be added via separate debug tooling, but must not be present in production error paths.

The two-class error system makes this trade-off explicit: **crypto errors hide information**, **misuse errors expose it**. Choose correctly.

## Stability Guarantee

The public `Error`, `CryptoError`, and `MisuseError` types are considered stable. New variants may be added in minor releases, but existing variants will not be removed or changed in breaking ways.

Internal error handling implementation may change without notice, but the public API will remain stable.
