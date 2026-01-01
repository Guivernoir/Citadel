# Security Properties of the Error Module

## Threat Model

The error module is designed under the assumption that:

1. **Errors are observable**: Attackers can see error types and messages
2. **Timing is observable**: Attackers can measure response times
3. **Memory patterns are observable**: Side-channel attacks may observe allocations
4. **Error channels leak information**: Different errors reveal different information

## Security Properties

### 1. Information Minimization

**Cryptographic errors are opaque by design.**

```rust
// ❌ LEAKS: Reveals which part of verification failed
Err("HMAC mismatch at offset 16")

// ✅ SECURE: No actionable information
Err(CryptoError::VerificationFailed)
```

**Principle**: If an attacker can distinguish two failure modes, they learn something. The error system provides only the minimum information needed for correct program flow.

### 2. Constant-cost with respect to error variants

Error creation must not leak information through timing.

```rust
// Error types are Copy, no allocations
#[derive(Debug, Clone, Copy)]
pub enum CryptoError {
    VerificationFailed,
    // ...
}

// Display is deterministic, no dynamic formatting
impl Display for CryptoError {
    fn fmt(&self, f: &mut Formatter) -> Result {
        f.write_str(match self {
            CryptoError::VerificationFailed => "verification failed",
            // Static strings only
        })
    }
}
```

**Properties**:

- Error creation cost is constant
- No conditional allocations
- No data-dependent branching in error paths
- Display implementation uses only static strings

### 3. No Side-Channel Amplification

Error handling must not create new side-channels.

**Protected Against**:

| Attack Vector                | Mitigation                              |
| ---------------------------- | --------------------------------------- |
| Timing attacks               | Constant-cost error creation            |
| Memory allocation patterns   | Copy types, no heap usage               |
| Error message fingerprinting | Generic messages for crypto errors      |
| Error frequency analysis     | Same error for multiple internal causes |
| Cache timing                 | No complex error formatting             |

### 4. Semantic Security

Two cryptographic failures that could reveal the same information to an attacker should produce the **same error**.

**Example**: Padding Oracle Prevention

```rust
// ❌ VULNERABLE: Distinguishable errors enable oracle attacks
fn decrypt(ct: &[u8]) -> Result<Vec<u8>> {
    let data = aead_decrypt(ct)?;

    if !valid_padding(&data) {
        return Err("invalid padding");  // LEAKS
    }
    if !verify_mac(&data) {
        return Err("MAC mismatch");     // LEAKS
    }

    Ok(data)
}

// ✅ SECURE: Same error for all decryption failures
fn decrypt(ct: &[u8]) -> Result<Vec<u8>> {
    aead_decrypt(ct)
        .map_err(|_| CryptoError::DecryptionFailed)
    // Padding and MAC failures are indistinguishable
}
```

### 5. Error Hierarchy Separation

The two-class error system has security implications:

**CryptoError** (opaque):

- Used for operations that could fail in adversarial contexts
- Provides minimal information
- Safe to return to untrusted callers
- Multiple internal causes map to same variant

**MisuseError** (detailed):

- Used for developer mistakes
- Provides diagnostic information
- Should never occur with validated inputs
- May expose implementation details
- MisuseError may cross module boundaries
- Must not cross trust boundaries

### 6. No Secret Leakage

Error types never contain secret data.

```rust
// ❌ DANGEROUS: Contains secret material
struct KeyMismatchError {
    expected_key_hash: [u8; 32],  // LEAKS
    actual_key_hash: [u8; 32],    // LEAKS
}

// ✅ SECURE: No data attached to errors
#[derive(Copy, Clone)]
pub enum CryptoError {
    VerificationFailed,  // No payload
}
```

## Attack Scenarios & Defenses

### Padding Oracle Attacks

**Attack**: Attacker sends malformed ciphertexts and uses error differences to decrypt data.

**Defense**: All decryption failures map to `CryptoError::DecryptionFailed`, regardless of whether padding, MAC, or ciphertext structure was invalid.

### Timing Side-Channels

**Attack**: Attacker measures response time to distinguish error types.

**Defense**:

- Error creation has constant cost
- No conditional allocations or complex formatting
- Same error for multiple internal failures

### Error Message Fingerprinting

**Attack**: Attacker uses error messages to identify algorithm or version.

**Defense**: Generic error messages with no algorithm-specific details.

```rust
// ❌ Reveals algorithm
"ML-KEM-768 decapsulation failed"

// ✅ Generic
"key encapsulation failed"
```

### Side-Channel via Allocation

**Attack**: Attacker observes memory allocation patterns through timing or cache attacks.

**Defense**: Error types are `Copy`, requiring no heap allocation.

### Error Frequency Analysis

**Attack**: Attacker counts error occurrences to infer system state.

**Defense**: Multiple internal failures map to the same error, preventing fine-grained analysis.

## Security Testing Checklist

When adding new error types or modifying existing ones:

- [ ] Error is `Copy` (no allocations)
- [ ] Display uses only static strings
- [ ] No secret data in error payload
- [ ] Timing-consistent creation
- [ ] No data-dependent branching in error path
- [ ] Appropriately classified (Crypto vs Misuse)
- [ ] Generic message for crypto errors
- [ ] No algorithm-specific details in public errors

## Integration Security

### In Applications

**Secure handling**:

```rust
match operation() {
    Ok(result) => process(result),
    Err(Error::Crypto(_)) => {
        // Log minimally, same response for all crypto errors
        log::warn!("operation failed");
        HttpResponse::Unauthorized()
    }
    Err(Error::Misuse(_)) => {
        // This is a bug - log details but don't expose to client
        log::error!("BUG: API misuse");
        HttpResponse::InternalServerError()
    }
}
```

**Insecure handling**:

```rust
// ❌ Exposes crypto error details to attacker
match operation() {
    Err(e) => HttpResponse::BadRequest().body(format!("{:?}", e))
}
```

### In Libraries

When wrapping Citadel errors:

```rust
// ✅ Preserves security properties
pub enum WrapperError {
    Citadel(citadel::Error),
    // ...
}

impl Display for WrapperError {
    fn fmt(&self, f: &mut Formatter) -> Result {
        match self {
            // Don't add details to crypto errors
            WrapperError::Citadel(e) => write!(f, "{}", e),
        }
    }
}
```

## Known Limitations

1. **Error existence is visible**: The presence or absence of an error is observable. This is unavoidable in any error-returning API.

2. **Coarse granularity**: The opaque crypto errors sacrifice diagnostic detail for security. Rich diagnostics must be added via separate instrumentation.

3. **User responsibility**: The module prevents accidental information leakage through errors, but cannot prevent intentional misuse (e.g., logging crypto error details).

## Comparison to Common Mistakes

| Common Pattern              | Citadel Approach                   |
| --------------------------- | ---------------------------------- |
| Detailed error messages     | Generic messages for crypto errors |
| Error chaining with context | Flat error hierarchy               |
| String-based errors         | Type-safe enums                    |
| Dynamic error formatting    | Static strings only                |
| Per-algorithm error types   | Unified crypto error type          |
| Auto-derived Display        | Hand-written minimal Display       |

## Audit Trail

Error module design reviewed for:

- [x] Information leakage
- [x] Timing side-channels
- [x] Memory side-channels
- [x] Oracle attack enablers
- [x] Secret data exposure
- [x] Constant-time properties

Last security review: 01/01/2026

## Reporting Security Issues

If you discover a security issue in the error module:

1. **DO NOT** open a public issue
2. Email strukturaenterprise@gmail.com with details
3. Include:
   - Description of the information leak
   - Attack scenario
   - Proof of concept (if applicable)

We take error-based information leakage seriously.

---

**Key Takeaway**: In cryptographic systems, errors are security-sensitive. The error module treats them as a potential attack surface and designs accordingly.
