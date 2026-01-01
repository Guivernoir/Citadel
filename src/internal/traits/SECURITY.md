# Security Properties of Internal Traits

## Threat Model

The internal traits module operates under the following threat assumptions:

| Assumption                           | Implication                                                  |
| ------------------------------------ | ------------------------------------------------------------ |
| **Implementations may contain bugs** | Trait design must not enable unsafe patterns                 |
| **Side-channels are observable**     | Timing, cache, memory access patterns visible to adversaries |
| **Error channels leak information**  | Different errors may reveal cryptographic state              |
| **Memory patterns are observable**   | Heap allocations, deallocations, and reuse are visible       |
| **Adversaries observe all outputs**  | Error types, timing, memory usage under scrutiny             |

---

## Core Security Principles

### 1. Defense in Depth

Traits provide **structural security**, not **algorithmic security**:

- ✅ Type safety prevents parameter confusion
- ✅ Const generics prevent size mismatches
- ✅ Error design prevents information leakage
- ✅ Explicit contracts guide implementers

**Security emerges from correct implementations, not from traits alone.**

### 2. Explicit Over Implicit

All security-critical operations must be visible in code:

```rust
// ✅ EXPLICIT: Caller sees cleanup
let mut key = generate_key();
use_key(&key);
key.zeroize(); // Visible security operation

// ❌ IMPLICIT: Hidden in Drop (less visible)
// Automatic cleanup can be forgotten or optimized away
```

### 3. Fail Secure, Not Fast

When in doubt, prioritize security over performance:

- Complete all validation before returning errors
- Use constant-time operations in critical paths
- Return generic errors that prevent oracle attacks
- Never optimize away security checks

### 4. Zero Trust in Callers

Traits assume callers may:

- Pass invalid parameters
- Reuse nonces
- Forget to zeroize secrets
- Mishandle errors

Validation and documentation mitigate these risks, but cannot eliminate them.

---

## Trait-Specific Security Properties

### KeyEncapsulation

**Critical Properties:**

1. **Constant-Time Decapsulation**

   All decapsulation failures must be indistinguishable:

   ```rust
   // ❌ VULNERABLE: Early exit creates timing oracle
   fn decapsulate(&self, sk: &[u8; SK], ct: &[u8; CT])
       -> Result<[u8; SS]>
   {
       if !valid_format(ct) {
           return Err(CryptoError::DecapsulationFailed.into()); // LEAK
       }
       if !valid_mac(ct, sk) {
           return Err(CryptoError::DecapsulationFailed.into()); // LEAK
       }
       // ...
   }

   // ✅ SECURE: Same timing for all failures
   fn decapsulate(&self, sk: &[u8; SK], ct: &[u8; CT])
       -> Result<[u8; SS]>
   {
       let format_ok = valid_format(ct);
       let mac_ok = valid_mac(ct, sk);

       if format_ok & mac_ok { // Bitwise AND (not short-circuit)
           // Proceed
       } else {
           Err(CryptoError::DecapsulationFailed.into())
       }
   }
   ```

2. **Randomness Hygiene**

   - Each `encapsulate()` call uses independent randomness
   - No global RNG state that could be exhausted
   - No randomness reuse across invocations

3. **Key Material Protection**

   - Secret keys implement `SecureMemory`
   - Callers explicitly zeroize after use
   - No automatic cleanup (prevents false sense of security)

**Attack Scenarios:**

| Attack            | Mitigation                     |
| ----------------- | ------------------------------ |
| Timing oracle     | Constant-time validation       |
| Chosen ciphertext | Generic error for all failures |
| Randomness reuse  | Fresh RNG per encapsulation    |
| Memory disclosure | Explicit zeroization           |

---

### SignatureScheme

**Critical Properties:**

1. **Verification Timing Consistency**

   All verification failures must complete in constant time:

   ```rust
   // ❌ VULNERABLE: Format check leaks information
   fn verify(&self, pk: &[u8; PK], msg: &[u8], sig: &[u8; SIG])
       -> Result<()>
   {
       if !valid_signature_format(sig) {
           return Err(CryptoError::VerificationFailed.into()); // LEAK
       }
       verify_cryptographic_signature(pk, msg, sig)
   }

   // ✅ SECURE: All checks complete before returning
   fn verify(&self, pk: &[u8; PK], msg: &[u8], sig: &[u8; SIG])
       -> Result<()>
   {
       let format_ok = valid_signature_format(sig);
       let crypto_ok = verify_cryptographic_signature(pk, msg, sig);

       if format_ok & crypto_ok {
           Ok(())
       } else {
           Err(CryptoError::VerificationFailed.into())
       }
   }
   ```

2. **Nonce Independence (Randomized Schemes)**

   For schemes like ML-DSA:

   - Each signature uses independent randomness
   - No nonce reuse (catastrophic for some schemes)
   - No predictable nonce generation

3. **Public Key Validation**

   - Malformed public keys rejected before verification
   - Validation errors distinct from verification failures
   - Implementation-specific validation logic

**Attack Scenarios:**

| Attack                 | Mitigation                       |
| ---------------------- | -------------------------------- |
| Timing oracle          | Complete all checks before error |
| Nonce reuse            | Fresh randomness per signature   |
| Fault injection        | Complete validation path         |
| Signature malleability | Implementation responsibility    |

---

### AeadCipher

**Critical Properties:**

1. **Authenticate-Then-Decrypt**

   Verification MUST occur before decryption:

   ```rust
   // ❌ VULNERABLE: Decrypts before verifying (padding oracle)
   fn decrypt(&self, key: &[u8; K], nonce: &[u8; N],
              ct: &[u8], ad: &[u8], out: &mut [u8])
       -> Result<()>
   {
       let plaintext = decrypt_raw(key, nonce, ct)?;
       if !verify_tag(ct, ad) {
           return Err(CryptoError::DecryptionFailed.into()); // TOO LATE
       }
       out.copy_from_slice(&plaintext);
       Ok(())
   }

   // ✅ SECURE: Verify before decrypt
   fn decrypt(&self, key: &[u8; K], nonce: &[u8; N],
              ct: &[u8], ad: &[u8], out: &mut [u8])
       -> Result<()>
   {
       if !verify_tag(ct, ad) {
           return Err(CryptoError::DecryptionFailed.into());
       }
       let plaintext = decrypt_raw(key, nonce, ct)?;
       out.copy_from_slice(&plaintext);
       Ok(())
   }
   ```

2. **Nonce Uniqueness (Caller Responsibility)**

   - Trait documents nonce requirements clearly
   - Each (key, nonce) pair used at most once
   - Nonce reuse catastrophically breaks confidentiality
   - Implementation cannot enforce this

3. **Tag Verification Timing**

   - Constant-time tag comparison
   - Same timing for format vs. tag failures
   - No partial plaintext on verification failure

**Attack Scenarios:**

| Attack            | Mitigation                            |
| ----------------- | ------------------------------------- |
| Padding oracle    | Authenticate before decrypt           |
| Timing oracle     | Constant-time tag comparison          |
| Nonce reuse       | Documentation + caller responsibility |
| Chosen ciphertext | Generic error on failure              |

---

### HashFunction

**Critical Properties:**

1. **Deterministic Output**

   - Same input always produces same output
   - No randomness in hash computation
   - No key material involved

2. **State Isolation (Incremental Hashing)**

   - `reset()` clears all internal state
   - No observable state leakage between contexts
   - Independent contexts don't interfere

3. **Preimage Resistance**

   - Implementation's algorithmic property
   - Trait design doesn't affect this
   - Test vectors verify correctness

**Attack Scenarios:**

| Attack           | Mitigation                             |
| ---------------- | -------------------------------------- |
| Length extension | Use resistant algorithms (SHA-384/512) |
| State recovery   | Clear state on reset                   |
| Collision        | Use appropriate output sizes           |

---

### SecureMemory

**Critical Properties:**

1. **Volatile Writes**

   Zeroization must not be optimized away:

   ```rust
   // ❌ INSECURE: Compiler may optimize away
   fn zeroize(&mut self) {
       for byte in self.data.iter_mut() {
           *byte = 0; // MAY BE REMOVED
       }
   }

   // ✅ SECURE: Volatile write with compiler barrier
   fn zeroize(&mut self) {
       for byte in self.data.iter_mut() {
           unsafe {
               core::ptr::write_volatile(byte, 0);
           }
       }
       core::sync::atomic::compiler_fence(
           core::sync::atomic::Ordering::SeqCst
       );
   }
   ```

2. **Explicit Invocation**

   - No automatic zeroization (makes security visible)
   - Callers explicitly call `zeroize()`
   - Drop may call `zeroize()` as defense-in-depth

3. **No Cloning**

   - Types with secrets don't implement Copy/Clone
   - Prevents accidental duplication
   - Forces explicit handling

**Attack Scenarios:**

| Attack                 | Mitigation                |
| ---------------------- | ------------------------- |
| Memory disclosure      | Explicit zeroization      |
| Optimizer removal      | Volatile writes + barrier |
| Accidental duplication | No Copy/Clone             |
| Premature deallocation | Caller responsibility     |

---

## Hybrid Construction Security

Hybrid post-quantum constructions have additional considerations:

### Combined Security Level

Security of a hybrid is the **minimum** of its components:

```
Security(Hybrid) = min(Security(PQ), Security(Classical))
```

If either component is broken, the hybrid is broken.

### Key Derivation

Shared secrets must be properly combined:

```rust
// ✅ SECURE: KDF with domain separation
let ss_pq = pq_kem.decapsulate(sk_pq, ct_pq)?;
let ss_classical = classical_kem.decapsulate(sk_c, ct_c)?;
let combined = kdf_with_label(b"hybrid-kem", &[&ss_pq, &ss_classical]);

// ❌ INSECURE: Simple concatenation (no domain separation)
let combined = [&ss_pq[..], &ss_classical[..]].concat();

// ❌ INSECURE: XOR (not a secure combiner)
let mut combined = ss_pq;
for (a, b) in combined.iter_mut().zip(ss_classical.iter()) {
    *a ^= b;
}
```

### Timing Consistency

Both operations must complete before error checking:

```rust
// ✅ SECURE: Both operations complete
let pq_result = pq_kem.decapsulate(sk_pq, ct_pq);
let c_result = c_kem.decapsulate(sk_c, ct_c);

match (pq_result, c_result) {
    (Ok(ss_pq), Ok(ss_c)) => Ok(combine(ss_pq, ss_c)),
    _ => Err(CryptoError::DecapsulationFailed.into()),
}

// ❌ VULNERABLE: Early exit on first failure
let ss_pq = pq_kem.decapsulate(sk_pq, ct_pq)?; // May leak timing
let ss_c = c_kem.decapsulate(sk_c, ct_c)?;
```

---

## Error Handling Security

### Information Leakage Prevention

The error system prevents leakage through:

1. **Opaque Crypto Errors**

   All cryptographic failures map to generic variants:

   - `CryptoError::VerificationFailed`
   - `CryptoError::DecryptionFailed`
   - `CryptoError::DecapsulationFailed`

2. **No Algorithm Details**

   Error messages contain no algorithm-specific information that could aid fingerprinting.

3. **Constant-Cost Creation**

   - Error types are Copy (no allocation)
   - Display uses static strings
   - No dynamic formatting

### Proper Error Handling Pattern

```rust
match operation() {
    Ok(result) => process(result),

    Err(e) if e.is_crypto() => {
        // Log minimally, no details
        log::warn!("cryptographic operation failed");
        HttpResponse::Unauthorized()
    }

    Err(e) if e.is_misuse() => {
        // Log details (this is a bug)
        log::error!("API misuse: {}", e);
        HttpResponse::InternalServerError()
    }

    Err(e) => {
        // Fallback
        HttpResponse::BadRequest()
    }
}
```

---

## Implementation Security Checklist

Before merging a trait implementation:

- [ ] All cryptographic failures return generic `CryptoError` variants
- [ ] Complete all validation before returning errors (no early exit)
- [ ] Use constant-time comparison for MACs/tags/signatures
- [ ] Use volatile writes + barriers for zeroization
- [ ] No Copy/Clone on types containing secrets
- [ ] Fresh randomness per operation (where applicable)
- [ ] Validate all parameters using `validation.rs` functions
- [ ] Document all const generic values and rationale
- [ ] Test with invalid inputs (fuzzing recommended)
- [ ] Test timing consistency where feasible
- [ ] Verify against test vectors (where available)

---

## Known Limitations

### What Traits Cannot Prevent

1. **Algorithmic Vulnerabilities**

   Traits don't protect against flaws in underlying algorithms.

2. **Caller-Introduced Vulnerabilities**

   - Nonce reuse in AEAD
   - Forgetting to zeroize secrets
   - Mishandling error information

3. **Hardware Side-Channels**

   - Power analysis
   - Electromagnetic emanations
   - Fault injection
   - Speculative execution (Spectre/Meltdown)

4. **Memory Allocation Patterns**

   While minimized, dynamic allocations have observable timing.

### Out of Scope

- Physical attacks on hardware
- Supply chain attacks
- Social engineering
- Rubber-hose cryptanalysis

---

## Testing for Security

### Timing Consistency Tests

```rust
#[test]
fn decapsulation_timing_consistency() {
    let valid_ct = generate_valid_ciphertext();
    let invalid_ct = generate_invalid_ciphertext();

    let time_valid = measure_time(|| {
        let _ = kem.decapsulate(sk, &valid_ct);
    });

    let time_invalid = measure_time(|| {
        let _ = kem.decapsulate(sk, &invalid_ct);
    });

    // Times should be similar (within reasonable variance)
    assert!((time_valid - time_invalid).abs() < THRESHOLD);
}
```

### Zeroization Verification

```rust
#[test]
fn zeroization_prevents_optimization() {
    let mut secret = [0x42u8; 32];
    let ptr = secret.as_ptr();

    secret.zeroize();

    // Verify memory actually changed
    assert_eq!(&secret, &[0u8; 32]);

    // Additional verification that write actually occurred
    unsafe {
        for i in 0..32 {
            assert_eq!(*ptr.add(i), 0);
        }
    }
}
```

### Error Opacity Tests

```rust
#[test]
fn crypto_errors_are_opaque() {
    let err = CryptoError::DecapsulationFailed;
    let msg = format!("{}", err);

    // Should not contain implementation details
    assert!(!msg.contains("padding"));
    assert!(!msg.contains("format"));
    assert!(!msg.contains("MAC"));
    assert!(!msg.contains("ML-KEM"));
}
```

---

## Audit Trail

| Date       | Auditor         | Focus Areas                                         |
| ---------- | --------------- | --------------------------------------------------- |
| 2026-01-01 | Internal Review | Information leakage, timing consistency             |
| TBD        | External Audit  | Side-channel resistance, implementation correctness |

---

## Vulnerability Disclosure

**If you discover a security issue:**

1. **DO NOT** open a public GitHub issue
2. Email: `strukturaenterprise@gmail.com`
3. Include:
   - Description of vulnerability
   - Attack scenario or proof-of-concept
   - Affected trait(s) and methods
   - Suggested remediation (if any)

We take trait-level security seriously, as design flaws enable vulnerabilities in all implementations.

---

## Summary

The internal traits module establishes security properties through:

1. **Type-level enforcement** via const generics
2. **Error design** that prevents information leakage
3. **Explicit contracts** for implementers
4. **Validation infrastructure** for parameter checking

**Critical Principle:** Traits provide structure and guidance, but security ultimately depends on correct, careful implementations. Defense in depth remains essential.
