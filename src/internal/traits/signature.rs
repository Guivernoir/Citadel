//! Digital Signature Scheme trait.
//!
//! # Security Properties
//!
//! Implementations MUST:
//! - Use cryptographically secure randomness for signing (if randomized)
//! - Perform constant-time operations in verification where feasible
//! - Complete all verification checks before returning error
//! - Not leak information about failure mode (use CryptoError::VerificationFailed)
//! - Zeroize secret keys when dropped
//!
//! Implementations MUST NOT:
//! - Reuse randomness across signatures (if randomized)
//! - Perform early-exit on verification failure (timing leak)
//! - Distinguish between signature format errors and verification failures in error type
//! - Log or expose intermediate values
//!
//! # Const Generics
//!
//! - `PUBLIC_KEY_SIZE`: Size of public key in bytes
//! - `SECRET_KEY_SIZE`: Size of secret key in bytes
//! - `SIGNATURE_SIZE`: Size of signature in bytes

use crate::errors::Result;

/// Digital Signature Scheme trait.
///
/// Provides key generation, signing, and verification operations.
/// All sizes are compile-time constants enforced through const generics.
///
/// # Type Parameters
///
/// - `PUBLIC_KEY_SIZE`: Public key size in bytes
/// - `SECRET_KEY_SIZE`: Secret key size in bytes
/// - `SIGNATURE_SIZE`: Signature size in bytes
///
/// # Signature Determinism
///
/// Some schemes (e.g., Ed25519) are deterministic, while others (e.g., ML-DSA)
/// may use randomness. This trait accommodates both.
///
/// # Example
///
/// ```ignore
/// fn use_signature<S>(scheme: &S, message: &[u8], public_key: &[u8; 2592])
/// where
///     S: SignatureScheme<2592, 4032, 4627>
/// {
///     scheme.verify(public_key, message, &signature).unwrap();
/// }
/// ```
pub trait SignatureScheme<
    const PUBLIC_KEY_SIZE: usize,
    const SECRET_KEY_SIZE: usize,
    const SIGNATURE_SIZE: usize,
>: Sized
{
    /// Generate a new signing keypair.
    ///
    /// # Returns
    ///
    /// A tuple of (public_key, secret_key).
    ///
    /// # Errors
    ///
    /// - `MisuseError`: If RNG fails or system is in invalid state
    ///
    /// # Security
    ///
    /// - Uses cryptographically secure randomness
    /// - Secret key must be zeroized when no longer needed
    /// - Public key may be freely distributed
    fn generate_keypair(
        &self,
    ) -> Result<([u8; PUBLIC_KEY_SIZE], [u8; SECRET_KEY_SIZE])>;

    /// Sign a message with the secret key.
    ///
    /// # Arguments
    ///
    /// - `secret_key`: Signer's secret key
    /// - `message`: Message to sign (arbitrary length)
    ///
    /// # Returns
    ///
    /// The signature.
    ///
    /// # Errors
    ///
    /// - `MisuseError::InvalidSecretKey`: If secret key format is invalid
    /// - `MisuseError`: If RNG fails (for randomized schemes)
    ///
    /// # Security
    ///
    /// - For randomized schemes, uses fresh randomness per signature
    /// - MUST NOT reuse randomness across signatures
    /// - Message is not modified
    fn sign(
        &self,
        secret_key: &[u8; SECRET_KEY_SIZE],
        message: &[u8],
    ) -> Result<[u8; SIGNATURE_SIZE]>;

    /// Verify a signature on a message with the public key.
    ///
    /// # Arguments
    ///
    /// - `public_key`: Signer's public key
    /// - `message`: Message that was signed
    /// - `signature`: Signature to verify
    ///
    /// # Returns
    ///
    /// `Ok(())` if verification succeeds.
    ///
    /// # Errors
    ///
    /// - `CryptoError::VerificationFailed`: If signature is invalid
    /// - `MisuseError::InvalidPublicKey`: If public key format is invalid
    ///
    /// # Security
    ///
    /// - Performs constant-time operations where possible
    /// - Completes all verification steps before returning error
    /// - Returns same error for all failure modes (no information leakage)
    /// - No early exit on format errors (timing consistency)
    ///
    /// # Important
    ///
    /// Signature verification failure is NOT an exceptional condition in
    /// adversarial contexts. Callers must handle `VerificationFailed` as
    /// an expected case.
    fn verify(
        &self,
        public_key: &[u8; PUBLIC_KEY_SIZE],
        message: &[u8],
        signature: &[u8; SIGNATURE_SIZE],
    ) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    // Compile-time size verification
    struct MockSignature;

    impl SignatureScheme<2592, 4032, 4627> for MockSignature {
        fn generate_keypair(&self) -> Result<([u8; 2592], [u8; 4032])> {
            unimplemented!("mock")
        }

        fn sign(
            &self,
            _secret_key: &[u8; 4032],
            _message: &[u8],
        ) -> Result<[u8; 4627]> {
            unimplemented!("mock")
        }

        fn verify(
            &self,
            _public_key: &[u8; 2592],
            _message: &[u8],
            _signature: &[u8; 4627],
        ) -> Result<()> {
            unimplemented!("mock")
        }
    }

    #[test]
    fn trait_is_sized() {
        fn assert_sized<T: Sized>() {}
        assert_sized::<MockSignature>();
    }
}