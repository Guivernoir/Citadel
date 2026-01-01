//! Key Encapsulation Mechanism trait.
//!
//! # Security Properties
//!
//! Implementations MUST:
//! - Use cryptographically secure randomness for encapsulation
//! - Perform constant-time operations where feasible
//! - Not leak information through error types (use CryptoError::DecapsulationFailed)
//! - Zeroize sensitive material when dropped
//!
//! Implementations MUST NOT:
//! - Reuse randomness across encapsulations
//! - Perform data-dependent branching in critical paths
//! - Log or expose intermediate values
//!
//! # Const Generics
//!
//! - `PUBLIC_KEY_SIZE`: Size of public key in bytes
//! - `SECRET_KEY_SIZE`: Size of secret key in bytes  
//! - `CIPHERTEXT_SIZE`: Size of ciphertext in bytes
//! - `SHARED_SECRET_SIZE`: Size of shared secret in bytes

use crate::errors::Result;

/// Key Encapsulation Mechanism trait.
///
/// Provides key generation, encapsulation, and decapsulation operations.
/// All sizes are compile-time constants enforced through const generics.
///
/// # Type Parameters
///
/// - `PUBLIC_KEY_SIZE`: Public key size in bytes
/// - `SECRET_KEY_SIZE`: Secret key size in bytes
/// - `CIPHERTEXT_SIZE`: Encapsulated ciphertext size in bytes
/// - `SHARED_SECRET_SIZE`: Shared secret size in bytes
///
/// # Example
///
/// ```ignore
/// fn use_kem<K>(kem: &K, public_key: &[u8; 1568]) 
/// where
///     K: KeyEncapsulation<1568, 3168, 1568, 32>
/// {
///     let (ciphertext, shared_secret) = kem.encapsulate(public_key).unwrap();
///     // Use shared_secret for key derivation...
/// }
/// ```
pub trait KeyEncapsulation<
    const PUBLIC_KEY_SIZE: usize,
    const SECRET_KEY_SIZE: usize,
    const CIPHERTEXT_SIZE: usize,
    const SHARED_SECRET_SIZE: usize,
>: Sized
{
    /// Generate a new keypair.
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
    fn generate_keypair(
        &self,
    ) -> Result<([u8; PUBLIC_KEY_SIZE], [u8; SECRET_KEY_SIZE])>;

    /// Encapsulate a shared secret for the given public key.
    ///
    /// # Arguments
    ///
    /// - `public_key`: Recipient's public key
    ///
    /// # Returns
    ///
    /// A tuple of (ciphertext, shared_secret).
    ///
    /// # Errors
    ///
    /// - `MisuseError::InvalidPublicKey`: If public key is malformed
    /// - `MisuseError`: If RNG fails
    ///
    /// # Security
    ///
    /// - Uses fresh randomness for each encapsulation
    /// - Shared secret must be zeroized when no longer needed
    /// - MUST NOT reuse randomness across calls
    fn encapsulate(
        &self,
        public_key: &[u8; PUBLIC_KEY_SIZE],
    ) -> Result<([u8; CIPHERTEXT_SIZE], [u8; SHARED_SECRET_SIZE])>;

    /// Decapsulate a shared secret from ciphertext using the secret key.
    ///
    /// # Arguments
    ///
    /// - `secret_key`: Recipient's secret key
    /// - `ciphertext`: Encapsulated shared secret
    ///
    /// # Returns
    ///
    /// The shared secret.
    ///
    /// # Errors
    ///
    /// - `CryptoError::DecapsulationFailed`: If decapsulation fails (invalid ciphertext or key)
    /// - `MisuseError::InvalidSecretKey`: If secret key format is invalid
    ///
    /// # Security
    ///
    /// - Performs constant-time operations where possible
    /// - Returns generic error on failure (no information leakage)
    /// - Completes all validation before returning error
    fn decapsulate(
        &self,
        secret_key: &[u8; SECRET_KEY_SIZE],
        ciphertext: &[u8; CIPHERTEXT_SIZE],
    ) -> Result<[u8; SHARED_SECRET_SIZE]>;
}

#[cfg(test)]
mod tests {
    use super::*;

    // Compile-time size verification
    struct MockKem;

    impl KeyEncapsulation<1568, 3168, 1568, 32> for MockKem {
        fn generate_keypair(&self) -> Result<([u8; 1568], [u8; 3168])> {
            unimplemented!("mock")
        }

        fn encapsulate(
            &self,
            _public_key: &[u8; 1568],
        ) -> Result<([u8; 1568], [u8; 32])> {
            unimplemented!("mock")
        }

        fn decapsulate(
            &self,
            _secret_key: &[u8; 3168],
            _ciphertext: &[u8; 1568],
        ) -> Result<[u8; 32]> {
            unimplemented!("mock")
        }
    }

    #[test]
    fn trait_is_sized() {
        fn assert_sized<T: Sized>() {}
        assert_sized::<MockKem>();
    }
}