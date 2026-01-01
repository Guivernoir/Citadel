//! Authenticated Encryption with Associated Data (AEAD) trait.
//!
//! # Security Properties
//!
//! Implementations MUST:
//! - Provide authenticated encryption (confidentiality + integrity)
//! - Use each (key, nonce) pair at most once
//! - Perform constant-time operations where feasible
//! - Complete all verification before decryption (no plaintext on failure)
//! - Not leak information through error types (use CryptoError::DecryptionFailed)
//! - Zeroize keys when dropped
//!
//! Implementations MUST NOT:
//! - Decrypt before verifying authentication tag
//! - Distinguish between tag failure and ciphertext format errors in error type
//! - Perform early-exit on verification failure (timing leak)
//! - Reuse nonces with the same key
//! - Log or expose keys or intermediate values
//!
//! # Const Generics
//!
//! - `KEY_SIZE`: Size of encryption key in bytes
//! - `NONCE_SIZE`: Size of nonce in bytes
//! - `TAG_SIZE`: Size of authentication tag in bytes

use crate::errors::Result;

/// Authenticated Encryption with Associated Data cipher trait.
///
/// Provides authenticated encryption and decryption operations.
/// All sizes are compile-time constants enforced through const generics.
///
/// # Type Parameters
///
/// - `KEY_SIZE`: Encryption key size in bytes
/// - `NONCE_SIZE`: Nonce/IV size in bytes
/// - `TAG_SIZE`: Authentication tag size in bytes
///
/// # Nonce Uniqueness
///
/// Callers MUST ensure that each (key, nonce) pair is used at most once.
/// Nonce reuse completely breaks security. Consider using a counter or random
/// nonces with sufficient size.
///
/// # Output Format
///
/// Ciphertext includes the authentication tag appended. Output length is
/// `plaintext.len() + TAG_SIZE`.
///
/// # Example
///
/// ```ignore
/// fn encrypt_data<A>(cipher: &A, key: &[u8; 32], plaintext: &[u8]) -> Vec<u8>
/// where
///     A: AeadCipher<32, 12, 16>
/// {
///     let nonce = generate_nonce(); // Caller ensures uniqueness
///     let mut ciphertext = vec![0u8; plaintext.len() + 16];
///     cipher.encrypt(key, &nonce, plaintext, &[], &mut ciphertext).unwrap();
///     ciphertext
/// }
/// ```
pub trait AeadCipher<
    const KEY_SIZE: usize,
    const NONCE_SIZE: usize,
    const TAG_SIZE: usize,
>: Sized
{
    /// Encrypt and authenticate plaintext with optional associated data.
    ///
    /// # Arguments
    ///
    /// - `key`: Encryption key
    /// - `nonce`: Nonce (must be unique for this key)
    /// - `plaintext`: Data to encrypt
    /// - `associated_data`: Additional authenticated data (not encrypted)
    /// - `output`: Buffer for ciphertext + tag (must be `plaintext.len() + TAG_SIZE`)
    ///
    /// # Returns
    ///
    /// `Ok(())` on success. `output` contains ciphertext || tag.
    ///
    /// # Errors
    ///
    /// - `MisuseError::InvalidKeyLength`: If key size is wrong
    /// - `MisuseError::InvalidNonceLength`: If nonce size is wrong
    /// - `MisuseError::InvalidOutputLength`: If output buffer size is wrong
    ///
    /// # Security
    ///
    /// - Each (key, nonce) pair MUST be used at most once
    /// - Nonce reuse completely breaks security
    /// - Associated data is authenticated but not encrypted
    /// - Caller is responsible for nonce uniqueness
    ///
    /// # Panics
    ///
    /// May panic if output buffer size is incorrect (implementation-defined).
    fn encrypt(
        &self,
        key: &[u8; KEY_SIZE],
        nonce: &[u8; NONCE_SIZE],
        plaintext: &[u8],
        associated_data: &[u8],
        output: &mut [u8],
    ) -> Result<()>;

    /// Decrypt and verify ciphertext with optional associated data.
    ///
    /// # Arguments
    ///
    /// - `key`: Decryption key
    /// - `nonce`: Nonce used for encryption
    /// - `ciphertext`: Encrypted data || tag (length must be >= TAG_SIZE)
    /// - `associated_data`: Additional authenticated data (must match encryption)
    /// - `output`: Buffer for plaintext (must be `ciphertext.len() - TAG_SIZE`)
    ///
    /// # Returns
    ///
    /// `Ok(())` on successful decryption and verification. `output` contains plaintext.
    ///
    /// # Errors
    ///
    /// - `CryptoError::DecryptionFailed`: If authentication fails or ciphertext is invalid
    /// - `MisuseError::InvalidKeyLength`: If key size is wrong
    /// - `MisuseError::InvalidNonceLength`: If nonce size is wrong
    /// - `MisuseError::InvalidCiphertextLength`: If ciphertext is too short
    /// - `MisuseError::InvalidOutputLength`: If output buffer size is wrong
    ///
    /// # Security
    ///
    /// - Verification is performed before any decryption
    /// - Returns generic error on failure (no information leakage)
    /// - Completes all checks before returning error
    /// - Output is not modified on verification failure
    /// - Associated data must match what was used for encryption
    ///
    /// # Important
    ///
    /// On authentication failure, the output buffer contents are undefined.
    /// Callers MUST NOT use output on `Err(_)`.
    fn decrypt(
        &self,
        key: &[u8; KEY_SIZE],
        nonce: &[u8; NONCE_SIZE],
        ciphertext: &[u8],
        associated_data: &[u8],
        output: &mut [u8],
    ) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    // Compile-time size verification
    struct MockAead;

    impl AeadCipher<32, 12, 16> for MockAead {
        fn encrypt(
            &self,
            _key: &[u8; 32],
            _nonce: &[u8; 12],
            _plaintext: &[u8],
            _associated_data: &[u8],
            _output: &mut [u8],
        ) -> Result<()> {
            unimplemented!("mock")
        }

        fn decrypt(
            &self,
            _key: &[u8; 32],
            _nonce: &[u8; 12],
            _ciphertext: &[u8],
            _associated_data: &[u8],
            _output: &mut [u8],
        ) -> Result<()> {
            unimplemented!("mock")
        }
    }

    #[test]
    fn trait_is_sized() {
        fn assert_sized<T: Sized>() {}
        assert_sized::<MockAead>();
    }
}