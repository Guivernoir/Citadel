//! Parameter validation functions.
//!
//! This module provides validation functions for cryptographic parameters.
//! All validation functions return `Result<()>` to indicate parameter correctness.
//!
//! # Design Principles
//!
//! 1. **Fail Fast**: Invalid parameters are caught early
//! 2. **Explicit Errors**: Each validation returns a specific MisuseError
//! 3. **No Silent Failures**: All checks return Result, no silent truncation
//! 4. **Const-Friendly**: Where possible, use const generics for compile-time checks
//!
//! # Usage
//!
//! Validation functions should be called at API boundaries before performing
//! cryptographic operations. They catch programmer errors (misuse), not
//! cryptographic failures.
//!
//! # Example
//!
//! ```ignore
//! pub fn encrypt(key: &[u8], nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
//!     validate_key_size::<32>(key)?;
//!     validate_nonce_size::<12>(nonce)?;
//!     // ... proceed with encryption
//! }
//! ```

use crate::errors::{MisuseError, Result};

/// Validate that a buffer has the expected size.
///
/// # Arguments
///
/// - `buffer`: Buffer to validate
/// - `expected_size`: Expected size in bytes
/// - `name`: Name of the parameter for error messages
///
/// # Returns
///
/// `Ok(())` if buffer size matches expected size.
///
/// # Errors
///
/// - `MisuseError::BufferTooSmall`: If buffer size is incorrect
///
/// # Example
///
/// ```ignore
/// validate_buffer_size(key, 32, "key")?;
/// ```
#[inline]
pub fn validate_buffer_size(
    buffer: &[u8],
    expected_size: usize,
    _name: &str,
) -> Result<()> {
    if buffer.len() == expected_size {
        Ok(())
    } else {
        Err(MisuseError::BufferTooSmall.into())
    }
}

/// Validate key size matches expected size.
///
/// # Type Parameters
///
/// - `N`: Expected key size in bytes
///
/// # Arguments
///
/// - `key`: Key buffer to validate
///
/// # Returns
///
/// `Ok(())` if key size matches `N`.
///
/// # Errors
///
/// - `MisuseError::InvalidKeyLength`: If key size is incorrect
///
/// # Example
///
/// ```ignore
/// validate_key_size::<32>(key)?;
/// ```
#[inline]
pub fn validate_key_size<const N: usize>(key: &[u8]) -> Result<()> {
    if key.len() == N {
        Ok(())
    } else {
        Err(MisuseError::InvalidKeyLength.into())
    }
}

/// Validate nonce size matches expected size.
///
/// # Type Parameters
///
/// - `N`: Expected nonce size in bytes
///
/// # Arguments
///
/// - `nonce`: Nonce buffer to validate
///
/// # Returns
///
/// `Ok(())` if nonce size matches `N`.
///
/// # Errors
///
/// - `MisuseError::InvalidNonceLength`: If nonce size is incorrect
///
/// # Example
///
/// ```ignore
/// validate_nonce_size::<12>(nonce)?;
/// ```
#[inline]
pub fn validate_nonce_size<const N: usize>(nonce: &[u8]) -> Result<()> {
    if nonce.len() == N {
        Ok(())
    } else {
        Err(MisuseError::InvalidNonceLength.into())
    }
}

/// Validate public key size matches expected size.
///
/// # Type Parameters
///
/// - `N`: Expected public key size in bytes
///
/// # Arguments
///
/// - `public_key`: Public key buffer to validate
///
/// # Returns
///
/// `Ok(())` if public key size matches `N`.
///
/// # Errors
///
/// - `MisuseError::InvalidPublicKeyLength`: If public key size is incorrect
///
/// # Example
///
/// ```ignore
/// validate_public_key_size::<1568>(public_key)?;
/// ```
#[inline]
pub fn validate_public_key_size<const N: usize>(public_key: &[u8]) -> Result<()> {
    if public_key.len() == N {
        Ok(())
    } else {
        Err(MisuseError::InvalidPublicKeyLength.into())
    }
}

/// Validate secret key size matches expected size.
///
/// # Type Parameters
///
/// - `N`: Expected secret key size in bytes
///
/// # Arguments
///
/// - `secret_key`: Secret key buffer to validate
///
/// # Returns
///
/// `Ok(())` if secret key size matches `N`.
///
/// # Errors
///
/// - `MisuseError::InvalidSecretKeyLength`: If secret key size is incorrect
///
/// # Example
///
/// ```ignore
/// validate_secret_key_size::<3168>(secret_key)?;
/// ```
#[inline]
pub fn validate_secret_key_size<const N: usize>(secret_key: &[u8]) -> Result<()> {
    if secret_key.len() == N {
        Ok(())
    } else {
        Err(MisuseError::InvalidSecretKeyLength.into())
    }
}

/// Validate ciphertext size is at least minimum required.
///
/// # Arguments
///
/// - `ciphertext`: Ciphertext buffer to validate
/// - `min_size`: Minimum required size in bytes (typically TAG_SIZE)
///
/// # Returns
///
/// `Ok(())` if ciphertext is large enough.
///
/// # Errors
///
/// - `MisuseError::InvalidCiphertextLength`: If ciphertext is too short
///
/// # Example
///
/// ```ignore
/// validate_ciphertext_min_size(ciphertext, 16)?; // At least tag size
/// ```
#[inline]
pub fn validate_ciphertext_min_size(ciphertext: &[u8], min_size: usize) -> Result<()> {
    if ciphertext.len() >= min_size {
        Ok(())
    } else {
        Err(MisuseError::InvalidCiphertextLength.into())
    }
}

/// Validate signature size matches expected size.
///
/// # Type Parameters
///
/// - `N`: Expected signature size in bytes
///
/// # Arguments
///
/// - `signature`: Signature buffer to validate
///
/// # Returns
///
/// `Ok(())` if signature size matches `N`.
///
/// # Errors
///
/// - `MisuseError::InvalidSignatureLength`: If signature size is incorrect
///
/// # Example
///
/// ```ignore
/// validate_signature_size::<4627>(signature)?;
/// ```
#[inline]
pub fn validate_signature_size<const N: usize>(signature: &[u8]) -> Result<()> {
    if signature.len() == N {
        Ok(())
    } else {
        Err(MisuseError::InvalidSignatureLength.into())
    }
}

/// Validate output buffer has sufficient capacity.
///
/// # Arguments
///
/// - `output`: Output buffer to validate
/// - `required_size`: Required size in bytes
///
/// # Returns
///
/// `Ok(())` if output buffer is large enough.
///
/// # Errors
///
/// - `MisuseError::InvalidPlaintextLength`: If output buffer is too small
///
/// # Example
///
/// ```ignore
/// let required = plaintext.len() + TAG_SIZE;
/// validate_output_size(output, required)?;
/// ```
#[inline]
pub fn validate_output_size(output: &[u8], required_size: usize) -> Result<()> {
    if output.len() >= required_size {
        Ok(())
    } else {
        Err(MisuseError::InvalidPlaintextLength.into())
    }
}

/// Validate that output buffer has exact required size.
///
/// This is stricter than `validate_output_size` and requires exact match.
///
/// # Arguments
///
/// - `output`: Output buffer to validate
/// - `required_size`: Required exact size in bytes
///
/// # Returns
///
/// `Ok(())` if output buffer size exactly matches.
///
/// # Errors
///
/// - `MisuseError::InvalidPlaintextLength`: If output buffer size doesn't match exactly
///
/// # Example
///
/// ```ignore
/// validate_output_exact_size(output, plaintext.len() + TAG_SIZE)?;
/// ```
#[inline]
pub fn validate_output_exact_size(output: &[u8], required_size: usize) -> Result<()> {
    if output.len() == required_size {
        Ok(())
    } else {
        Err(MisuseError::InvalidPlaintextLength.into())
    }
}

/// Validate that a slice is not empty.
///
/// # Arguments
///
/// - `data`: Slice to validate
///
/// # Returns
///
/// `Ok(())` if slice is not empty.
///
/// # Errors
///
/// - `MisuseError::BufferTooSmall`: If slice is empty
///
/// # Example
///
/// ```ignore
/// validate_not_empty(message)?;
/// ```
#[inline]
pub fn validate_not_empty(data: &[u8]) -> Result<()> {
    if !data.is_empty() {
        Ok(())
    } else {
        Err(MisuseError::BufferTooSmall.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_buffer_size_ok() {
        let buf = [0u8; 32];
        assert!(validate_buffer_size(&buf, 32, "test").is_ok());
    }

    #[test]
    fn validate_buffer_size_err() {
        let buf = [0u8; 32];
        assert!(validate_buffer_size(&buf, 16, "test").is_err());
    }

    #[test]
    fn validate_key_size_ok() {
        let key = [0u8; 32];
        assert!(validate_key_size::<32>(&key).is_ok());
    }

    #[test]
    fn validate_key_size_err() {
        let key = [0u8; 16];
        assert!(validate_key_size::<32>(&key).is_err());
    }

    #[test]
    fn validate_nonce_size_ok() {
        let nonce = [0u8; 12];
        assert!(validate_nonce_size::<12>(&nonce).is_ok());
    }

    #[test]
    fn validate_ciphertext_min_size_ok() {
        let ct = [0u8; 32];
        assert!(validate_ciphertext_min_size(&ct, 16).is_ok());
        assert!(validate_ciphertext_min_size(&ct, 32).is_ok());
    }

    #[test]
    fn validate_ciphertext_min_size_err() {
        let ct = [0u8; 15];
        assert!(validate_ciphertext_min_size(&ct, 16).is_err());
    }

    #[test]
    fn validate_output_size_ok() {
        let out = [0u8; 100];
        assert!(validate_output_size(&out, 50).is_ok());
        assert!(validate_output_size(&out, 100).is_ok());
    }

    #[test]
    fn validate_output_size_err() {
        let out = [0u8; 50];
        assert!(validate_output_size(&out, 100).is_err());
    }

    #[test]
    fn validate_output_exact_size_ok() {
        let out = [0u8; 100];
        assert!(validate_output_exact_size(&out, 100).is_ok());
    }

    #[test]
    fn validate_output_exact_size_err() {
        let out = [0u8; 100];
        assert!(validate_output_exact_size(&out, 99).is_err());
        assert!(validate_output_exact_size(&out, 101).is_err());
    }

    #[test]
    fn validate_not_empty_ok() {
        let data = [0u8; 1];
        assert!(validate_not_empty(&data).is_ok());
    }

    #[test]
    fn validate_not_empty_err() {
        let data = [];
        assert!(validate_not_empty(&data).is_err());
    }
}