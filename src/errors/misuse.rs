//! Developer misuse and configuration errors.
//!
//! These errors represent incorrect API usage or invalid configurations.
//! They are deterministic, actionable, and should never occur in production
//! if the library is used correctly.
//!
//! Unlike cryptographic errors, these can be detailed and logged safely,
//! as they don't reveal information about cryptographic operations or secrets.

use core::fmt;

/// Errors from incorrect API usage or invalid configuration.
///
/// These are deterministic and should be caught during development.
/// They do not represent cryptographic failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MisuseError {
    /// Key has invalid length for the specified algorithm.
    ///
    /// Check algorithm documentation for required key sizes.
    InvalidKeyLength,

    /// Signature has invalid length.
    ///
    /// The signature buffer does not match the expected size
    /// for the algorithm in use.
    InvalidSignatureLength,

    /// Ciphertext buffer has invalid length.
    ///
    /// The ciphertext is too short or does not match expected
    /// structure for the algorithm in use.
    InvalidCiphertextLength,

    /// Public key has invalid length or format.
    InvalidPublicKeyLength,

    /// Secret key has invalid length or format.
    InvalidSecretKeyLength,

    /// Shared secret has invalid length.
    InvalidSharedSecretLength,

    /// Plaintext buffer has invalid length for this operation.
    InvalidPlaintextLength,

    /// Nonce or IV has invalid length for the specified algorithm.
    InvalidNonceLength,

    /// Authentication tag has invalid length.
    InvalidTagLength,

    /// Output buffer is too small for the operation.
    ///
    /// Increase buffer size to match algorithm requirements.
    BufferTooSmall,

    /// The specified algorithm or algorithm combination is not supported.
    ///
    /// This may indicate a version mismatch or unsupported feature.
    UnsupportedAlgorithm,

    /// The specified hybrid mode is not supported or invalid.
    ///
    /// Check that the combination of KEM and AEAD is valid.
    UnsupportedHybridMode,

    /// Parameter set is invalid or unsupported.
    ///
    /// This may occur with ML-KEM or ML-DSA parameter selection.
    InvalidParameterSet,

    /// Invalid algorithm identifier or selector.
    InvalidAlgorithmIdentifier,

    /// Context string exceeds maximum allowed length.
    ContextTooLong,

    /// Associated data exceeds maximum allowed length.
    AssociatedDataTooLong,

    /// Operation requires a feature that was not compiled in.
    ///
    /// Rebuild with the appropriate feature flags enabled.
    FeatureNotEnabled,

    /// Invalid state for this operation.
    ///
    /// The object is not in the correct state to perform
    /// the requested operation. Check API usage.
    InvalidState,
}

impl MisuseError {
    /// Returns true if this error is related to buffer sizing.
    #[inline]
    pub const fn is_length_error(&self) -> bool {
        matches!(
            self,
            MisuseError::InvalidKeyLength
                | MisuseError::InvalidSignatureLength
                | MisuseError::InvalidCiphertextLength
                | MisuseError::InvalidPublicKeyLength
                | MisuseError::InvalidSecretKeyLength
                | MisuseError::InvalidSharedSecretLength
                | MisuseError::InvalidPlaintextLength
                | MisuseError::InvalidNonceLength
                | MisuseError::InvalidTagLength
                | MisuseError::BufferTooSmall
        )
    }

    /// Returns true if this error is related to algorithm support.
    #[inline]
    pub const fn is_algorithm_error(&self) -> bool {
        matches!(
            self,
            MisuseError::UnsupportedAlgorithm
                | MisuseError::UnsupportedHybridMode
                | MisuseError::InvalidParameterSet
                | MisuseError::InvalidAlgorithmIdentifier
        )
    }
}

impl fmt::Display for MisuseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // These errors are safe to be descriptive - they represent
        // developer mistakes, not cryptographic failures.
        let msg = match self {
            MisuseError::InvalidKeyLength => "invalid key length for algorithm",
            MisuseError::InvalidSignatureLength => "invalid signature length",
            MisuseError::InvalidCiphertextLength => "invalid ciphertext length",
            MisuseError::InvalidPublicKeyLength => "invalid public key length",
            MisuseError::InvalidSecretKeyLength => "invalid secret key length",
            MisuseError::InvalidSharedSecretLength => "invalid shared secret length",
            MisuseError::InvalidPlaintextLength => "invalid plaintext length",
            MisuseError::InvalidNonceLength => "invalid nonce length",
            MisuseError::InvalidTagLength => "invalid authentication tag length",
            MisuseError::BufferTooSmall => "output buffer too small",
            MisuseError::UnsupportedAlgorithm => "algorithm not supported",
            MisuseError::UnsupportedHybridMode => "hybrid mode not supported",
            MisuseError::InvalidParameterSet => "invalid parameter set",
            MisuseError::InvalidAlgorithmIdentifier => "invalid algorithm identifier",
            MisuseError::ContextTooLong => "context string exceeds maximum length",
            MisuseError::AssociatedDataTooLong => "associated data exceeds maximum length",
            MisuseError::FeatureNotEnabled => "feature not enabled at compile time",
            MisuseError::InvalidState => "invalid state for operation",
        };
        f.write_str(msg)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for MisuseError {}
