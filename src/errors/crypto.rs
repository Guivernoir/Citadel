//! Cryptographic operation errors.
//!
//! These errors represent valid operations that failed securely.
//! They are intentionally opaque to avoid leaking information through
//! error channels that could aid timing attacks or other side-channel analysis.
//!
//! # Security Note
//!
//! Error messages are deliberately vague. Do not add detailed diagnostic
//! information to these types, as they may be observable by attackers.

use core::fmt;

/// Errors from cryptographic operations.
///
/// These are coarse-grained by design. Multiple internal failure modes
/// map to the same error variant to prevent information leakage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    /// Signature or MAC verification failed.
    ///
    /// This may indicate tampering, corruption, or key mismatch.
    /// The specific cause is intentionally not distinguished.
    VerificationFailed,

    /// Decryption operation failed.
    ///
    /// This encompasses authentication failures, padding errors,
    /// and other decryption-related issues. Specific causes are
    /// intentionally not distinguished to prevent oracle attacks.
    DecryptionFailed,

    /// Ciphertext is malformed or invalid.
    ///
    /// This may indicate corruption, truncation, or version mismatch.
    /// Specific structural issues are not detailed.
    /// NOTE:
    /// This error MUST only be returned from pre-authentication,
    /// constant-time-independent parsing paths.
    InvalidCiphertext,

    /// Key encapsulation failed.
    ///
    /// This may occur during KEM decapsulation or key agreement.
    /// Specific failure points are not distinguished.
    KeyEncapsulationFailed,

    /// Internal failure.
    ///
    /// This typically indicates an internal error during signing.
    /// Should be rare in correct implementations.
    InternalFailure,

    /// Generic cryptographic operation failure.
    ///
    /// Used for operations that don't fit other categories or
    /// where more specific categorization would leak information.
    OperationFailed,
}

impl CryptoError {
    /// Returns true if this error represents a verification failure.
    #[inline]
    pub const fn is_verification_failure(&self) -> bool {
        matches!(self, CryptoError::VerificationFailed)
    }

    /// Returns true if this error represents a decryption failure.
    #[inline]
    pub const fn is_decryption_failure(&self) -> bool {
        matches!(self, CryptoError::DecryptionFailed)
    }
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Keep messages intentionally vague - no algorithm details,
        // no specific failure modes, no data that could aid analysis.
        let msg = match self {
            CryptoError::VerificationFailed => "verification failed",
            CryptoError::DecryptionFailed => "decryption failed",
            CryptoError::InvalidCiphertext => "invalid ciphertext",
            CryptoError::KeyEncapsulationFailed => "key encapsulation failed",
            CryptoError::InternalFailure => "internal process failed",
            CryptoError::OperationFailed => "cryptographic operation failed",
        };
        f.write_str(msg)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CryptoError {}
