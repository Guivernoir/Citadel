//! Error types for Citadel.
//!
//! # Design Philosophy
//!
//! Citadel error types are designed to balance diagnosability and security.
//! Cryptographic failures are intentionally opaque to avoid leaking information
//! that could aid side-channel attacks, while misuse errors provide explicit
//! feedback for correct integration.
//!
//! ## Two Error Classes
//!
//! 1. **Cryptographic errors** ([`CryptoError`]) - Expected failures from
//!    valid operations. These are coarse-grained and provide minimal detail
//!    to prevent information leakage.
//!
//! 2. **Misuse errors** ([`MisuseError`]) - Developer mistakes such as
//!    invalid buffer sizes or unsupported algorithms. These are actionable
//!    and provide clear diagnostic information.
//!
//! ## Security Considerations
//!
//! Error behavior is designed to be:
//! - **Deterministic**: No data-dependent error paths
//! - **Timing-consistent**: Error creation has constant cost
//! - **Allocation-consistent**: No conditional allocations
//!
//! Display implementations avoid dynamic formatting and algorithm details.
//! In security-sensitive contexts, consider treating all errors uniformly.

use core::fmt;

mod crypto;
mod misuse;

pub use crypto::CryptoError;
pub use misuse::MisuseError;

/// Unified error type for all Citadel operations.
///
/// This enum separates cryptographic failures from API misuse,
/// allowing consumers to handle each class appropriately.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// A cryptographic operation failed.
    ///
    /// These are expected, non-fatal errors that represent valid
    /// operations that failed securely (e.g., verification failure,
    /// decryption failure). Error messages are intentionally vague.
    Crypto(CryptoError),

    /// The API was used incorrectly.
    ///
    /// These represent developer mistakes such as invalid buffer sizes,
    /// unsupported algorithms, or incorrect parameter sets. These errors
    /// are deterministic and should be caught during development.
    Misuse(MisuseError),
}

impl Error {
    /// Returns true if this is a cryptographic error.
    #[inline]
    pub const fn is_crypto(&self) -> bool {
        matches!(self, Error::Crypto(_))
    }

    /// Returns true if this is a misuse error.
    #[inline]
    pub const fn is_misuse(&self) -> bool {
        matches!(self, Error::Misuse(_))
    }

    /// Returns the underlying `CryptoError` if this is a crypto error.
    #[inline]
    pub const fn crypto(&self) -> Option<CryptoError> {
        match self {
            Error::Crypto(e) => Some(*e),
            _ => None,
        }
    }

    /// Returns the underlying `MisuseError` if this is a misuse error.
    #[inline]
    pub const fn misuse(&self) -> Option<MisuseError> {
        match self {
            Error::Misuse(e) => Some(*e),
            _ => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Crypto(e) => write!(f, "cryptographic error: {}", e),
            Error::Misuse(e) => write!(f, "misuse error: {}", e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Crypto(e) => Some(e),
            Error::Misuse(e) => Some(e),
        }
    }
}

// Conversions for ergonomic error handling

impl From<CryptoError> for Error {
    #[inline]
    fn from(e: CryptoError) -> Self {
        Error::Crypto(e)
    }
}

impl From<MisuseError> for Error {
    #[inline]
    fn from(e: MisuseError) -> Self {
        Error::Misuse(e)
    }
}

/// Convenience type alias for results using [`Error`].
pub type Result<T> = core::result::Result<T, Error>;

/// Convenience type alias for results using [`CryptoError`].
pub type CryptoResult<T> = core::result::Result<T, CryptoError>;

/// Convenience type alias for results using [`MisuseError`].
pub type MisuseResult<T> = core::result::Result<T, MisuseError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_type_checks() {
        let crypto = Error::from(CryptoError::VerificationFailed);
        let misuse = Error::from(MisuseError::InvalidKeyLength);

        assert!(crypto.is_crypto());
        assert!(!crypto.is_misuse());
        assert!(misuse.is_misuse());
        assert!(!misuse.is_crypto());
    }

    #[test]
    fn error_unwrapping() {
        let crypto = Error::from(CryptoError::DecryptionFailed);
        assert_eq!(crypto.crypto(), Some(CryptoError::DecryptionFailed));
        assert_eq!(crypto.misuse(), None);

        let misuse = Error::from(MisuseError::BufferTooSmall);
        assert_eq!(misuse.misuse(), Some(MisuseError::BufferTooSmall));
        assert_eq!(misuse.crypto(), None);
    }

    #[test]
    fn error_display_is_deterministic() {
        // Ensure Display doesn't allocate or do complex formatting
        let crypto = Error::from(CryptoError::VerificationFailed);
        let msg1 = format!("{}", crypto);
        let msg2 = format!("{}", crypto);
        assert_eq!(msg1, msg2);
        assert!(msg1.len() < 100); // Sanity check for bounded output
    }

    #[test]
    fn crypto_error_helpers() {
        assert!(CryptoError::VerificationFailed.is_verification_failure());
        assert!(!CryptoError::DecryptionFailed.is_verification_failure());

        assert!(CryptoError::DecryptionFailed.is_decryption_failure());
        assert!(!CryptoError::VerificationFailed.is_decryption_failure());
    }

    #[test]
    fn misuse_error_helpers() {
        assert!(MisuseError::InvalidKeyLength.is_length_error());
        assert!(MisuseError::BufferTooSmall.is_length_error());
        assert!(!MisuseError::UnsupportedAlgorithm.is_length_error());

        assert!(MisuseError::UnsupportedAlgorithm.is_algorithm_error());
        assert!(MisuseError::InvalidParameterSet.is_algorithm_error());
        assert!(!MisuseError::InvalidKeyLength.is_algorithm_error());
    }

    #[test]
    fn error_size_is_reasonable() {
        // Ensure error types don't bloat
        assert!(core::mem::size_of::<Error>() <= 8);
        assert!(core::mem::size_of::<CryptoError>() <= 4);
        assert!(core::mem::size_of::<MisuseError>() <= 4);
    }
}
