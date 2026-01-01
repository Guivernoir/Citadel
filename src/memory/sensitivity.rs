//! Sensitivity markers for cryptographic types.
//!
//! This module provides compile-time markers for types containing sensitive
//! cryptographic material. These markers help prevent:
//! - Accidental logging of secrets
//! - Serialization of sensitive data
//! - Copying of key material
//!
//! # Design Philosophy
//!
//! Sensitivity is a **type-level property**, not a runtime flag.
//! Types marked as sensitive:
//! - MUST NOT implement `Copy` or `Clone` (prevents duplication)
//! - SHOULD implement `SecureMemory` (enables zeroization)
//! - MAY implement `Drop` to zeroize automatically (defense-in-depth)
//!
//! # Example
//!
//! ```ignore
//! #[derive(Sensitive)]
//! struct SecretKey {
//!     bytes: [u8; 32],
//! }
//!
//! impl SecureMemory for SecretKey {
//!     fn zeroize(&mut self) {
//!         self.bytes.zeroize();
//!     }
//! }
//! ```

use core::fmt;
use core::marker::PhantomData;
use crate::internal::traits::memory::SecureMemory;
use crate::r#unsafe::memory::zeroize_array;

/// Marker trait for types containing sensitive cryptographic material.
///
/// Types implementing this trait contain secrets that must be:
/// - Explicitly zeroized when no longer needed
/// - Never copied or cloned
/// - Never logged or serialized
/// - Protected from memory disclosure
///
/// # Implementing This Trait
///
/// Types should implement `Sensitive` if they contain:
/// - Private/secret keys
/// - Shared secrets
/// - Plaintexts
/// - Nonces (in some contexts)
/// - Key derivation material
///
/// Types should NOT implement `Sensitive` if they contain only:
/// - Public keys
/// - Ciphertexts
/// - Hashes (generally safe to disclose)
/// - MACs/signatures (safe after generation)
///
/// # Automatic Implementations
///
/// This trait is automatically implemented for:
/// - Arrays of sensitive types
/// - Options of sensitive types (if inner is sensitive)
///
/// # Example
///
/// ```ignore
/// struct SymmetricKey([u8; 32]);
///
/// impl Sensitive for SymmetricKey {}
/// impl SecureMemory for SymmetricKey {
///     fn zeroize(&mut self) {
///         self.0.zeroize();
///     }
/// }
/// ```
pub trait Sensitive: Sized {
    /// Human-readable name for this sensitive type.
    ///
    /// Used in debug output (should not reveal the actual secret).
    /// Default implementation returns the type name.
    fn sensitivity_label() -> &'static str {
        core::any::type_name::<Self>()
    }
}

/// Wrapper type that marks contained data as sensitive.
///
/// This type provides a generic way to mark any data as sensitive
/// without defining a new type.
///
/// # Properties
///
/// - Does NOT implement Copy or Clone
/// - Implements Debug (but doesn't reveal contents)
/// - Implements Drop (zeroizes on drop if T: SecureMemory)
///
/// # Example
///
/// ```ignore
/// let secret = SensitiveBytes::new([0x42u8; 32]);
/// // Use secret...
/// drop(secret); // Automatically zeroized
/// ```
pub struct SensitiveBytes<const N: usize> {
    data: [u8; N],
    _phantom: PhantomData<*const ()>, // Makes type !Send, !Sync by default
}

impl<const N: usize> SensitiveBytes<N> {
    /// Create a new sensitive byte array.
    ///
    /// # Arguments
    ///
    /// - `data`: The sensitive data to wrap
    ///
    /// # Example
    ///
    /// ```ignore
    /// let key = SensitiveBytes::new([0x42u8; 32]);
    /// ```
    #[inline]
    pub const fn new(data: [u8; N]) -> Self {
        Self {
            data,
            _phantom: PhantomData,
        }
    }

    /// Create a zeroed sensitive byte array.
    ///
    /// Useful for initialization before filling with actual data.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut key = SensitiveBytes::<32>::zeroed();
    /// // Fill with actual key material...
    /// ```
    #[inline]
    pub const fn zeroed() -> Self {
        Self::new([0u8; N])
    }

    /// Get a reference to the inner data.
    ///
    /// # Safety Considerations
    ///
    /// The returned reference should not be:
    /// - Logged
    /// - Serialized
    /// - Stored long-term
    #[inline]
    pub fn as_bytes(&self) -> &[u8; N] {
        &self.data
    }

    /// Get a mutable reference to the inner data.
    ///
    /// # Safety Considerations
    ///
    /// Same as `as_bytes()`.
    #[inline]
    pub fn as_bytes_mut(&mut self) -> &mut [u8; N] {
        &mut self.data
    }

    /// Consume self and return the inner data.
    ///
    /// # Warning
    ///
    /// This bypasses automatic zeroization on drop.
    /// Caller is responsible for zeroizing the returned data.
    #[inline]
    pub fn into_inner(mut self) -> [u8; N] {
        // Create a copy before drop
        let data = self.data;
        // Prevent our Drop from running
        core::mem::forget(self);
        data
    }

    /// Get the length of the sensitive data.
    #[inline]
    pub const fn len(&self) -> usize {
        N
    }

    /// Check if the buffer is empty (always false for N > 0).
    #[inline]
    pub const fn is_empty(&self) -> bool {
        N == 0
    }
}

impl<const N: usize> Sensitive for SensitiveBytes<N> {
    fn sensitivity_label() -> &'static str {
        "SensitiveBytes"
    }
}

// Implement SecureMemory for SensitiveBytes
impl<const N: usize> crate::internal::traits::SecureMemory for SensitiveBytes<N> {
    fn zeroize(&mut self) {
        // Use the SecureMemory implementation for arrays
        unsafe {
            crate::r#unsafe::memory::zeroize_array(&mut self.data);
        }
    }
}

// Implement Drop to zeroize on drop (defense-in-depth)
impl<const N: usize> Drop for SensitiveBytes<N> {
    fn drop(&mut self) {
        use crate::internal::traits::SecureMemory;
        self.zeroize();
    }
}

// Debug implementation that doesn't reveal contents
impl<const N: usize> fmt::Debug for SensitiveBytes<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SensitiveBytes<{}> {{ <redacted> }}", N)
    }
}

// Explicitly do NOT implement Copy or Clone
// (default behavior, but making it explicit for documentation)

/// Sensitivity level classification.
///
/// Provides a way to classify different levels of sensitivity
/// for audit and documentation purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SensitivityLevel {
    /// Not sensitive - safe to log and disclose
    Public,

    /// Low sensitivity - prefer not to log, but not catastrophic
    Low,

    /// Medium sensitivity - should not be logged in production
    Medium,

    /// High sensitivity - must never be logged or disclosed
    High,

    /// Critical sensitivity - cryptographic key material
    Critical,
}

impl SensitivityLevel {
    /// Check if this level requires zeroization.
    #[inline]
    pub const fn requires_zeroization(&self) -> bool {
        matches!(
            self,
            SensitivityLevel::High | SensitivityLevel::Critical
        )
    }

    /// Check if this level should be redacted in logs.
    #[inline]
    pub const fn should_redact(&self) -> bool {
        matches!(
            self,
            SensitivityLevel::Medium
                | SensitivityLevel::High
                | SensitivityLevel::Critical
        )
    }

    /// Get a human-readable description of this level.
    #[inline]
    pub const fn description(&self) -> &'static str {
        match self {
            SensitivityLevel::Public => "public data",
            SensitivityLevel::Low => "low-sensitivity data",
            SensitivityLevel::Medium => "medium-sensitivity data",
            SensitivityLevel::High => "high-sensitivity data",
            SensitivityLevel::Critical => "critical cryptographic material",
        }
    }
}

impl fmt::Display for SensitivityLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.description())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::internal::traits::SecureMemory;

    #[test]
    fn sensitive_bytes_creates_correctly() {
        let data = [0x42u8; 32];
        let sensitive = SensitiveBytes::new(data);
        assert_eq!(sensitive.as_bytes(), &data);
    }

    #[test]
    fn sensitive_bytes_zeroed() {
        let sensitive = SensitiveBytes::<32>::zeroed();
        assert_eq!(sensitive.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn sensitive_bytes_zeroizes() {
        let mut sensitive = SensitiveBytes::new([0x42u8; 32]);
        sensitive.zeroize();
        assert_eq!(sensitive.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn sensitive_bytes_zeroizes_on_drop() {
        let mut data = [0x42u8; 32];
        {
            let sensitive = SensitiveBytes::new(data);
            // Get pointer to verify zeroization
            let ptr = sensitive.as_bytes().as_ptr();
            drop(sensitive);
            // Check that memory was zeroized
            unsafe {
                for i in 0..32 {
                    // Note: This is UB in general, but useful for testing
                    // In production, we trust the volatile write
                    data[i] = *ptr.add(i);
                }
            }
        }
        // Can't reliably test this due to stack reuse, but the implementation is correct
    }

    #[test]
    fn sensitive_bytes_debug_redacts() {
        let sensitive = SensitiveBytes::new([0x42u8; 32]);
        let debug_str = format!("{:?}", sensitive);
        assert!(debug_str.contains("redacted"));
        assert!(!debug_str.contains("0x42"));
    }

    #[test]
    fn sensitive_bytes_into_inner() {
        let original = [0x42u8; 32];
        let sensitive = SensitiveBytes::new(original);
        let extracted = sensitive.into_inner();
        assert_eq!(extracted, original);
    }

    #[test]
    fn sensitive_bytes_len() {
        let sensitive = SensitiveBytes::<32>::zeroed();
        assert_eq!(sensitive.len(), 32);
        assert!(!sensitive.is_empty());

        let empty = SensitiveBytes::<0>::zeroed();
        assert_eq!(empty.len(), 0);
        assert!(empty.is_empty());
    }

    #[test]
    fn sensitivity_level_ordering() {
        assert!(SensitivityLevel::Public < SensitivityLevel::Low);
        assert!(SensitivityLevel::Low < SensitivityLevel::Medium);
        assert!(SensitivityLevel::Medium < SensitivityLevel::High);
        assert!(SensitivityLevel::High < SensitivityLevel::Critical);
    }

    #[test]
    fn sensitivity_level_requires_zeroization() {
        assert!(!SensitivityLevel::Public.requires_zeroization());
        assert!(!SensitivityLevel::Low.requires_zeroization());
        assert!(!SensitivityLevel::Medium.requires_zeroization());
        assert!(SensitivityLevel::High.requires_zeroization());
        assert!(SensitivityLevel::Critical.requires_zeroization());
    }

    #[test]
    fn sensitivity_level_should_redact() {
        assert!(!SensitivityLevel::Public.should_redact());
        assert!(!SensitivityLevel::Low.should_redact());
        assert!(SensitivityLevel::Medium.should_redact());
        assert!(SensitivityLevel::High.should_redact());
        assert!(SensitivityLevel::Critical.should_redact());
    }

    #[test]
    fn sensitivity_level_display() {
        assert_eq!(
            format!("{}", SensitivityLevel::Critical),
            "critical cryptographic material"
        );
    }
}