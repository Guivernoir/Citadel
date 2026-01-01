//! Secure memory handling trait.
//!
//! # Security Properties
//!
//! Implementations MUST:
//! - Overwrite sensitive data with zeros when `zeroize()` is called
//! - Use compiler barriers or volatile writes to prevent optimization removal
//! - Zeroize in Drop implementation (recommended)
//!
//! Implementations MUST NOT:
//! - Rely on optimizer behavior for zeroization
//! - Leave sensitive data in memory after zeroization
//! - Implement Copy or Clone (prevents accidental duplication)
//!
//! # Design Philosophy
//!
//! This trait provides **explicit** zeroization control. Unlike automatic
//! zeroization-on-drop patterns, callers must explicitly invoke `zeroize()`.
//!
//! This design choice is intentional:
//! - Makes security-critical operations visible in code
//! - Allows zeroization at specific points before drop
//! - Prevents false sense of security from "auto-magic" behavior
//!
//! Types SHOULD implement zeroization in their Drop implementation as a
//! defense-in-depth measure, but callers should not rely solely on this.

/// Secure memory handling trait for types containing sensitive data.
///
/// This trait marks types that contain cryptographic secrets (keys, plaintexts,
/// shared secrets, etc.) and require explicit zeroization.
///
/// # Zeroization Guarantees
///
/// Implementing `SecureMemory` signals:
/// - The type contains sensitive data
/// - The type will overwrite its memory with zeros when `zeroize()` is called
/// - Zeroization uses compiler barriers to prevent optimization removal
///
/// # Usage
///
/// ```ignore
/// let mut key = [0u8; 32];
/// // ... use key ...
/// key.zeroize(); // Explicit zeroization
/// // key memory is now all zeros
/// ```
///
/// # Best Practices
///
/// 1. Call `zeroize()` explicitly when done with sensitive data
/// 2. Do not rely solely on Drop-based zeroization
/// 3. Minimize sensitive data lifetime
/// 4. Avoid cloning sensitive data
///
/// # Not Automatic
///
/// Unlike some libraries, this trait does NOT automatically zeroize on drop.
/// Callers must explicitly call `zeroize()`. This is intentional for explicitness.
///
/// Types MAY implement `Drop` to call `zeroize()` as defense-in-depth, but
/// this should not be the primary zeroization mechanism.

use crate::r#unsafe::zeroize_slice;

pub trait SecureMemory {
    /// Securely overwrite this value's memory with zeros.
    ///
    /// This operation:
    /// - Overwrites all sensitive bytes with 0x00
    /// - Uses compiler barriers to prevent optimization removal
    /// - Is NOT guaranteed to affect copies made before this call
    ///
    /// # After Zeroization
    ///
    /// After calling `zeroize()`, the value should be considered invalid
    /// for cryptographic use. Do not attempt to use it.
    ///
    /// # Multiple Calls
    ///
    /// Calling `zeroize()` multiple times is safe but unnecessary.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut secret = [0x42u8; 32];
    /// secret.zeroize();
    /// assert_eq!(&secret, &[0u8; 32]);
    /// ```
    fn zeroize(&mut self);
}

// Implement SecureMemory for common sensitive types
impl SecureMemory for [u8; 32] {
    fn zeroize(&mut self) {
        zeroize_slice(self);
    }
}

impl SecureMemory for Vec<u8> {
    fn zeroize(&mut self) {
        zeroize_slice(self.as_mut_slice());
    }
}

// Implement for fixed-size arrays of common key sizes
macro_rules! impl_secure_memory_array {
    ($($N:expr),+) => {
        $(
            impl SecureMemory for [u8; $N] {
                fn zeroize(&mut self) {
                    zeroize_slice(self);
                }
            }
        )+
    };
}

// Common cryptographic key sizes
impl_secure_memory_array!(
    16, 24, 48, 64, 96, 128, 256, 512, 1024, 2048, 3168, 4032
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zeroize_slice_works() {
        let mut data = [0x42u8; 32];
        zeroize_slice(&mut data);
        assert_eq!(&data, &[0u8; 32]);
    }

    #[test]
    fn zeroize_array_works() {
        let mut key = [0x42u8; 32];
        key.zeroize();
        assert_eq!(&key, &[0u8; 32]);
    }

    #[test]
    fn zeroize_vec_works() {
        let mut secret = vec![0x42u8; 100];
        secret.zeroize();
        assert_eq!(&secret, &vec![0u8; 100]);
    }

    #[test]
    fn multiple_zeroize_is_safe() {
        let mut data = [0x42u8; 16];
        data.zeroize();
        data.zeroize();
        data.zeroize();
        assert_eq!(&data, &[0u8; 16]);
    }

    // Verify SecureMemory is implemented for common sizes
    #[test]
    fn trait_implemented_for_common_sizes() {
        fn assert_secure_memory<T: SecureMemory>() {}
        assert_secure_memory::<[u8; 16]>();
        assert_secure_memory::<[u8; 32]>();
        assert_secure_memory::<[u8; 64]>();
        assert_secure_memory::<Vec<u8>>();
    }
}