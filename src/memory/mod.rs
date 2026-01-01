//! Secure memory management for cryptographic operations.
//!
//! This module provides facilities for handling sensitive cryptographic material
//! with explicit zeroization, constant-time operations, and type-level safety.
//!
//! # Design Philosophy
//!
//! Security-critical memory operations should be:
//! 1. **Explicit** - Visible in code, not hidden behind abstractions
//! 2. **Type-safe** - Use Rust's type system to prevent misuse
//! 3. **Verifiable** - Implementation inspectable and testable
//! 4. **Defensive** - Multiple layers of protection
//!
//! # Key Components
//!
//! - **Zeroization** - Explicit clearing of sensitive data using volatile writes
//! - **Sensitivity markers** - Type-level tracking of sensitive data
//! - **Constant-time operations** - Comparisons resistant to timing attacks
//! - **Secure buffers** - RAII wrappers with automatic cleanup
//!
//! # Usage Example
//!
//! ```ignore
//! use citadel::memory::{SecureBuffer, SensitiveBytes};
//! use citadel::internal::traits::SecureMemory;
//!
//! // Create a secure buffer for a secret key
//! let mut key = SecureBuffer::zeroed(32);
//! // ... fill with key material ...
//!
//! // Explicitly zeroize when done
//! key.zeroize();
//!
//! // Or use SensitiveBytes for fixed-size secrets
//! let secret = SensitiveBytes::new([0x42u8; 32]);
//! // Automatically zeroized on drop
//! ```
//!
//! # Security Considerations
//!
//! While this module provides tools for secure memory handling, it cannot
//! prevent all attacks:
//!
//! - **Memory dumps** - OS/hardware level dumps may capture secrets
//! - **Speculative execution** - CPU speculation may leak data
//! - **Hardware attacks** - DMA, cold boot attacks, etc.
//! - **Compiler optimizations** - We mitigate but cannot eliminate all risks
//!
//! Use these tools as part of defense-in-depth, not as sole protection.
//!
//! # Platform Support
//!
//! Core functionality (zeroization, constant-time ops) works on all platforms.
//! Platform-specific features (memory locking) may have limited availability.

mod zeroize;
mod sensitivity;

// Re-export public items
pub use zeroize::{
    constant_time_eq, constant_time_eq_array, constant_time_select, lock_memory,
    unlock_memory, SecureBuffer, SecureBufferBuilder,
};

pub use sensitivity::{Sensitive, SensitiveBytes, SensitivityLevel};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_exports_are_accessible() {
        // Verify public API is accessible
        let _buffer = SecureBuffer::zeroed(32);
        let _sensitive = SensitiveBytes::<32>::zeroed();
        let _level = SensitivityLevel::Critical;

        // Verify constant-time operations
        let a = [0u8; 16];
        let b = [0u8; 16];
        assert!(constant_time_eq(&a, &b));
    }

    #[test]
    fn internal_unsafe_accessible() {
        // Internal code can access unsafe operations
        let mut data = [0x42u8; 32];
        unsafe {
            crate::r#unsafe::zeroize_volatile(&mut data);
        }
        assert_eq!(data, [0u8; 32]);
    }
}