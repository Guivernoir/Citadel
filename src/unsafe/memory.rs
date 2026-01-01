//! Unsafe memory operations for secure zeroization.
//!
//! This module isolates all unsafe code required for secure memory handling.
//! Functions here use volatile writes and compiler barriers to prevent
//! optimization removal of security-critical operations.
//!
//! # Safety
//!
//! All functions in this module are `unsafe` because they:
//! - Perform volatile writes that bypass Rust's safety guarantees
//! - Use raw pointers
//! - Invoke compiler intrinsics
//!
//! Callers must ensure:
//! - Pointers are valid and properly aligned
//! - Memory regions don't overlap (for multi-region operations)
//! - No concurrent access to being-zeroized memory

use core::sync::atomic::{compiler_fence, Ordering};

/// Helper function to zeroize a slice using volatile writes.
///
/// This function provides a reusable implementation for zeroizing byte slices
/// with guaranteed execution (not optimized away by compiler).
///
/// # Arguments
///
/// - `data`: Mutable slice to zeroize
///
/// # Implementation Note
///
/// Uses `core::ptr::write_volatile` to ensure the compiler cannot optimize
/// away the zeroization.
///
/// # Example
///
/// ```ignore
/// impl SecureMemory for MyKey {
///     fn zeroize(&mut self) {
///         zeroize_slice(&mut self.bytes);
///     }
/// }
/// ```
#[inline]
pub unsafe fn zeroize_slice(data: &mut [u8]) {
    for byte in data.iter_mut() {
        // Use volatile write to prevent compiler optimization
        core::ptr::write_volatile(byte, 0);    
    }
    // Add a compiler fence to prevent reordering
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// Zeroize a byte slice using volatile writes.
///
/// This function overwrites all bytes in the slice with zeros using
/// `core::ptr::write_volatile`, which cannot be optimized away by the compiler.
///
/// # Safety
///
/// - `data` must be a valid, properly aligned mutable slice
/// - No other references to `data` may exist during this operation
/// - The memory must not be accessed concurrently
///
/// # Implementation Notes
///
/// 1. Each byte is written individually using `write_volatile`
/// 2. A `SeqCst` compiler fence prevents reordering
/// 3. The fence does NOT prevent hardware reordering (CPU-level)
///
/// # Example
///
/// ```ignore
/// let mut secret = [0x42u8; 32];
/// unsafe {
///     zeroize_volatile(&mut secret);
/// }
/// assert_eq!(&secret, &[0u8; 32]);
/// ```
#[inline]
pub unsafe fn zeroize_volatile(data: &mut [u8]) {
    // Write each byte individually with volatile semantics
    for byte in data.iter_mut() {
        // SAFETY: Caller guarantees the pointer is valid and properly aligned
        core::ptr::write_volatile(byte as *mut u8, 0);
    }

    // Compiler fence prevents reordering of the zeroization
    // SeqCst is strongest ordering - prevents all reordering
    compiler_fence(Ordering::SeqCst);
}

/// Zeroize a fixed-size array using volatile writes.
///
/// Type-safe wrapper around `zeroize_volatile` for arrays.
///
/// # Safety
///
/// Same safety requirements as `zeroize_volatile`.
///
/// # Example
///
/// ```ignore
/// let mut key = [0x42u8; 32];
/// unsafe {
///     zeroize_array(&mut key);
/// }
/// assert_eq!(key, [0u8; 32]);
/// ```
#[inline]
pub unsafe fn zeroize_array<const N: usize>(data: &mut [u8; N]) {
    // SAFETY: Array is a contiguous slice, safety requirements passed through
    zeroize_volatile(data.as_mut_slice());
}

/// Zeroize multiple byte slices in sequence.
///
/// Useful for zeroizing composite structures with multiple sensitive fields.
///
/// # Safety
///
/// - All slices must be valid and properly aligned
/// - Slices must not overlap
/// - No concurrent access to any slice
///
/// # Example
///
/// ```ignore
/// let mut key = [0x42u8; 32];
/// let mut nonce = [0x43u8; 12];
/// unsafe {
///     zeroize_multiple(&mut [&mut key[..], &mut nonce[..]]);
/// }
/// ```
#[inline]
pub unsafe fn zeroize_multiple(regions: &mut [&mut [u8]]) {
    for region in regions.iter_mut() {
        // SAFETY: Caller guarantees no overlap and valid slices
        zeroize_volatile(region);
    }
}

/// Check if a memory region is fully zeroed.
///
/// This is primarily useful for testing and verification.
/// NOT constant-time - do not use in security-critical comparisons.
///
/// # Safety
///
/// - `data` must be a valid slice
/// - Safe for testing, but timing-dependent
///
/// # Returns
///
/// `true` if all bytes are zero, `false` otherwise.
///
/// # Example
///
/// ```ignore
/// let data = [0u8; 32];
/// unsafe {
///     assert!(is_zeroized(&data));
/// }
/// ```
#[inline]
pub unsafe fn is_zeroized(data: &[u8]) -> bool {
    // NOT constant-time - early exit on first non-zero byte
    data.iter().all(|&b| b == 0)
}

/// Overwrite memory with a specific byte pattern.
///
/// Similar to `zeroize_volatile` but with a custom fill byte.
/// Useful for debugging or specific security protocols.
///
/// # Safety
///
/// Same safety requirements as `zeroize_volatile`.
///
/// # Arguments
///
/// - `data`: Memory region to overwrite
/// - `pattern`: Byte value to write
///
/// # Example
///
/// ```ignore
/// let mut buffer = [0u8; 32];
/// unsafe {
///     fill_volatile(&mut buffer, 0xFF);
/// }
/// assert_eq!(&buffer, &[0xFFu8; 32]);
/// ```
#[inline]
pub unsafe fn fill_volatile(data: &mut [u8], pattern: u8) {
    for byte in data.iter_mut() {
        // SAFETY: Caller guarantees validity
        core::ptr::write_volatile(byte as *mut u8, pattern);
    }
    compiler_fence(Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zeroize_volatile_works() {
        let mut data = [0x42u8; 32];
        unsafe {
            zeroize_volatile(&mut data);
        }
        assert_eq!(&data, &[0u8; 32]);
    }

    #[test]
    fn zeroize_array_works() {
        let mut key = [0x42u8; 32];
        unsafe {
            zeroize_array(&mut key);
        }
        assert_eq!(key, [0u8; 32]);
    }

    #[test]
    fn zeroize_multiple_works() {
        let mut buf1 = [0x42u8; 16];
        let mut buf2 = [0x43u8; 24];
        let mut buf3 = [0x44u8; 8];

        unsafe {
            zeroize_multiple(&mut [&mut buf1[..], &mut buf2[..], &mut buf3[..]]);
        }

        assert_eq!(&buf1, &[0u8; 16]);
        assert_eq!(&buf2, &[0u8; 24]);
        assert_eq!(&buf3, &[0u8; 8]);
    }

    #[test]
    fn is_zeroized_detects_zeros() {
        let zeros = [0u8; 32];
        let non_zeros = [0x42u8; 32];

        unsafe {
            assert!(is_zeroized(&zeros));
            assert!(!is_zeroized(&non_zeros));
        }
    }

    #[test]
    fn is_zeroized_detects_partial() {
        let mut partial = [0u8; 32];
        partial[16] = 0x42;

        unsafe {
            assert!(!is_zeroized(&partial));
        }
    }

    #[test]
    fn fill_volatile_works() {
        let mut buffer = [0u8; 32];
        unsafe {
            fill_volatile(&mut buffer, 0xFF);
        }
        assert_eq!(&buffer, &[0xFFu8; 32]);
    }

    #[test]
    fn fill_volatile_with_zero_equivalent_to_zeroize() {
        let mut buf1 = [0x42u8; 32];
        let mut buf2 = [0x42u8; 32];

        unsafe {
            fill_volatile(&mut buf1, 0);
            zeroize_volatile(&mut buf2);
        }

        assert_eq!(buf1, buf2);
        assert_eq!(&buf1, &[0u8; 32]);
    }

    #[test]
    fn zeroize_empty_slice_safe() {
        let mut empty: [u8; 0] = [];
        unsafe {
            zeroize_volatile(&mut empty);
        }
        // Should not panic
    }

    #[test]
    fn multiple_zeroizations_idempotent() {
        let mut data = [0x42u8; 32];

        unsafe {
            zeroize_volatile(&mut data);
            zeroize_volatile(&mut data);
            zeroize_volatile(&mut data);
        }

        assert_eq!(&data, &[0u8; 32]);
    }
}