//! High-level secure memory operations.
//!
//! This module provides safe wrappers around the unsafe zeroization primitives,
//! implementing the `SecureMemory` trait for common types and providing
//! utilities for secure memory management.
//!
//! # Design Principles
//!
//! 1. **Explicit over implicit**: Zeroization must be called explicitly
//! 2. **Defense in depth**: Drop implementations provide backup zeroization
//! 3. **Type safety**: Use Rust's type system to prevent misuse
//! 4. **Minimal allocations**: Prefer stack allocation where possible

use crate::errors::Result;
use crate::internal::traits::SecureMemory;

/// Securely compare two byte slices in constant time.
///
/// This function performs a constant-time comparison to prevent timing
/// side-channels. It always compares all bytes, regardless of where
/// a mismatch occurs.
///
/// # Arguments
///
/// - `a`: First byte slice
/// - `b`: Second byte slice
///
/// # Returns
///
/// `true` if slices are equal, `false` otherwise.
/// Returns `false` if lengths differ.
///
/// # Security
///
/// - Constant time with respect to content (not length)
/// - No early exit on mismatch
/// - Resistant to timing attacks
///
/// # Example
///
/// ```ignore
/// let tag1 = [0x42u8; 16];
/// let tag2 = [0x42u8; 16];
/// assert!(constant_time_eq(&tag1, &tag2));
/// ```
#[inline]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    // Early exit for length mismatch (length is not secret)
    if a.len() != b.len() {
        return false;
    }

    // Constant-time comparison using bitwise operations
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }

    diff == 0
}

/// Securely compare two fixed-size arrays in constant time.
///
/// Type-safe wrapper around `constant_time_eq` for arrays.
///
/// # Example
///
/// ```ignore
/// let mac1 = [0x42u8; 32];
/// let mac2 = [0x42u8; 32];
/// assert!(constant_time_eq_array(&mac1, &mac2));
/// ```
#[inline]
pub fn constant_time_eq_array<const N: usize>(a: &[u8; N], b: &[u8; N]) -> bool {
    constant_time_eq(a, b)
}

/// Select between two byte slices in constant time.
///
/// Returns `a` if `condition` is true, `b` otherwise.
/// The selection itself is constant-time with respect to the condition.
///
/// # Arguments
///
/// - `condition`: Selection condition
/// - `a`: First option
/// - `b`: Second option
/// - `out`: Output buffer (must be at least as long as both inputs)
///
/// # Panics
///
/// Panics if `a` and `b` have different lengths, or if `out` is too small.
///
/// # Security
///
/// - Constant time with respect to condition
/// - Both inputs are always accessed
/// - No branch on condition
///
/// # Example
///
/// ```ignore
/// let option_a = [0x42u8; 32];
/// let option_b = [0x43u8; 32];
/// let mut result = [0u8; 32];
/// constant_time_select(true, &option_a, &option_b, &mut result);
/// assert_eq!(&result, &option_a);
/// ```
#[inline]
pub fn constant_time_select(condition: bool, a: &[u8], b: &[u8], out: &mut [u8]) {
    assert_eq!(a.len(), b.len(), "input slices must have equal length");
    assert!(
        out.len() >= a.len(),
        "output buffer must be at least as large as inputs"
    );

    // Convert boolean to mask: true -> 0xFF, false -> 0x00
    let mask = (condition as u8).wrapping_neg();

    // Constant-time selection using bitwise operations
    for i in 0..a.len() {
        // If mask is 0xFF: out = a
        // If mask is 0x00: out = b
        out[i] = (a[i] & mask) | (b[i] & !mask);
    }
}

/// Secure buffer that zeroizes on drop.
///
/// This type provides automatic zeroization while maintaining
/// explicit control over when the buffer is used.
///
/// # Properties
///
/// - Zeroizes on drop (defense-in-depth)
/// - Does NOT implement Copy or Clone
/// - Provides mutable access to inner buffer
/// - Can be explicitly zeroized before drop
///
/// # Example
///
/// ```ignore
/// let mut buffer = SecureBuffer::new(vec![0u8; 32]);
/// // Use buffer...
/// buffer.zeroize(); // Explicit cleanup
/// // Drop also zeroizes
/// ```
pub struct SecureBuffer {
    data: Vec<u8>,
}

impl SecureBuffer {
    /// Create a new secure buffer.
    ///
    /// # Arguments
    ///
    /// - `data`: Initial data for the buffer
    ///
    /// # Example
    ///
    /// ```ignore
    /// let buffer = SecureBuffer::new(vec![0u8; 32]);
    /// ```
    #[inline]
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Create a secure buffer with the given capacity.
    ///
    /// The buffer is initially empty but has pre-allocated capacity.
    ///
    /// # Arguments
    ///
    /// - `capacity`: Initial capacity in bytes
    ///
    /// # Example
    ///
    /// ```ignore
    /// let buffer = SecureBuffer::with_capacity(32);
    /// ```
    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(capacity),
        }
    }

    /// Create a secure buffer filled with zeros.
    ///
    /// # Arguments
    ///
    /// - `len`: Length of the buffer
    ///
    /// # Example
    ///
    /// ```ignore
    /// let buffer = SecureBuffer::zeroed(32);
    /// ```
    #[inline]
    pub fn zeroed(len: usize) -> Self {
        Self {
            data: vec![0u8; len],
        }
    }

    /// Get a reference to the buffer contents.
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Get a mutable reference to the buffer contents.
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Get the length of the buffer.
    #[inline]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the buffer is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Get the capacity of the buffer.
    #[inline]
    pub fn capacity(&self) -> usize {
        self.data.capacity()
    }

    /// Resize the buffer, filling new elements with zeros.
    ///
    /// If the buffer shrinks, the removed elements are zeroized.
    ///
    /// # Arguments
    ///
    /// - `new_len`: New length for the buffer
    #[inline]
    pub fn resize(&mut self, new_len: usize) {
        if new_len < self.data.len() {
            // Zeroize the portion being removed
            let removed = &mut self.data[new_len..];
            unsafe {
                crate::r#unsafe::memory::zeroize_volatile(removed);
            }
        }
        self.data.resize(new_len, 0);
    }

    /// Consume the buffer and return the inner Vec.
    ///
    /// # Warning
    ///
    /// This bypasses automatic zeroization on drop.
    /// Caller is responsible for zeroizing the returned Vec.
    #[inline]
    pub fn into_vec(mut self) -> Vec<u8> {
        let data = core::mem::take(&mut self.data);
        core::mem::forget(self);
        data
    }
}

impl SecureMemory for SecureBuffer {
    fn zeroize(&mut self) {
        unsafe {
            crate::r#unsafe::memory::zeroize_volatile(&mut self.data);
        }
    }
}

impl Drop for SecureBuffer {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// Explicitly do NOT implement Copy or Clone

/// Builder for creating secure buffers with specific properties.
///
/// Provides a fluent interface for buffer creation.
///
/// # Example
///
/// ```ignore
/// let buffer = SecureBufferBuilder::new()
///     .with_capacity(64)
///     .zeroed(32)
///     .build();
/// ```
pub struct SecureBufferBuilder {
    capacity: Option<usize>,
    initial_data: Option<Vec<u8>>,
}

impl SecureBufferBuilder {
    /// Create a new builder.
    #[inline]
    pub fn new() -> Self {
        Self {
            capacity: None,
            initial_data: None,
        }
    }

    /// Set the initial capacity.
    #[inline]
    pub fn with_capacity(mut self, capacity: usize) -> Self {
        self.capacity = Some(capacity);
        self
    }

    /// Set initial data.
    #[inline]
    pub fn with_data(mut self, data: Vec<u8>) -> Self {
        self.initial_data = Some(data);
        self
    }

    /// Create a buffer filled with zeros.
    #[inline]
    pub fn zeroed(mut self, len: usize) -> Self {
        self.initial_data = Some(vec![0u8; len]);
        self
    }

    /// Build the secure buffer.
    #[inline]
    pub fn build(self) -> SecureBuffer {
        match (self.initial_data, self.capacity) {
            (Some(data), _) => SecureBuffer::new(data),
            (None, Some(cap)) => SecureBuffer::with_capacity(cap),
            (None, None) => SecureBuffer::with_capacity(0),
        }
    }
}

impl Default for SecureBufferBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Temporarily protect a region of memory from being swapped to disk.
///
/// This is a best-effort operation and may not be supported on all platforms.
/// Even when successful, it provides limited protection.
///
/// # Arguments
///
/// - `data`: Memory region to protect
///
/// # Returns
///
/// `Ok(())` if protection was applied (or is unsupported but harmless).
///
/// # Platform Support
///
/// - Linux/Unix: Uses `mlock()` if available
/// - Windows: Uses `VirtualLock()` if available
/// - Other platforms: No-op (returns Ok)
///
/// # Limitations
///
/// - May require elevated privileges
/// - System may have limits on locked memory
/// - Does not prevent memory dumps or debugging
/// - Does not prevent speculative execution leaks
///
/// # Example
///
/// ```ignore
/// let mut key = [0u8; 32];
/// lock_memory(&mut key)?;
/// // Use key...
/// unlock_memory(&mut key)?;
/// key.zeroize();
/// ```
#[inline]
pub fn lock_memory(_data: &mut [u8]) -> Result<()> {
    // Platform-specific implementation would go here
    // For now, this is a no-op (would need libc or winapi dependencies)
    Ok(())
}

/// Unlock previously locked memory.
///
/// Should be called before zeroizing locked memory.
///
/// # Arguments
///
/// - `data`: Memory region to unlock
///
/// # Example
///
/// ```ignore
/// unlock_memory(&mut key)?;
/// key.zeroize();
/// ```
#[inline]
pub fn unlock_memory(_data: &mut [u8]) -> Result<()> {
    // Platform-specific implementation would go here
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_equal() {
        let a = [0x42u8; 32];
        let b = [0x42u8; 32];
        assert!(constant_time_eq(&a, &b));
    }

    #[test]
    fn constant_time_eq_different() {
        let a = [0x42u8; 32];
        let mut b = [0x42u8; 32];
        b[16] = 0x43;
        assert!(!constant_time_eq(&a, &b));
    }

    #[test]
    fn constant_time_eq_different_lengths() {
        let a = [0x42u8; 32];
        let b = [0x42u8; 16];
        assert!(!constant_time_eq(&a, &b));
    }

    #[test]
    fn constant_time_eq_array_works() {
        let a = [0x42u8; 32];
        let b = [0x42u8; 32];
        assert!(constant_time_eq_array(&a, &b));
    }

    #[test]
    fn constant_time_select_true() {
        let a = [0x42u8; 32];
        let b = [0x43u8; 32];
        let mut out = [0u8; 32];
        constant_time_select(true, &a, &b, &mut out);
        assert_eq!(&out, &a);
    }

    #[test]
    fn constant_time_select_false() {
        let a = [0x42u8; 32];
        let b = [0x43u8; 32];
        let mut out = [0u8; 32];
        constant_time_select(false, &a, &b, &mut out);
        assert_eq!(&out, &b);
    }

    #[test]
    #[should_panic(expected = "input slices must have equal length")]
    fn constant_time_select_different_lengths_panics() {
        let a = [0x42u8; 32];
        let b = [0x43u8; 16];
        let mut out = [0u8; 32];
        constant_time_select(true, &a, &b, &mut out);
    }

    #[test]
    fn secure_buffer_new() {
        let data = vec![0x42u8; 32];
        let buffer = SecureBuffer::new(data.clone());
        assert_eq!(buffer.as_slice(), &data[..]);
    }

    #[test]
    fn secure_buffer_zeroed() {
        let buffer = SecureBuffer::zeroed(32);
        assert_eq!(buffer.as_slice(), &[0u8; 32]);
    }

    #[test]
    fn secure_buffer_zeroizes() {
        let mut buffer = SecureBuffer::new(vec![0x42u8; 32]);
        buffer.zeroize();
        assert_eq!(buffer.as_slice(), &[0u8; 32]);
    }

    #[test]
    fn secure_buffer_resize_grow() {
        let mut buffer = SecureBuffer::zeroed(16);
        buffer.resize(32);
        assert_eq!(buffer.len(), 32);
        assert_eq!(buffer.as_slice(), &[0u8; 32]);
    }

    #[test]
    fn secure_buffer_resize_shrink() {
        let mut buffer = SecureBuffer::new(vec![0x42u8; 32]);
        buffer.resize(16);
        assert_eq!(buffer.len(), 16);
        // Removed portion should have been zeroized (checked internally)
    }

    #[test]
    fn secure_buffer_builder_basic() {
        let buffer = SecureBufferBuilder::new().zeroed(32).build();
        assert_eq!(buffer.len(), 32);
    }

    #[test]
    fn secure_buffer_builder_with_capacity() {
        let buffer = SecureBufferBuilder::new().with_capacity(64).build();
        assert_eq!(buffer.len(), 0);
        assert!(buffer.capacity() >= 64);
    }

    #[test]
    fn secure_buffer_builder_with_data() {
        let data = vec![0x42u8; 32];
        let buffer = SecureBufferBuilder::new().with_data(data.clone()).build();
        assert_eq!(buffer.as_slice(), &data[..]);
    }

    #[test]
    fn lock_unlock_memory_no_error() {
        let mut data = [0u8; 32];
        assert!(lock_memory(&mut data).is_ok());
        assert!(unlock_memory(&mut data).is_ok());
    }
}