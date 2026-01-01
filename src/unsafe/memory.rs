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
pub fn zeroize_slice(data: &mut [u8]) {
    for byte in data.iter_mut() {
        // Use volatile write to prevent compiler optimization
        unsafe {
            core::ptr::write_volatile(byte, 0);
        }
    }
    // Add a compiler fence to prevent reordering
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}