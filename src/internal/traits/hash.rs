//! Cryptographic Hash Function trait.
//!
//! # Security Properties
//!
//! Implementations MUST:
//! - Provide collision resistance
//! - Provide preimage resistance
//! - Provide second preimage resistance
//! - Produce deterministic output
//! - Support arbitrary-length input
//!
//! Implementations MUST NOT:
//! - Use keyed hashing (use HMAC/KDF for that)
//! - Perform non-deterministic operations
//! - Log or expose intermediate state
//!
//! # Const Generics
//!
//! - `OUTPUT_SIZE`: Size of hash output in bytes

use crate::errors::Result;

/// Cryptographic Hash Function trait.
///
/// Provides one-shot and incremental hashing operations.
/// Output size is a compile-time constant enforced through const generics.
///
/// # Type Parameters
///
/// - `OUTPUT_SIZE`: Hash output size in bytes
///
/// # Determinism
///
/// Hash functions are deterministic: the same input always produces the same output.
///
/// # Example
///
/// ```ignore
/// fn hash_data<H>(hasher: &H, data: &[u8]) -> [u8; 48]
/// where
///     H: HashFunction<48>
/// {
///     hasher.hash(data).unwrap()
/// }
/// ```
pub trait HashFunction<const OUTPUT_SIZE: usize>: Sized {
    /// Hash data in a single operation.
    ///
    /// # Arguments
    ///
    /// - `input`: Data to hash (arbitrary length)
    ///
    /// # Returns
    ///
    /// The hash output.
    ///
    /// # Errors
    ///
    /// This operation should not fail under normal circumstances.
    /// `MisuseError` may be returned if the implementation is in an invalid state.
    ///
    /// # Security
    ///
    /// - Deterministic: same input produces same output
    /// - No secret keys involved (use HMAC for keyed hashing)
    fn hash(&self, input: &[u8]) -> Result<[u8; OUTPUT_SIZE]>;

    /// Create a new hasher context for incremental hashing.
    ///
    /// # Returns
    ///
    /// A hasher context that can be updated incrementally.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let mut ctx = hasher.new_context();
    /// ctx.update(b"Hello, ");
    /// ctx.update(b"world!");
    /// let hash = ctx.finalize();
    /// ```
    fn new_context(&self) -> Box<dyn HashContext<OUTPUT_SIZE>>;
}

/// Incremental hash computation context.
///
/// Allows hashing data in multiple chunks. This is a stateful context
/// (unlike the trait itself which is stateless).
///
/// # Type Parameters
///
/// - `OUTPUT_SIZE`: Hash output size in bytes
///
/// # Example
///
/// ```ignore
/// let mut ctx = hasher.new_context();
/// for chunk in data.chunks(1024) {
///     ctx.update(chunk);
/// }
/// let hash = ctx.finalize();
/// ```
pub trait HashContext<const OUTPUT_SIZE: usize> {
    /// Update the hash with additional data.
    ///
    /// # Arguments
    ///
    /// - `data`: Data to include in the hash
    ///
    /// # Panics
    ///
    /// May panic if the context has already been finalized (implementation-defined).
    fn update(&mut self, data: &[u8]);

    /// Finalize the hash and return the output.
    ///
    /// # Returns
    ///
    /// The hash output.
    ///
    /// # Note
    ///
    /// After calling `finalize()`, the context is consumed and cannot be used again.
    /// To hash the same data again, create a new context.
    fn finalize(self: Box<Self>) -> [u8; OUTPUT_SIZE];

    /// Reset the context to its initial state.
    ///
    /// Allows reusing the same context for multiple hash computations.
    ///
    /// # Security
    ///
    /// Previous data is cleared from internal state.
    fn reset(&mut self);
}

#[cfg(test)]
mod tests {
    use super::*;

    // Compile-time size verification
    struct MockHash;
    
    impl HashFunction<48> for MockHash {
        fn hash(&self, _input: &[u8]) -> Result<[u8; 48]> {
            unimplemented!("mock")
        }

        fn new_context(&self) -> Box<dyn HashContext<48>> {
            unimplemented!("mock")
        }
    }

    struct MockHashContext;

    impl HashContext<48> for MockHashContext {
        fn update(&mut self, _data: &[u8]) {
            unimplemented!("mock")
        }

        fn finalize(self: Box<Self>) -> [u8; 48] {
            unimplemented!("mock")
        }

        fn reset(&mut self) {
            unimplemented!("mock")
        }
    }

    #[test]
    fn trait_is_sized() {
        fn assert_sized<T: Sized>() {}
        assert_sized::<MockHash>();
        assert_sized::<MockHashContext>();
    }
}