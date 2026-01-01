//! Internal trait abstractions for cryptographic operations.
//!
//! # Purpose
//!
//! This module defines internal-only trait abstractions that enable:
//! - Algorithm-agnostic implementations while maintaining explicit control
//! - Type-safe interfaces with compile-time size guarantees
//! - Consistent error handling across cryptographic operations
//! - Support for hybrid constructions through composition
//!
//! # NOT PUBLIC API
//!
//! These traits are internal implementation details. They are NOT part of the
//! public API and may change without notice. Public APIs expose concrete types,
//! not these trait abstractions.
//!
//! # Design Principles
//!
//! 1. **Security-First**: Traits must not enable timing leaks or side-channels
//! 2. **Explicit Constraints**: All sizes and requirements in type signatures
//! 3. **Stateless**: No mutable state in trait methods (except contexts)
//! 4. **Sized**: All trait objects are Sized, no lifetime parameters
//! 5. **No Implicit Cloning**: No Copy/Clone to prevent accidental key duplication
//! 6. **Validation Required**: All parameters validated, return MisuseError on invalid input
//!
//! # Structure
//!
//! - `kem`: Key encapsulation mechanism traits
//! - `signature`: Digital signature scheme traits  
//! - `symmetric`: Symmetric cipher traits (AEAD)
//! - `hash`: Cryptographic hash function traits
//! - `memory`: Secure memory handling traits
//! - `validation`: Parameter validation functions
//!
//! # Hybrid Composition
//!
//! Hybrid constructions are implemented through wrapper types that compose
//! post-quantum and classical implementations, NOT through trait extension.

pub mod kem;
pub mod signature;
pub mod symmetric;
pub mod hash;
pub mod memory;
pub mod validation;

// Re-export commonly used types
pub use kem::KeyEncapsulation;
pub use signature::SignatureScheme;
pub use symmetric::AeadCipher;
pub use hash::{HashFunction, HashContext};
pub use memory::SecureMemory;