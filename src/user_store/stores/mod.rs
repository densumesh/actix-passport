/// In-memory user store implementation.
pub mod in_memory;

/// Common utilities shared across store implementations.
pub mod common;

/// `PostgreSQL` user store implementation.
#[cfg(feature = "postgres")]
pub mod postgres;
