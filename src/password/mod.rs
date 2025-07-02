//! Password-based authentication module.
//!
//! This module provides functionality for username/password authentication,
//! including password hashing, verification, and user registration.

pub mod hasher;
pub mod service;

use crate::types::AuthResult;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Credentials for password-based login.
///
/// This struct represents the user's login credentials, supporting
/// both email and username-based authentication.
///
/// # Examples
///
/// ```rust
/// use actix_passport::LoginCredentials;
///
/// let creds = LoginCredentials {
///     identifier: "user@example.com".to_string(),
///     password: "secure_password".to_string(),
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginCredentials {
    /// Email address or username
    pub identifier: String,
    /// Plain text password
    pub password: String,
}

/// Credentials for user registration.
///
/// This struct contains all the information needed to register a new user
/// with password-based authentication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterCredentials {
    /// User's email address
    pub email: String,
    /// Desired username (optional)
    pub username: Option<String>,
    /// Plain text password
    pub password: String,
    /// User's display name (optional)
    pub display_name: Option<String>,
}

/// Trait for password hashing and verification.
///
/// This trait allows for pluggable password hashing implementations.
/// The default implementation uses Argon2, but users can provide
/// their own implementations for different hashing algorithms.
///
/// # Examples
///
/// ```rust
/// use actix_passport::{PasswordHasher, AuthResult};
/// use async_trait::async_trait;
///
/// struct MyPasswordHasher;
///
/// #[async_trait]
/// impl PasswordHasher for MyPasswordHasher {
///     async fn hash_password(&self, password: &str) -> AuthResult<String> {
///         // Custom hashing implementation
///         Ok("hashed_password".to_string())
///     }
///     
///     async fn verify_password(&self, password: &str, hash: &str) -> AuthResult<bool> {
///         // Custom verification implementation
///         Ok(password == "correct_password")
///     }
/// }
/// ```
#[async_trait]
pub trait PasswordHasher: Send + Sync {
    /// Hashes a plain text password.
    ///
    /// # Arguments
    ///
    /// * `password` - The plain text password to hash
    ///
    /// # Returns
    ///
    /// Returns the hashed password as a string.
    async fn hash_password(&self, password: &str) -> AuthResult<String>;

    /// Verifies a password against its hash.
    ///
    /// # Arguments
    ///
    /// * `password` - The plain text password to verify
    /// * `hash` - The stored password hash
    ///
    /// # Returns
    ///
    /// Returns `true` if the password matches the hash, `false` otherwise.
    async fn verify_password(&self, password: &str, hash: &str) -> AuthResult<bool>;
}
