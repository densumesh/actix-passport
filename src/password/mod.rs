//! Password-based authentication module.
//!
//! This module provides functionality for username/password authentication,
//! including password hashing, verification, and user registration.

/// Password authentication service implementation.
pub mod service;

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

