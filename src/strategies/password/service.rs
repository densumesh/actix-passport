use crate::{
    errors::AuthError,
    types::{AuthResult, AuthUser},
    UserStore,
};

use argon2::{
    password_hash::{
        rand_core::OsRng, PasswordHash, PasswordHasher as _, PasswordVerifier, SaltString,
    },
    Argon2,
};
use serde::{Deserialize, Serialize};
use serde_json;

/// Credentials for password-based login.
///
/// This struct represents the user's login credentials, supporting
/// both email and username-based authentication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginCredentials {
    /// Email address
    pub email: Option<String>,
    /// Username
    pub username: Option<String>,
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

/// Hashes a password using Argon2.
fn hash_password(password: &str) -> AuthResult<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| AuthError::Internal {
            component: "password_service".to_string(),
            message: format!("Password hashing failed: {e}"),
            context: None,
        })?;

    Ok(password_hash.to_string())
}

/// Verifies a password against its hash using Argon2.
fn verify_password(password: &str, hash: &str) -> AuthResult<bool> {
    let parsed_hash = PasswordHash::new(hash).map_err(|e| AuthError::Internal {
        component: "password_service".to_string(),
        message: format!("Invalid password hash: {e}"),
        context: None,
    })?;

    let argon2 = Argon2::default();

    match argon2.verify_password(password.as_bytes(), &parsed_hash) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Authenticates a user with email/username and password.
///
/// # Arguments
///
/// * `credentials` - The login credentials
///
/// # Returns
///
/// Returns the authenticated user if credentials are valid.
///
/// # Errors
///
/// Returns `AuthError::InvalidCredentials` if the credentials are invalid,
/// or `AuthError::UserNotFound` if the user doesn't exist.
pub async fn login(
    user_store: &dyn UserStore,
    credentials: LoginCredentials,
) -> AuthResult<AuthUser> {
    // Try to find user by email first, then by username
    let user = if let Some(email) = credentials.email {
        user_store.find_by_email(&email).await?
    } else if let Some(username) = credentials.username {
        user_store.find_by_username(&username).await?
    } else {
        return Err(AuthError::invalid_credentials("email or username"));
    };

    let user = user.ok_or_else(|| AuthError::user_not_found("email or username", ""))?;

    // For this example, we assume password hash is stored in metadata
    let stored_hash = user
        .metadata
        .get("password_hash")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AuthError::invalid_credentials("email or username"))?;

    let is_valid = verify_password(&credentials.password, stored_hash)?;

    if !is_valid {
        return Err(AuthError::invalid_credentials("email or username"));
    }

    Ok(user)
}

/// Registers a new user with password authentication.
///
/// # Arguments
///
/// * `credentials` - The registration credentials
///
/// # Returns
///
/// Returns the newly created user.
///
/// # Errors
///
/// Returns an error if the email or username is already taken,
/// or if the user creation fails.
pub async fn register(
    user_store: &dyn UserStore,
    credentials: RegisterCredentials,
) -> AuthResult<AuthUser> {
    // Check if email already exists
    if (user_store.find_by_email(&credentials.email).await?).is_some() {
        return Err(AuthError::RegistrationFailed {
            reason: "Email already exists".to_string(),
            field_errors: std::collections::HashMap::from([(
                "email".to_string(),
                vec!["Email is already taken".to_string()],
            )]),
        });
    }

    // Check if username already exists (if provided)
    if let Some(ref username) = credentials.username {
        if (user_store.find_by_username(username).await?).is_some() {
            return Err(AuthError::RegistrationFailed {
                reason: "Username already exists".to_string(),
                field_errors: std::collections::HashMap::from([(
                    "username".to_string(),
                    vec!["Username is already taken".to_string()],
                )]),
            });
        }
    }

    // Hash the password
    let password_hash = hash_password(&credentials.password)?;

    // Create user with hashed password in metadata
    let mut user = AuthUser::new(uuid::Uuid::new_v4().to_string()).with_email(credentials.email);

    if let Some(username) = credentials.username {
        user = user.with_username(username);
    }

    if let Some(display_name) = credentials.display_name {
        user = user.with_display_name(display_name);
    }

    // Store password hash in metadata
    user.metadata.insert(
        "password_hash".to_string(),
        serde_json::Value::String(password_hash),
    );

    // Create the user
    let created_user = user_store.create_user(user).await?;

    Ok(created_user)
}

/// Changes a user's password.
///
/// # Arguments
///
/// * `user_id` - The ID of the user whose password to change
/// * `old_password` - The user's current password
/// * `new_password` - The new password
///
/// # Returns
///
/// Returns the updated user.
///
/// # Errors
///
/// Returns `AuthError::InvalidCredentials` if the old password is incorrect,
/// or `AuthError::UserNotFound` if the user doesn't exist.
pub async fn change_password(
    user_store: &dyn UserStore,
    user_id: &str,
    old_password: &str,
    new_password: &str,
) -> AuthResult<AuthUser> {
    let mut user = user_store
        .find_by_id(user_id)
        .await?
        .ok_or_else(|| AuthError::user_not_found("id", user_id))?;

    // Verify old password
    let stored_hash = user
        .metadata
        .get("password_hash")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AuthError::invalid_credentials(user_id))?;

    let is_valid = verify_password(old_password, stored_hash)?;

    if !is_valid {
        return Err(AuthError::invalid_credentials(user_id));
    }

    // Hash new password
    let new_hash = hash_password(new_password)?;

    // Update password hash
    user.metadata.insert(
        "password_hash".to_string(),
        serde_json::Value::String(new_hash),
    );

    // Update user
    let updated_user = user_store.update_user(user).await?;

    Ok(updated_user)
}
