use crate::{
    core::UserStore,
    errors::AuthError,
    password::{LoginCredentials, PasswordHasher, RegisterCredentials},
    types::{AuthResult, AuthUser},
};

use serde_json;

/// Service for password-based authentication operations.
///
/// This service handles login, registration, and password management
/// operations. It coordinates between the user store and password hasher.
///
/// # Examples
///
/// ```rust
/// use actix_passport::{PasswordAuthService, Argon2PasswordHasher};
///
/// let auth_service = PasswordAuthService::new(
///     my_user_store,
///     Argon2PasswordHasher::default(),
/// );
/// ```
#[derive(Clone)]
pub struct PasswordAuthService<U, H>
where
    U: UserStore,
    H: PasswordHasher,
{
    user_store: U,
    password_hasher: H,
}

impl<U, H> PasswordAuthService<U, H>
where
    U: UserStore,
    H: PasswordHasher,
{
    /// Creates a new password authentication service.
    ///
    /// # Arguments
    ///
    /// * `user_store` - The user store implementation
    /// * `password_hasher` - The password hasher implementation
    pub const fn new(user_store: U, password_hasher: H) -> Self {
        Self {
            user_store,
            password_hasher,
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
    pub async fn login(&self, credentials: LoginCredentials) -> AuthResult<AuthUser> {
        // Try to find user by email first, then by username
        let user = if credentials.identifier.contains('@') {
            self.user_store
                .find_by_email(&credentials.identifier)
                .await?
        } else {
            self.user_store
                .find_by_username(&credentials.identifier)
                .await?
        };

        let user = user.ok_or(AuthError::UserNotFound)?;

        // For this example, we assume password hash is stored in metadata
        let stored_hash = user
            .metadata
            .get("password_hash")
            .and_then(|v| v.as_str())
            .ok_or(AuthError::InvalidCredentials)?;

        let is_valid = self
            .password_hasher
            .verify_password(&credentials.password, stored_hash)
            .await?;

        if !is_valid {
            return Err(AuthError::InvalidCredentials);
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
    pub async fn register(&self, credentials: RegisterCredentials) -> AuthResult<AuthUser> {
        // Check if email already exists
        if (self.user_store.find_by_email(&credentials.email).await?).is_some() {
            return Err(AuthError::Internal("Email already exists".to_string()));
        }

        // Check if username already exists (if provided)
        if let Some(ref username) = credentials.username {
            if (self.user_store.find_by_username(username).await?).is_some() {
                return Err(AuthError::Internal("Username already exists".to_string()));
            }
        }

        // Hash the password
        let password_hash = self
            .password_hasher
            .hash_password(&credentials.password)
            .await?;

        // Create user with hashed password in metadata
        let mut user =
            AuthUser::new(uuid::Uuid::new_v4().to_string()).with_email(credentials.email);

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
        let created_user = self.user_store.create_user(user).await?;

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
        &self,
        user_id: &str,
        old_password: &str,
        new_password: &str,
    ) -> AuthResult<AuthUser> {
        let mut user = self
            .user_store
            .find_by_id(user_id)
            .await?
            .ok_or(AuthError::UserNotFound)?;

        // Verify old password
        let stored_hash = user
            .metadata
            .get("password_hash")
            .and_then(|v| v.as_str())
            .ok_or(AuthError::InvalidCredentials)?;

        let is_valid = self
            .password_hasher
            .verify_password(old_password, stored_hash)
            .await?;

        if !is_valid {
            return Err(AuthError::InvalidCredentials);
        }

        // Hash new password
        let new_hash = self.password_hasher.hash_password(new_password).await?;

        // Update password hash
        user.metadata.insert(
            "password_hash".to_string(),
            serde_json::Value::String(new_hash),
        );

        // Update user
        let updated_user = self.user_store.update_user(user).await?;

        Ok(updated_user)
    }
}
