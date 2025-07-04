use crate::{
    errors::AuthError,
    password::{LoginCredentials, RegisterCredentials},
    prelude::UserStore,
    types::{AuthResult, AuthUser},
};

use argon2::{
    password_hash::{
        rand_core::OsRng, PasswordHash, PasswordHasher as _, PasswordVerifier, SaltString,
    },
    Argon2,
};
use serde_json;

/// Service for password-based authentication operations.
///
/// This service handles login, registration, and password management
/// operations using Argon2 for password hashing.
///
/// # Examples
///
/// ```rust
/// use actix_passport::{PasswordAuthService, user_store::UserStore, AuthUser, AuthResult};
/// use async_trait::async_trait;
///
/// #[derive(Clone)]
/// struct MyUserStore;
///
/// #[async_trait]
/// impl UserStore for MyUserStore {
///     async fn find_by_id(&self, _id: &str) -> AuthResult<Option<AuthUser>> { Ok(None) }
///     async fn find_by_email(&self, _email: &str) -> AuthResult<Option<AuthUser>> { Ok(None) }
///     async fn find_by_username(&self, _username: &str) -> AuthResult<Option<AuthUser>> { Ok(None) }
///     async fn create_user(&self, user: AuthUser) -> AuthResult<AuthUser> { Ok(user) }
///     async fn update_user(&self, user: AuthUser) -> AuthResult<AuthUser> { Ok(user) }
///     async fn delete_user(&self, _id: &str) -> AuthResult<()> { Ok(()) }
/// }
///
/// let auth_service = PasswordAuthService::new(MyUserStore);
/// ```
#[derive(Clone)]
pub struct PasswordAuthService {
    user_store: Box<dyn UserStore>,
}

impl PasswordAuthService {
    /// Creates a new password authentication service.
    ///
    /// # Arguments
    ///
    /// * `user_store` - The user store implementation
    #[must_use]
    pub fn new(user_store: impl UserStore + 'static) -> Self {
        Self {
            user_store: Box::new(user_store),
        }
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

        let user =
            user.ok_or_else(|| AuthError::user_not_found("identifier", &credentials.identifier))?;

        // For this example, we assume password hash is stored in metadata
        let stored_hash = user
            .metadata
            .get("password_hash")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthError::invalid_credentials(&credentials.identifier))?;

        let is_valid = Self::verify_password(&credentials.password, stored_hash)?;

        if !is_valid {
            return Err(AuthError::invalid_credentials(&credentials.identifier));
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
            if (self.user_store.find_by_username(username).await?).is_some() {
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
        let password_hash = Self::hash_password(&credentials.password)?;

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
            .ok_or_else(|| AuthError::user_not_found("id", user_id))?;

        // Verify old password
        let stored_hash = user
            .metadata
            .get("password_hash")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthError::invalid_credentials(user_id))?;

        let is_valid = Self::verify_password(old_password, stored_hash)?;

        if !is_valid {
            return Err(AuthError::invalid_credentials(user_id));
        }

        // Hash new password
        let new_hash = Self::hash_password(new_password)?;

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
