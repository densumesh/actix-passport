//! Token management for email verification and password reset.

use crate::errors::AuthError;
use crate::types::AuthResult;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Duration, Utc};
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

/// Token type for different email operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenType {
    /// Email verification token for new accounts
    EmailVerification,
    /// Password reset token
    PasswordReset,
}

impl TokenType {
    /// Returns the default expiration duration for this token type.
    #[must_use]
    pub const fn default_expiration(self) -> Duration {
        match self {
            Self::EmailVerification => Duration::hours(24), // 24 hours for email verification
            Self::PasswordReset => Duration::hours(1),      // 1 hour for password reset
        }
    }

    /// Returns a human-readable name for this token type.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::EmailVerification => "email verification",
            Self::PasswordReset => "password reset",
        }
    }
}

/// A secure token for email operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailToken {
    /// User ID this token is for
    pub user_id: String,
    /// Email address this token is for
    pub email: String,
    /// Type of token
    pub token_type: TokenType,
    /// When the token expires
    pub expires_at: DateTime<Utc>,
    /// When the token was created
    pub created_at: DateTime<Utc>,
    /// Random nonce for uniqueness
    pub nonce: String,
}

impl EmailToken {
    /// Creates a new email token.
    ///
    /// # Arguments
    ///
    /// * `user_id` - The user ID this token is for
    /// * `email` - The email address this token is for
    /// * `token_type` - The type of token to create
    /// * `expiration` - Optional custom expiration duration
    #[must_use]
    pub fn new(
        user_id: impl Into<String>,
        email: impl Into<String>,
        token_type: TokenType,
        expiration: Option<Duration>,
    ) -> Self {
        let now = Utc::now();
        let expiration = expiration.unwrap_or_else(|| token_type.default_expiration());

        // Generate a random nonce for uniqueness
        let mut nonce_bytes = [0u8; 16];
        rand::rng().fill_bytes(&mut nonce_bytes);
        let nonce = URL_SAFE_NO_PAD.encode(nonce_bytes);

        Self {
            user_id: user_id.into(),
            email: email.into(),
            token_type,
            expires_at: now + expiration,
            created_at: now,
            nonce,
        }
    }

    /// Checks if the token is expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Checks if the token is valid (not expired).
    #[must_use]
    pub fn is_valid(&self) -> bool {
        !self.is_expired()
    }

    /// Returns the time remaining until expiration.
    #[must_use]
    pub fn time_until_expiration(&self) -> Option<Duration> {
        let now = Utc::now();
        if now < self.expires_at {
            Some(self.expires_at - now)
        } else {
            None
        }
    }
}

/// Service for managing email tokens with HMAC signing.
#[derive(Clone)]
pub struct TokenService {
    /// Secret key for HMAC signing
    secret_key: String,
}

impl TokenService {
    /// Creates a new token service with the given secret key.
    ///
    /// # Arguments
    ///
    /// * `secret_key` - Secret key for HMAC signing (should be long and random)
    ///
    /// # Security Note
    ///
    /// The secret key should be at least 32 bytes long and cryptographically random.
    /// It should be kept secret and never exposed in logs or error messages.
    #[must_use]
    pub fn new(secret_key: impl Into<String>) -> Self {
        Self {
            secret_key: secret_key.into(),
        }
    }

    /// Generates a signed token string that can be sent in emails.
    ///
    /// # Arguments
    ///
    /// * `token` - The email token to sign
    ///
    /// # Returns
    ///
    /// Returns a base64-encoded string containing the token data and HMAC signature.
    ///
    /// # Errors
    ///
    /// Returns an error if token serialization or signing fails.
    pub fn generate_token_string(&self, token: &EmailToken) -> AuthResult<String> {
        // Serialize the token to JSON
        let token_json = serde_json::to_string(token).map_err(|e| AuthError::TokenError {
            message: format!("Failed to serialize token: {e}"),
        })?;

        // Create HMAC signature
        let mut mac = Hmac::<Sha256>::new_from_slice(self.secret_key.as_bytes()).map_err(|e| {
            AuthError::TokenError {
                message: format!("Invalid HMAC key: {e}"),
            }
        })?;

        mac.update(token_json.as_bytes());
        let signature = mac.finalize().into_bytes();

        // Combine token and signature
        let mut combined = token_json.into_bytes();
        combined.extend_from_slice(&signature);

        // Base64 encode the result
        Ok(URL_SAFE_NO_PAD.encode(combined))
    }

    /// Verifies and parses a token string.
    ///
    /// # Arguments
    ///
    /// * `token_string` - The base64-encoded token string to verify
    ///
    /// # Returns
    ///
    /// Returns the parsed token if verification succeeds.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The token string is malformed
    /// - The HMAC signature is invalid
    /// - The token is expired
    /// - The token cannot be deserialized
    pub fn verify_token_string(&self, token_string: &str) -> AuthResult<EmailToken> {
        // Base64 decode
        let combined = URL_SAFE_NO_PAD
            .decode(token_string)
            .map_err(|e| AuthError::TokenError {
                message: format!("Invalid token format: {e}"),
            })?;

        // Split token data and signature (HMAC-SHA256 is 32 bytes)
        if combined.len() < 32 {
            return Err(AuthError::TokenError {
                message: "Token too short".to_string(),
            });
        }

        let (token_data, signature) = combined.split_at(combined.len() - 32);

        // Verify HMAC signature
        let mut mac = Hmac::<Sha256>::new_from_slice(self.secret_key.as_bytes()).map_err(|e| {
            AuthError::TokenError {
                message: format!("Invalid HMAC key: {e}"),
            }
        })?;

        mac.update(token_data);

        if mac.verify_slice(signature).is_err() {
            return Err(AuthError::TokenError {
                message: "Invalid token signature".to_string(),
            });
        }

        // Deserialize token
        let token_json = std::str::from_utf8(token_data).map_err(|e| AuthError::TokenError {
            message: format!("Invalid token encoding: {e}"),
        })?;

        let token: EmailToken =
            serde_json::from_str(token_json).map_err(|e| AuthError::TokenError {
                message: format!("Failed to deserialize token: {e}"),
            })?;

        // Check expiration
        if token.is_expired() {
            return Err(AuthError::TokenError {
                message: format!("Token expired at {}", token.expires_at),
            });
        }

        Ok(token)
    }

    /// Creates a new email verification token.
    ///
    /// # Arguments
    ///
    /// * `user_id` - The user ID to create the token for
    /// * `email` - The email address to verify
    /// * `expiration` - Optional custom expiration duration
    #[must_use]
    pub fn create_verification_token(
        &self,
        user_id: impl Into<String>,
        email: impl Into<String>,
        expiration: Option<Duration>,
    ) -> EmailToken {
        EmailToken::new(user_id, email, TokenType::EmailVerification, expiration)
    }

    /// Creates a new password reset token.
    ///
    /// # Arguments
    ///
    /// * `user_id` - The user ID to create the token for
    /// * `email` - The email address associated with the account
    /// * `expiration` - Optional custom expiration duration
    #[must_use]
    pub fn create_password_reset_token(
        &self,
        user_id: impl Into<String>,
        email: impl Into<String>,
        expiration: Option<Duration>,
    ) -> EmailToken {
        EmailToken::new(user_id, email, TokenType::PasswordReset, expiration)
    }

    /// Generates a verification URL for email links.
    ///
    /// # Arguments
    ///
    /// * `base_url` - The base URL of your application
    /// * `token_string` - The signed token string
    /// * `route` - The route to append (e.g., "/auth/verify-email")
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use actix_passport::email::{TokenService, TokenType};
    ///
    /// let service = TokenService::new("secret_key");
    /// let token = service.create_verification_token("user123", "user@example.com", None);
    /// let token_string = service.generate_token_string(&token).unwrap();
    /// let url = service.generate_verification_url(
    ///     "https://myapp.com",
    ///     &token_string,
    ///     "/auth/verify-email"
    /// );
    /// println!("Verification URL: {url}");
    /// ```
    #[must_use]
    pub fn generate_verification_url(
        &self,
        base_url: &str,
        token_string: &str,
        route: &str,
    ) -> String {
        let base = base_url.trim_end_matches('/');
        let route = route.trim_start_matches('/');
        format!("{base}/{route}?token={token_string}")
    }
}
