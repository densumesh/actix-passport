use actix_web::Error as ActixError;

/// Authentication-related errors.
///
/// This enum represents all possible errors that can occur during
/// authentication operations.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// The requested user was not found in the store.
    #[error("User not found")]
    UserNotFound,
    /// The provided credentials (email/username and password) are invalid.
    #[error("Invalid credentials")]
    InvalidCredentials,
    /// The user's session has expired and they need to log in again.
    #[error("Session expired")]
    SessionExpired,
    /// The user is not authorized to access the requested resource.
    #[error("Unauthorized")]
    Unauthorized,
    /// An error occurred during OAuth authentication flow.
    #[error("OAuth error: {0}")]
    OAuth(String),
    /// A database or storage-related error occurred.
    #[error("Database error: {0}")]
    Database(#[from] anyhow::Error),
    /// An error occurred while serializing or deserializing data.
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    /// An internal framework error occurred.
    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<AuthError> for ActixError {
    fn from(err: AuthError) -> Self {
        match err {
            AuthError::UserNotFound => actix_web::error::ErrorNotFound(err),
            AuthError::InvalidCredentials | AuthError::Unauthorized => {
                actix_web::error::ErrorUnauthorized(err)
            }
            AuthError::SessionExpired => actix_web::error::ErrorUnauthorized(err),
            _ => actix_web::error::ErrorInternalServerError(err),
        }
    }
}
