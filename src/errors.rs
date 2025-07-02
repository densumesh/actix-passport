use actix_web::Error as ActixError;

/// Authentication-related errors.
///
/// This enum represents all possible errors that can occur during
/// authentication operations.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("User not found")]
    UserNotFound,
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("Session expired")]
    SessionExpired,
    #[error("Unauthorized")]
    Unauthorized,
    #[error("OAuth error: {0}")]
    OAuth(String),
    #[error("Database error: {0}")]
    Database(#[from] anyhow::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
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
