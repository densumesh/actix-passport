//! Database error to `AuthError` mapping utilities.

use crate::errors::AuthError;

/// Maps common database errors to appropriate `AuthError` variants.
#[cfg(feature = "postgres")]
#[must_use]
pub fn map_sqlx_error(operation: &str, error: sqlx::Error) -> AuthError {
    use sqlx::Error as SqlxError;

    match error {
        SqlxError::Database(ref db_err) => {
            // Check for constraint violations (duplicate keys, etc.)
            let error_code = db_err.code().unwrap_or_default();
            let error_message = db_err.message();

            // PostgreSQL constraint violation codes
            if error_code == "23505" || error_message.contains("duplicate key") {
                if error_message.contains("email") {
                    return AuthError::user_already_exists("email", "");
                } else if error_message.contains("username") {
                    return AuthError::user_already_exists("username", "");
                }
            }

            // MySQL constraint violation codes
            if error_code == "1062" || error_message.contains("Duplicate entry") {
                if error_message.contains("email") {
                    return AuthError::user_already_exists("email", "");
                } else if error_message.contains("username") {
                    return AuthError::user_already_exists("username", "");
                }
            }

            // SQLite constraint violation
            if error_message.contains("UNIQUE constraint failed") {
                if error_message.contains("email") {
                    return AuthError::user_already_exists("email", "");
                } else if error_message.contains("username") {
                    return AuthError::user_already_exists("username", "");
                }
            }

            // Default database error
            AuthError::database_error(operation, error.to_string())
        }
        SqlxError::RowNotFound => AuthError::user_not_found("id", ""),
        SqlxError::PoolTimedOut => AuthError::database_error(operation, "Connection pool timeout"),
        SqlxError::PoolClosed => AuthError::database_error(operation, "Connection pool closed"),
        _ => AuthError::database_error(operation, error),
    }
}

/// Generic error mapper for string-based errors.
pub fn map_string_error(operation: &str, error: &impl ToString) -> AuthError {
    AuthError::database_error(operation, error.to_string())
}
