use actix_web::Error as ActixError;
use std::collections::HashMap;

/// Authentication-related errors with contextual information.
///
/// This enum represents all possible errors that can occur during
/// authentication operations, providing detailed context for debugging
/// and user-friendly error messages.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// The requested user was not found in the store.
    #[error("User not found with {field}: {value}")]
    UserNotFound {
        /// The field that was searched (e.g., "id", "email", "username")
        field: String,
        /// The value that was searched for
        value: String,
    },

    /// The provided credentials are invalid.
    #[error("Authentication failed for user: {identifier}")]
    InvalidCredentials {
        /// The identifier used for authentication (email/username)
        identifier: String,
    },

    /// The user's session has expired and they need to log in again.
    #[error("Session expired for user: {user_id}")]
    SessionExpired {
        /// The ID of the user whose session expired
        user_id: String,
    },

    /// The user is not authorized to access the requested resource.
    #[error("User {user_id} is not authorized to access {resource}")]
    Unauthorized {
        /// The ID of the user attempting access
        user_id: String,
        /// The resource being accessed
        resource: String,
    },

    /// An error occurred during OAuth authentication flow.
    #[error("OAuth provider '{provider}' error: {message}")]
    OAuthError {
        /// The name of the OAuth provider (e.g., "google", "github")
        provider: String,
        /// The error message from the OAuth provider
        message: String,
        /// Additional context about the OAuth error
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// OAuth provider configuration is invalid or missing.
    #[error("OAuth provider '{provider}' is not configured or has invalid configuration")]
    OAuthProviderNotConfigured {
        /// The name of the OAuth provider
        provider: String,
    },

    /// Invalid OAuth state parameter (CSRF protection).
    #[error("Invalid OAuth state parameter - potential CSRF attack")]
    InvalidOAuthState,

    /// A database or storage-related error occurred.
    #[error("Database operation '{operation}' failed")]
    DatabaseError {
        /// The database operation that failed (e.g., "`find_user`", "`create_user`")
        operation: String,
        /// The underlying database error
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// An error occurred while serializing or deserializing data.
    #[error("Serialization error while processing {data_type}: {message}")]
    SerializationError {
        /// The type of data being serialized/deserialized
        data_type: String,
        /// The serialization error message
        message: String,
        /// The underlying serialization error
        #[source]
        source: serde_json::Error,
    },

    /// Configuration error during framework setup.
    #[error("Configuration error: {message}")]
    ConfigurationError {
        /// Description of the configuration issue
        message: String,
        /// Suggestions for fixing the configuration
        suggestions: Vec<String>,
    },

    /// A required feature is not enabled.
    #[error("Feature '{feature}' is required but not enabled")]
    FeatureNotEnabled {
        /// The name of the required feature
        feature: String,
    },

    /// A requested operation is not supported by the current implementation.
    #[error("Operation '{operation}' is not supported")]
    NotSupported {
        /// The operation that is not supported
        operation: String,
    },

    /// Password validation failed.
    #[error("Password validation failed: {reason}")]
    PasswordValidationFailed {
        /// The reason why password validation failed
        reason: String,
    },

    /// User registration failed due to validation errors.
    #[error("User registration failed: {reason}")]
    RegistrationFailed {
        /// The reason why registration failed
        reason: String,
        /// Field-specific validation errors
        field_errors: HashMap<String, Vec<String>>,
    },

    /// An internal framework error occurred.
    #[error("Internal error in {component}: {message}")]
    Internal {
        /// The component where the error occurred
        component: String,
        /// The error message
        message: String,
        /// Additional context for debugging
        context: Option<HashMap<String, String>>,
    },
}

impl AuthError {
    /// Returns a stable error code for this error type.
    ///
    /// This can be used by client applications to handle specific
    /// error types programmatically.
    #[must_use]
    pub const fn error_code(&self) -> &'static str {
        match self {
            Self::UserNotFound { .. } => "USER_NOT_FOUND",
            Self::InvalidCredentials { .. } => "INVALID_CREDENTIALS",
            Self::SessionExpired { .. } => "SESSION_EXPIRED",
            Self::Unauthorized { .. } => "UNAUTHORIZED",
            Self::OAuthError { .. } => "OAUTH_ERROR",
            Self::OAuthProviderNotConfigured { .. } => "OAUTH_PROVIDER_NOT_CONFIGURED",
            Self::InvalidOAuthState => "INVALID_OAUTH_STATE",
            Self::DatabaseError { .. } => "DATABASE_ERROR",
            Self::SerializationError { .. } => "SERIALIZATION_ERROR",
            Self::ConfigurationError { .. } => "CONFIGURATION_ERROR",
            Self::FeatureNotEnabled { .. } => "FEATURE_NOT_ENABLED",
            Self::NotSupported { .. } => "NOT_SUPPORTED",
            Self::PasswordValidationFailed { .. } => "PASSWORD_VALIDATION_FAILED",
            Self::RegistrationFailed { .. } => "REGISTRATION_FAILED",
            Self::Internal { .. } => "INTERNAL_ERROR",
        }
    }

    /// Returns a user-friendly error message suitable for display.
    ///
    /// This strips technical details and provides a message that
    /// end users can understand.
    #[must_use]
    pub fn user_message(&self) -> String {
        match self {
            Self::UserNotFound { .. } => {
                "User not found. Please check your login details.".to_string()
            }
            Self::InvalidCredentials { .. } => {
                "Invalid username or password. Please try again.".to_string()
            }
            Self::SessionExpired { .. } => {
                "Your session has expired. Please log in again.".to_string()
            }
            Self::Unauthorized { .. } => {
                "You are not authorized to access this resource.".to_string()
            }
            Self::OAuthError { provider, .. } => {
                format!("Authentication with {provider} failed. Please try again.")
            }
            Self::OAuthProviderNotConfigured { provider } => {
                format!("{provider} authentication is not available at this time.")
            }
            Self::InvalidOAuthState => {
                "Authentication request appears to be invalid. Please try again.".to_string()
            }
            Self::DatabaseError { .. } => {
                "A temporary error occurred. Please try again later.".to_string()
            }
            Self::SerializationError { .. } => {
                "Data processing error. Please try again.".to_string()
            }
            Self::ConfigurationError { .. } => {
                "Service configuration error. Please contact support.".to_string()
            }
            Self::FeatureNotEnabled { .. } => "This feature is not available.".to_string(),
            Self::NotSupported { .. } => "This operation is not supported.".to_string(),
            Self::PasswordValidationFailed { reason } => {
                format!("Password requirements not met: {reason}")
            }
            Self::RegistrationFailed { reason, .. } => format!("Registration failed: {reason}"),
            Self::Internal { .. } => {
                "An unexpected error occurred. Please try again later.".to_string()
            }
        }
    }

    /// Returns detailed debugging information including context.
    ///
    /// This includes technical details that are useful for developers
    /// but should not be shown to end users.
    #[must_use]
    pub fn debug_info(&self) -> HashMap<String, String> {
        let mut info = HashMap::new();
        info.insert("error_code".to_string(), self.error_code().to_string());
        info.insert("error_message".to_string(), self.to_string());

        match self {
            Self::UserNotFound { field, value } => {
                info.insert("search_field".to_string(), field.clone());
                info.insert("search_value".to_string(), value.clone());
            }
            Self::InvalidCredentials { identifier } => {
                info.insert("identifier".to_string(), identifier.clone());
            }
            Self::SessionExpired { user_id } => {
                info.insert("user_id".to_string(), user_id.clone());
            }
            Self::Unauthorized { user_id, resource } => {
                info.insert("user_id".to_string(), user_id.clone());
                info.insert("resource".to_string(), resource.clone());
            }
            Self::OAuthError {
                provider, message, ..
            } => {
                info.insert("provider".to_string(), provider.clone());
                info.insert("provider_message".to_string(), message.clone());
            }
            Self::OAuthProviderNotConfigured { provider } => {
                info.insert("provider".to_string(), provider.clone());
            }
            Self::DatabaseError { operation, .. } | Self::NotSupported { operation } => {
                info.insert("operation".to_string(), operation.clone());
            }
            Self::SerializationError {
                data_type, message, ..
            } => {
                info.insert("data_type".to_string(), data_type.clone());
                info.insert("serialization_message".to_string(), message.clone());
            }
            Self::ConfigurationError {
                message,
                suggestions,
            } => {
                info.insert("config_message".to_string(), message.clone());
                info.insert("suggestions".to_string(), suggestions.join(", "));
            }
            Self::FeatureNotEnabled { feature } => {
                info.insert("feature".to_string(), feature.clone());
            }
            Self::PasswordValidationFailed { reason } => {
                info.insert("validation_reason".to_string(), reason.clone());
            }
            Self::RegistrationFailed {
                reason,
                field_errors,
            } => {
                info.insert("registration_reason".to_string(), reason.clone());
                for (field, errors) in field_errors {
                    info.insert(format!("field_error_{field}"), errors.join(", "));
                }
            }
            Self::Internal {
                component,
                message,
                context,
            } => {
                info.insert("component".to_string(), component.clone());
                info.insert("internal_message".to_string(), message.clone());
                if let Some(ctx) = context {
                    for (key, value) in ctx {
                        info.insert(format!("context_{key}"), value.clone());
                    }
                }
            }
            Self::InvalidOAuthState => {
                info.insert(
                    "security_issue".to_string(),
                    "Potential CSRF attack detected".to_string(),
                );
            }
        }

        info
    }
}

impl From<AuthError> for ActixError {
    fn from(err: AuthError) -> Self {
        match err {
            AuthError::UserNotFound { .. } => actix_web::error::ErrorNotFound(err),
            AuthError::InvalidCredentials { .. }
            | AuthError::Unauthorized { .. }
            | AuthError::SessionExpired { .. }
            | AuthError::InvalidOAuthState => actix_web::error::ErrorUnauthorized(err),
            AuthError::OAuthProviderNotConfigured { .. } | AuthError::FeatureNotEnabled { .. } => {
                actix_web::error::ErrorServiceUnavailable(err)
            }
            AuthError::NotSupported { .. } => actix_web::error::ErrorNotImplemented(err),
            AuthError::PasswordValidationFailed { .. } | AuthError::RegistrationFailed { .. } => {
                actix_web::error::ErrorBadRequest(err)
            }
            _ => actix_web::error::ErrorInternalServerError(err),
        }
    }
}

// Convenience constructors for common error cases
impl AuthError {
    /// Creates a user not found error for a specific field search.
    pub fn user_not_found(field: impl Into<String>, value: impl Into<String>) -> Self {
        Self::UserNotFound {
            field: field.into(),
            value: value.into(),
        }
    }

    /// Creates an invalid credentials error.
    pub fn invalid_credentials(identifier: impl Into<String>) -> Self {
        Self::InvalidCredentials {
            identifier: identifier.into(),
        }
    }

    /// Creates an OAuth error with provider and message.
    pub fn oauth_error(provider: impl Into<String>, message: impl Into<String>) -> Self {
        Self::OAuthError {
            provider: provider.into(),
            message: message.into(),
            source: None,
        }
    }

    /// Creates a user already exists error for a specific field.
    pub fn user_already_exists(field: impl Into<String>, value: impl Into<String>) -> Self {
        let field_name = field.into();
        let value = value.into();
        Self::RegistrationFailed {
            reason: format!("{field_name} already exists: {value}"),
            field_errors: std::collections::HashMap::from([(
                field_name.clone(),
                vec![format!("This {field_name} is already taken")],
            )]),
        }
    }

    /// Creates a database error with operation context.
    pub fn database_error(
        operation: impl Into<String>,
        source: impl Into<Box<dyn std::error::Error + Send + Sync>>,
    ) -> Self {
        Self::DatabaseError {
            operation: operation.into(),
            source: source.into(),
        }
    }

    /// Creates a configuration error with suggestions.
    pub fn configuration_error(message: impl Into<String>, suggestions: Vec<String>) -> Self {
        Self::ConfigurationError {
            message: message.into(),
            suggestions,
        }
    }
}
