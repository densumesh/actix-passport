//! Email configuration for SMTP providers.

use crate::types::AuthResult;
use crate::errors::AuthError;
use std::time::Duration;

/// Configuration for which email features are enabled.
///
/// This allows selective enabling/disabling of email verification and password reset
/// functionality to provide fine-grained control over email capabilities.
#[derive(Debug, Clone)]
pub struct EmailServiceConfig {
    /// Whether email verification is enabled
    pub email_verification_enabled: bool,
    /// Whether password reset via email is enabled
    pub password_reset_enabled: bool,
}

impl EmailServiceConfig {
    /// Creates a new email service configuration with all features enabled.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use actix_passport::email::EmailServiceConfig;
    ///
    /// let config = EmailServiceConfig::all_enabled();
    /// assert!(config.email_verification_enabled);
    /// assert!(config.password_reset_enabled);
    /// ```
    #[must_use]
    pub const fn all_enabled() -> Self {
        Self {
            email_verification_enabled: true,
            password_reset_enabled: true,
        }
    }

    /// Creates a new email service configuration with all features disabled.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use actix_passport::email::EmailServiceConfig;
    ///
    /// let config = EmailServiceConfig::all_disabled();
    /// assert!(!config.email_verification_enabled);
    /// assert!(!config.password_reset_enabled);
    /// ```
    #[must_use]
    pub const fn all_disabled() -> Self {
        Self {
            email_verification_enabled: false,
            password_reset_enabled: false,
        }
    }

    /// Creates a configuration with only email verification enabled.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use actix_passport::email::EmailServiceConfig;
    ///
    /// let config = EmailServiceConfig::verification_only();
    /// assert!(config.email_verification_enabled);
    /// assert!(!config.password_reset_enabled);
    /// ```
    #[must_use]
    pub const fn verification_only() -> Self {
        Self {
            email_verification_enabled: true,
            password_reset_enabled: false,
        }
    }

    /// Creates a configuration with only password reset enabled.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use actix_passport::email::EmailServiceConfig;
    ///
    /// let config = EmailServiceConfig::password_reset_only();
    /// assert!(!config.email_verification_enabled);
    /// assert!(config.password_reset_enabled);
    /// ```
    #[must_use]
    pub const fn password_reset_only() -> Self {
        Self {
            email_verification_enabled: false,
            password_reset_enabled: true,
        }
    }

    /// Enables email verification.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use actix_passport::email::EmailServiceConfig;
    ///
    /// let config = EmailServiceConfig::all_disabled()
    ///     .with_email_verification(true);
    /// assert!(config.email_verification_enabled);
    /// ```
    #[must_use]
    pub const fn with_email_verification(mut self, enabled: bool) -> Self {
        self.email_verification_enabled = enabled;
        self
    }

    /// Enables password reset.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use actix_passport::email::EmailServiceConfig;
    ///
    /// let config = EmailServiceConfig::all_disabled()
    ///     .with_password_reset(true);
    /// assert!(config.password_reset_enabled);
    /// ```
    #[must_use]
    pub const fn with_password_reset(mut self, enabled: bool) -> Self {
        self.password_reset_enabled = enabled;
        self
    }
}

impl Default for EmailServiceConfig {
    fn default() -> Self {
        Self::all_enabled()
    }
}

/// Configuration for email services.
///
/// This struct contains all the necessary settings for connecting to
/// SMTP servers and sending emails. It supports various SMTP providers
/// and custom configurations.
#[derive(Debug, Clone)]
pub struct EmailConfig {
    /// SMTP server hostname
    pub smtp_host: String,
    /// SMTP server port (typically 25, 465, 587)
    pub smtp_port: u16,
    /// Username for SMTP authentication
    pub username: String,
    /// Password or app-specific password for SMTP authentication
    pub password: String,
    /// Email address to send from
    pub from_email: String,
    /// Display name for the sender
    pub from_name: String,
    /// Whether to use TLS encryption
    pub use_tls: bool,
    /// Connection timeout for SMTP
    pub timeout: Duration,
    /// Maximum number of emails per hour (rate limiting)
    pub max_emails_per_hour: Option<u32>,
    /// Base URL for email links (e.g., "<https://myapp.com>")
    pub base_url: String,
}

impl EmailConfig {
    /// Creates a new builder for `EmailConfig`.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use actix_passport::email::EmailConfig;
    ///
    /// let config = EmailConfig::builder()
    ///     .smtp_host("smtp.gmail.com")
    ///     .smtp_port(587)
    ///     .username("user@gmail.com")
    ///     .password("app_password")
    ///     .from_email("user@gmail.com")
    ///     .from_name("My App")
    ///     .base_url("https://myapp.com")
    ///     .build()
    ///     .unwrap();
    /// ```
    #[must_use]
    pub const fn builder() -> EmailConfigBuilder {
        EmailConfigBuilder::new()
    }

    /// Creates a Gmail configuration with sensible defaults.
    ///
    /// # Arguments
    ///
    /// * `email` - Gmail email address
    /// * `app_password` - Gmail app-specific password (not your regular password)
    /// * `base_url` - Base URL for your application
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use actix_passport::email::EmailConfig;
    ///
    /// let config = EmailConfig::gmail(
    ///     "user@gmail.com",
    ///     "app_password",
    ///     "https://myapp.com"
    /// );
    /// ```
    #[must_use]
    pub fn gmail(email: &str, app_password: &str, base_url: &str) -> Self {
        Self {
            smtp_host: "smtp.gmail.com".to_string(),
            smtp_port: 587,
            username: email.to_string(),
            password: app_password.to_string(),
            from_email: email.to_string(),
            from_name: "App".to_string(),
            use_tls: true,
            timeout: Duration::from_secs(30),
            max_emails_per_hour: Some(100),
            base_url: base_url.to_string(),
        }
    }

    /// Creates a `SendGrid` configuration.
    ///
    /// # Arguments
    ///
    /// * `api_key` - `SendGrid` API key
    /// * `from_email` - Verified sender email address
    /// * `from_name` - Display name for sender
    /// * `base_url` - Base URL for your application
    #[must_use]
    pub fn sendgrid(api_key: &str, from_email: &str, from_name: &str, base_url: &str) -> Self {
        Self {
            smtp_host: "smtp.sendgrid.net".to_string(),
            smtp_port: 587,
            username: "apikey".to_string(),
            password: api_key.to_string(),
            from_email: from_email.to_string(),
            from_name: from_name.to_string(),
            use_tls: true,
            timeout: Duration::from_secs(30),
            max_emails_per_hour: Some(1000),
            base_url: base_url.to_string(),
        }
    }

    /// Creates a Mailgun configuration.
    ///
    /// # Arguments
    ///
    /// * `api_key` - Mailgun API key
    /// * `domain` - Mailgun domain
    /// * `from_email` - Verified sender email address
    /// * `from_name` - Display name for sender
    /// * `base_url` - Base URL for your application
    #[must_use]
    pub fn mailgun(api_key: &str, domain: &str, from_email: &str, from_name: &str, base_url: &str) -> Self {
        Self {
            smtp_host: format!("smtp.{domain}"),
            smtp_port: 587,
            username: format!("postmaster@{domain}"),
            password: api_key.to_string(),
            from_email: from_email.to_string(),
            from_name: from_name.to_string(),
            use_tls: true,
            timeout: Duration::from_secs(30),
            max_emails_per_hour: Some(500),
            base_url: base_url.to_string(),
        }
    }
}

/// Builder for `EmailConfig`.
pub struct EmailConfigBuilder {
    smtp_host: Option<String>,
    smtp_port: Option<u16>,
    username: Option<String>,
    password: Option<String>,
    from_email: Option<String>,
    from_name: Option<String>,
    use_tls: bool,
    timeout: Duration,
    max_emails_per_hour: Option<u32>,
    base_url: Option<String>,
}

impl EmailConfigBuilder {
    /// Creates a new builder.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            smtp_host: None,
            smtp_port: None,
            username: None,
            password: None,
            from_email: None,
            from_name: None,
            use_tls: true,
            timeout: Duration::from_secs(30),
            max_emails_per_hour: None,
            base_url: None,
        }
    }

    /// Sets the SMTP host.
    #[must_use]
    pub fn smtp_host(mut self, host: impl Into<String>) -> Self {
        self.smtp_host = Some(host.into());
        self
    }

    /// Sets the SMTP port.
    #[must_use]
    pub const fn smtp_port(mut self, port: u16) -> Self {
        self.smtp_port = Some(port);
        self
    }

    /// Sets the username for SMTP authentication.
    #[must_use]
    pub fn username(mut self, username: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self
    }

    /// Sets the password for SMTP authentication.
    #[must_use]
    pub fn password(mut self, password: impl Into<String>) -> Self {
        self.password = Some(password.into());
        self
    }

    /// Sets the from email address.
    #[must_use]
    pub fn from_email(mut self, email: impl Into<String>) -> Self {
        self.from_email = Some(email.into());
        self
    }

    /// Sets the from name (display name).
    #[must_use]
    pub fn from_name(mut self, name: impl Into<String>) -> Self {
        self.from_name = Some(name.into());
        self
    }

    /// Sets whether to use TLS encryption.
    #[must_use]
    pub const fn use_tls(mut self, use_tls: bool) -> Self {
        self.use_tls = use_tls;
        self
    }

    /// Sets the connection timeout.
    #[must_use]
    pub const fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Sets the maximum emails per hour for rate limiting.
    #[must_use]
    pub const fn max_emails_per_hour(mut self, max: u32) -> Self {
        self.max_emails_per_hour = Some(max);
        self
    }

    /// Sets the base URL for email links.
    #[must_use]
    pub fn base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = Some(url.into());
        self
    }

    /// Builds the `EmailConfig`.
    ///
    /// # Errors
    ///
    /// Returns an error if any required fields are missing.
    pub fn build(self) -> AuthResult<EmailConfig> {
        Ok(EmailConfig {
            smtp_host: self.smtp_host.ok_or_else(|| AuthError::ConfigurationError {
                message: "SMTP host is required".to_string(),
                suggestions: vec!["Call .smtp_host() on the builder".to_string()],
            })?,
            smtp_port: self.smtp_port.ok_or_else(|| AuthError::ConfigurationError {
                message: "SMTP port is required".to_string(),
                suggestions: vec!["Call .smtp_port() on the builder".to_string()],
            })?,
            username: self.username.ok_or_else(|| AuthError::ConfigurationError {
                message: "Username is required".to_string(),
                suggestions: vec!["Call .username() on the builder".to_string()],
            })?,
            password: self.password.ok_or_else(|| AuthError::ConfigurationError {
                message: "Password is required".to_string(),
                suggestions: vec!["Call .password() on the builder".to_string()],
            })?,
            from_email: self.from_email.ok_or_else(|| AuthError::ConfigurationError {
                message: "From email is required".to_string(),
                suggestions: vec!["Call .from_email() on the builder".to_string()],
            })?,
            from_name: self.from_name.ok_or_else(|| AuthError::ConfigurationError {
                message: "From name is required".to_string(),
                suggestions: vec!["Call .from_name() on the builder".to_string()],
            })?,
            base_url: self.base_url.ok_or_else(|| AuthError::ConfigurationError {
                message: "Base URL is required".to_string(),
                suggestions: vec!["Call .base_url() on the builder".to_string()],
            })?,
            use_tls: self.use_tls,
            timeout: self.timeout,
            max_emails_per_hour: self.max_emails_per_hour,
        })
    }
}

impl Default for EmailConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}