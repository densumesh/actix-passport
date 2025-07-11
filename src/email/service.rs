//! Core email service for sending verification and password reset emails.

use crate::email::{
    EmailConfig, EmailServiceConfig, EmailTemplateEngine, SmtpProvider, StandardSmtpProvider,
    TemplateContext, TokenService, TokenType,
};
use crate::errors::AuthError;
use crate::types::{AuthResult, AuthUser};
use chrono::Duration;
use std::{collections::HashMap, sync::Arc};

/// Builder for creating `EmailService` with custom templates.
#[derive(Clone)]
pub struct EmailServiceBuilder {
    /// Email configuration
    config: EmailConfig,
    /// Service configuration for feature enabling/disabling
    service_config: EmailServiceConfig,
    /// Application name for emails
    app_name: String,
    /// Token secret for signing tokens
    token_secret: String,
    /// Custom SMTP provider
    smtp_provider: Option<Arc<dyn SmtpProvider>>,
    /// Custom email verification templates (subject, html, text)
    verification_templates: Option<(String, String, Option<String>)>,
    /// Custom password reset templates (subject, html, text)
    reset_templates: Option<(String, String, Option<String>)>,
    /// Additional custom templates
    custom_templates: HashMap<String, String>,
}

impl EmailServiceBuilder {
    /// Creates a new email service builder.
    ///
    /// # Arguments
    ///
    /// * `config` - Email configuration
    /// * `app_name` - Name of your application
    /// * `token_secret` - Secret key for token signing
    pub fn new(
        config: EmailConfig,
        app_name: impl Into<String>,
        token_secret: impl Into<String>,
    ) -> Self {
        Self {
            config,
            service_config: EmailServiceConfig::all_enabled(),
            app_name: app_name.into(),
            token_secret: token_secret.into(),
            smtp_provider: None,
            verification_templates: None,
            reset_templates: None,
            custom_templates: HashMap::new(),
        }
    }

    /// Sets the service configuration for enabling/disabling features.
    #[must_use]
    pub const fn with_service_config(mut self, service_config: EmailServiceConfig) -> Self {
        self.service_config = service_config;
        self
    }

    /// Sets a custom SMTP provider.
    #[must_use]
    pub fn with_smtp_provider(mut self, smtp_provider: Arc<dyn SmtpProvider>) -> Self {
        self.smtp_provider = Some(smtp_provider);
        self
    }

    /// Sets custom email verification templates.
    ///
    /// # Arguments
    ///
    /// * `subject` - Subject line template (Tera syntax)
    /// * `html_body` - HTML body template (Tera syntax)
    /// * `text_body` - Optional plain text body template (Tera syntax)
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use actix_passport::email::{EmailConfig, EmailServiceBuilder};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = EmailConfig::gmail("user@gmail.com", "password", "https://myapp.com");
    ///
    /// let email_service = EmailServiceBuilder::new(config, "My App", "secret")
    ///     .with_email_verification_template(
    ///         "Welcome to {{ app_name }}!",
    ///         "<h1>Welcome!</h1><p><a href=\"{{ action_url }}\">Verify</a></p>",
    ///         Some("Welcome! Visit: {{ action_url }}")
    ///     )
    ///     .build()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn with_email_verification_template(
        mut self,
        subject: impl Into<String>,
        html_body: impl Into<String>,
        text_body: Option<impl Into<String>>,
    ) -> Self {
        self.verification_templates =
            Some((subject.into(), html_body.into(), text_body.map(Into::into)));
        self
    }

    /// Sets custom password reset templates.
    ///
    /// # Arguments
    ///
    /// * `subject` - Subject line template (Tera syntax)
    /// * `html_body` - HTML body template (Tera syntax)
    /// * `text_body` - Optional plain text body template (Tera syntax)
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use actix_passport::email::{EmailConfig, EmailServiceBuilder};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = EmailConfig::gmail("user@gmail.com", "password", "https://myapp.com");
    ///
    /// let email_service = EmailServiceBuilder::new(config, "My App", "secret")
    ///     .with_password_reset_template(
    ///         "Reset your password",
    ///         "<h1>Reset</h1><p><a href=\"{{ action_url }}\">Reset</a></p>",
    ///         Some("Reset: {{ action_url }}")
    ///     )
    ///     .build()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn with_password_reset_template(
        mut self,
        subject: impl Into<String>,
        html_body: impl Into<String>,
        text_body: Option<impl Into<String>>,
    ) -> Self {
        self.reset_templates = Some((subject.into(), html_body.into(), text_body.map(Into::into)));
        self
    }

    /// Adds a custom template.
    ///
    /// # Arguments
    ///
    /// * `name` - Template name
    /// * `content` - Template content (Tera syntax)
    #[must_use]
    pub fn with_custom_template(
        mut self,
        name: impl Into<String>,
        content: impl Into<String>,
    ) -> Self {
        self.custom_templates.insert(name.into(), content.into());
        self
    }

    /// Builds the `EmailService`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Template engine initialization fails
    /// - SMTP provider configuration is invalid
    pub async fn build(self) -> AuthResult<EmailService> {
        let smtp_provider = self
            .smtp_provider
            .unwrap_or_else(|| Arc::new(StandardSmtpProvider::new(self.config.clone())));

        let template_engine = EmailTemplateEngine::with_custom_templates(
            self.verification_templates.as_ref(),
            self.reset_templates.as_ref(),
            self.custom_templates,
        )?;

        let token_service = TokenService::new(self.token_secret);

        // Validate the SMTP configuration
        smtp_provider.validate_config().await?;

        Ok(EmailService {
            smtp_provider,
            template_engine,
            token_service,
            config: self.config,
            service_config: self.service_config,
            app_name: self.app_name,
        })
    }
}

/// Main email service that coordinates SMTP, templates, and tokens.
///
/// This service provides a high-level interface for sending email verification
/// and password reset emails. It handles token generation, template rendering,
/// and SMTP delivery.
#[derive(Clone)]
pub struct EmailService {
    /// SMTP provider for sending emails
    smtp_provider: Arc<dyn SmtpProvider>,
    /// Template engine for rendering emails
    template_engine: EmailTemplateEngine,
    /// Token service for generating and verifying tokens
    token_service: TokenService,
    /// Email configuration
    config: EmailConfig,
    /// Service configuration for feature enabling/disabling
    service_config: EmailServiceConfig,
    /// Application name for emails
    app_name: String,
}

impl EmailService {
    /// Creates a new email service with all features enabled.
    ///
    /// # Arguments
    ///
    /// * `config` - Email configuration
    /// * `app_name` - Name of your application (used in email templates)
    /// * `token_secret` - Secret key for token signing (should be long and random)
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use actix_passport::email::{EmailConfig, EmailService};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = EmailConfig::gmail(
    ///     "user@gmail.com",
    ///     "app_password",
    ///     "https://myapp.com"
    /// );
    ///
    /// let email_service = EmailService::new(
    ///     config,
    ///     "My App",
    ///     "your-long-random-secret-key"
    /// ).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Template engine initialization fails
    /// - SMTP provider configuration is invalid
    pub async fn new(
        config: EmailConfig,
        app_name: impl Into<String>,
        token_secret: impl Into<String>,
    ) -> AuthResult<Self> {
        Self::with_service_config(
            config,
            EmailServiceConfig::all_enabled(),
            app_name,
            token_secret,
        )
        .await
    }

    /// Creates a new email service with custom feature configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - Email configuration
    /// * `service_config` - Configuration for which email features to enable
    /// * `app_name` - Name of your application (used in email templates)
    /// * `token_secret` - Secret key for token signing (should be long and random)
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use actix_passport::email::{EmailConfig, EmailService, EmailServiceConfig};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = EmailConfig::gmail(
    ///     "user@gmail.com",
    ///     "app_password",
    ///     "https://myapp.com"
    /// );
    ///
    /// // Only enable email verification, disable password reset
    /// let service_config = EmailServiceConfig::verification_only();
    ///
    /// let email_service = EmailService::with_service_config(
    ///     config,
    ///     service_config,
    ///     "My App",
    ///     "your-long-random-secret-key"
    /// ).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Template engine initialization fails
    /// - SMTP provider configuration is invalid
    pub async fn with_service_config(
        config: EmailConfig,
        service_config: EmailServiceConfig,
        app_name: impl Into<String>,
        token_secret: impl Into<String>,
    ) -> AuthResult<Self> {
        let smtp_provider = Arc::new(StandardSmtpProvider::new(config.clone()));
        let template_engine = EmailTemplateEngine::new()?;
        let token_service = TokenService::new(token_secret);

        // Validate the SMTP configuration
        smtp_provider.validate_config().await?;

        Ok(Self {
            smtp_provider,
            template_engine,
            token_service,
            config,
            service_config,
            app_name: app_name.into(),
        })
    }

    /// Creates an email service with a custom SMTP provider.
    ///
    /// # Arguments
    ///
    /// * `smtp_provider` - Custom SMTP provider implementation
    /// * `config` - Email configuration
    /// * `app_name` - Name of your application
    /// * `token_secret` - Secret key for token signing
    ///
    /// # Errors
    ///
    /// Returns an error if template engine initialization fails.
    pub async fn with_smtp_provider(
        smtp_provider: Arc<dyn SmtpProvider>,
        config: EmailConfig,
        app_name: impl Into<String>,
        token_secret: impl Into<String>,
    ) -> AuthResult<Self> {
        Self::with_smtp_provider_and_service_config(
            smtp_provider,
            config,
            EmailServiceConfig::all_enabled(),
            app_name,
            token_secret,
        )
        .await
    }

    /// Creates an email service with a custom SMTP provider and service configuration.
    ///
    /// # Arguments
    ///
    /// * `smtp_provider` - Custom SMTP provider implementation
    /// * `config` - Email configuration
    /// * `service_config` - Configuration for which email features to enable
    /// * `app_name` - Name of your application
    /// * `token_secret` - Secret key for token signing
    ///
    /// # Errors
    ///
    /// Returns an error if template engine initialization fails.
    pub async fn with_smtp_provider_and_service_config(
        smtp_provider: Arc<dyn SmtpProvider>,
        config: EmailConfig,
        service_config: EmailServiceConfig,
        app_name: impl Into<String>,
        token_secret: impl Into<String>,
    ) -> AuthResult<Self> {
        let template_engine = EmailTemplateEngine::new()?;
        let token_service = TokenService::new(token_secret);

        // Validate the SMTP configuration
        smtp_provider.validate_config().await?;

        Ok(Self {
            smtp_provider,
            template_engine,
            token_service,
            config,
            service_config,
            app_name: app_name.into(),
        })
    }

    /// Creates a new `EmailServiceBuilder` for configuring custom templates and settings.
    ///
    /// # Arguments
    ///
    /// * `config` - Email configuration
    /// * `app_name` - Name of your application
    /// * `token_secret` - Secret key for token signing
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use actix_passport::email::{EmailConfig, EmailService};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = EmailConfig::gmail(
    ///     "user@gmail.com",
    ///     "app_password",
    ///     "https://myapp.com"
    /// );
    ///
    /// let email_service = EmailService::builder(config, "My App", "secret-key")
    ///     .with_password_reset_template(
    ///         "Reset your {{ app_name }} password",
    ///         "<h1>Custom Reset</h1><p><a href=\"{{ action_url }}\">Reset</a></p>",
    ///         Some("Reset: {{ action_url }}")
    ///     )
    ///     .with_email_verification_template(
    ///         "Verify your {{ app_name }} account",
    ///         "<h1>Custom Verify</h1><p><a href=\"{{ action_url }}\">Verify</a></p>",
    ///         Some("Verify: {{ action_url }}")
    ///     )
    ///     .build()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn builder(
        config: EmailConfig,
        app_name: impl Into<String>,
        token_secret: impl Into<String>,
    ) -> EmailServiceBuilder {
        EmailServiceBuilder::new(config, app_name, token_secret)
    }

    /// Sends an email verification email to a user.
    ///
    /// # Arguments
    ///
    /// * `user` - The user to send verification email to
    /// * `custom_expiration` - Optional custom expiration duration
    ///
    /// # Returns
    ///
    /// Returns the verification token string that was sent in the email.
    /// This can be used for testing or logging purposes.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Token generation fails
    /// - Template rendering fails
    /// - Email sending fails
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use actix_passport::{AuthUser, email::EmailService};
    ///
    /// # async fn example(email_service: EmailService) -> Result<(), Box<dyn std::error::Error>> {
    /// let user = AuthUser::new("user123")
    ///     .with_email("user@example.com")
    ///     .with_display_name("John Doe");
    ///
    /// let token = email_service.send_verification_email(&user, None).await?;
    /// println!("Verification token sent: {}", token);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn send_verification_email(
        &self,
        user: &AuthUser,
        custom_expiration: Option<Duration>,
    ) -> AuthResult<String> {
        // Check if email verification is enabled
        if !self.service_config.email_verification_enabled {
            return Err(AuthError::ConfigurationError {
                message: "Email verification is not enabled".to_string(),
                suggestions: vec![
                    "Enable email verification in EmailServiceConfig".to_string(),
                    "Use EmailServiceConfig::verification_only() or all_enabled()".to_string(),
                ],
            });
        }
        let email = user.email.as_ref().ok_or_else(|| AuthError::EmailError {
            message: "User does not have an email address".to_string(),
        })?;

        // Create verification token
        let token =
            self.token_service
                .create_verification_token(&user.id, email, custom_expiration);

        // Generate signed token string
        let token_string = self.token_service.generate_token_string(&token)?;

        // Generate verification URL
        let verification_url = self.token_service.generate_verification_url(
            &self.config.base_url,
            &token_string,
            "/auth/verify-email",
        );

        // Create template context
        let user_name = user
            .display_name
            .as_deref()
            .or(user.username.as_deref())
            .unwrap_or(email);

        let expiration_time = Self::format_duration(token.time_until_expiration());

        let context = TemplateContext::new(
            user_name,
            email,
            verification_url,
            &self.app_name,
            expiration_time,
        );

        // Render email template
        let email_template = self.template_engine.render_email_verification(&context)?;

        // Send email
        self.smtp_provider
            .send_email(email, Some(user_name), &email_template)
            .await?;

        Ok(token_string)
    }

    /// Sends a password reset email to a user.
    ///
    /// # Arguments
    ///
    /// * `user` - The user to send password reset email to
    /// * `custom_expiration` - Optional custom expiration duration
    ///
    /// # Returns
    ///
    /// Returns the reset token string that was sent in the email.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Token generation fails
    /// - Template rendering fails
    /// - Email sending fails
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use actix_passport::{AuthUser, email::EmailService};
    ///
    /// # async fn example(email_service: EmailService) -> Result<(), Box<dyn std::error::Error>> {
    /// let user = AuthUser::new("user123")
    ///     .with_email("user@example.com")
    ///     .with_display_name("John Doe");
    ///
    /// let token = email_service.send_password_reset_email(&user, None).await?;
    /// println!("Password reset token sent: {}", token);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn send_password_reset_email(
        &self,
        user: &AuthUser,
        custom_expiration: Option<Duration>,
    ) -> AuthResult<String> {
        // Check if password reset is enabled
        if !self.service_config.password_reset_enabled {
            return Err(AuthError::ConfigurationError {
                message: "Password reset is not enabled".to_string(),
                suggestions: vec![
                    "Enable password reset in EmailServiceConfig".to_string(),
                    "Use EmailServiceConfig::password_reset_only() or all_enabled()".to_string(),
                ],
            });
        }
        let email = user.email.as_ref().ok_or_else(|| AuthError::EmailError {
            message: "User does not have an email address".to_string(),
        })?;

        // Create password reset token
        let token =
            self.token_service
                .create_password_reset_token(&user.id, email, custom_expiration);

        // Generate signed token string
        let token_string = self.token_service.generate_token_string(&token)?;

        // Generate reset URL
        let reset_url = self.token_service.generate_verification_url(
            &self.config.base_url,
            &token_string,
            "/auth/reset-password",
        );

        // Create template context
        let user_name = user
            .display_name
            .as_deref()
            .or(user.username.as_deref())
            .unwrap_or(email);

        let expiration_time = Self::format_duration(token.time_until_expiration());

        let context =
            TemplateContext::new(user_name, email, reset_url, &self.app_name, expiration_time);

        // Render email template
        let email_template = self.template_engine.render_password_reset(&context)?;

        // Send email
        self.smtp_provider
            .send_email(email, Some(user_name), &email_template)
            .await?;

        Ok(token_string)
    }

    /// Verifies an email verification token.
    ///
    /// # Arguments
    ///
    /// * `token_string` - The token string to verify
    ///
    /// # Returns
    ///
    /// Returns the token data if verification succeeds.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The token is invalid or expired
    /// - The token is not an email verification token
    pub fn verify_email_token(&self, token_string: &str) -> AuthResult<(String, String)> {
        // Check if email verification is enabled
        if !self.service_config.email_verification_enabled {
            return Err(AuthError::ConfigurationError {
                message: "Email verification is not enabled".to_string(),
                suggestions: vec![
                    "Enable email verification in EmailServiceConfig".to_string(),
                    "Use EmailServiceConfig::verification_only() or all_enabled()".to_string(),
                ],
            });
        }
        let token = self.token_service.verify_token_string(token_string)?;

        if token.token_type != TokenType::EmailVerification {
            return Err(AuthError::TokenError {
                message: "Token is not an email verification token".to_string(),
            });
        }

        Ok((token.user_id, token.email))
    }

    /// Verifies a password reset token.
    ///
    /// # Arguments
    ///
    /// * `token_string` - The token string to verify
    ///
    /// # Returns
    ///
    /// Returns the token data if verification succeeds.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The token is invalid or expired
    /// - The token is not a password reset token
    pub fn verify_password_reset_token(&self, token_string: &str) -> AuthResult<(String, String)> {
        // Check if password reset is enabled
        if !self.service_config.password_reset_enabled {
            return Err(AuthError::ConfigurationError {
                message: "Password reset is not enabled".to_string(),
                suggestions: vec![
                    "Enable password reset in EmailServiceConfig".to_string(),
                    "Use EmailServiceConfig::password_reset_only() or all_enabled()".to_string(),
                ],
            });
        }
        let token = self.token_service.verify_token_string(token_string)?;

        if token.token_type != TokenType::PasswordReset {
            return Err(AuthError::TokenError {
                message: "Token is not a password reset token".to_string(),
            });
        }

        Ok((token.user_id, token.email))
    }

    /// Returns the SMTP provider name.
    #[must_use]
    pub fn provider_name(&self) -> &str {
        self.smtp_provider.provider_name()
    }

    /// Returns the base URL configured for this service.
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.config.base_url
    }

    /// Returns the application name.
    #[must_use]
    pub fn app_name(&self) -> &str {
        &self.app_name
    }

    /// Returns whether email verification is enabled.
    #[must_use]
    pub const fn is_email_verification_enabled(&self) -> bool {
        self.service_config.email_verification_enabled
    }

    /// Returns whether password reset is enabled.
    #[must_use]
    pub const fn is_password_reset_enabled(&self) -> bool {
        self.service_config.password_reset_enabled
    }

    /// Returns the service configuration.
    #[must_use]
    pub const fn service_config(&self) -> &EmailServiceConfig {
        &self.service_config
    }

    /// Formats a duration into a human-readable string.
    fn format_duration(duration: Option<Duration>) -> String {
        duration.map_or_else(
            || "expired".to_string(),
            |d| {
                let hours = d.num_hours();
                let minutes = d.num_minutes() % 60;

                if hours > 0 {
                    if minutes > 0 {
                        format!("{hours} hours and {minutes} minutes")
                    } else {
                        format!("{hours} hours")
                    }
                } else if minutes > 0 {
                    format!("{minutes} minutes")
                } else {
                    "a few moments".to_string()
                }
            },
        )
    }
}
