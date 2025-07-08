//! SMTP provider implementations for different email services.

use crate::email::{EmailConfig, EmailTemplate};
use crate::errors::AuthError;
use crate::types::AuthResult;
use async_trait::async_trait;
use dyn_clone::DynClone;
use lettre::message::{header::ContentType, Mailbox, MultiPart, SinglePart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Address, AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

/// Trait for SMTP providers that can send emails.
#[async_trait]
pub trait SmtpProvider: Send + Sync + DynClone {
    /// Sends an email using this provider.
    ///
    /// # Arguments
    ///
    /// * `to_email` - Recipient email address
    /// * `to_name` - Recipient display name (optional)
    /// * `template` - Email template with subject and body
    ///
    /// # Errors
    ///
    /// Returns an error if email sending fails.
    async fn send_email(
        &self,
        to_email: &str,
        to_name: Option<&str>,
        template: &EmailTemplate,
    ) -> AuthResult<()>;

    /// Returns the name of this SMTP provider.
    fn provider_name(&self) -> &str;

    /// Validates the provider configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration is invalid.
    async fn validate_config(&self) -> AuthResult<()>;
}

dyn_clone::clone_trait_object!(SmtpProvider);

/// Standard SMTP provider implementation using lettre.
#[derive(Clone)]
pub struct StandardSmtpProvider {
    config: EmailConfig,
    rate_limiter: Option<Arc<Mutex<RateLimiter>>>,
}

impl StandardSmtpProvider {
    /// Creates a new standard SMTP provider.
    ///
    /// # Arguments
    ///
    /// * `config` - Email configuration
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use actix_passport::email::{EmailConfig, StandardSmtpProvider};
    ///
    /// let config = EmailConfig::gmail(
    ///     "user@gmail.com",
    ///     "app_password",
    ///     "https://myapp.com"
    /// );
    /// let provider = StandardSmtpProvider::new(config);
    /// ```
    #[must_use]
    pub fn new(config: EmailConfig) -> Self {
        let rate_limiter = config.max_emails_per_hour.map(|limit| {
            Arc::new(Mutex::new(RateLimiter::new(
                limit,
                Duration::from_secs(3600),
            )))
        });

        Self {
            config,
            rate_limiter,
        }
    }

    /// Creates a Gmail provider with the given credentials.
    ///
    /// # Arguments
    ///
    /// * `email` - Gmail email address
    /// * `app_password` - Gmail app-specific password
    /// * `base_url` - Base URL for your application
    #[must_use]
    pub fn gmail(email: &str, app_password: &str, base_url: &str) -> Self {
        Self::new(EmailConfig::gmail(email, app_password, base_url))
    }

    /// Creates a `SendGrid` provider with the given API key.
    ///
    /// # Arguments
    ///
    /// * `api_key` - `SendGrid` API key
    /// * `from_email` - Verified sender email address
    /// * `from_name` - Display name for sender
    /// * `base_url` - Base URL for your application
    #[must_use]
    pub fn sendgrid(api_key: &str, from_email: &str, from_name: &str, base_url: &str) -> Self {
        Self::new(EmailConfig::sendgrid(
            api_key, from_email, from_name, base_url,
        ))
    }

    /// Creates the SMTP transport for sending emails.
    fn create_transport(&self) -> AuthResult<lettre::AsyncSmtpTransport<lettre::Tokio1Executor>> {
        let creds = Credentials::new(self.config.username.clone(), self.config.password.clone());

        let transport =
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&self.config.smtp_host)
                .map_err(|e| AuthError::EmailError {
                    message: format!("Failed to create SMTP transport: {e}"),
                })?
                .credentials(creds)
                .port(self.config.smtp_port)
                .timeout(Some(self.config.timeout))
                .build();

        Ok(transport)
    }

    /// Checks rate limits before sending an email.
    async fn check_rate_limit(&self) -> AuthResult<()> {
        if let Some(rate_limiter) = &self.rate_limiter {
            let mut limiter = rate_limiter.lock().await;
            if !limiter.try_acquire() {
                let reset_after = limiter.time_until_reset().map(|d| d.as_secs());
                return Err(AuthError::RateLimitExceeded {
                    message: format!("Email rate limit of {} per hour exceeded", limiter.limit),
                    reset_after,
                });
            }
        }
        Ok(())
    }
}

#[async_trait]
impl SmtpProvider for StandardSmtpProvider {
    async fn send_email(
        &self,
        to_email: &str,
        to_name: Option<&str>,
        template: &EmailTemplate,
    ) -> AuthResult<()> {
        // Check rate limits first
        self.check_rate_limit().await?;

        // Parse email addresses
        let from_address: Address =
            self.config
                .from_email
                .parse()
                .map_err(|e| AuthError::EmailError {
                    message: format!("Invalid from email address: {e}"),
                })?;

        let to_address: Address = to_email.parse().map_err(|e| AuthError::EmailError {
            message: format!("Invalid to email address: {e}"),
        })?;

        let from_mailbox = Mailbox::new(Some(self.config.from_name.clone()), from_address);

        let to_mailbox = Mailbox::new(to_name.map(String::from), to_address);

        // Build the email message
        let message_builder = Message::builder()
            .from(from_mailbox)
            .to(to_mailbox)
            .subject(&template.subject);

        let html_part = SinglePart::builder()
            .header(ContentType::TEXT_HTML)
            .body(template.html_body.clone());

        // Create multipart email with HTML and text
        let email = if let Some(text_body) = &template.text_body {
            let text_part = SinglePart::builder()
                .header(ContentType::TEXT_PLAIN)
                .body(text_body.clone());

            let multipart = MultiPart::alternative()
                .singlepart(text_part)
                .singlepart(html_part);

            message_builder.multipart(multipart)
        } else {
            message_builder.singlepart(html_part)
        };

        let email = email.map_err(|e| AuthError::EmailError {
            message: format!("Failed to build email message: {e}"),
        })?;

        // Send the email
        let transport = self.create_transport()?;

        transport
            .send(email)
            .await
            .map_err(|e| AuthError::EmailError {
                message: format!("Failed to send email: {e}"),
            })?;

        Ok(())
    }

    fn provider_name(&self) -> &'static str {
        "standard_smtp"
    }

    async fn validate_config(&self) -> AuthResult<()> {
        // Try to create a transport to validate the configuration
        let _transport = self.create_transport()?;
        Ok(())
    }
}

/// Simple rate limiter for email sending.
#[derive(Debug)]
struct RateLimiter {
    limit: u32,
    window_duration: Duration,
    requests: Vec<Instant>,
}

impl RateLimiter {
    const fn new(limit: u32, window_duration: Duration) -> Self {
        Self {
            limit,
            window_duration,
            requests: Vec::new(),
        }
    }

    fn try_acquire(&mut self) -> bool {
        let now = Instant::now();

        // Remove expired requests
        self.requests
            .retain(|&time| now.duration_since(time) < self.window_duration);

        // Check if we're under the limit
        if self.requests.len() < self.limit as usize {
            self.requests.push(now);
            true
        } else {
            false
        }
    }

    fn time_until_reset(&self) -> Option<Duration> {
        if let Some(&oldest) = self.requests.first() {
            let elapsed = oldest.elapsed();
            if elapsed < self.window_duration {
                Some(self.window_duration - elapsed)
            } else {
                None
            }
        } else {
            None
        }
    }
}

/// Represents an email that was sent via the mock provider.
#[derive(Clone, Debug)]
pub struct SentEmail {
    /// Recipient email address
    pub to_email: String,
    /// Recipient display name
    pub to_name: Option<String>,
    /// Email subject
    pub subject: String,
    /// HTML body
    pub html_body: String,
    /// Text body
    pub text_body: Option<String>,
    /// Timestamp when the email was "sent"
    pub sent_at: Instant,
}
