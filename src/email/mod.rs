//! Email functionality for actix-passport.
//!
//! This module provides email verification and password reset capabilities
//! using SMTP providers. It includes template rendering, token management,
//! and configurable SMTP backends.
//!
//! # Features
//!
//! - Email verification for new user accounts
//! - Password reset via email tokens
//! - Multiple SMTP provider support (Gmail, SendGrid, Mailgun, custom)
//! - HTML and text email templates with Tera templating
//! - Secure token generation and validation
//! - Rate limiting for email sends
//!
//! # Examples
//!
//! ## Full Email Functionality (Verification + Password Reset)
//!
//! ```rust,no_run
//! use actix_passport::{ActixPassportBuilder, email::{EmailConfig, EmailService, EmailServiceConfig}};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let email_config = EmailConfig::gmail(
//!     "user@gmail.com",
//!     "app_password",
//!     "https://myapp.com"
//! );
//!
//! let email_service = EmailService::new(
//!     email_config,
//!     "My App",
//!     "secret_key"
//! ).await?;
//!
//! let auth = ActixPassportBuilder::with_in_memory_store()
//!     .enable_password_auth_with_email(email_service)
//!     .build();
//! # Ok(())
//! # }
//! ```
//!
//! ## Email Verification Only
//!
//! ```rust,no_run
//! use actix_passport::{ActixPassportBuilder, email::{EmailConfig, EmailService, EmailServiceConfig}};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//! let email_config = EmailConfig::gmail(
//!     "user@gmail.com",
//!     "app_password",
//!     "https://myapp.com"
//! );
//!
//! let email_service = EmailService::with_service_config(
//!     email_config,
//!     EmailServiceConfig::verification_only(),
//!     "My App",
//!     "secret_key"
//! ).await?;
//!
//! let auth = ActixPassportBuilder::with_in_memory_store()
//!     .enable_password_auth_with_email(email_service)
//!     .build();
//! # Ok(())
//! # }
//! ```
//!
//! ## Password Reset Only
//!
//! ```rust,no_run
//! use actix_passport::{ActixPassportBuilder, email::{EmailConfig, EmailService, EmailServiceConfig}};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//! let email_config = EmailConfig::gmail(
//!     "user@gmail.com",
//!     "app_password",
//!     "https://myapp.com"
//! );
//!
//! let email_service = EmailService::with_service_config(
//!     email_config,
//!     EmailServiceConfig::password_reset_only(),
//!     "My App",
//!     "secret_key"
//! ).await?;
//!
//! let auth = ActixPassportBuilder::with_in_memory_store()
//!     .enable_password_auth_with_email(email_service)
//!     .build();
//! # Ok(())
//! # }
//! ```
//!
//! ## Custom Configuration
//!
//! ```rust,no_run
//! use actix_passport::{ActixPassportBuilder, email::{EmailConfig, EmailService, EmailServiceConfig}};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//! let email_config = EmailConfig::gmail(
//!     "user@gmail.com",
//!     "app_password",
//!     "https://myapp.com"
//! );
//!
//! // Custom feature configuration
//! let service_config = EmailServiceConfig::all_disabled()
//!     .with_email_verification(true)
//!     .with_password_reset(false);
//!
//! let email_service = EmailService::with_service_config(
//!     email_config,
//!     service_config,
//!     "My App",
//!     "secret_key"
//! ).await?;
//!
//! let auth = ActixPassportBuilder::with_in_memory_store()
//!     .enable_password_auth_with_email(email_service)
//!     .build();
//! # Ok(())
//! # }
//! ```

#[cfg(feature = "email")]
pub mod config;
#[cfg(feature = "email")]
pub mod service;
#[cfg(feature = "email")]
pub mod smtp_provider;
#[cfg(feature = "email")]
pub mod templates;
#[cfg(feature = "email")]
pub mod tokens;

#[cfg(feature = "email")]
pub use config::{EmailConfig, EmailServiceConfig};
#[cfg(feature = "email")]
pub use service::*;
#[cfg(feature = "email")]
pub use smtp_provider::*;
#[cfg(feature = "email")]
pub use templates::*;
#[cfg(feature = "email")]
pub use tokens::*;
