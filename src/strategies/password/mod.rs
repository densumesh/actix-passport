//! Password authentication strategy implementation.

use crate::{strategies::AuthStrategy, types::AuthUser, ActixPassport, USER_ID_KEY};
use actix_session::SessionExt;
use actix_web::{
    web::{self},
    HttpRequest,
};
use async_trait::async_trait;

#[cfg(feature = "email")]
use crate::email::EmailService;
#[cfg(feature = "email")]
use std::sync::Arc;

pub(crate) mod routes;
pub(crate) mod service;

/// Password-based authentication strategy.
///
/// This strategy provides traditional username/password authentication using
/// Argon2 hashing. It registers routes for user registration, login, and logout.
/// When the email feature is enabled, it also supports email verification and
/// password reset functionality.
///
/// # Examples
///
/// ```rust,no_run
/// use actix_passport::strategies::password::PasswordStrategy;
/// use actix_passport::{ActixPassportBuilder, prelude::InMemoryUserStore};
///
/// let framework = ActixPassportBuilder::with_in_memory_store()
///     .add_strategy(PasswordStrategy::new())
///     .build();
/// ```
///
/// With email verification:
///
/// ```rust,no_run
/// # #[cfg(feature = "email")]
/// # {
/// use actix_passport::strategies::password::PasswordStrategy;
/// use actix_passport::{ActixPassportBuilder, email::{EmailConfig, EmailService}};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let email_config = EmailConfig::gmail("user@gmail.com", "app_password", "https://myapp.com");
/// let email_service = EmailService::new(email_config, "My App", "secret_key").await?;
///
/// let framework = ActixPassportBuilder::with_in_memory_store()
///     .add_strategy(PasswordStrategy::with_email_service(email_service))
///     .build();
/// # Ok(())
/// # }
/// # }
/// ```
#[derive(Clone)]
pub struct PasswordStrategy {
    #[cfg(feature = "email")]
    email_service: Option<Arc<EmailService>>,
}

impl Default for PasswordStrategy {
    fn default() -> Self {
        Self::new()
    }
}

impl PasswordStrategy {
    /// Creates a new password authentication strategy.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            #[cfg(feature = "email")]
            email_service: None,
        }
    }

    /// Creates a password strategy with email verification support.
    ///
    /// # Arguments
    ///
    /// * `email_service` - Email service for sending verification and reset emails
    #[cfg(feature = "email")]
    #[must_use]
    pub fn with_email_service(email_service: EmailService) -> Self {
        Self {
            email_service: Some(Arc::new(email_service)),
        }
    }
}

#[async_trait(?Send)]
impl AuthStrategy for PasswordStrategy {
    fn name(&self) -> &'static str {
        "password"
    }

    fn configure(&self, scope: actix_web::Scope) -> actix_web::Scope {
        let mut scope = scope
            .service(web::resource("/register").route(web::post().to(routes::register_user)))
            .service(web::resource("/login").route(web::post().to(routes::login_user)))
            .service(web::resource("/logout").route(web::post().to(routes::logout_user)));

        // Add email verification routes if email service is available and features are enabled
        #[cfg(feature = "email")]
        if let Some(email_service) = &self.email_service {
            scope = scope.app_data(web::Data::from(email_service.clone()));

            // Only add email verification route if it's enabled
            if email_service.is_email_verification_enabled() {
                scope = scope.service(
                    web::resource("/verify-email")
                        .route(web::post().to(routes::email_routes::verify_email)),
                );
            }
            if email_service.is_password_reset_enabled() {
                scope = scope
                    .service(
                        web::resource("/forgot-password")
                            .route(web::post().to(routes::email_routes::forgot_password)),
                    )
                    .service(
                        web::resource("/reset-password")
                            .route(web::post().to(routes::email_routes::reset_password)),
                    );
            }
        }

        scope
    }

    async fn authenticate(&self, req: &HttpRequest) -> Option<AuthUser> {
        if let Some(framework) = req.app_data::<web::Data<ActixPassport>>() {
            let session = req.get_session();

            let user_id = session.get::<String>(USER_ID_KEY).ok()??;

            framework.user_store.find_by_id(&user_id).await.ok()?
        } else {
            None
        }
    }
}
