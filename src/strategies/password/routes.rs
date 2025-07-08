//! Handlers for standard authentication routes.

use super::service;
use crate::strategies::password::service::{LoginCredentials, RegisterCredentials};
use crate::{ActixPassport, USER_ID_KEY};
use actix_session::Session;
use actix_web::{web, HttpResponse, Responder};

#[cfg(feature = "email")]
use crate::email::EmailService;
#[cfg(feature = "email")]
use serde::{Deserialize, Serialize};

/// Handles user registration.
///
/// `POST /auth/register`
pub async fn register_user(
    credentials: web::Json<RegisterCredentials>,
    framework: web::Data<ActixPassport>,
    #[cfg(feature = "email")] email_service: Option<web::Data<crate::email::EmailService>>,
) -> impl Responder {
    match service::register(framework.user_store.as_ref(), credentials.into_inner()).await {
        Ok(user) => {
            #[cfg(feature = "email")]
            let mut email_verification_sent = false;

            // Automatically send email verification if email service is available and enabled
            #[cfg(feature = "email")]
            if let Some(email_service) = email_service {
                if email_service.is_email_verification_enabled() {
                    if let Err(e) = email_service.send_verification_email(&user, None).await {
                        // Log the error but don't fail registration
                        eprintln!("Failed to send verification email during registration: {e}");
                    } else {
                        email_verification_sent = true;
                    }
                }
            }

            #[cfg(feature = "email")]
            {
                let mut response = serde_json::to_value(&user).unwrap_or_default();
                if let Some(obj) = response.as_object_mut() {
                    obj.insert(
                        "email_verification_sent".to_string(),
                        serde_json::Value::Bool(email_verification_sent),
                    );
                }
                HttpResponse::Ok().json(response)
            }

            #[cfg(not(feature = "email"))]
            HttpResponse::Ok().json(user)
        }
        Err(e) => HttpResponse::BadRequest().json(e.to_string()),
    }
}

/// Handles user login.
///
/// `POST /auth/login`
#[allow(clippy::future_not_send)]
pub async fn login_user(
    credentials: web::Json<LoginCredentials>,
    framework: web::Data<ActixPassport>,
    session: Session,
) -> impl Responder
where
{
    match service::login(framework.user_store.as_ref(), credentials.into_inner()).await {
        Ok(user) => {
            if session.insert(USER_ID_KEY, &user.id).is_err() {
                return HttpResponse::InternalServerError().finish();
            }
            HttpResponse::Ok().json(user)
        }
        Err(e) => HttpResponse::Unauthorized().json(e.to_string()),
    }
}

/// Handles user logout.
///
/// `POST /auth/logout`
#[allow(clippy::future_not_send)]
pub async fn logout_user(session: Session) -> impl Responder {
    session.remove(USER_ID_KEY);
    session.purge();
    HttpResponse::Ok().finish()
}

// Email verification and password reset routes
#[cfg(feature = "email")]
pub mod email_routes {
    use super::{
        email_routes, service, web, ActixPassport, Deserialize, EmailService, HttpResponse,
        Responder, Serialize,
    };

    /// Request payload for sending verification email.
    #[derive(Debug, Serialize, Deserialize)]
    pub struct SendVerificationRequest {
        /// User ID to send verification email to
        pub user_id: String,
    }

    /// Request payload for email verification.
    #[derive(Debug, Serialize, Deserialize)]
    pub struct VerifyEmailRequest {
        /// Verification token from email
        pub token: String,
    }

    /// Request payload for forgot password.
    #[derive(Debug, Serialize, Deserialize)]
    pub struct ForgotPasswordRequest {
        /// Email address to send reset link to
        pub email: String,
    }

    /// Request payload for password reset.
    #[derive(Debug, Serialize, Deserialize)]
    pub struct ResetPasswordRequest {
        /// Reset token from email
        pub token: String,
        /// New password
        pub new_password: String,
    }

    /// Response for successful email operations.
    #[derive(Debug, Serialize, Deserialize)]
    pub struct EmailResponse {
        /// Success message
        pub message: String,
    }

    /// Handles email verification.
    ///
    /// `POST /auth/verify-email`
    #[cfg(feature = "email")]
    pub async fn verify_email(
        request: web::Json<email_routes::VerifyEmailRequest>,
        framework: web::Data<ActixPassport>,
        email_service: web::Data<EmailService>,
    ) -> impl Responder {
        // Verify the token
        let (user_id, _email) = match email_service.verify_email_token(&request.token) {
            Ok(result) => result,
            Err(e) => {
                return HttpResponse::BadRequest().json(format!("Invalid token: {e}"));
            }
        };

        // Mark email as verified
        match framework
            .user_store
            .set_email_verified(&user_id, true)
            .await
        {
            Ok(user) => HttpResponse::Ok().json(user),
            Err(e) => HttpResponse::InternalServerError().json(format!("Database error: {e}")),
        }
    }

    /// Handles forgot password request.
    ///
    /// `POST /auth/forgot-password`
    pub async fn forgot_password(
        request: web::Json<email_routes::ForgotPasswordRequest>,
        framework: web::Data<ActixPassport>,
        email_service: web::Data<EmailService>,
    ) -> impl Responder {
        // Find the user by email
        let user = match framework.user_store.find_by_email(&request.email).await {
            Ok(Some(user)) => user,
            Ok(None) => {
                // Don't reveal whether the email exists or not for security
                return HttpResponse::Ok().json(email_routes::EmailResponse {
                    message: "If the email address exists, a password reset link has been sent"
                        .to_string(),
                });
            }
            Err(e) => {
                return HttpResponse::InternalServerError().json(format!("Database error: {e}"));
            }
        };

        // Send password reset email
        match email_service.send_password_reset_email(&user, None).await {
            Ok(_) => HttpResponse::Ok().json(email_routes::EmailResponse {
                message: "If the email address exists, a password reset link has been sent"
                    .to_string(),
            }),
            Err(e) => {
                // Log the error but don't reveal it to the user
                println!("Failed to send password reset email: {e}");
                HttpResponse::Ok().json(email_routes::EmailResponse {
                    message: "If the email address exists, a password reset link has been sent"
                        .to_string(),
                })
            }
        }
    }

    /// Handles password reset.
    ///
    /// `POST /auth/reset-password`
    pub async fn reset_password(
        request: web::Json<email_routes::ResetPasswordRequest>,
        framework: web::Data<ActixPassport>,
        email_service: web::Data<EmailService>,
    ) -> impl Responder {
        // Verify the reset token
        let (user_id, _email) = match email_service.verify_password_reset_token(&request.token) {
            Ok(result) => result,
            Err(e) => {
                return HttpResponse::BadRequest().json(format!("Invalid or expired token: {e}"));
            }
        };

        // Update the password
        match service::change_password(
            framework.user_store.as_ref(),
            &user_id,
            &request.new_password,
        )
        .await
        {
            Ok(_) => HttpResponse::Ok().json(email_routes::EmailResponse {
                message: "Password reset successfully".to_string(),
            }),
            Err(e) => {
                HttpResponse::InternalServerError().json(format!("Failed to reset password: {e}"))
            }
        }
    }
}
