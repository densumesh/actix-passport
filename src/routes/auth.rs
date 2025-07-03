//! Handlers for standard authentication routes.

use crate::builder::ActixPassport;
use crate::middleware::AuthedUser;
use crate::password::{LoginCredentials, RegisterCredentials};
use actix_session::Session;
use actix_web::{web, HttpResponse, Responder};

const USER_ID_KEY: &str = "actix_passport_user_id";

/// Handles user registration.
///
/// `POST /auth/register`
pub async fn register_user(
    credentials: web::Json<RegisterCredentials>,
    framework: web::Data<ActixPassport>,
) -> impl Responder {
    if let Some(ref password_service) = framework.password_service {
        match password_service.register(credentials.into_inner()).await {
            Ok(user) => HttpResponse::Ok().json(user),
            Err(e) => HttpResponse::BadRequest().json(e.to_string()),
        }
    } else {
        HttpResponse::NotFound().finish()
    }
}

/// Handles user login.
///
/// `POST /auth/login`
pub async fn login_user(
    credentials: web::Json<LoginCredentials>,
    framework: web::Data<ActixPassport>,
    session: Session,
) -> impl Responder
where
{
    if let Some(ref password_service) = framework.password_service {
        match password_service.login(credentials.into_inner()).await {
            Ok(user) => {
                if session.insert(USER_ID_KEY, &user.id).is_err() {
                    return HttpResponse::InternalServerError().finish();
                }
                HttpResponse::Ok().json(user)
            }
            Err(e) => HttpResponse::Unauthorized().json(e.to_string()),
        }
    } else {
        HttpResponse::NotFound().finish()
    }
}

/// Handles user logout.
///
/// `POST /auth/logout`
pub async fn logout_user(session: Session) -> impl Responder {
    session.remove(USER_ID_KEY);
    session.purge();
    HttpResponse::Ok().finish()
}

/// Gets the current authenticated user's profile.
///
/// `GET /auth/me`
pub async fn get_me(user: AuthedUser) -> impl Responder {
    HttpResponse::Ok().json(user.0)
}
