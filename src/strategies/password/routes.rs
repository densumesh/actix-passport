//! Handlers for standard authentication routes.

use super::service;
use crate::strategies::password::service::{LoginCredentials, RegisterCredentials};
use crate::{ActixPassport, USER_ID_KEY};
use actix_session::Session;
use actix_web::{web, HttpResponse, Responder};

/// Handles user registration.
///
/// `POST /auth/register`
pub async fn register_user(
    credentials: web::Json<RegisterCredentials>,
    framework: web::Data<ActixPassport>,
) -> impl Responder {
    match service::register(framework.user_store.as_ref(), credentials.into_inner()).await {
        Ok(user) => HttpResponse::Ok().json(user),
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
