//! Handlers for standard authentication routes.

use crate::builder::ActixPassport;
use crate::middleware::{utils, AuthedUser};
use crate::password::{LoginCredentials, RegisterCredentials};
use crate::{
    core::{SessionStore, UserStore},
    password::PasswordHasher,
};
use actix_session::Session;
use actix_web::{web, HttpResponse, Responder};

/// Handles user registration.
///
/// **POST /auth/register**
pub async fn register_user<U, S, H>(
    credentials: web::Json<RegisterCredentials>,
    framework: web::Data<ActixPassport<U, S, H>>,
) -> impl Responder
where
    U: UserStore,
    S: SessionStore,
    H: PasswordHasher,
{
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
/// **POST /auth/login**
pub async fn login_user<U, S, H>(
    credentials: web::Json<LoginCredentials>,
    framework: web::Data<ActixPassport<U, S, H>>,
    session: Session,
) -> impl Responder
where
    U: UserStore,
    S: SessionStore,
    H: PasswordHasher,
{
    if let Some(ref password_service) = framework.password_service {
        match password_service.login(credentials.into_inner()).await {
            Ok(user) => {
                let user_session =
                    utils::create_user_session(&user, framework.config.session_duration);
                if let Err(e) = framework
                    .session_store
                    .create_session(user_session.clone())
                    .await
                {
                    return HttpResponse::InternalServerError().json(e.to_string());
                }

                if let Err(e) = utils::set_session_id(&session, user_session.id) {
                    return HttpResponse::InternalServerError().json(e.to_string());
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
/// **POST /auth/logout**
pub async fn logout_user<U, S, H>(
    session: Session,
    framework: web::Data<ActixPassport<U, S, H>>,
) -> impl Responder
where
    U: UserStore,
    S: SessionStore,
    H: PasswordHasher,
{
    if let Ok(Some(session_id_str)) = session.get::<String>("session_id") {
        if let Ok(session_id) = uuid::Uuid::parse_str(&session_id_str) {
            let _ = framework.session_store.delete_session(session_id).await;
        }
    }

    utils::clear_session(&session);
    HttpResponse::Ok().finish()
}

/// Gets the current authenticated user's profile.
///
/// **GET /auth/me**
pub async fn get_me(user: AuthedUser) -> impl Responder {
    HttpResponse::Ok().json(user.0)
}
