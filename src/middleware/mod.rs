//! Authentication middleware for actix-web.
//!
//! This module provides middleware for handling authentication in actix-web applications.
//! It includes session-based authentication, JWT token validation, and user identity injection.

/// Authentication middleware schemes for different authentication methods.
pub mod schemes;

use crate::types::AuthUser;
use actix_web::{error::ErrorUnauthorized, FromRequest, HttpMessage, HttpRequest};
use std::future::{ready, Ready};

pub use schemes::jwt_auth::JwtAuthMiddleware;
pub use schemes::session_auth::SessionAuthMiddleware;

/// Extractable authenticated user from request.
///
/// This struct can be used in handler functions to extract the authenticated
/// user from the request. It implements `FromRequest` so it can be used
/// as a parameter in handler functions.
///
/// # Examples
///
/// ```rust
/// use actix_web::{get, HttpResponse};
/// use actix_passport::AuthedUser;
///
/// #[get("/profile")]
/// async fn get_profile(user: AuthedUser) -> HttpResponse {
///     HttpResponse::Ok().json(&user.0)
/// }
/// ```
#[derive(Debug, Clone)]
pub struct AuthedUser(pub AuthUser);

impl FromRequest for AuthedUser {
    type Error = actix_web::Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut actix_web::dev::Payload) -> Self::Future {
        req.extensions().get::<AuthUser>().map_or_else(
            || ready(Err(ErrorUnauthorized("Authentication required"))),
            |user| ready(Ok(Self(user.clone()))),
        )
    }
}

/// Optional authenticated user extractor.
///
/// Similar to `AuthenticatedUser`, but returns `None` instead of an error
/// when the user is not authenticated. This is useful for endpoints that
/// work differently for authenticated vs unauthenticated users.
///
/// # Examples
///
/// ```rust
/// use actix_web::{get, HttpResponse};
/// use actix_passport::OptionalAuthedUser;
///
/// #[get("/home")]
/// async fn home(user: OptionalAuthedUser) -> HttpResponse {
///     match user.0 {
///         Some(user) => HttpResponse::Ok().json(format!("Welcome, {}!", user.id)),
///         None => HttpResponse::Ok().json("Welcome, guest!"),
///     }
/// }
/// ```
#[derive(Debug, Clone)]
pub struct OptionalAuthedUser(pub Option<AuthUser>);

impl FromRequest for OptionalAuthedUser {
    type Error = actix_web::Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut actix_web::dev::Payload) -> Self::Future {
        let user = req.extensions().get::<AuthUser>().cloned();
        ready(Ok(Self(user)))
    }
}
