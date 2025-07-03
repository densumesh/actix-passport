//! Authentication middleware for actix-web.
//!
//! This module provides middleware for handling authentication in actix-web applications.
//! It includes session-based authentication, JWT token validation, and user identity injection.

/// Authentication middleware schemes for different authentication methods.
pub mod schemes;

use crate::middleware::schemes::get_user_from_request;
use crate::types::AuthUser;
use actix_web::{error::ErrorUnauthorized, FromRequest, HttpMessage, HttpRequest};
use futures_util::future::{FutureExt, LocalBoxFuture};
use std::{
    future::{ready, Ready},
    ops::Deref,
};

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

impl Deref for AuthedUser {
    type Target = AuthUser;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl FromRequest for AuthedUser {
    type Error = actix_web::Error;
    type Future = LocalBoxFuture<'static, Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut actix_web::dev::Payload) -> Self::Future {
        let req = req.clone();
        async move {
            get_user_from_request(&req).await.map_or_else(
                || Err(ErrorUnauthorized("Authentication required")),
                |user| Ok(Self(user)),
            )
        }
        .boxed_local()
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
