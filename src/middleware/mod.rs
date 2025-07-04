//! Authentication middleware for actix-web.
//!
//! This module provides middleware for handling authentication in actix-web applications.
//! It includes session-based authentication, JWT token validation, and user identity injection.

use crate::{types::AuthUser, ActixPassport};
use actix_web::{
    error::{ErrorBadRequest, ErrorUnauthorized},
    web, FromRequest, HttpMessage, HttpRequest,
};
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
            let framework = req.app_data::<web::Data<ActixPassport>>().map_or_else(
                ||
                Err(ErrorBadRequest(
                    "Could not extract `ActixPassport` from the app data. This usually means that you have not added 
                        `.configure(|cfg| auth_framework.configure_routes(cfg))` or `.app_data(auth_framework)` prior to 
                        defining your routes. ")), 
                Ok)?;
            let mut user = None;
            for strategy in &framework.strategies {
                user = strategy.authenticate(&req).await;
            }

            user.map_or_else(
                || Err(ErrorUnauthorized("Unauthorized"))
                ,
            |user| Ok(Self(user))
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
