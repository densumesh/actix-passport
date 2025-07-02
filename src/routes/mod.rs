//! Defines the HTTP routes for authentication.
//!
//! This module groups all the authentication-related endpoints and provides
//! a function to configure them within an actix-web application.

pub mod auth;
pub mod oauth;

use actix_web::web;

/// Configures the authentication routes for the application.
///
/// This function adds the following routes to the specified service config:
/// - `POST /auth/register`
/// - `POST /auth/login`
/// - `POST /auth/logout`
/// - `GET /auth/me`
/// - `GET /auth/{provider}`
/// - `GET /auth/{provider}/callback`
///
/// # Arguments
///
/// * `cfg` - The service config to add the routes to.
pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/auth")
            .service(web::resource("/register").route(web::post().to(auth::register_user)))
            .service(web::resource("/login").route(web::post().to(auth::login_user)))
            .service(web::resource("/logout").route(web::post().to(auth::logout_user)))
            .service(web::resource("/me").route(web::get().to(auth::get_me)))
            .service(web::resource("/{provider}").route(web::get().to(oauth::oauth_initiate)))
            .service(
                web::resource("/{provider}/callback").route(web::get().to(oauth::oauth_callback)),
            ),
    );
}
