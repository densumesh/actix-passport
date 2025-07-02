//! Defines the HTTP routes for authentication.
//!
//! This module groups all the authentication-related endpoints and provides
//! a function to configure them within an actix-web application.

#![allow(clippy::future_not_send)]

use crate::builder::ActixPassport;
use actix_web::web;

pub mod auth;
pub mod oauth;

impl ActixPassport {
    /// Configures the authentication routes for the application.
    ///
    /// This function adds the following routes to the specified service config:
    /// - `POST /auth/register`
    /// - `POST /auth/login`
    /// - `POST /auth/logout`
    /// - `GET /auth/me`
    /// - `GET /auth/{provider}`
    /// - `GET /auth/{provider}/callback`
    /// - `POST /auth/jwt-token` (if JWT feature enabled)
    /// - `POST /auth/jwt-refresh` (if JWT feature enabled)
    /// - `GET /auth/jwt-validate` (if JWT feature enabled)
    ///
    /// # Arguments
    ///
    /// * `cfg` - The service config to add the routes to.
    pub fn configure_routes(&self, cfg: &mut web::ServiceConfig) {
        cfg.app_data(web::Data::new(self.clone()));
        cfg.service(web::resource("/auth/me").route(web::get().to(auth::get_me)));

        #[cfg(feature = "password")]
        if self.config.password_auth {
            self.configure_password_routes(cfg);
        }

        #[cfg(feature = "oauth")]
        if self.config.oauth_auth {
            self.configure_oauth_routes(cfg);
        }
    }
}

impl ActixPassport {
    /// Configures password authentication routes.
    ///
    /// Adds routes for password-based authentication including registration, login, and logout.
    fn configure_password_routes(&self, cfg: &mut web::ServiceConfig) {
        let auth_scope = web::scope("/auth")
            .service(web::resource("/register").route(web::post().to(auth::register_user)))
            .service(web::resource("/login").route(web::post().to(auth::login_user)))
            .service(web::resource("/logout").route(web::post().to(auth::logout_user)));

        cfg.service(auth_scope);
    }

    /// Configures OAuth authentication routes.
    ///
    /// Adds routes for OAuth-based authentication including provider initiation and callback handling.
    fn configure_oauth_routes(&self, cfg: &mut web::ServiceConfig) {
        let auth_scope = web::scope("/auth")
            .service(web::resource("/{provider}").route(web::get().to(oauth::oauth_initiate)))
            .service(web::resource("/{provider}/callback").route(web::get().to(oauth::oauth_callback)));

        cfg.service(auth_scope);
    }
}
