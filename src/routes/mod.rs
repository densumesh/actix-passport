//! Defines the HTTP routes for authentication.
//!
//! This module groups all the authentication-related endpoints and provides
//! a function to configure them within an actix-web application.

#![allow(clippy::future_not_send)]

use crate::builder::ActixPassport;
use actix_web::web;

impl ActixPassport {
    /// Configures the authentication routes for the application.
    ///
    /// This function adds the following routes to the specified service config:
    ///
    /// ## Password Authentication
    /// - `POST /auth/register`
    /// - `POST /auth/login`
    /// - `POST /auth/logout`
    ///
    /// ## OAuth Authentication
    /// - `GET /auth/{provider}`
    /// - `GET /auth/{provider}/callback`
    ///
    /// ## User Information
    /// - `GET /auth/me`
    ///
    /// # Arguments
    ///
    /// * `cfg` - The service config to add the routes to.
    pub fn configure_routes(&self, cfg: &mut web::ServiceConfig) {
        cfg.app_data(web::Data::new(self.clone()));
        let mut auth_scope = web::scope("/auth");

        for strategy in &self.strategies {
            auth_scope = strategy.configure(auth_scope);
        }

        cfg.service(auth_scope);
    }
}
