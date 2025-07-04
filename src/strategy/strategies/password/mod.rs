//! Password authentication strategy implementation.

use crate::{
    password::service::PasswordAuthService, prelude::UserStore, strategy::AuthStrategy,
    types::AuthUser, ActixPassport, USER_ID_KEY,
};
use actix_session::SessionExt;
use actix_web::{
    web::{self},
    HttpRequest,
};
use async_trait::async_trait;
use std::sync::Arc;

pub mod routes;

/// Password-based authentication strategy.
///
/// This strategy provides traditional username/password authentication using
/// Argon2 hashing. It registers routes for user registration, login, and logout.
///
/// # Examples
///
/// ```rust,no_run
/// use actix_passport::strategy::strategies::password::PasswordStrategy;
/// use actix_passport::{ActixPassportBuilder, prelude::InMemoryUserStore};
///
/// let store = InMemoryUserStore::new();
/// let strategy = PasswordStrategy::new(store.clone());
/// let framework = ActixPassportBuilder::new(store)
///     .add_strategy(strategy)
///     .build();
/// ```
pub struct PasswordStrategy {
    service: Arc<PasswordAuthService>,
}

impl PasswordStrategy {
    /// Creates a new password authentication strategy.
    ///
    /// # Arguments
    ///
    /// * `user_store` - The user store implementation for persisting users
    #[must_use]
    pub fn new(user_store: impl UserStore + 'static) -> Self {
        Self {
            service: Arc::new(PasswordAuthService::new(user_store)),
        }
    }
}

impl Clone for PasswordStrategy {
    fn clone(&self) -> Self {
        Self {
            service: Arc::clone(&self.service),
        }
    }
}

#[async_trait(?Send)]
impl AuthStrategy for PasswordStrategy {
    fn name(&self) -> &'static str {
        "password"
    }

    fn configure(&self, scope: actix_web::Scope) -> actix_web::Scope {
        scope
            .app_data(web::Data::from(self.service.clone()))
            .service(web::resource("/register").route(web::post().to(routes::register_user)))
            .service(web::resource("/login").route(web::post().to(routes::login_user)))
            .service(web::resource("/logout").route(web::post().to(routes::logout_user)))
    }

    async fn authenticate(&self, req: &HttpRequest) -> Option<AuthUser> {
        if let Some(framework) = req.app_data::<web::Data<ActixPassport>>() {
            let session = req.get_session();

            let user_id = session.get::<String>(USER_ID_KEY).ok()??;

            framework.user_store.find_by_id(&user_id).await.ok()?
        } else {
            None
        }
    }
}
