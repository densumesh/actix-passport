//! Password authentication strategy implementation.

use crate::{strategies::AuthStrategy, types::AuthUser, ActixPassport, USER_ID_KEY};
use actix_session::SessionExt;
use actix_web::{
    web::{self},
    HttpRequest,
};
use async_trait::async_trait;

pub(crate) mod routes;
pub(crate) mod service;

/// Password-based authentication strategy.
///
/// This strategy provides traditional username/password authentication using
/// Argon2 hashing. It registers routes for user registration, login, and logout.
///
/// # Examples
///
/// ```rust,no_run
/// use actix_passport::strategies::password::PasswordStrategy;
/// use actix_passport::{ActixPassportBuilder, prelude::InMemoryUserStore};
///
/// let framework = ActixPassportBuilder::with_in_memory_store()
///     .add_strategy(PasswordStrategy::new())
///     .build();
/// ```
#[derive(Clone, Default)]
pub struct PasswordStrategy;

impl PasswordStrategy {
    /// Creates a new password authentication strategy.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[async_trait(?Send)]
impl AuthStrategy for PasswordStrategy {
    fn name(&self) -> &'static str {
        "password"
    }

    fn configure(&self, scope: actix_web::Scope) -> actix_web::Scope {
        scope
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
