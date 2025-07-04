//! OAuth authentication strategy implementation.

use crate::{
    strategies::oauth::{provider::OAuthProvider, service::OAuthService},
    strategies::AuthStrategy,
    types::AuthUser,
    ActixPassport, USER_ID_KEY,
};
use actix_session::SessionExt;
use actix_web::{
    web::{self},
    HttpRequest,
};
use async_trait::async_trait;
use std::sync::Arc;

pub mod provider;
pub(crate) mod routes;
pub(crate) mod service;

/// OAuth-based authentication strategy.
///
/// This strategy provides OAuth 2.0 authentication with configurable providers.
/// It registers routes for OAuth initiation and callback handling.
///
/// # Examples
///
/// ```rust,no_run
/// use actix_passport::strategies::oauth::OAuthStrategy;
/// use actix_passport::{ActixPassportBuilder, GoogleOAuthProvider, prelude::InMemoryUserStore};
///
/// let store = InMemoryUserStore::new();
/// let provider = GoogleOAuthProvider::new("client_id".to_string(), "client_secret".to_string());
/// let strategy = OAuthStrategy::new(vec![Box::new(provider)]);
/// let framework = ActixPassportBuilder::new(store)
///     .add_strategy(strategy)
///     .build();
/// ```
pub struct OAuthStrategy {
    service: Arc<OAuthService>,
}

impl OAuthStrategy {
    /// Creates a new OAuth authentication strategy.
    ///
    /// # Arguments
    ///
    /// * `user_store` - The user store implementation for persisting users
    #[must_use]
    pub fn new(providers: Vec<Box<dyn OAuthProvider>>) -> Self {
        Self {
            service: Arc::new(OAuthService::new(providers)),
        }
    }

    /// Adds an OAuth provider to this strategy.
    ///
    /// # Arguments
    ///
    /// * `provider` - The OAuth provider implementation
    #[must_use]
    pub fn with_provider(mut self, provider: Box<dyn OAuthProvider>) -> Self {
        // Should be ok because there should be no one else using this prior to this
        Arc::make_mut(&mut self.service).add_provider(provider);
        self
    }
}

impl Clone for OAuthStrategy {
    fn clone(&self) -> Self {
        Self {
            service: Arc::clone(&self.service),
        }
    }
}

#[async_trait(?Send)]
impl AuthStrategy for OAuthStrategy {
    fn name(&self) -> &'static str {
        "oauth"
    }

    fn configure(&self, scope: actix_web::Scope) -> actix_web::Scope {
        scope
            .app_data(web::Data::from(self.service.clone()))
            .service(web::resource("/{provider}").route(web::get().to(routes::oauth_initiate)))
            .service(
                web::resource("/{provider}/callback").route(web::get().to(routes::oauth_callback)),
            )
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
