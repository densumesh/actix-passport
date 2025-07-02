//! Builder for constructing the main authentication framework.

use crate::{
    core::{AuthConfig, SessionStore, UserStore},
    oauth::{service::OAuthService, OAuthProvider},
    password::{service::PasswordAuthService, PasswordHasher},
};

/// The main authentication framework object.
///
/// This struct is created by the `AuthFrameworkBuilder` and holds all the
/// configured services and stores. It is intended to be cloned and stored
/// in the actix-web application data.
#[derive(Clone)]
pub struct AuthFramework<U, S, H>
where
    U: UserStore + 'static,
    S: SessionStore + 'static,
    H: PasswordHasher + 'static,
{
    pub user_store: U,
    pub session_store: S,
    pub password_service: Option<PasswordAuthService<U, H>>,
    pub oauth_service: Option<OAuthService>,
    pub config: AuthConfig,
}

/// Builder for `AuthFramework`.
pub struct AuthFrameworkBuilder<U, S, H>
where
    U: UserStore + 'static,
    S: SessionStore + 'static,
    H: PasswordHasher + 'static,
{
    user_store: Option<U>,
    session_store: Option<S>,
    password_hasher: Option<H>,
    oauth_providers: Vec<Box<dyn OAuthProvider>>,
    config: AuthConfig,
}

impl<U, S, H> Default for AuthFrameworkBuilder<U, S, H>
where
    U: UserStore + 'static,
    S: SessionStore + 'static,
    H: PasswordHasher + 'static,
{
    fn default() -> Self {
        Self {
            user_store: None,
            session_store: None,
            password_hasher: None,
            oauth_providers: Vec::new(),
            config: AuthConfig::default(),
        }
    }
}

impl<U, S, H> AuthFrameworkBuilder<U, S, H>
where
    U: UserStore + Clone,
    S: SessionStore,
    H: PasswordHasher,
{
    /// Creates a new builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the user store.
    pub fn with_user_store(mut self, store: U) -> Self {
        self.user_store = Some(store);
        self
    }

    /// Sets the session store.
    pub fn with_session_store(mut self, store: S) -> Self {
        self.session_store = Some(store);
        self
    }

    /// Enables password authentication with the given hasher.
    pub fn enable_password_auth(mut self, hasher: H) -> Self {
        self.password_hasher = Some(hasher);
        self
    }

    /// Adds an OAuth provider.
    pub fn with_oauth(mut self, provider: impl OAuthProvider + 'static) -> Self {
        self.oauth_providers.push(Box::new(provider));
        self
    }

    /// Sets the authentication configuration.
    pub fn with_config(mut self, config: AuthConfig) -> Self {
        self.config = config;
        self
    }

    /// Builds the `AuthFramework`.
    ///
    /// # Panics
    ///
    /// Panics if `user_store` or `session_store` are not set.
    pub fn build(self) -> AuthFramework<U, S, H> {
        let user_store = self.user_store.expect("A UserStore is required.");
        let session_store = self.session_store.expect("A SessionStore is required.");

        let password_service = self
            .password_hasher
            .map(|hasher| PasswordAuthService::new(user_store.clone(), hasher));

        let oauth_service = if !self.oauth_providers.is_empty() {
            let mut service = OAuthService::new();
            for provider in self.oauth_providers {
                service.add_provider(provider);
            }
            Some(service)
        } else {
            None
        };

        AuthFramework {
            user_store,
            session_store,
            password_service,
            oauth_service,
            config: self.config,
        }
    }
}
