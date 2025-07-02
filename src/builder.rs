//! Builder for constructing the main authentication framework.

use crate::{
    core::{AuthConfig, SessionStore, UserStore},
    errors::AuthError,
    oauth::{service::OAuthService, OAuthProvider},
    password::{service::PasswordAuthService, PasswordHasher},
};

/// The main authentication framework object.
///
/// This struct is created by the `ActixPassportBuilder` and holds all the
/// configured services and stores. It is intended to be cloned and stored
/// in the actix-web application data.
#[derive(Clone)]
pub struct ActixPassport<U, S, H>
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

/// Builder for `ActixPassport`.
pub struct ActixPassportBuilder<U, S, H>
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

impl<U, S, H> Default for ActixPassportBuilder<U, S, H>
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

impl<U, S, H> ActixPassportBuilder<U, S, H>
where
    U: UserStore + Clone,
    S: SessionStore,
    H: PasswordHasher,
{
    /// Creates a new builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the user store.
    #[must_use]
    pub fn with_user_store(mut self, store: U) -> Self {
        self.user_store = Some(store);
        self
    }

    /// Sets the session store.
    #[must_use]
    pub fn with_session_store(mut self, store: S) -> Self {
        self.session_store = Some(store);
        self
    }

    /// Enables password authentication with the given hasher.
    #[must_use]
    pub fn enable_password_auth(mut self, hasher: H) -> Self {
        self.password_hasher = Some(hasher);
        self
    }

    /// Adds an OAuth provider.
    #[must_use]
    pub fn with_oauth(mut self, provider: impl OAuthProvider + 'static) -> Self {
        self.oauth_providers.push(Box::new(provider));
        self
    }

    /// Sets the authentication configuration.
    #[must_use]
    pub fn with_config(mut self, config: AuthConfig) -> Self {
        self.config = config;
        self
    }

    /// Builds the `ActixPassport`.
    ///
    /// # Panics
    ///
    /// Panics if `user_store` or `session_store` are not set.
    ///
    /// # Errors
    ///
    /// Returns an error if `user_store` or `session_store` are not set.
    pub fn build(self) -> Result<ActixPassport<U, S, H>, Box<dyn std::error::Error>> {
        let user_store = self
            .user_store
            .ok_or_else(|| AuthError::Internal("A UserStore is required.".to_string()))?;
        let session_store = self
            .session_store
            .ok_or_else(|| AuthError::Internal("A SessionStore is required.".to_string()))?;

        let password_service = self
            .password_hasher
            .map(|hasher| PasswordAuthService::new(user_store.clone(), hasher));

        let oauth_service = if self.oauth_providers.is_empty() {
            None
        } else {
            let mut service = OAuthService::new();
            for provider in self.oauth_providers {
                service.add_provider(provider);
            }
            Some(service)
        };

        Ok(ActixPassport {
            user_store,
            session_store,
            password_service,
            oauth_service,
            config: self.config,
        })
    }
}
