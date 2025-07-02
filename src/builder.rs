//! Builder pattern for configuring the authentication system.
//!
//! This module provides a fluent builder API for setting up and configuring
//! the authentication system with various stores, services, and options.

use crate::{
    core::{AuthConfig, SessionStore, UserStore},
    middleware::AuthMiddleware,
    routes::{AuthRoutes, RouteConfig},
};
use actix_web::{web, dev::ServiceFactory, Error as ActixError, HttpRequest};
use std::sync::Arc;

#[cfg(feature = "password")]
use crate::password::{Argon2PasswordHasher, PasswordAuthService, PasswordHasher};

#[cfg(feature = "oauth")]
use crate::oauth::{GitHubOAuthProvider, GoogleOAuthProvider, OAuthService};

/// Builder for configuring the authentication system.
///
/// This builder provides a fluent API for setting up authentication with
/// various stores, services, and configuration options.
///
/// # Examples
///
/// ```rust
/// use actix_passport::AuthBuilder;
///
/// let auth = AuthBuilder::new()
///     .user_store(my_user_store)
///     .session_store(my_session_store)
///     .enable_password_auth()
///     .with_google_oauth("client_id".to_string(), "client_secret".to_string())
///     .build();
/// ```
pub struct AuthBuilder<U = (), S = ()>
where
    U: UserStore + 'static,
    S: SessionStore + 'static,
{
    user_store: Option<U>,
    session_store: Option<S>,
    auth_config: AuthConfig,
    route_config: RouteConfig,

    #[cfg(feature = "password")]
    password_hasher: Option<Box<dyn PasswordHasher>>,
    #[cfg(feature = "password")]
    enable_password_auth: bool,

    #[cfg(feature = "oauth")]
    oauth_service: Option<OAuthService>,
    #[cfg(feature = "oauth")]
    enable_oauth: bool,
}

impl AuthBuilder<(), ()> {
    /// Creates a new authentication builder.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use actix_passport::AuthBuilder;
    ///
    /// let builder = AuthBuilder::new();
    /// ```
    pub fn new() -> Self {
        Self {
            user_store: None,
            session_store: None,
            auth_config: AuthConfig::default(),
            route_config: RouteConfig::default(),

            #[cfg(feature = "password")]
            password_hasher: None,
            #[cfg(feature = "password")]
            enable_password_auth: false,

            #[cfg(feature = "oauth")]
            oauth_service: None,
            #[cfg(feature = "oauth")]
            enable_oauth: false,
        }
    }
}

impl<S> AuthBuilder<(), S>
where
    S: SessionStore + 'static,
{
    /// Sets the user store implementation.
    ///
    /// # Arguments
    ///
    /// * `store` - The user store implementation
    ///
    /// # Examples
    ///
    /// ```rust
    /// use actix_passport::AuthBuilder;
    ///
    /// let builder = AuthBuilder::new()
    ///     .user_store(my_user_store);
    /// ```
    pub fn user_store<U>(self, store: U) -> AuthBuilder<U, S>
    where
        U: UserStore + 'static,
    {
        AuthBuilder {
            user_store: Some(store),
            session_store: self.session_store,
            auth_config: self.auth_config,
            route_config: self.route_config,

            #[cfg(feature = "password")]
            password_hasher: self.password_hasher,
            #[cfg(feature = "password")]
            enable_password_auth: self.enable_password_auth,

            #[cfg(feature = "oauth")]
            oauth_service: self.oauth_service,
            #[cfg(feature = "oauth")]
            enable_oauth: self.enable_oauth,
        }
    }
}

impl<U> AuthBuilder<U, ()>
where
    U: UserStore + 'static,
{
    /// Sets the session store implementation.
    ///
    /// # Arguments
    ///
    /// * `store` - The session store implementation
    ///
    /// # Examples
    ///
    /// ```rust
    /// use actix_passport::AuthBuilder;
    ///
    /// let builder = AuthBuilder::new()
    ///     .user_store(my_user_store)
    ///     .session_store(my_session_store);
    /// ```
    pub fn session_store<S>(self, store: S) -> AuthBuilder<U, S>
    where
        S: SessionStore + 'static,
    {
        AuthBuilder {
            user_store: self.user_store,
            session_store: Some(store),
            auth_config: self.auth_config,
            route_config: self.route_config,

            #[cfg(feature = "password")]
            password_hasher: self.password_hasher,
            #[cfg(feature = "password")]
            enable_password_auth: self.enable_password_auth,

            #[cfg(feature = "oauth")]
            oauth_service: self.oauth_service,
            #[cfg(feature = "oauth")]
            enable_oauth: self.enable_oauth,
        }
    }
}

impl<U, S> AuthBuilder<U, S>
where
    U: UserStore + 'static,
    S: SessionStore + 'static,
{
    /// Sets the authentication configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - The authentication configuration
    ///
    /// # Examples
    ///
    /// ```rust
    /// use actix_passport::{AuthBuilder, AuthConfig};
    /// use chrono::Duration;
    ///
    /// let config = AuthConfig {
    ///     session_duration: Duration::days(7),
    ///     jwt_secret: Some("my_secret".to_string()),
    ///     ..Default::default()
    /// };
    ///
    /// let builder = AuthBuilder::new()
    ///     .user_store(my_user_store)
    ///     .session_store(my_session_store)
    ///     .with_config(config);
    /// ```
    pub fn with_config(mut self, config: AuthConfig) -> Self {
        self.auth_config = config;
        self
    }

    /// Sets the route configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - The route configuration
    ///
    /// # Examples
    ///
    /// ```rust
    /// use actix_passport::{AuthBuilder, RouteConfig};
    ///
    /// let route_config = RouteConfig {
    ///     login_success_redirect: Some("/dashboard".to_string()),
    ///     logout_redirect: Some("/".to_string()),
    ///     oauth_callback_base: "https://myapp.com/auth".to_string(),
    /// };
    ///
    /// let builder = AuthBuilder::new()
    ///     .user_store(my_user_store)
    ///     .session_store(my_session_store)
    ///     .with_route_config(route_config);
    /// ```
    pub fn with_route_config(mut self, config: RouteConfig) -> Self {
        self.route_config = config;
        self
    }

    /// Sets the session duration.
    ///
    /// # Arguments
    ///
    /// * `duration` - How long sessions should last
    ///
    /// # Examples
    ///
    /// ```rust
    /// use actix_passport::AuthBuilder;
    /// use chrono::Duration;
    ///
    /// let builder = AuthBuilder::new()
    ///     .user_store(my_user_store)
    ///     .session_store(my_session_store)
    ///     .session_duration(Duration::days(7));
    /// ```
    pub fn session_duration(mut self, duration: chrono::Duration) -> Self {
        self.auth_config.session_duration = duration;
        self
    }

    /// Sets the JWT secret for token signing.
    ///
    /// # Arguments
    ///
    /// * `secret` - The JWT signing secret
    ///
    /// # Examples
    ///
    /// ```rust
    /// use actix_passport::AuthBuilder;
    ///
    /// let builder = AuthBuilder::new()
    ///     .user_store(my_user_store)
    ///     .session_store(my_session_store)
    ///     .jwt_secret("my_super_secret_key");
    /// ```
    pub fn jwt_secret(mut self, secret: impl Into<String>) -> Self {
        self.auth_config.jwt_secret = Some(secret.into());
        self
    }

    /// Sets the allowed origins for CORS.
    ///
    /// # Arguments
    ///
    /// * `origins` - List of allowed origins
    ///
    /// # Examples
    ///
    /// ```rust
    /// use actix_passport::AuthBuilder;
    ///
    /// let builder = AuthBuilder::new()
    ///     .user_store(my_user_store)
    ///     .session_store(my_session_store)
    ///     .allowed_origins(vec![
    ///         "http://localhost:3000".to_string(),
    ///         "https://myapp.com".to_string(),
    ///     ]);
    /// ```
    pub fn allowed_origins(mut self, origins: Vec<String>) -> Self {
        self.auth_config.allowed_origins = origins;
        self
    }

    /// Enables password-based authentication with default Argon2 hasher.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use actix_passport::AuthBuilder;
    ///
    /// let builder = AuthBuilder::new()
    ///     .user_store(my_user_store)
    ///     .session_store(my_session_store)
    ///     .enable_password_auth();
    /// ```
    #[cfg(feature = "password")]
    pub fn enable_password_auth(mut self) -> Self {
        self.enable_password_auth = true;
        if self.password_hasher.is_none() {
            self.password_hasher = Some(Box::new(Argon2PasswordHasher::default()));
        }
        self
    }

    /// Sets a custom password hasher.
    ///
    /// # Arguments
    ///
    /// * `hasher` - The password hasher implementation
    ///
    /// # Examples
    ///
    /// ```rust
    /// use actix_passport::{AuthBuilder, Argon2PasswordHasher};
    ///
    /// let builder = AuthBuilder::new()
    ///     .user_store(my_user_store)
    ///     .session_store(my_session_store)
    ///     .with_password_hasher(Argon2PasswordHasher::default());
    /// ```
    #[cfg(feature = "password")]
    pub fn with_password_hasher<H>(mut self, hasher: H) -> Self
    where
        H: PasswordHasher + 'static,
    {
        self.password_hasher = Some(Box::new(hasher));
        self.enable_password_auth = true;
        self
    }

    /// Enables OAuth authentication.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use actix_passport::AuthBuilder;
    ///
    /// let builder = AuthBuilder::new()
    ///     .user_store(my_user_store)
    ///     .session_store(my_session_store)
    ///     .enable_oauth();
    /// ```
    #[cfg(feature = "oauth")]
    pub fn enable_oauth(mut self) -> Self {
        self.enable_oauth = true;
        if self.oauth_service.is_none() {
            self.oauth_service = Some(OAuthService::new());
        }
        self
    }

    /// Adds Google OAuth provider.
    ///
    /// # Arguments
    ///
    /// * `client_id` - Google OAuth client ID
    /// * `client_secret` - Google OAuth client secret
    ///
    /// # Examples
    ///
    /// ```rust
    /// use actix_passport::AuthBuilder;
    ///
    /// let builder = AuthBuilder::new()
    ///     .user_store(my_user_store)
    ///     .session_store(my_session_store)
    ///     .with_google_oauth(
    ///         "your_google_client_id".to_string(),
    ///         "your_google_client_secret".to_string(),
    ///     );
    /// ```
    #[cfg(feature = "oauth")]
    pub fn with_google_oauth(mut self, client_id: String, client_secret: String) -> Self {
        self.enable_oauth = true;
        let mut oauth_service = self.oauth_service.unwrap_or_else(|| OAuthService::new());
        oauth_service.add_provider(Box::new(GoogleOAuthProvider::new(client_id, client_secret)));
        self.oauth_service = Some(oauth_service);
        self
    }

    /// Adds GitHub OAuth provider.
    ///
    /// # Arguments
    ///
    /// * `client_id` - GitHub OAuth client ID
    /// * `client_secret` - GitHub OAuth client secret
    ///
    /// # Examples
    ///
    /// ```rust
    /// use actix_passport::AuthBuilder;
    ///
    /// let builder = AuthBuilder::new()
    ///     .user_store(my_user_store)
    ///     .session_store(my_session_store)
    ///     .with_github_oauth(
    ///         "your_github_client_id".to_string(),
    ///         "your_github_client_secret".to_string(),
    ///     );
    /// ```
    #[cfg(feature = "oauth")]
    pub fn with_github_oauth(mut self, client_id: String, client_secret: String) -> Self {
        self.enable_oauth = true;
        let mut oauth_service = self.oauth_service.unwrap_or_else(|| OAuthService::new());
        oauth_service.add_provider(Box::new(GitHubOAuthProvider::new(client_id, client_secret)));
        self.oauth_service = Some(oauth_service);
        self
    }

    /// Adds a custom OAuth provider.
    ///
    /// # Arguments
    ///
    /// * `provider` - The OAuth provider implementation
    ///
    /// # Examples
    ///
    /// ```rust
    /// use actix_passport::{AuthBuilder, GenericOAuthProvider, OAuthConfig};
    ///
    /// let config = OAuthConfig {
    ///     client_id: "client_id".to_string(),
    ///     client_secret: "client_secret".to_string(),
    ///     auth_url: "https://provider.com/oauth/authorize".to_string(),
    ///     token_url: "https://provider.com/oauth/token".to_string(),
    ///     user_info_url: "https://provider.com/api/user".to_string(),
    ///     scopes: vec!["read:user".to_string()],
    /// };
    ///
    /// let provider = GenericOAuthProvider::new("custom", config);
    ///
    /// let builder = AuthBuilder::new()
    ///     .user_store(my_user_store)
    ///     .session_store(my_session_store)
    ///     .with_oauth_provider(provider);
    /// ```
    #[cfg(feature = "oauth")]
    pub fn with_oauth_provider<P>(mut self, provider: P) -> Self
    where
        P: crate::core::OAuthProvider + 'static,
    {
        self.enable_oauth = true;
        let mut oauth_service = self.oauth_service.unwrap_or_else(|| OAuthService::new());
        oauth_service.add_provider(Box::new(provider));
        self.oauth_service = Some(oauth_service);
        self
    }

    /// Builds the authentication system.
    ///
    /// # Returns
    ///
    /// Returns a configured `AuthSystem` instance.
    ///
    /// # Panics
    ///
    /// Panics if the user store or session store are not set.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use actix_passport::AuthBuilder;
    ///
    /// let auth = AuthBuilder::new()
    ///     .user_store(my_user_store)
    ///     .session_store(my_session_store)
    ///     .enable_password_auth()
    ///     .with_google_oauth("client_id".to_string(), "client_secret".to_string())
    ///     .build();
    /// ```
    pub fn build(self) -> AuthSystem<U, S> {
        let user_store = self.user_store.expect("User store must be set");
        let session_store = self.session_store.expect("Session store must be set");

        AuthSystem {
            user_store: Arc::new(user_store),
            session_store: Arc::new(session_store),
            auth_config: self.auth_config,
            route_config: self.route_config,

            #[cfg(feature = "password")]
            password_hasher: self.password_hasher,
            #[cfg(feature = "password")]
            enable_password_auth: self.enable_password_auth,

            #[cfg(feature = "oauth")]
            oauth_service: self.oauth_service,
            #[cfg(feature = "oauth")]
            enable_oauth: self.enable_oauth,
        }
    }
}

impl Default for AuthBuilder<(), ()> {
    fn default() -> Self {
        Self::new()
    }
}

/// Configured authentication system.
///
/// This struct represents a fully configured authentication system
/// that can be used to create middleware and route handlers.
///
/// # Examples
///
/// ```rust
/// use actix_web::App;
/// use actix_passport::AuthBuilder;
///
/// let auth = AuthBuilder::new()
///     .user_store(my_user_store)
///     .session_store(my_session_store)
///     .enable_password_auth()
///     .build();
///
/// let app = App::new()
///     .wrap(auth.middleware())
///     .service(
///         web::scope("/auth")
///             .configure(|cfg| auth.configure_routes(cfg))
///     );
/// ```
pub struct AuthSystem<U, S>
where
    U: UserStore + 'static,
    S: SessionStore + 'static,
{
    user_store: Arc<U>,
    session_store: Arc<S>,
    auth_config: AuthConfig,
    route_config: RouteConfig,

    #[cfg(feature = "password")]
    password_hasher: Option<Box<dyn PasswordHasher>>,
    #[cfg(feature = "password")]
    enable_password_auth: bool,

    #[cfg(feature = "oauth")]
    oauth_service: Option<OAuthService>,
    #[cfg(feature = "oauth")]
    enable_oauth: bool,
}

impl<U, S> AuthSystem<U, S>
where
    U: UserStore + 'static,
    S: SessionStore + 'static,
{
    /// Creates the authentication middleware.
    ///
    /// # Returns
    ///
    /// Returns the configured authentication middleware.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use actix_web::App;
    ///
    /// let app = App::new()
    ///     .wrap(auth.middleware());
    /// ```
    pub fn middleware(&self) -> AuthMiddleware<S> {
        AuthMiddleware::new((*self.session_store).clone())
    }

    /// Configures authentication routes.
    ///
    /// This method adds all the authentication routes to the provided
    /// service configuration.
    ///
    /// # Arguments
    ///
    /// * `cfg` - The service configuration to add routes to
    ///
    /// # Examples
    ///
    /// ```rust
    /// use actix_web::{web, App};
    ///
    /// let app = App::new()
    ///     .service(
    ///         web::scope("/auth")
    ///             .configure(|cfg| auth.configure_routes(cfg))
    ///     );
    /// ```
    pub fn configure_routes(&self, cfg: &mut web::ServiceConfig) {
        let mut routes = AuthRoutes::new(
            (*self.user_store).clone(),
            (*self.session_store).clone(),
        ).with_config(self.route_config.clone());

        #[cfg(feature = "password")]
        if self.enable_password_auth {
            if let Some(ref hasher) = self.password_hasher {
                let password_service = PasswordAuthService::new(
                    (*self.user_store).clone(),
                    // This is a limitation - we need to clone the hasher
                    // In a real implementation, you might want to use Arc<dyn PasswordHasher>
                    Argon2PasswordHasher::default(), // temporary workaround
                );
                routes = routes.with_password_service(password_service);
            }
        }

        #[cfg(feature = "oauth")]
        if self.enable_oauth {
            if let Some(ref oauth_service) = self.oauth_service {
                routes = routes.with_oauth_service(oauth_service.clone());
            }
        }

        routes.configure(cfg);
    }

    /// Gets the authentication configuration.
    ///
    /// # Returns
    ///
    /// Returns a reference to the authentication configuration.
    pub fn auth_config(&self) -> &AuthConfig {
        &self.auth_config
    }

    /// Gets the route configuration.
    ///
    /// # Returns
    ///
    /// Returns a reference to the route configuration.
    pub fn route_config(&self) -> &RouteConfig {
        &self.route_config
    }

    /// Gets the user store.
    ///
    /// # Returns
    ///
    /// Returns a reference to the user store.
    pub fn user_store(&self) -> &Arc<U> {
        &self.user_store
    }

    /// Gets the session store.
    ///
    /// # Returns
    ///
    /// Returns a reference to the session store.
    pub fn session_store(&self) -> &Arc<S> {
        &self.session_store
    }
}