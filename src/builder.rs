//! Builder for constructing the main authentication framework.

use crate::{
    core::{AuthConfig, UserStore},
    errors::AuthError,
    oauth::{service::OAuthService, OAuthProvider},
    password::service::PasswordAuthService,
};
use std::sync::Arc;

/// The main authentication framework object.
///
/// This struct is created by the `ActixPassportBuilder` and holds all the
/// configured services and stores. It is intended to be cloned and stored
/// in the actix-web application data.
///
/// # Type Parameters
///
/// * `U` - The user store implementation that handles user persistence
///
/// # Examples
///
/// ```rust,no_run
/// use actix_passport::{ActixPassportBuilder, core::UserStore};
/// # use actix_passport::types::{AuthResult, AuthUser};
/// # use async_trait::async_trait;
/// # #[derive(Clone)] struct MyUserStore;
/// # #[async_trait]
/// # impl UserStore for MyUserStore {
/// #   async fn find_by_id(&self, id: &str) -> AuthResult<Option<AuthUser>> { Ok(None) }
/// #   async fn find_by_email(&self, email: &str) -> AuthResult<Option<AuthUser>> { Ok(None) }
/// #   async fn find_by_username(&self, username: &str) -> AuthResult<Option<AuthUser>> { Ok(None) }
/// #   async fn create_user(&self, user: AuthUser) -> AuthResult<AuthUser> { Ok(user) }
/// #   async fn update_user(&self, user: AuthUser) -> AuthResult<AuthUser> { Ok(user) }
/// #   async fn delete_user(&self, id: &str) -> AuthResult<()> { Ok(()) }
/// # }
///
/// let auth_framework = ActixPassportBuilder::new()
///     .with_user_store(MyUserStore)
///     .enable_password_auth()
///     .build()
///     .expect("Failed to build framework");
/// ```
#[derive(Clone)]
pub struct ActixPassport {
    /// The user store implementation for persisting user data
    pub user_store: Box<dyn UserStore>,
    /// Optional password authentication service (available when password auth is enabled)
    pub password_service: Option<PasswordAuthService>,
    /// Optional OAuth service (available when OAuth providers are configured)
    pub oauth_service: Option<OAuthService>,
    /// Authentication configuration settings
    pub(crate) config: Arc<AuthConfig>,
}

/// Builder for configuring and creating an `ActixPassport`.
///
/// This builder allows you to configure various authentication methods
/// and services before creating the final framework instance.
///
/// # Type Parameters
///
/// * `U` - The user store implementation that handles user persistence
///
/// # Examples
///
/// ```rust,no_run
/// use actix_passport::{ActixPassportBuilder, core::UserStore};
/// # use actix_passport::types::{AuthResult, AuthUser};
/// # use async_trait::async_trait;
/// # #[derive(Clone)] struct MyUserStore;
/// # #[async_trait] impl UserStore for MyUserStore {
/// #   async fn find_by_id(&self, id: &str) -> AuthResult<Option<AuthUser>> { Ok(None) }
/// #   async fn find_by_email(&self, email: &str) -> AuthResult<Option<AuthUser>> { Ok(None) }
/// #   async fn find_by_username(&self, username: &str) -> AuthResult<Option<AuthUser>> { Ok(None) }
/// #   async fn create_user(&self, user: AuthUser) -> AuthResult<AuthUser> { Ok(user) }
/// #   async fn update_user(&self, user: AuthUser) -> AuthResult<AuthUser> { Ok(user) }
/// #   async fn delete_user(&self, id: &str) -> AuthResult<()> { Ok(()) }
/// # }
/// # #[cfg(feature = "oauth")]
/// # use actix_passport::GoogleOAuthProvider;
///
/// let builder = ActixPassportBuilder::new()
///     .with_user_store(MyUserStore)
///     .enable_password_auth();  // Enables Argon2-based password authentication
///
/// # #[cfg(feature = "oauth")]
/// # let builder = builder.with_oauth(GoogleOAuthProvider::new("client_id".to_string(), "client_secret".to_string()));
///
/// let framework = builder.build().expect("Failed to build framework");
/// ```
pub struct ActixPassportBuilder<U>
where
    U: UserStore + 'static,
{
    user_store: Option<U>,
    enable_password_auth: bool,
    oauth_providers: Vec<Box<dyn OAuthProvider>>,
    config: AuthConfig,
}

impl<U> Default for ActixPassportBuilder<U>
where
    U: UserStore + 'static,
{
    fn default() -> Self {
        Self {
            user_store: None,
            enable_password_auth: false,
            oauth_providers: Vec::new(),
            config: AuthConfig::default(),
        }
    }
}

impl<U> ActixPassportBuilder<U>
where
    U: UserStore + Clone,
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

    /// Enables password authentication using Argon2 hashing.
    ///
    /// When enabled, this adds password-based authentication capabilities
    /// to the framework. Users will be able to register and login using
    /// email/username and password combinations. Passwords are securely
    /// hashed using the Argon2 algorithm.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use actix_passport::ActixPassportBuilder;
    /// # use actix_passport::{core::UserStore, types::{AuthResult, AuthUser}};
    /// # use async_trait::async_trait;
    /// # #[derive(Clone)] struct MyUserStore;
    /// # #[async_trait] impl UserStore for MyUserStore {
    /// #   async fn find_by_id(&self, id: &str) -> AuthResult<Option<AuthUser>> { Ok(None) }
    /// #   async fn find_by_email(&self, email: &str) -> AuthResult<Option<AuthUser>> { Ok(None) }
    /// #   async fn find_by_username(&self, username: &str) -> AuthResult<Option<AuthUser>> { Ok(None) }
    /// #   async fn create_user(&self, user: AuthUser) -> AuthResult<AuthUser> { Ok(user) }
    /// #   async fn update_user(&self, user: AuthUser) -> AuthResult<AuthUser> { Ok(user) }
    /// #   async fn delete_user(&self, id: &str) -> AuthResult<()> { Ok(()) }
    /// # }
    ///
    /// let framework = ActixPassportBuilder::new()
    ///     .with_user_store(MyUserStore)
    ///     .enable_password_auth()  // Enables password auth with Argon2
    ///     .build()
    ///     .expect("Failed to build framework");
    /// ```
    #[must_use]
    pub const fn enable_password_auth(mut self) -> Self {
        self.enable_password_auth = true;
        self
    }

    /// Adds an OAuth provider.
    #[must_use]
    pub fn with_oauth(mut self, provider: impl OAuthProvider + 'static) -> Self {
        self.oauth_providers.push(Box::new(provider));
        self
    }

    /// Adds Google OAuth authentication with the provided client credentials.
    ///
    /// This is a convenience method that creates and configures a Google OAuth
    /// provider with the standard Google OAuth endpoints and scopes.
    ///
    /// # Arguments
    ///
    /// * `client_id` - Your Google OAuth client ID
    /// * `client_secret` - Your Google OAuth client secret
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use actix_passport::ActixPassportBuilder;
    /// # use actix_passport::{core::UserStore, types::{AuthResult, AuthUser}};
    /// # use async_trait::async_trait;
    /// # #[derive(Clone)] struct MyUserStore;
    /// # #[async_trait] impl UserStore for MyUserStore {
    /// #   async fn find_by_id(&self, id: &str) -> AuthResult<Option<AuthUser>> { Ok(None) }
    /// #   async fn find_by_email(&self, email: &str) -> AuthResult<Option<AuthUser>> { Ok(None) }
    /// #   async fn find_by_username(&self, username: &str) -> AuthResult<Option<AuthUser>> { Ok(None) }
    /// #   async fn create_user(&self, user: AuthUser) -> AuthResult<AuthUser> { Ok(user) }
    /// #   async fn update_user(&self, user: AuthUser) -> AuthResult<AuthUser> { Ok(user) }
    /// #   async fn delete_user(&self, id: &str) -> AuthResult<()> { Ok(()) }
    /// # }
    ///
    /// let framework = ActixPassportBuilder::new()
    ///     .with_user_store(MyUserStore)
    ///     .with_google_oauth("your_client_id".to_string(), "your_client_secret".to_string())
    ///     .build()
    ///     .expect("Failed to build framework");
    /// ```
    #[cfg(feature = "oauth")]
    #[must_use]
    pub fn with_google_oauth(self, client_id: String, client_secret: String) -> Self {
        use crate::GoogleOAuthProvider;
        let provider = GoogleOAuthProvider::new(client_id, client_secret);
        self.with_oauth(provider)
    }

    /// Adds GitHub OAuth authentication with the provided client credentials.
    ///
    /// This is a convenience method that creates and configures a GitHub OAuth
    /// provider with the standard GitHub OAuth endpoints and scopes.
    ///
    /// # Arguments
    ///
    /// * `client_id` - Your GitHub OAuth client ID
    /// * `client_secret` - Your GitHub OAuth client secret
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use actix_passport::ActixPassportBuilder;
    /// # use actix_passport::{core::UserStore, types::{AuthResult, AuthUser}};
    /// # use async_trait::async_trait;
    /// # #[derive(Clone)] struct MyUserStore;
    /// # #[async_trait] impl UserStore for MyUserStore {
    /// #   async fn find_by_id(&self, id: &str) -> AuthResult<Option<AuthUser>> { Ok(None) }
    /// #   async fn find_by_email(&self, email: &str) -> AuthResult<Option<AuthUser>> { Ok(None) }
    /// #   async fn find_by_username(&self, username: &str) -> AuthResult<Option<AuthUser>> { Ok(None) }
    /// #   async fn create_user(&self, user: AuthUser) -> AuthResult<AuthUser> { Ok(user) }
    /// #   async fn update_user(&self, user: AuthUser) -> AuthResult<AuthUser> { Ok(user) }
    /// #   async fn delete_user(&self, id: &str) -> AuthResult<()> { Ok(()) }
    /// # }
    ///
    /// let framework = ActixPassportBuilder::new()
    ///     .with_user_store(MyUserStore)
    ///     .with_github_oauth("your_client_id".to_string(), "your_client_secret".to_string())
    ///     .build()
    ///     .expect("Failed to build framework");
    /// ```
    #[cfg(feature = "oauth")]
    #[must_use]
    pub fn with_github_oauth(self, client_id: String, client_secret: String) -> Self {
        use crate::GitHubOAuthProvider;
        let provider = GitHubOAuthProvider::new(client_id, client_secret);
        self.with_oauth(provider)
    }

    /// Configures OAuth providers from environment variables.
    ///
    /// This convenience method automatically configures Google and GitHub OAuth
    /// providers based on environment variables, if they are present.
    ///
    /// Expected environment variables:
    /// - `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` for Google OAuth
    /// - `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET` for GitHub OAuth
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use actix_passport::ActixPassportBuilder;
    /// # use actix_passport::{core::UserStore, types::{AuthResult, AuthUser}};
    /// # use async_trait::async_trait;
    /// # #[derive(Clone)] struct MyUserStore;
    /// # #[async_trait] impl UserStore for MyUserStore {
    /// #   async fn find_by_id(&self, id: &str) -> AuthResult<Option<AuthUser>> { Ok(None) }
    /// #   async fn find_by_email(&self, email: &str) -> AuthResult<Option<AuthUser>> { Ok(None) }
    /// #   async fn find_by_username(&self, username: &str) -> AuthResult<Option<AuthUser>> { Ok(None) }
    /// #   async fn create_user(&self, user: AuthUser) -> AuthResult<AuthUser> { Ok(user) }
    /// #   async fn update_user(&self, user: AuthUser) -> AuthResult<AuthUser> { Ok(user) }
    /// #   async fn delete_user(&self, id: &str) -> AuthResult<()> { Ok(()) }
    /// # }
    ///
    /// let framework = ActixPassportBuilder::new()
    ///     .with_user_store(MyUserStore)
    ///     .with_oauth_from_env()
    ///     .build()
    ///     .expect("Failed to build framework");
    /// ```
    #[cfg(feature = "oauth")]
    #[must_use]
    pub fn with_oauth_from_env(mut self) -> Self {
        // Try to configure Google OAuth from environment
        if let (Ok(google_client_id), Ok(google_client_secret)) = (
            std::env::var("GOOGLE_CLIENT_ID"),
            std::env::var("GOOGLE_CLIENT_SECRET"),
        ) {
            self = self.with_google_oauth(google_client_id, google_client_secret);
        }

        // Try to configure GitHub OAuth from environment
        if let (Ok(github_client_id), Ok(github_client_secret)) = (
            std::env::var("GITHUB_CLIENT_ID"),
            std::env::var("GITHUB_CLIENT_SECRET"),
        ) {
            self = self.with_github_oauth(github_client_id, github_client_secret);
        }

        self
    }

    

    /// Builds the `ActixPassport`.
    ///
    /// # Panics
    ///
    /// Panics if `user_store` is not set.
    ///
    /// # Errors
    ///
    /// Returns an error if `user_store` is not set.
    pub fn build(self) -> Result<ActixPassport, Box<dyn std::error::Error>> {
        let user_store = self
            .user_store
            .ok_or_else(|| AuthError::ConfigurationError {
                message: "A UserStore is required".to_string(),
                suggestions: vec!["Call .with_user_store() on the builder".to_string()],
            })?;

        let password_service = if self.enable_password_auth {
            Some(PasswordAuthService::new(Box::new(user_store.clone())))
        } else {
            None
        };

        let has_oauth = !self.oauth_providers.is_empty();
        let oauth_service = if has_oauth {
            let mut service = OAuthService::new();
            for provider in self.oauth_providers {
                service.add_provider(provider);
            }
            Some(service)
        } else {
            None
        };

        // Auto-enable session auth if password auth or OAuth is enabled
        let mut config = self.config;
        if self.enable_password_auth {
            config.password_auth = true;
        }
        if has_oauth {
            config.oauth_auth = true;
        }

        Ok(ActixPassport {
            user_store: Box::new(user_store),
            password_service,
            oauth_service,
            config: Arc::new(config),
        })
    }
}
