//! Builder for constructing the main authentication framework.

use crate::{
    oauth::{service::OAuthService, OAuthProvider},
    password::service::PasswordAuthService,
    prelude::UserStore,
    types::AuthConfig,
    user_store::stores::in_memory::InMemoryUserStore,
};
#[cfg(feature = "postgres")]
use crate::{PostgresConfig, PostgresUserStore};
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
/// use actix_passport::{ActixPassportBuilder, user_store::UserStore};
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
/// let auth_framework = ActixPassportBuilder::new(MyUserStore)
///     .enable_password_auth()
///     .build();
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
/// use actix_passport::{ActixPassportBuilder, user_store::UserStore};
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
/// let builder = ActixPassportBuilder::new(MyUserStore)
///     .enable_password_auth();  // Enables Argon2-based password authentication
///
/// # #[cfg(feature = "oauth")]
/// # let builder = builder.with_oauth(GoogleOAuthProvider::new("client_id".to_string(), "client_secret".to_string()));
///
/// let framework = builder.build();
/// ```
pub struct ActixPassportBuilder<U>
where
    U: UserStore + 'static,
{
    user_store: U,
    enable_password_auth: bool,
    oauth_providers: Vec<Box<dyn OAuthProvider>>,
    config: AuthConfig,
}

impl<U> ActixPassportBuilder<U>
where
    U: UserStore + Clone,
{
    /// Creates a new builder.
    #[must_use]
    pub fn new(user_store: U) -> Self {
        Self {
            user_store,
            enable_password_auth: false,
            oauth_providers: Vec::new(),
            config: AuthConfig::default(),
        }
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
    /// # use actix_passport::{user_store::UserStore, types::{AuthResult, AuthUser}};
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
    /// let framework = ActixPassportBuilder::new(MyUserStore)
    ///     .enable_password_auth()  // Enables password auth with Argon2
    ///     .build();
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
    /// # use actix_passport::{user_store::UserStore, types::{AuthResult, AuthUser}};
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
    /// let framework = ActixPassportBuilder::new(MyUserStore)
    ///     .with_google_oauth("your_client_id".to_string(), "your_client_secret".to_string())
    ///     .build();
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
    /// # use actix_passport::{user_store::UserStore, types::{AuthResult, AuthUser}};
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
    /// let framework = ActixPassportBuilder::new(MyUserStore)
    ///     .with_github_oauth("your_client_id".to_string(), "your_client_secret".to_string())
    ///     .build();
    /// ```
    #[cfg(feature = "oauth")]
    #[must_use]
    pub fn with_github_oauth(self, client_id: String, client_secret: String) -> Self {
        use crate::GitHubOAuthProvider;
        let provider = GitHubOAuthProvider::new(client_id, client_secret);
        self.with_oauth(provider)
    }

    /// Builds the `ActixPassport`.
    pub fn build(self) -> ActixPassport {
        let password_service = if self.enable_password_auth {
            Some(PasswordAuthService::new(Box::new(self.user_store.clone())))
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

        ActixPassport {
            user_store: Box::new(self.user_store),
            password_service,
            oauth_service,
            config: Arc::new(config),
        }
    }
}

impl ActixPassportBuilder<InMemoryUserStore> {
    /// Creates a new builder with an in-memory user store.
    ///
    /// This is a convenience method for quick setup and development.
    /// The in-memory store is not persistent and data will be lost
    /// when the application restarts.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use actix_passport::ActixPassportBuilder;
    ///
    /// let framework = ActixPassportBuilder::with_in_memory_store()
    ///     .enable_password_auth()
    ///     .build();
    /// ```
    #[must_use]
    pub fn with_in_memory_store() -> Self {
        Self::new(InMemoryUserStore::new())
    }
}

#[cfg(feature = "postgres")]
impl ActixPassportBuilder<PostgresUserStore> {
    /// Creates a new builder with a `PostgreSQL` user store.
    ///
    /// This method connects to `PostgreSQL` using the provided connection string
    /// and automatically runs migrations if enabled in the configuration.
    ///
    /// # Arguments
    ///
    /// * `database_url` - `PostgreSQL` connection string (e.g., "<postgres://user:pass@localhost/db>")
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use actix_passport::ActixPassportBuilder;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let framework = ActixPassportBuilder::with_postgres_store("postgres://user:pass@localhost/db")
    ///     .await
    ///     .unwrap()
    ///     .enable_password_auth()
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the database connection fails or migrations fail.
    pub async fn with_postgres_store(
        database_url: &str,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let store = PostgresUserStore::new(database_url).await?;
        Ok(Self::new(store))
    }

    /// Creates a new builder with a `PostgreSQL` user store using custom configuration.
    ///
    /// # Arguments
    ///
    /// * `database_url` - `PostgreSQL` connection string
    /// * `config` - `PostgreSQL` store configuration
    ///
    /// # Errors
    ///
    /// * `Err(Box<dyn std::error::Error + Send + Sync>)` - If the database connection fails or migrations fail
    ///
    /// # Returns
    ///
    /// * `Ok(Self)` - If the store is created successfully
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use actix_passport::{ActixPassportBuilder, user_store::stores::postgres::PostgresConfig};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = PostgresConfig {
    ///     max_connections: 20,
    ///     auto_migrate: false,
    /// };
    ///
    /// let framework = ActixPassportBuilder::with_postgres_store_config(
    ///         "postgres://user:pass@localhost/db",
    ///         config
    ///     )
    ///     .await
    ///     .unwrap()
    ///     .enable_password_auth()
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    pub async fn with_postgres_store_config(
        database_url: &str,
        config: PostgresConfig,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let store = PostgresUserStore::with_config(database_url, config).await?;
        Ok(Self::new(store))
    }
}
