//! Builder for constructing the main authentication framework.

#[cfg(feature = "oauth")]
use crate::OAuthProvider;
use crate::{
    prelude::UserStore, strategies::AuthStrategy, user_store::stores::in_memory::InMemoryUserStore,
};
#[cfg(feature = "postgres")]
use crate::{PostgresConfig, PostgresUserStore};

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
/// use actix_passport::{ActixPassportBuilder, user_store::UserStore, prelude::PasswordStrategy};
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
/// let password_strategy = PasswordStrategy::new();
/// let auth_framework = ActixPassportBuilder::new(MyUserStore)
///     .add_strategy(password_strategy)
///     .build();
/// ```
#[derive(Clone)]
pub struct ActixPassport {
    /// The user store implementation for persisting user data
    pub user_store: Box<dyn UserStore>,
    /// Registered authentication strategies
    pub strategies: Vec<Box<dyn AuthStrategy>>,
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
/// use actix_passport::{ActixPassportBuilder, user_store::UserStore, prelude::PasswordStrategy};
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
/// let password_strategy = PasswordStrategy::new();
/// let builder = ActixPassportBuilder::new(MyUserStore)
///     .add_strategy(password_strategy);  // Add password authentication strategy
///
/// let framework = builder.build();
/// ```
pub struct ActixPassportBuilder<U>
where
    U: UserStore + 'static,
{
    user_store: U,
    strategies: Vec<Box<dyn AuthStrategy>>,
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
            strategies: Vec::new(),
        }
    }

    /// Adds an authentication strategy to the framework.
    ///
    /// This method allows you to register any authentication strategy
    /// that implements the `AuthStrategy` trait. The strategy will be
    /// used for both authentication and route configuration.
    ///
    /// # Arguments
    ///
    /// * `strategy` - The authentication strategy to add
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use actix_passport::{ActixPassportBuilder, strategies::password::PasswordStrategy};
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
    /// let strategy = PasswordStrategy::new();
    /// let framework = ActixPassportBuilder::new(MyUserStore)
    ///     .add_strategy(strategy)
    ///     .build();
    /// ```
    #[must_use]
    pub fn add_strategy(mut self, strategy: impl AuthStrategy + 'static) -> Self {
        self.strategies.push(Box::new(strategy));
        self
    }

    /// Enables password authentication using Argon2 hashing.
    ///
    /// This is a convenience method that creates and adds a `PasswordStrategy`
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
    ///     .enable_password_auth()  // Creates and adds PasswordStrategy internally
    ///     .build();
    /// ```
    #[cfg(feature = "password")]
    #[must_use]
    pub fn enable_password_auth(mut self) -> Self {
        use crate::prelude::PasswordStrategy;

        let strategy = PasswordStrategy::new();
        self.strategies.push(Box::new(strategy));
        self
    }

    /// Enables OAuth authentication with support for multiple providers.
    ///
    /// This is a convenience method that creates and adds an `OAuthStrategy`
    /// to the framework. You can then add specific OAuth providers using
    /// the `with_google_oauth()`, `with_github_oauth()`, or `with_oauth()` methods.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use actix_passport::{ActixPassportBuilder, GoogleOAuthProvider, GitHubOAuthProvider};
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
    /// let google_provider = GoogleOAuthProvider::new("client_id".to_string(), "client_secret".to_string());
    /// let github_provider = GitHubOAuthProvider::new("client_id".to_string(), "client_secret".to_string());
    ///
    /// let framework = ActixPassportBuilder::new(MyUserStore)
    ///     .enable_oauth(vec![Box::new(google_provider), Box::new(github_provider)])
    ///     .build();
    /// ```
    #[cfg(feature = "oauth")]
    #[must_use]
    pub fn enable_oauth(mut self, providers: Vec<Box<dyn OAuthProvider>>) -> Self {
        use crate::strategies::oauth::OAuthStrategy;
        let strategy = OAuthStrategy::new(providers);
        self.strategies.push(Box::new(strategy));

        self
    }

    /// Builds the `ActixPassport`.
    pub fn build(self) -> ActixPassport {
        ActixPassport {
            user_store: Box::new(self.user_store),
            strategies: self.strategies,
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
    /// # async fn example() -> std::io::Result<()> {
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
    /// # async fn example() -> std::io::Result<()> {
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
