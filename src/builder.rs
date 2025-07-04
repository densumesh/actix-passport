//! Builder for constructing the main authentication framework.

use crate::{prelude::UserStore, strategy::AuthStrategy};

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
/// let password_strategy = actix_passport::strategy::strategies::password::PasswordStrategy::new(MyUserStore);
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
/// let password_strategy = actix_passport::strategy::strategies::password::PasswordStrategy::new(MyUserStore);
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
    /// use actix_passport::{ActixPassportBuilder, strategy::strategies::password::PasswordStrategy};
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
    /// let strategy = actix_passport::strategy::strategies::password::PasswordStrategy::new(MyUserStore);
    /// let framework = ActixPassportBuilder::new(MyUserStore)
    ///     .add_strategy(strategy)
    ///     .build();
    /// ```
    #[must_use]
    pub fn add_strategy(mut self, strategy: impl AuthStrategy + 'static) -> Self {
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
