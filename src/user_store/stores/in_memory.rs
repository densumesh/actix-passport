use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use async_trait::async_trait;

use crate::{
    errors::AuthError,
    prelude::UserStore,
    types::{AuthResult, AuthUser},
};

/// In-memory user store implementation for development and testing.
///
/// This implementation stores users in memory using a thread-safe `HashMap`.
/// It's perfect for prototyping, development, and testing, but data is lost
/// when the application restarts.
///
/// **Warning**: This store is not persistent. All user data will be lost
/// when the application shuts down. Use a database-backed implementation
/// for production applications.
///
/// # Examples
///
/// ```rust
/// use actix_passport::{user_store::stores::in_memory::InMemoryUserStore, ActixPassportBuilder};
///
/// let auth_framework = ActixPassportBuilder::with_in_memory_store()
///     .enable_password_auth()
///     .build();
/// ```
///
/// Or use the convenience method:
///
/// ```rust
/// use actix_passport::ActixPassportBuilder;
///
/// let auth_framework = ActixPassportBuilder::with_in_memory_store()
///     .enable_password_auth()
///     .build();
/// ```
#[derive(Clone)]
pub struct InMemoryUserStore {
    /// Thread-safe storage for users indexed by ID
    users: Arc<RwLock<HashMap<String, AuthUser>>>,
    /// Secondary index for email lookups
    email_index: Arc<RwLock<HashMap<String, String>>>,
    /// Secondary index for username lookups
    username_index: Arc<RwLock<HashMap<String, String>>>,
}

impl InMemoryUserStore {
    /// Creates a new empty in-memory user store.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use actix_passport::prelude::InMemoryUserStore;
    ///
    /// let store = InMemoryUserStore::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            users: Arc::new(RwLock::new(HashMap::new())),
            email_index: Arc::new(RwLock::new(HashMap::new())),
            username_index: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Creates a new in-memory user store pre-populated with users.
    ///
    /// This is useful for testing or demo scenarios where you want
    /// to start with some existing users.
    ///
    /// # Arguments
    ///
    /// * `users` - Vector of users to pre-populate the store with
    ///
    /// # Examples
    ///
    /// ```rust
    /// use actix_passport::{prelude::InMemoryUserStore, AuthUser};
    ///
    /// let demo_user = AuthUser::new("demo-id".to_string())
    ///     .with_email("demo@example.com")
    ///     .with_username("demo");
    ///
    /// let store = InMemoryUserStore::with_users(vec![demo_user]);
    /// ```
    #[must_use]
    pub fn with_users(users: Vec<AuthUser>) -> Self {
        let store = Self::new();

        for user in users {
            // Pre-populate indexes
            if let Some(ref email) = user.email {
                if !email.is_empty() {
                    if let Ok(mut email_index) = store.email_index.write() {
                        email_index.insert(email.clone(), user.id.clone());
                    }
                }
            }

            if let Some(ref username) = user.username {
                if !username.is_empty() {
                    if let Ok(mut username_index) = store.username_index.write() {
                        username_index.insert(username.clone(), user.id.clone());
                    }
                }
            }

            // Store user
            if let Ok(mut users_map) = store.users.write() {
                users_map.insert(user.id.clone(), user);
            }
        }

        store
    }

    /// Returns the current number of users in the store.
    ///
    /// This is useful for testing and debugging.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use actix_passport::prelude::InMemoryUserStore;
    ///
    /// let store = InMemoryUserStore::new();
    /// assert_eq!(store.user_count(), 0);
    /// ```
    #[must_use]
    pub fn user_count(&self) -> usize {
        self.users.read().map_or(0, |users| users.len())
    }

    /// Clears all users from the store.
    ///
    /// This is useful for testing scenarios where you need to reset state.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use actix_passport::prelude::InMemoryUserStore;
    ///
    /// let store = InMemoryUserStore::new();
    /// store.clear();
    /// assert_eq!(store.user_count(), 0);
    /// ```
    pub fn clear(&self) {
        if let (Ok(mut users), Ok(mut email_index), Ok(mut username_index)) = (
            self.users.write(),
            self.email_index.write(),
            self.username_index.write(),
        ) {
            users.clear();
            email_index.clear();
            username_index.clear();
        }
    }
}

impl Default for InMemoryUserStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl UserStore for InMemoryUserStore {
    async fn find_by_id(&self, id: &str) -> AuthResult<Option<AuthUser>> {
        let users = self.users.read().map_err(|_| {
            AuthError::database_error("find_by_id", "Failed to acquire read lock on user store")
        })?;

        Ok(users.get(id).cloned())
    }

    async fn find_by_email(&self, email: &str) -> AuthResult<Option<AuthUser>> {
        let user_id = {
            let email_index = self.email_index.read().map_err(|_| {
                AuthError::database_error(
                    "find_by_email",
                    "Failed to acquire read lock on email index",
                )
            })?;

            email_index.get(email).cloned()
        };

        if let Some(user_id) = user_id {
            self.find_by_id(&user_id).await
        } else {
            Ok(None)
        }
    }

    async fn find_by_username(&self, username: &str) -> AuthResult<Option<AuthUser>> {
        let user_id = {
            let username_index = self.username_index.read().map_err(|_| {
                AuthError::database_error(
                    "find_by_username",
                    "Failed to acquire read lock on username index",
                )
            })?;

            username_index.get(username).cloned()
        };

        if let Some(user_id) = user_id {
            self.find_by_id(&user_id).await
        } else {
            Ok(None)
        }
    }

    async fn create_user(&self, user: AuthUser) -> AuthResult<AuthUser> {
        // Check if user with this email already exists
        if let Some(ref email) = user.email {
            if !email.is_empty() && self.find_by_email(email).await?.is_some() {
                return Err(AuthError::user_already_exists("email", email));
            }
        }

        // Check if user with this username already exists
        if let Some(ref username) = user.username {
            if !username.is_empty() && self.find_by_username(username).await?.is_some() {
                return Err(AuthError::user_already_exists("username", username));
            }
        }

        let (mut users, mut email_index, mut username_index) = (
            self.users.write().map_err(|_| {
                AuthError::database_error(
                    "create_user",
                    "Failed to acquire write lock on user store",
                )
            })?,
            self.email_index.write().map_err(|_| {
                AuthError::database_error(
                    "create_user",
                    "Failed to acquire write lock on email index",
                )
            })?,
            self.username_index.write().map_err(|_| {
                AuthError::database_error(
                    "create_user",
                    "Failed to acquire write lock on username index",
                )
            })?,
        );

        // Insert into indexes
        if let Some(ref email) = user.email {
            if !email.is_empty() {
                email_index.insert(email.clone(), user.id.clone());
            }
        }

        if let Some(ref username) = user.username {
            if !username.is_empty() {
                username_index.insert(username.clone(), user.id.clone());
            }
        }

        // Insert user
        users.insert(user.id.clone(), user.clone());

        Ok(user)
    }

    async fn update_user(&self, user: AuthUser) -> AuthResult<AuthUser> {
        let (mut users, mut email_index, mut username_index) = (
            self.users.write().map_err(|_| {
                AuthError::database_error(
                    "update_user",
                    "Failed to acquire write lock on user store",
                )
            })?,
            self.email_index.write().map_err(|_| {
                AuthError::database_error(
                    "update_user",
                    "Failed to acquire write lock on email index",
                )
            })?,
            self.username_index.write().map_err(|_| {
                AuthError::database_error(
                    "update_user",
                    "Failed to acquire write lock on username index",
                )
            })?,
        );

        // Check if user exists
        let existing_user = users
            .get(&user.id)
            .ok_or_else(|| AuthError::user_not_found("id", &user.id))?;

        // Update indexes if email or username changed
        if existing_user.email != user.email {
            // Remove old email from index
            if let Some(ref old_email) = existing_user.email {
                if !old_email.is_empty() {
                    email_index.remove(old_email);
                }
            }
            // Add new email to index
            if let Some(ref new_email) = user.email {
                if !new_email.is_empty() {
                    email_index.insert(new_email.clone(), user.id.clone());
                }
            }
        }

        if existing_user.username != user.username {
            // Remove old username from index
            if let Some(ref old_username) = existing_user.username {
                if !old_username.is_empty() {
                    username_index.remove(old_username);
                }
            }
            // Add new username to index
            if let Some(ref new_username) = user.username {
                if !new_username.is_empty() {
                    username_index.insert(new_username.clone(), user.id.clone());
                }
            }
        }

        // Update user
        users.insert(user.id.clone(), user.clone());

        Ok(user)
    }

    async fn delete_user(&self, id: &str) -> AuthResult<()> {
        let (mut users, mut email_index, mut username_index) = (
            self.users.write().map_err(|_| {
                AuthError::database_error(
                    "delete_user",
                    "Failed to acquire write lock on user store",
                )
            })?,
            self.email_index.write().map_err(|_| {
                AuthError::database_error(
                    "delete_user",
                    "Failed to acquire write lock on email index",
                )
            })?,
            self.username_index.write().map_err(|_| {
                AuthError::database_error(
                    "delete_user",
                    "Failed to acquire write lock on username index",
                )
            })?,
        );

        // Get user to remove from indexes
        if let Some(user) = users.remove(id) {
            // Remove from indexes
            if let Some(ref email) = user.email {
                if !email.is_empty() {
                    email_index.remove(email);
                }
            }
            if let Some(ref username) = user.username {
                if !username.is_empty() {
                    username_index.remove(username);
                }
            }
        }

        Ok(())
    }
}
