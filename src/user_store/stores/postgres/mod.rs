/// `PostgreSQL` user store implementation using `SQLx`.
use crate::{
    errors::AuthError,
    types::{AuthResult, AuthUser},
    user_store::{
        stores::common::{error_mapping, json_helpers, sql_helpers},
        UserStore,
    },
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::Value as JsonValue;
use sqlx::{postgres::PgPoolOptions, PgPool, Row};
use uuid::Uuid;

/// `PostgreSQL` user store with connection pooling and migrations.
#[derive(Clone)]
pub struct PostgresUserStore {
    pool: PgPool,
}

impl PostgresUserStore {
    /// Create a new `PostgreSQL` user store with default configuration.
    ///
    /// # Arguments
    ///
    /// * `database_url` - `PostgreSQL` connection string
    ///
    /// # Errors
    ///
    /// * `Err(sqlx::Error::Configuration(format!("Migration failed: {e}")))` - If the migration fails
    ///
    /// # Returns
    ///
    /// * `Ok(Self)` - If the store is created successfully
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use actix_passport::user_store::stores::postgres::PostgresUserStore;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let store = PostgresUserStore::new("postgres://user:pass@localhost/db").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn new(database_url: &str) -> Result<Self, sqlx::Error> {
        Self::with_config(database_url, PostgresConfig::default()).await
    }

    /// Create a new `PostgreSQL` user store with custom configuration.
    ///
    /// # Arguments
    ///
    /// * `database_url` - `PostgreSQL` connection string
    /// * `config` - Store configuration options
    ///
    /// # Errors
    ///
    /// * `Err(sqlx::Error::Configuration(format!("Migration failed: {e}")))` - If the migration fails
    ///
    /// # Returns
    ///
    /// * `Ok(Self)` - If the store is created successfully
    pub async fn with_config(
        database_url: &str,
        config: PostgresConfig,
    ) -> Result<Self, sqlx::Error> {
        let pool = PgPoolOptions::new()
            .max_connections(config.max_connections)
            .connect(database_url)
            .await?;

        let store = Self { pool };

        if config.auto_migrate {
            store
                .migrate()
                .await
                .map_err(|e| sqlx::Error::Configuration(format!("Migration failed: {e}").into()))?;
        }

        Ok(store)
    }

    /// Run database migrations.
    ///
    /// # Errors
    ///
    /// * `Err(AuthError::database_error("migrate", e))` - If the migration fails
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the migration succeeds
    pub async fn migrate(&self) -> AuthResult<()> {
        sqlx::migrate!("src/user_store/stores/postgres/migrations")
            .run(&self.pool)
            .await
            .map_err(|e| AuthError::database_error("migrate", e))
    }

    /// Convert database row to `AuthUser`.
    fn row_to_auth_user(row: &sqlx::postgres::PgRow) -> AuthResult<AuthUser> {
        let id: Uuid = row
            .try_get("id")
            .map_err(|e| AuthError::database_error("row_to_auth_user", e))?;
        let email: Option<String> = row
            .try_get("email")
            .map_err(|e| AuthError::database_error("row_to_auth_user", e))?;
        let username: Option<String> = row
            .try_get("username")
            .map_err(|e| AuthError::database_error("row_to_auth_user", e))?;
        let display_name: Option<String> = row
            .try_get("display_name")
            .map_err(|e| AuthError::database_error("row_to_auth_user", e))?;
        let avatar_url: Option<String> = row
            .try_get("avatar_url")
            .map_err(|e| AuthError::database_error("row_to_auth_user", e))?;
        let created_at: DateTime<Utc> = row
            .try_get("created_at")
            .map_err(|e| AuthError::database_error("row_to_auth_user", e))?;
        let last_login: Option<DateTime<Utc>> = row
            .try_get("last_login")
            .map_err(|e| AuthError::database_error("row_to_auth_user", e))?;
        let metadata_json: JsonValue = row
            .try_get("metadata")
            .map_err(|e| AuthError::database_error("row_to_auth_user", e))?;

        let metadata = json_helpers::json_to_metadata(&metadata_json);
        let oauth_providers = json_helpers::json_to_oauth_providers(&metadata_json);

        let mut user = AuthUser::new(id.to_string()).with_created_at(created_at);

        if let Some(email) = email {
            user = user.with_email(&email);
        }
        if let Some(username) = username {
            user = user.with_username(&username);
        }
        if let Some(display_name) = display_name {
            user = user.with_display_name(&display_name);
        }
        if let Some(avatar_url) = avatar_url {
            user = user.with_avatar_url(&avatar_url);
        }

        // Set last_login directly since there's no with_last_login method
        user.last_login = last_login;

        // Add metadata
        for (key, value) in metadata {
            user.metadata.insert(key, value);
        }

        // Add OAuth providers
        for provider in oauth_providers {
            user = user.with_oauth_provider(provider);
        }

        Ok(user)
    }
}

#[async_trait]
impl UserStore for PostgresUserStore {
    async fn find_by_id(&self, id: &str) -> AuthResult<Option<AuthUser>> {
        let user_id = Uuid::parse_str(id).map_err(|_| AuthError::user_not_found("id", id))?;

        let row = sqlx::query(sql_helpers::UserQueries::FIND_BY_ID)
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| error_mapping::map_sqlx_error("find_by_id", e))?;

        match row {
            Some(row) => Ok(Some(Self::row_to_auth_user(&row)?)),
            None => Ok(None),
        }
    }

    async fn find_by_email(&self, email: &str) -> AuthResult<Option<AuthUser>> {
        let row = sqlx::query(sql_helpers::UserQueries::FIND_BY_EMAIL)
            .bind(email)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| error_mapping::map_sqlx_error("find_by_email", e))?;

        match row {
            Some(row) => Ok(Some(Self::row_to_auth_user(&row)?)),
            None => Ok(None),
        }
    }

    async fn find_by_username(&self, username: &str) -> AuthResult<Option<AuthUser>> {
        let row = sqlx::query(sql_helpers::UserQueries::FIND_BY_USERNAME)
            .bind(username)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| error_mapping::map_sqlx_error("find_by_username", e))?;

        match row {
            Some(row) => Ok(Some(Self::row_to_auth_user(&row)?)),
            None => Ok(None),
        }
    }

    async fn create_user(&self, user: AuthUser) -> AuthResult<AuthUser> {
        // Validate required fields
        sql_helpers::validate_user_for_creation(&user.email, &user.username).map_err(|e| {
            AuthError::configuration_error(
                e,
                vec!["Provide either email or username for user creation".to_string()],
            )
        })?;

        // Check for existing users
        if let Some(ref email) = user.email {
            if self.find_by_email(email).await?.is_some() {
                return Err(AuthError::user_already_exists("email", email));
            }
        }

        if let Some(ref username) = user.username {
            if self.find_by_username(username).await?.is_some() {
                return Err(AuthError::user_already_exists("username", username));
            }
        }

        let user_id = Uuid::new_v4();
        let metadata_json = json_helpers::metadata_to_json(&user.metadata);
        let oauth_providers_json =
            json_helpers::oauth_providers_to_json(&user.get_oauth_providers());

        let row = sqlx::query(sql_helpers::UserQueries::INSERT_USER)
            .bind(user_id)
            .bind(&user.email)
            .bind(&user.username)
            .bind(&user.display_name)
            .bind(&user.avatar_url)
            .bind(metadata_json)
            .bind(oauth_providers_json)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| error_mapping::map_sqlx_error("create_user", e))?;

        Self::row_to_auth_user(&row)
    }

    async fn update_user(&self, user: AuthUser) -> AuthResult<AuthUser> {
        let user_id =
            Uuid::parse_str(&user.id).map_err(|_| AuthError::user_not_found("id", &user.id))?;

        let metadata_json = json_helpers::metadata_to_json(&user.metadata);
        let oauth_providers_json =
            json_helpers::oauth_providers_to_json(&user.get_oauth_providers());

        let row = sqlx::query(sql_helpers::UserQueries::UPDATE_USER)
            .bind(user_id)
            .bind(&user.email)
            .bind(&user.username)
            .bind(&user.display_name)
            .bind(&user.avatar_url)
            .bind(user.last_login)
            .bind(metadata_json)
            .bind(oauth_providers_json)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| error_mapping::map_sqlx_error("update_user", e))?;

        match row {
            Some(row) => Self::row_to_auth_user(&row),
            None => Err(AuthError::user_not_found("id", &user.id)),
        }
    }

    async fn delete_user(&self, id: &str) -> AuthResult<()> {
        let user_id = Uuid::parse_str(id).map_err(|_| AuthError::user_not_found("id", id))?;

        let result = sqlx::query(sql_helpers::UserQueries::DELETE_USER)
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map_err(|e| error_mapping::map_sqlx_error("delete_user", e))?;

        if result.rows_affected() == 0 {
            return Err(AuthError::user_not_found("id", id));
        }

        Ok(())
    }
}

/// Configuration for `PostgreSQL` user store.
#[derive(Debug, Clone)]
pub struct PostgresConfig {
    /// Maximum number of connections in the pool.
    pub max_connections: u32,
    /// Whether to automatically run migrations on startup.
    pub auto_migrate: bool,
}

impl Default for PostgresConfig {
    fn default() -> Self {
        Self {
            max_connections: 10,
            auto_migrate: true,
        }
    }
}
