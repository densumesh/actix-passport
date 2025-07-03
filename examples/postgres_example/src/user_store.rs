use actix_passport::{
    types::{AuthResult, AuthUser},
    user_store::UserStore,
    errors::AuthError,
};
use async_trait::async_trait;
use bb8::Pool;
use diesel::prelude::*;
use diesel_async::{
    pooled_connection::{bb8::Pool as AsyncPool, AsyncDieselConnectionManager},
    AsyncPgConnection, RunQueryDsl,
};
use serde_json::Value as JsonValue;
use std::collections::HashMap;
use uuid::Uuid;

use crate::models::{NewUser, User};
use crate::schema::users;

type DbPool = AsyncPool<AsyncPgConnection>;

#[derive(Clone)]
pub struct PostgresUserStore {
    pool: DbPool,
}

impl PostgresUserStore {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn create_pool(database_url: &str) -> Result<DbPool, Box<dyn std::error::Error>> {
        let config = AsyncDieselConnectionManager::<AsyncPgConnection>::new(database_url);
        let pool = Pool::builder().build(config).await?;
        Ok(pool)
    }

    fn user_to_auth_user(user: User) -> AuthResult<AuthUser> {
        let metadata: HashMap<String, JsonValue> = match user.metadata {
            JsonValue::Object(map) => map.into_iter().collect(),
            _ => HashMap::new(),
        };

        let oauth_providers: Vec<String> = match user.oauth_providers {
            JsonValue::Array(arr) => arr
                .into_iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect(),
            _ => Vec::new(),
        };

        let mut auth_user = AuthUser::new(user.id.to_string())
            .with_created_at(user.created_at);

        if let Some(email) = user.email {
            auth_user = auth_user.with_email(&email);
        }

        if let Some(username) = user.username {
            auth_user = auth_user.with_username(&username);
        }

        if let Some(display_name) = user.display_name {
            auth_user = auth_user.with_display_name(&display_name);
        }

        if let Some(avatar_url) = user.avatar_url {
            auth_user = auth_user.with_avatar_url(&avatar_url);
        }

        if let Some(last_login) = user.last_login {
            auth_user = auth_user.with_last_login(last_login);
        }

        // Add metadata
        for (key, value) in metadata {
            auth_user.metadata.insert(key, value);
        }

        // Add OAuth providers
        for provider in oauth_providers {
            auth_user = auth_user.with_oauth_provider(&provider);
        }

        Ok(auth_user)
    }

    fn auth_user_to_new_user(user: &AuthUser) -> NewUser {
        let metadata = serde_json::to_value(&user.metadata).unwrap_or_else(|_| serde_json::json!({}));
        let oauth_providers = serde_json::to_value(&user.get_oauth_providers()).unwrap_or_else(|_| serde_json::json!([]));

        NewUser {
            email: user.email.clone(),
            username: user.username.clone(),
            display_name: user.display_name.clone(),
            avatar_url: user.avatar_url.clone(),
            password_hash: None, // This should be handled separately
            metadata,
            oauth_providers,
        }
    }
}

#[async_trait]
impl UserStore for PostgresUserStore {
    async fn find_by_id(&self, id: &str) -> AuthResult<Option<AuthUser>> {
        let user_id = Uuid::parse_str(id)
            .map_err(|_| AuthError::user_not_found("id", id))?;

        let mut conn = self.pool.get().await
            .map_err(|e| AuthError::database_error("find_by_id", format!("Connection error: {}", e)))?;

        let user_result = users::table
            .find(user_id)
            .first::<User>(&mut conn)
            .await
            .optional()
            .map_err(|e| AuthError::database_error("find_by_id", format!("Query error: {}", e)))?;

        match user_result {
            Some(user) => Ok(Some(Self::user_to_auth_user(user)?)),
            None => Ok(None),
        }
    }

    async fn find_by_email(&self, email: &str) -> AuthResult<Option<AuthUser>> {
        let mut conn = self.pool.get().await
            .map_err(|e| AuthError::database_error("find_by_email", format!("Connection error: {}", e)))?;

        let user_result = users::table
            .filter(users::email.eq(email))
            .first::<User>(&mut conn)
            .await
            .optional()
            .map_err(|e| AuthError::database_error("find_by_email", format!("Query error: {}", e)))?;

        match user_result {
            Some(user) => Ok(Some(Self::user_to_auth_user(user)?)),
            None => Ok(None),
        }
    }

    async fn find_by_username(&self, username: &str) -> AuthResult<Option<AuthUser>> {
        let mut conn = self.pool.get().await
            .map_err(|e| AuthError::database_error("find_by_username", format!("Connection error: {}", e)))?;

        let user_result = users::table
            .filter(users::username.eq(username))
            .first::<User>(&mut conn)
            .await
            .optional()
            .map_err(|e| AuthError::database_error("find_by_username", format!("Query error: {}", e)))?;

        match user_result {
            Some(user) => Ok(Some(Self::user_to_auth_user(user)?)),
            None => Ok(None),
        }
    }

    async fn create_user(&self, user: AuthUser) -> AuthResult<AuthUser> {
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

        let mut conn = self.pool.get().await
            .map_err(|e| AuthError::database_error("create_user", format!("Connection error: {}", e)))?;

        let new_user = Self::auth_user_to_new_user(&user);

        let created_user = diesel::insert_into(users::table)
            .values(&new_user)
            .get_result::<User>(&mut conn)
            .await
            .map_err(|e| AuthError::database_error("create_user", format!("Insert error: {}", e)))?;

        Self::user_to_auth_user(created_user)
    }

    async fn update_user(&self, user: AuthUser) -> AuthResult<AuthUser> {
        let user_id = Uuid::parse_str(&user.id)
            .map_err(|_| AuthError::user_not_found("id", &user.id))?;

        let mut conn = self.pool.get().await
            .map_err(|e| AuthError::database_error("update_user", format!("Connection error: {}", e)))?;

        // Check if user exists
        let existing_user = users::table
            .find(user_id)
            .first::<User>(&mut conn)
            .await
            .optional()
            .map_err(|e| AuthError::database_error("update_user", format!("Query error: {}", e)))?
            .ok_or_else(|| AuthError::user_not_found("id", &user.id))?;

        let metadata = serde_json::to_value(&user.metadata).unwrap_or_else(|_| serde_json::json!({}));
        let oauth_providers = serde_json::to_value(&user.get_oauth_providers()).unwrap_or_else(|_| serde_json::json!([]));

        let updated_user = diesel::update(users::table.find(user_id))
            .set((
                users::email.eq(&user.email),
                users::username.eq(&user.username),
                users::display_name.eq(&user.display_name),
                users::avatar_url.eq(&user.avatar_url),
                users::last_login.eq(&user.last_login),
            ))
            .get_result::<User>(&mut conn)
            .await
            .map_err(|e| AuthError::database_error("update_user", format!("Update error: {}", e)))?;

        Self::user_to_auth_user(updated_user)
    }

    async fn delete_user(&self, id: &str) -> AuthResult<()> {
        let user_id = Uuid::parse_str(id)
            .map_err(|_| AuthError::user_not_found("id", id))?;

        let mut conn = self.pool.get().await
            .map_err(|e| AuthError::database_error("delete_user", format!("Connection error: {}", e)))?;

        let deleted_rows = diesel::delete(users::table.find(user_id))
            .execute(&mut conn)
            .await
            .map_err(|e| AuthError::database_error("delete_user", format!("Delete error: {}", e)))?;

        if deleted_rows == 0 {
            return Err(AuthError::user_not_found("id", id));
        }

        Ok(())
    }
}