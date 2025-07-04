use actix_passport::{
    errors::AuthError,
    types::{AuthResult, AuthUser},
    user_store::UserStore,
};
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, Row};
use serde_json::Value as JsonValue;
use std::collections::HashMap;
use uuid::Uuid;

pub type SqlitePool = Pool<SqliteConnectionManager>;

#[derive(Clone)]
pub struct SqliteUserStore {
    pool: SqlitePool,
}

impl SqliteUserStore {
    pub fn new(database_path: &str) -> AuthResult<Self> {
        let manager = SqliteConnectionManager::file(database_path);
        let pool = Pool::new(manager)
            .map_err(|e| AuthError::database_error("connection_pool", e))?;

        let store = Self { pool };
        store.run_migrations()?;
        Ok(store)
    }

    fn run_migrations(&self) -> AuthResult<()> {
        let conn = self.pool.get()
            .map_err(|e| AuthError::database_error("get_connection", e))?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                email TEXT UNIQUE,
                username TEXT UNIQUE,
                password_hash TEXT,
                display_name TEXT,
                avatar_url TEXT,
                created_at TEXT NOT NULL,
                last_login TEXT,
                metadata TEXT NOT NULL DEFAULT '{}'
            )",
            [],
        ).map_err(|e| AuthError::database_error("create_users_table", e))?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS auth_tokens (
                token TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )",
            [],
        ).map_err(|e| AuthError::database_error("create_tokens_table", e))?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)",
            [],
        ).map_err(|e| AuthError::database_error("create_email_index", e))?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)",
            [],
        ).map_err(|e| AuthError::database_error("create_username_index", e))?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_tokens_user_id ON auth_tokens(user_id)",
            [],
        ).map_err(|e| AuthError::database_error("create_tokens_index", e))?;

        Ok(())
    }

    fn row_to_auth_user(row: &Row) -> rusqlite::Result<AuthUser> {
        let id: String = row.get("id")?;
        let email: Option<String> = row.get("email")?;
        let username: Option<String> = row.get("username")?;
        let display_name: Option<String> = row.get("display_name")?;
        let avatar_url: Option<String> = row.get("avatar_url")?;
        let created_at_str: String = row.get("created_at")?;
        let last_login_str: Option<String> = row.get("last_login")?;
        let metadata_str: String = row.get("metadata")?;

        let created_at = DateTime::parse_from_rfc3339(&created_at_str)
            .map_err(|_| rusqlite::Error::InvalidColumnType(0, "created_at".to_string(), rusqlite::types::Type::Text))?
            .with_timezone(&Utc);

        let last_login = last_login_str
            .as_ref()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc));

        let metadata: HashMap<String, JsonValue> = serde_json::from_str(&metadata_str)
            .unwrap_or_default();

        let mut user = AuthUser::new(id).with_created_at(created_at);

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

        user.last_login = last_login;
        user.metadata = metadata;

        Ok(user)
    }

    pub fn create_user_with_password(&self, mut user: AuthUser, password_hash: &str) -> AuthResult<AuthUser> {
        let conn = self.pool.get()
            .map_err(|e| AuthError::database_error("get_connection", e))?;

        if user.email.is_none() && user.username.is_none() {
            return Err(AuthError::configuration_error(
                "missing_identifier",
                vec!["Either email or username must be provided".to_string()],
            ));
        }

        // Check for existing users
        if let Some(ref email) = user.email {
            let exists: bool = conn.query_row(
                "SELECT 1 FROM users WHERE email = ? LIMIT 1",
                params![email],
                |_| Ok(true),
            ).unwrap_or(false);
            
            if exists {
                return Err(AuthError::user_already_exists("email", email));
            }
        }

        if let Some(ref username) = user.username {
            let exists: bool = conn.query_row(
                "SELECT 1 FROM users WHERE username = ? LIMIT 1",
                params![username],
                |_| Ok(true),
            ).unwrap_or(false);
            
            if exists {
                return Err(AuthError::user_already_exists("username", username));
            }
        }

        let user_id = Uuid::new_v4().to_string();
        user.id = user_id.clone();

        let metadata_json = serde_json::to_string(&user.metadata)
            .map_err(|e| AuthError::database_error("serialize_metadata", e))?;

        conn.execute(
            "INSERT INTO users (id, email, username, password_hash, display_name, avatar_url, created_at, last_login, metadata)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                user_id,
                user.email,
                user.username,
                password_hash,
                user.display_name,
                user.avatar_url,
                user.created_at.to_rfc3339(),
                user.last_login.map(|dt| dt.to_rfc3339()),
                metadata_json,
            ],
        ).map_err(|e| AuthError::database_error("insert_user", e))?;

        Ok(user)
    }

    pub fn verify_password(&self, identifier: &str, password: &str) -> AuthResult<Option<AuthUser>> {
        let conn = self.pool.get()
            .map_err(|e| AuthError::database_error("get_connection", e))?;

        let result = conn.query_row(
            "SELECT id, email, username, password_hash, display_name, avatar_url, created_at, last_login, metadata
             FROM users 
             WHERE email = ? OR username = ?",
            params![identifier, identifier],
            |row| {
                let password_hash: String = row.get("password_hash")?;
                let user = Self::row_to_auth_user(row)?;
                Ok((user, password_hash))
            },
        );

        match result {
            Ok((user, stored_hash)) => {
                let parsed_hash = PasswordHash::new(&stored_hash)
                    .map_err(|e| AuthError::invalid_credentials(format!("invalid_hash_format: {e}")))?;
                
                if Argon2::default().verify_password(
                    password.as_bytes(),
                    &parsed_hash
                ).is_ok()
                {
                    Ok(Some(user))
                } else {
                    Ok(None)
                }
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(AuthError::database_error("verify_password", e)),
        }
    }

    pub fn store_auth_token(&self, token: &str, user_id: &str, expires_at: Option<DateTime<Utc>>) -> AuthResult<()> {
        let conn = self.pool.get()
            .map_err(|e| AuthError::database_error("get_connection", e))?;

        conn.execute(
            "INSERT INTO auth_tokens (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
            params![
                token,
                user_id,
                Utc::now().to_rfc3339(),
                expires_at.map(|dt| dt.to_rfc3339()),
            ],
        ).map_err(|e| AuthError::database_error("store_token", e))?;

        Ok(())
    }

    pub fn find_user_by_token(&self, token: &str) -> AuthResult<Option<AuthUser>> {
        let conn = self.pool.get()
            .map_err(|e| AuthError::database_error("get_connection", e))?;

        let result = conn.query_row(
            "SELECT u.id, u.email, u.username, u.display_name, u.avatar_url, u.created_at, u.last_login, u.metadata, t.expires_at
             FROM users u
             INNER JOIN auth_tokens t ON u.id = t.user_id
             WHERE t.token = ?",
            params![token],
            |row| {
                let expires_at_str: Option<String> = row.get("expires_at")?;
                
                // Check if token is expired
                if let Some(expires_str) = expires_at_str {
                    if let Ok(expires_at) = DateTime::parse_from_rfc3339(&expires_str) {
                        if Utc::now() > expires_at.with_timezone(&Utc) {
                            return Err(rusqlite::Error::QueryReturnedNoRows);
                        }
                    }
                }

                Self::row_to_auth_user(row)
            },
        );

        match result {
            Ok(user) => Ok(Some(user)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(AuthError::database_error("find_user_by_token", e)),
        }
    }

    pub fn revoke_token(&self, token: &str) -> AuthResult<()> {
        let conn = self.pool.get()
            .map_err(|e| AuthError::database_error("get_connection", e))?;

        conn.execute(
            "DELETE FROM auth_tokens WHERE token = ?",
            params![token],
        ).map_err(|e| AuthError::database_error("revoke_token", e))?;

        Ok(())
    }
}

#[async_trait]
impl UserStore for SqliteUserStore {
    async fn find_by_id(&self, id: &str) -> AuthResult<Option<AuthUser>> {
        let conn = self.pool.get()
            .map_err(|e| AuthError::database_error("get_connection", e))?;

        let result = conn.query_row(
            "SELECT id, email, username, display_name, avatar_url, created_at, last_login, metadata FROM users WHERE id = ?",
            params![id],
            Self::row_to_auth_user,
        );

        match result {
            Ok(user) => Ok(Some(user)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(AuthError::database_error("find_by_id", e)),
        }
    }

    async fn find_by_email(&self, email: &str) -> AuthResult<Option<AuthUser>> {
        let conn = self.pool.get()
            .map_err(|e| AuthError::database_error("get_connection", e))?;

        let result = conn.query_row(
            "SELECT id, email, username, display_name, avatar_url, created_at, last_login, metadata FROM users WHERE email = ?",
            params![email],
            Self::row_to_auth_user,
        );

        match result {
            Ok(user) => Ok(Some(user)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(AuthError::database_error("find_by_email", e)),
        }
    }

    async fn find_by_username(&self, username: &str) -> AuthResult<Option<AuthUser>> {
        let conn = self.pool.get()
            .map_err(|e| AuthError::database_error("get_connection", e))?;

        let result = conn.query_row(
            "SELECT id, email, username, display_name, avatar_url, created_at, last_login, metadata FROM users WHERE username = ?",
            params![username],
            Self::row_to_auth_user,
        );

        match result {
            Ok(user) => Ok(Some(user)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(AuthError::database_error("find_by_username", e)),
        }
    }

    async fn create_user(&self, _user: AuthUser) -> AuthResult<AuthUser> {
        Err(AuthError::configuration_error(
            "use_create_user_with_password",
            vec!["Use create_user_with_password method instead".to_string()],
        ))
    }

    async fn update_user(&self, user: AuthUser) -> AuthResult<AuthUser> {
        let conn = self.pool.get()
            .map_err(|e| AuthError::database_error("get_connection", e))?;

        let metadata_json = serde_json::to_string(&user.metadata)
            .map_err(|e| AuthError::database_error("serialize_metadata", e))?;

        let rows_affected = conn.execute(
            "UPDATE users SET email = ?, username = ?, display_name = ?, avatar_url = ?, last_login = ?, metadata = ?
             WHERE id = ?",
            params![
                user.email,
                user.username,
                user.display_name,
                user.avatar_url,
                user.last_login.map(|dt| dt.to_rfc3339()),
                metadata_json,
                user.id,
            ],
        ).map_err(|e| AuthError::database_error("update_user", e))?;

        if rows_affected == 0 {
            return Err(AuthError::user_not_found("id", &user.id));
        }

        Ok(user)
    }

    async fn delete_user(&self, id: &str) -> AuthResult<()> {
        let conn = self.pool.get()
            .map_err(|e| AuthError::database_error("get_connection", e))?;

        let rows_affected = conn.execute(
            "DELETE FROM users WHERE id = ?",
            params![id],
        ).map_err(|e| AuthError::database_error("delete_user", e))?;

        if rows_affected == 0 {
            return Err(AuthError::user_not_found("id", id));
        }

        Ok(())
    }
}