use chrono::{DateTime, Utc};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::schema::users;

#[derive(Debug, Clone, Queryable, Serialize, Deserialize)]
#[diesel(table_name = users)]
pub struct User {
    pub id: Uuid,
    pub email: Option<String>,
    pub username: Option<String>,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    pub password_hash: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_login: Option<DateTime<Utc>>,
    pub metadata: serde_json::Value,
    pub oauth_providers: serde_json::Value,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = users)]
pub struct NewUser {
    pub email: Option<String>,
    pub username: Option<String>,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    pub password_hash: Option<String>,
    pub metadata: serde_json::Value,
    pub oauth_providers: serde_json::Value,
}

impl NewUser {
    pub fn new() -> Self {
        Self {
            email: None,
            username: None,
            display_name: None,
            avatar_url: None,
            password_hash: None,
            metadata: serde_json::json!({}),
            oauth_providers: serde_json::json!([]),
        }
    }

    pub fn with_email(mut self, email: String) -> Self {
        self.email = Some(email);
        self
    }

    pub fn with_username(mut self, username: String) -> Self {
        self.username = Some(username);
        self
    }

    pub fn with_display_name(mut self, display_name: String) -> Self {
        self.display_name = Some(display_name);
        self
    }

    pub fn with_password_hash(mut self, password_hash: String) -> Self {
        self.password_hash = Some(password_hash);
        self
    }
}

impl Default for NewUser {
    fn default() -> Self {
        Self::new()
    }
}
