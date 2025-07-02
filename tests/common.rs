#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    missing_docs,
    clippy::missing_panics_doc
)]
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use actix_passport::{AuthResult, AuthUser, UserStore};
use async_trait::async_trait;

/// Mock user store for testing
#[derive(Clone)]
pub struct MockUserStore {
    users: Arc<Mutex<HashMap<String, AuthUser>>>,
}

impl Default for MockUserStore {
    fn default() -> Self {
        Self::new()
    }
}

impl MockUserStore {
    #[must_use]
    pub fn new() -> Self {
        Self {
            users: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn add_user(&self, user: AuthUser) {
        let mut users = self.users.lock().unwrap();
        users.insert(user.id.clone(), user);
    }

    #[must_use]
    pub fn get_user_count(&self) -> usize {
        let users = self.users.lock().unwrap();
        users.len()
    }
}

#[async_trait]
impl UserStore for MockUserStore {
    async fn find_by_id(&self, id: &str) -> AuthResult<Option<AuthUser>> {
        let users = self.users.lock().unwrap();
        Ok(users.get(id).cloned())
    }

    async fn find_by_email(&self, email: &str) -> AuthResult<Option<AuthUser>> {
        let users = self.users.lock().unwrap();
        Ok(users
            .values()
            .find(|u| u.email.as_ref() == Some(&email.to_string()))
            .cloned())
    }

    async fn find_by_username(&self, username: &str) -> AuthResult<Option<AuthUser>> {
        let users = self.users.lock().unwrap();
        Ok(users
            .values()
            .find(|u| u.username.as_ref() == Some(&username.to_string()))
            .cloned())
    }

    async fn create_user(&self, user: AuthUser) -> AuthResult<AuthUser> {
        self.users
            .lock()
            .unwrap()
            .insert(user.id.clone(), user.clone());

        Ok(user)
    }

    async fn update_user(&self, user: AuthUser) -> AuthResult<AuthUser> {
        self.users
            .lock()
            .unwrap()
            .insert(user.id.clone(), user.clone());

        Ok(user)
    }

    async fn delete_user(&self, id: &str) -> AuthResult<()> {
        self.users.lock().unwrap().remove(id);

        Ok(())
    }
}
