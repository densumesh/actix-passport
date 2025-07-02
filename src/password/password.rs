use crate::{errors::AuthError, types::AuthResult, PasswordHasher};
use argon2::{
    password_hash::{
        rand_core::OsRng, PasswordHash, PasswordHasher as _, PasswordVerifier, SaltString,
    },
    Argon2,
};
use async_trait::async_trait;

/// Default Argon2 password hasher implementation.
///
/// This is the default password hasher that uses the Argon2 algorithm,
/// which is currently recommended for password hashing.
#[derive(Debug, Default)]
pub struct Argon2PasswordHasher;

#[async_trait]
impl PasswordHasher for Argon2PasswordHasher {
    async fn hash_password(&self, password: &str) -> AuthResult<String> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();

        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| AuthError::Internal(format!("Password hashing failed: {}", e)))?;

        Ok(password_hash.to_string())
    }

    async fn verify_password(&self, password: &str, hash: &str) -> AuthResult<bool> {
        let parsed_hash = PasswordHash::new(hash)
            .map_err(|e| AuthError::Internal(format!("Invalid password hash: {}", e)))?;

        let argon2 = Argon2::default();

        match argon2.verify_password(password.as_bytes(), &parsed_hash) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}
