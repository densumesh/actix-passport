use actix_passport::errors::AuthError;
use rand::{thread_rng, Rng};
use argon2::password_hash::{rand_core::OsRng, SaltString};

#[derive(Clone)]
pub struct TokenService;

impl TokenService {
    pub fn new() -> Self {
        Self
    }

    pub fn generate_token(&self, user_id: &str) -> Result<String, AuthError> {
        let mut random_bytes = [0u8; 32];
        thread_rng().fill(&mut random_bytes);
        
        // Create a simple token by combining user_id prefix with random hex
        let token = format!("{}_{}", 
            &user_id[..std::cmp::min(8, user_id.len())], 
            hex::encode(random_bytes)
        );
        
        Ok(token)
    }

    pub fn generate_salt(&self) -> SaltString {
        SaltString::generate(&mut OsRng)
    }
}

impl Default for TokenService {
    fn default() -> Self {
        Self::new()
    }
}