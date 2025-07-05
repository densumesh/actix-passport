use actix_passport::errors::AuthError;
use argon2::password_hash::{rand_core::OsRng, SaltString};
use rand::{thread_rng, Rng};

pub fn generate_token(user_id: &str) -> Result<String, AuthError> {
    let mut random_bytes = [0u8; 32];
    thread_rng().fill(&mut random_bytes);

    // Create a simple token by combining user_id prefix with random hex
    let token = format!(
        "{}_{}",
        &user_id[..std::cmp::min(8, user_id.len())],
        hex::encode(random_bytes)
    );

    Ok(token)
}

pub fn generate_salt() -> SaltString {
    SaltString::generate(&mut OsRng)
}
