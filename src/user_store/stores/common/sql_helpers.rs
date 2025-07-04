//! SQL query helpers and common patterns for database stores.

/// Standard SQL queries for user operations.
pub struct UserQueries;

impl UserQueries {
    /// SQL query to find user by ID.
    pub const FIND_BY_ID: &'static str = 
        "SELECT id, email, username, display_name, avatar_url, created_at, last_login, metadata FROM auth.users WHERE id = $1";
    
    /// SQL query to find user by email.
    pub const FIND_BY_EMAIL: &'static str = 
        "SELECT id, email, username, display_name, avatar_url, created_at, last_login, metadata FROM auth.users WHERE email = $1";
    
    /// SQL query to find user by username.
    pub const FIND_BY_USERNAME: &'static str = 
        "SELECT id, email, username, display_name, avatar_url, created_at, last_login, metadata FROM auth.users WHERE username = $1";
    
    /// SQL query to insert a new user.
    pub const INSERT_USER: &'static str = 
        "INSERT INTO auth.users (id, email, username, display_name, avatar_url, metadata) 
         VALUES ($1, $2, $3, $4, $5, $6) 
         RETURNING id, email, username, display_name, avatar_url, created_at, last_login, metadata";
    
    /// SQL query to update user.
    pub const UPDATE_USER: &'static str = 
        "UPDATE auth.users SET email = $2, username = $3, display_name = $4, avatar_url = $5, last_login = $6, metadata = $7 
         WHERE id = $1 
         RETURNING id, email, username, display_name, avatar_url, created_at, last_login, metadata";
    
    /// SQL query to delete user.
    pub const DELETE_USER: &'static str = 
        "DELETE FROM auth.users WHERE id = $1";
    
    /// SQL query to count users (health check).
    pub const COUNT_USERS: &'static str = 
        "SELECT COUNT(*) FROM auth.users";
}


/// Helper to generate UUID strings for databases that don't have native UUID support.
#[must_use] pub fn generate_uuid_string() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Validates that required fields are present for user creation.
///
/// # Arguments
///
/// * `email` - The email of the user
/// * `username` - The username of the user
///
/// # Errors
///
/// * `Err("Either email or username must be provided")` - If both email and username are `None`
///
/// # Returns
///
/// * `Ok(())` - If either email or username is provided
pub const fn validate_user_for_creation(email: &Option<String>, username: &Option<String>) -> Result<(), &'static str> {
    if email.is_none() && username.is_none() {
        return Err("Either email or username must be provided");
    }
    Ok(())
}