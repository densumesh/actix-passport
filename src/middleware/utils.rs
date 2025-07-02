use crate::{
    errors::AuthError,
    types::{AuthResult, AuthUser, Session},
};
use actix_session::Session as ActixSession;
use chrono::{Duration, Utc};
use std::collections::HashMap;
use uuid::Uuid;

/// Creates a new session for the given user.
///
/// # Arguments
///
/// * `user` - The user to create a session for
/// * `duration` - How long the session should last
///
/// # Returns
///
/// Returns a new session with user data stored in the session data.
#[must_use]
pub fn create_user_session(user: &AuthUser, duration: Duration) -> Session {
    let mut session_data = HashMap::new();

    // Store user data in session
    if let Some(ref email) = user.email {
        session_data.insert(
            "email".to_string(),
            serde_json::Value::String(email.clone()),
        );
    }
    if let Some(ref username) = user.username {
        session_data.insert(
            "username".to_string(),
            serde_json::Value::String(username.clone()),
        );
    }
    if let Some(ref display_name) = user.display_name {
        session_data.insert(
            "display_name".to_string(),
            serde_json::Value::String(display_name.clone()),
        );
    }
    if let Some(ref avatar_url) = user.avatar_url {
        session_data.insert(
            "avatar_url".to_string(),
            serde_json::Value::String(avatar_url.clone()),
        );
    }

    session_data.insert(
        "created_at".to_string(),
        serde_json::Value::String(user.created_at.to_rfc3339()),
    );

    if let Some(ref last_login) = user.last_login {
        session_data.insert(
            "last_login".to_string(),
            serde_json::Value::String(last_login.to_rfc3339()),
        );
    }

    session_data.insert(
        "metadata".to_string(),
        serde_json::to_value(&user.metadata).unwrap_or_default(),
    );

    Session {
        id: Uuid::new_v4(),
        user_id: user.id.clone(),
        created_at: Utc::now(),
        expires_at: Utc::now() + duration,
        data: session_data,
    }
}

/// Sets the session ID in the actix session.
///
/// # Arguments
///
/// * `actix_session` - The actix session
/// * `session_id` - The session ID to store
///
/// # Returns
///
/// Returns `Ok(())` if successful, or an error if the session operation fails.
///
/// # Errors
///
/// Returns an error if the session operation fails.
pub fn set_session_id(actix_session: &ActixSession, session_id: Uuid) -> AuthResult<()> {
    actix_session
        .insert("session_id", session_id.to_string())
        .map_err(|e| AuthError::Internal(format!("Failed to set session ID: {e}")))?;
    Ok(())
}

/// Clears the session.
///
/// # Arguments
///
/// * `actix_session` - The actix session to clear
pub fn clear_session(actix_session: &ActixSession) {
    actix_session.purge();
}
