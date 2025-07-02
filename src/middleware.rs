//! Authentication middleware for actix-web.
//!
//! This module provides middleware for handling authentication in actix-web applications.
//! It includes session-based authentication, JWT token validation, and user identity injection.

use crate::core::{AuthError, AuthResult, AuthUser, SessionStore};
use actix_session::Session;
use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    error::ErrorUnauthorized,
    FromRequest, HttpMessage, HttpRequest,
};
use futures_util::future::LocalBoxFuture;
use std::{
    future::{ready, Ready},
    rc::Rc,
};
use uuid::Uuid;

/// Extractable authenticated user from request.
///
/// This struct can be used in handler functions to extract the authenticated
/// user from the request. It implements `FromRequest` so it can be used
/// as a parameter in handler functions.
///
/// # Examples
///
/// ```rust
/// use actix_web::{get, HttpResponse};
/// use actix_passport::AuthenticatedUser;
///
/// #[get("/profile")]
/// async fn get_profile(user: AuthenticatedUser) -> HttpResponse {
///     HttpResponse::Ok().json(&user.0)
/// }
/// ```
#[derive(Debug, Clone)]
pub struct AuthenticatedUser(pub AuthUser);

impl FromRequest for AuthenticatedUser {
    type Error = actix_web::Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut actix_web::dev::Payload) -> Self::Future {
        match req.extensions().get::<AuthUser>() {
            Some(user) => ready(Ok(AuthenticatedUser(user.clone()))),
            None => ready(Err(ErrorUnauthorized("Authentication required"))),
        }
    }
}

/// Optional authenticated user extractor.
///
/// Similar to `AuthenticatedUser`, but returns `None` instead of an error
/// when the user is not authenticated. This is useful for endpoints that
/// work differently for authenticated vs unauthenticated users.
///
/// # Examples
///
/// ```rust
/// use actix_web::{get, HttpResponse};
/// use actix_passport::OptionalAuthenticatedUser;
///
/// #[get("/home")]
/// async fn home(user: OptionalAuthenticatedUser) -> HttpResponse {
///     match user.0 {
///         Some(user) => HttpResponse::Ok().json(format!("Welcome, {}!", user.id)),
///         None => HttpResponse::Ok().json("Welcome, guest!"),
///     }
/// }
/// ```
#[derive(Debug, Clone)]
pub struct OptionalAuthenticatedUser(pub Option<AuthUser>);

impl FromRequest for OptionalAuthenticatedUser {
    type Error = actix_web::Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut actix_web::dev::Payload) -> Self::Future {
        let user = req.extensions().get::<AuthUser>().cloned();
        ready(Ok(OptionalAuthenticatedUser(user)))
    }
}

/// Authentication middleware factory.
///
/// This middleware handles session-based authentication and injects the
/// authenticated user into the request extensions so it can be extracted
/// in handler functions.
///
/// # Examples
///
/// ```rust
/// use actix_web::App;
/// use actix_passport::AuthMiddleware;
///
/// let app = App::new()
///     .wrap(AuthMiddleware::new(session_store));
/// ```
pub struct AuthMiddleware<S> {
    session_store: Rc<S>,
}

impl<S> AuthMiddleware<S>
where
    S: SessionStore + 'static,
{
    /// Creates a new authentication middleware.
    ///
    /// # Arguments
    ///
    /// * `session_store` - The session store implementation
    pub fn new(session_store: S) -> Self {
        Self {
            session_store: Rc::new(session_store),
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for AuthMiddleware<B>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error>,
    S::Future: 'static,
    B: SessionStore + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = actix_web::Error;
    type InitError = ();
    type Transform = AuthMiddlewareService<S, B>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AuthMiddlewareService {
            service,
            session_store: self.session_store.clone(),
        }))
    }
}

/// Authentication middleware service.
///
/// This is the actual middleware service that processes requests and
/// handles authentication logic.
pub struct AuthMiddlewareService<S, B> {
    service: S,
    session_store: Rc<B>,
}

impl<S, B> Service<ServiceRequest> for AuthMiddlewareService<S, B>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error>,
    S::Future: 'static,
    B: SessionStore + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = actix_web::Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let session_store = self.session_store.clone();
        let service = &self.service;

        Box::pin(async move {
            // Try to get user from session
            if let Some(user) = get_user_from_session(&req, &*session_store).await {
                req.extensions_mut().insert(user);
            }

            service.call(req).await
        })
    }
}

/// Extracts authenticated user from session.
///
/// This function checks the current session for a valid user ID and
/// loads the corresponding user from the session store.
async fn get_user_from_session<S>(req: &ServiceRequest, session_store: &S) -> Option<AuthUser>
where
    S: SessionStore,
{
    // Get session from request
    let session = Session::from_request(req.request(), &mut actix_web::dev::Payload::None)
        .await
        .ok()?;

    // Get session ID from session
    let session_id_str = session.get::<String>("session_id").ok()??;
    let session_id = Uuid::parse_str(&session_id_str).ok()?;

    // Find session in store
    let stored_session = session_store.find_session(session_id).await.ok()??;

    // Check if session is expired
    if stored_session.expires_at < chrono::Utc::now() {
        // Session expired, try to clean it up
        let _ = session_store.delete_session(session_id).await;
        return None;
    }

    // Create AuthUser from session data
    // Note: In a real implementation, you might want to fetch the full user
    // from a UserStore instead of reconstructing from session data
    let user = AuthUser {
        id: stored_session.user_id,
        email: stored_session
            .data
            .get("email")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        username: stored_session
            .data
            .get("username")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        display_name: stored_session
            .data
            .get("display_name")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        avatar_url: stored_session
            .data
            .get("avatar_url")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        created_at: stored_session
            .data
            .get("created_at")
            .and_then(|v| v.as_str())
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&chrono::Utc))
            .unwrap_or_else(|| chrono::Utc::now()),
        last_login: stored_session
            .data
            .get("last_login")
            .and_then(|v| v.as_str())
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&chrono::Utc)),
        metadata: stored_session
            .data
            .get("metadata")
            .and_then(|v| v.as_object())
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(|(k, v)| (k, v))
            .collect(),
    };

    Some(user)
}

/// JWT authentication middleware factory.
///
/// This middleware handles JWT token-based authentication. It looks for
/// JWT tokens in the Authorization header and validates them.
///
/// # Examples
///
/// ```rust
/// use actix_web::App;
/// use actix_passport::JwtAuthMiddleware;
///
/// let app = App::new()
///     .wrap(JwtAuthMiddleware::new("your_jwt_secret".to_string()));
/// ```
#[cfg(feature = "jwt")]
pub struct JwtAuthMiddleware {
    secret: String,
}

#[cfg(feature = "jwt")]
impl JwtAuthMiddleware {
    /// Creates a new JWT authentication middleware.
    ///
    /// # Arguments
    ///
    /// * `secret` - The secret key used to sign and verify JWT tokens
    pub fn new(secret: String) -> Self {
        Self { secret }
    }
}

#[cfg(feature = "jwt")]
impl<S, B> Transform<S, ServiceRequest> for JwtAuthMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error>,
    S::Future: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = actix_web::Error;
    type InitError = ();
    type Transform = JwtAuthMiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(JwtAuthMiddlewareService {
            service,
            secret: self.secret.clone(),
        }))
    }
}

/// JWT authentication middleware service.
#[cfg(feature = "jwt")]
pub struct JwtAuthMiddlewareService<S> {
    service: S,
    secret: String,
}

#[cfg(feature = "jwt")]
impl<S, B> Service<ServiceRequest> for JwtAuthMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error>,
    S::Future: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = actix_web::Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let secret = self.secret.clone();
        let service = &self.service;

        Box::pin(async move {
            // Try to get user from JWT token
            if let Some(user) = get_user_from_jwt(&req, &secret).await {
                req.extensions_mut().insert(user);
            }

            service.call(req).await
        })
    }
}

/// Extracts authenticated user from JWT token.
///
/// This function looks for a JWT token in the Authorization header,
/// validates it, and extracts the user information.
#[cfg(feature = "jwt")]
async fn get_user_from_jwt(req: &ServiceRequest, secret: &str) -> Option<AuthUser> {
    use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize)]
    struct Claims {
        sub: String, // user ID
        email: Option<String>,
        username: Option<String>,
        display_name: Option<String>,
        exp: usize, // expiration timestamp
    }

    // Get Authorization header
    let auth_header = req.headers().get("Authorization")?;
    let auth_str = auth_header.to_str().ok()?;

    // Extract bearer token
    if !auth_str.starts_with("Bearer ") {
        return None;
    }
    let token = &auth_str[7..];

    // Decode and validate JWT
    let decoding_key = DecodingKey::from_secret(secret.as_ref());
    let validation = Validation::new(Algorithm::HS256);

    let token_data = decode::<Claims>(token, &decoding_key, &validation).ok()?;

    let claims = token_data.claims;

    // Create AuthUser from JWT claims
    Some(AuthUser {
        id: claims.sub,
        email: claims.email,
        username: claims.username,
        display_name: claims.display_name,
        avatar_url: None,
        created_at: chrono::Utc::now(), // We don't have this info in JWT
        last_login: Some(chrono::Utc::now()),
        metadata: std::collections::HashMap::new(),
    })
}

/// Utility functions for session management.
pub mod session_utils {
    use super::*;
    use crate::core::Session;
    use actix_session::Session as ActixSession;
    use chrono::{Duration, Utc};
    use std::collections::HashMap;

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
    pub fn create_user_session(user: &AuthUser, duration: Duration) -> Session {
        let mut session_data = HashMap::new();
        
        // Store user data in session
        if let Some(ref email) = user.email {
            session_data.insert("email".to_string(), serde_json::Value::String(email.clone()));
        }
        if let Some(ref username) = user.username {
            session_data.insert("username".to_string(), serde_json::Value::String(username.clone()));
        }
        if let Some(ref display_name) = user.display_name {
            session_data.insert("display_name".to_string(), serde_json::Value::String(display_name.clone()));
        }
        if let Some(ref avatar_url) = user.avatar_url {
            session_data.insert("avatar_url".to_string(), serde_json::Value::String(avatar_url.clone()));
        }
        
        session_data.insert(
            "created_at".to_string(), 
            serde_json::Value::String(user.created_at.to_rfc3339())
        );
        
        if let Some(ref last_login) = user.last_login {
            session_data.insert(
                "last_login".to_string(), 
                serde_json::Value::String(last_login.to_rfc3339())
            );
        }
        
        session_data.insert(
            "metadata".to_string(), 
            serde_json::to_value(&user.metadata).unwrap_or_default()
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
    pub fn set_session_id(actix_session: &ActixSession, session_id: Uuid) -> AuthResult<()> {
        actix_session
            .insert("session_id", session_id.to_string())
            .map_err(|e| AuthError::Internal(format!("Failed to set session ID: {}", e)))?;
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
}