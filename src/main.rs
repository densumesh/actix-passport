//! Example usage of the actix-passport authentication framework.
//!
//! This example demonstrates how to set up a complete authentication system
//! with password and OAuth authentication using actix-passport.

use actix_passport::{
    AuthBuilder, AuthResult, AuthUser, AuthedUser, OptionalAuthedUser, SessionStore, UserStore,
};
use actix_session::{config::PersistentSession, storage::CookieSessionStore, SessionMiddleware};
use actix_web::{
    cookie::{Key, SameSite},
    get,
    middleware::Logger,
    web, App, HttpResponse, HttpServer, Responder, Result,
};
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Example in-memory user store implementation.
///
/// In a real application, you would implement this with a database
/// like PostgreSQL, MySQL, or MongoDB.
#[derive(Debug, Clone)]
pub struct InMemoryUserStore {
    users: std::sync::Arc<std::sync::RwLock<HashMap<String, AuthUser>>>,
}

impl InMemoryUserStore {
    pub fn new() -> Self {
        Self {
            users: std::sync::Arc::new(std::sync::RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl UserStore for InMemoryUserStore {
    async fn find_by_id(&self, id: &str) -> AuthResult<Option<AuthUser>> {
        let users = self.users.read().unwrap();
        Ok(users.get(id).cloned())
    }

    async fn find_by_email(&self, email: &str) -> AuthResult<Option<AuthUser>> {
        let users = self.users.read().unwrap();
        Ok(users
            .values()
            .find(|user| user.email.as_ref() == Some(&email.to_string()))
            .cloned())
    }

    async fn find_by_username(&self, username: &str) -> AuthResult<Option<AuthUser>> {
        let users = self.users.read().unwrap();
        Ok(users
            .values()
            .find(|user| user.username.as_ref() == Some(&username.to_string()))
            .cloned())
    }

    async fn create_user(&self, user: AuthUser) -> AuthResult<AuthUser> {
        let mut users = self.users.write().unwrap();
        users.insert(user.id.clone(), user.clone());
        Ok(user)
    }

    async fn update_user(&self, user: AuthUser) -> AuthResult<AuthUser> {
        let mut users = self.users.write().unwrap();
        users.insert(user.id.clone(), user.clone());
        Ok(user)
    }

    async fn delete_user(&self, id: &str) -> AuthResult<()> {
        let mut users = self.users.write().unwrap();
        users.remove(id);
        Ok(())
    }
}

/// Example in-memory session store implementation.
///
/// In a real application, you would implement this with Redis
/// or a database for scalability and persistence.
#[derive(Debug, Clone)]
pub struct InMemorySessionStore {
    sessions: std::sync::Arc<std::sync::RwLock<HashMap<Uuid, actix_passport::Session>>>,
}

impl InMemorySessionStore {
    pub fn new() -> Self {
        Self {
            sessions: std::sync::Arc::new(std::sync::RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl SessionStore for InMemorySessionStore {
    async fn create_session(
        &self,
        session: actix_passport::Session,
    ) -> AuthResult<actix_passport::Session> {
        let mut sessions = self.sessions.write().unwrap();
        sessions.insert(session.id, session.clone());
        Ok(session)
    }

    async fn find_session(&self, id: Uuid) -> AuthResult<Option<actix_passport::Session>> {
        let sessions = self.sessions.read().unwrap();
        Ok(sessions.get(&id).cloned())
    }

    async fn update_session(
        &self,
        session: actix_passport::Session,
    ) -> AuthResult<actix_passport::Session> {
        let mut sessions = self.sessions.write().unwrap();
        sessions.insert(session.id, session.clone());
        Ok(session)
    }

    async fn delete_session(&self, id: Uuid) -> AuthResult<()> {
        let mut sessions = self.sessions.write().unwrap();
        sessions.remove(&id);
        Ok(())
    }

    async fn delete_user_sessions(&self, user_id: &str) -> AuthResult<()> {
        let mut sessions = self.sessions.write().unwrap();
        sessions.retain(|_, session| session.user_id != user_id);
        Ok(())
    }

    async fn cleanup_expired_sessions(&self) -> AuthResult<u64> {
        let mut sessions = self.sessions.write().unwrap();
        let now = Utc::now();
        let initial_count = sessions.len() as u64;
        sessions.retain(|_, session| session.expires_at > now);
        let final_count = sessions.len() as u64;
        Ok(initial_count - final_count)
    }
}

// Example route handlers

/// Home page - shows different content for authenticated vs unauthenticated users.
#[get("/")]
async fn home(user: OptionalAuthedUser) -> Result<impl Responder> {
    match user.0 {
        Some(user) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "message": format!("Welcome back, {}!", user.display_name.unwrap_or(user.id)),
            "authenticated": true,
            "user": user
        }))),
        None => Ok(HttpResponse::Ok().json(serde_json::json!({
            "message": "Welcome to our app! Please log in or register.",
            "authenticated": false
        }))),
    }
}

/// Protected dashboard - requires authentication.
#[get("/dashboard")]
async fn dashboard(user: AuthedUser) -> Result<impl Responder> {
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Welcome to your dashboard!",
        "user": user.0,
        "data": {
            "recent_activity": ["Logged in", "Updated profile", "Changed password"],
            "stats": {
                "login_count": 42,
                "last_login": Utc::now()
            }
        }
    })))
}

/// Public API endpoint.
#[get("/api/public")]
async fn public_api() -> Result<impl Responder> {
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "This is a public API endpoint",
        "data": "Anyone can access this"
    })))
}

/// Protected API endpoint.
#[get("/api/protected")]
async fn protected_api(user: AuthedUser) -> Result<impl Responder> {
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "This is a protected API endpoint",
        "user_id": user.0.id,
        "sensitive_data": "Only authenticated users can see this"
    })))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize logging
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    // Create stores
    let user_store = InMemoryUserStore::new();
    let session_store = InMemorySessionStore::new();

    // Build authentication system
    let auth = AuthBuilder::new()
        .user_store(user_store)
        .session_store(session_store)
        .session_duration(Duration::days(30))
        .jwt_secret("your-super-secret-jwt-key-here")
        .allowed_origins(vec![
            "http://localhost:3000".to_string(),
            "http://localhost:8080".to_string(),
        ])
        .enable_password_auth()
        // Uncomment these lines to enable OAuth providers:
        // .with_google_oauth(
        //     std::env::var("GOOGLE_CLIENT_ID").expect("GOOGLE_CLIENT_ID not set"),
        //     std::env::var("GOOGLE_CLIENT_SECRET").expect("GOOGLE_CLIENT_SECRET not set"),
        // )
        // .with_github_oauth(
        //     std::env::var("GITHUB_CLIENT_ID").expect("GITHUB_CLIENT_ID not set"),
        //     std::env::var("GITHUB_CLIENT_SECRET").expect("GITHUB_CLIENT_SECRET not set"),
        // )
        .build();

    println!("🚀 Starting server at http://localhost:8080");
    println!("📚 Available endpoints:");
    println!("  GET  /                    - Home page");
    println!("  GET  /dashboard           - Protected dashboard (requires auth)");
    println!("  GET  /api/public          - Public API endpoint");
    println!("  GET  /api/protected       - Protected API endpoint (requires auth)");
    println!("  GET  /auth/me             - Get current user info");
    println!("  POST /auth/login          - Login with email/password");
    println!("  POST /auth/register       - Register new user");
    println!("  POST /auth/logout         - Logout");
    // println!("  GET  /auth/google         - Login with Google OAuth");
    // println!("  GET  /auth/github         - Login with GitHub OAuth");

    // Start HTTP server
    HttpServer::new(move || {
        // Create session middleware
        let session_key = Key::generate();
        let session_middleware =
            SessionMiddleware::builder(CookieSessionStore::default(), session_key)
                .cookie_name("actix-passport-session".to_string())
                .cookie_secure(false) // Set to true in production with HTTPS
                .cookie_same_site(SameSite::Lax)
                .session_lifecycle(
                    PersistentSession::default().session_ttl(Duration::days(30).to_std().unwrap()),
                )
                .build();

        App::new()
            .wrap(Logger::default())
            .wrap(session_middleware)
            .wrap(auth.middleware())
            .service(home)
            .service(dashboard)
            .service(public_api)
            .service(protected_api)
            .service(web::scope("/auth").configure(|cfg| auth.configure_routes(cfg)))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
