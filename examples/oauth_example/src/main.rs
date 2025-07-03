use actix_files::Files;
use actix_passport::{
    core::UserStore,
    types::{AuthResult, AuthUser},
    ActixPassportBuilder, AuthedUser, GitHubOAuthProvider, GoogleOAuthProvider,
};
use actix_session::{storage::CookieSessionStore, SessionMiddleware};
use actix_web::{cookie::Key, web, App, HttpResponse, HttpServer};
use async_trait::async_trait;
use std::collections::HashMap;
use std::env;
use std::sync::{Arc, Mutex};

// --- In-memory UserStore for demonstration --- //
#[derive(Clone, Default)]
struct InMemoryUserStore {
    users: Arc<Mutex<HashMap<String, AuthUser>>>,
}

#[async_trait]
impl UserStore for InMemoryUserStore {
    async fn find_by_id(&self, id: &str) -> AuthResult<Option<AuthUser>> {
        let users = self.users.lock().unwrap();
        Ok(users.get(id).cloned())
    }

    async fn find_by_email(&self, email: &str) -> AuthResult<Option<AuthUser>> {
        let users = self.users.lock().unwrap();
        Ok(users
            .values()
            .find(|u| u.email.as_deref() == Some(email))
            .cloned())
    }

    async fn find_by_username(&self, username: &str) -> AuthResult<Option<AuthUser>> {
        let users = self.users.lock().unwrap();
        Ok(users
            .values()
            .find(|u| u.username.as_deref() == Some(username))
            .cloned())
    }

    async fn create_user(&self, user: AuthUser) -> AuthResult<AuthUser> {
        let mut users = self.users.lock().unwrap();
        users.insert(user.id.clone(), user.clone());
        Ok(user)
    }

    async fn update_user(&self, user: AuthUser) -> AuthResult<AuthUser> {
        let mut users = self.users.lock().unwrap();
        users.insert(user.id.clone(), user.clone());
        Ok(user)
    }

    async fn delete_user(&self, id: &str) -> AuthResult<()> {
        let mut users = self.users.lock().unwrap();
        users.remove(id);
        Ok(())
    }
}

async fn hello_world(user: AuthedUser) -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({
        "message": format!("Hello, {}!", user.0.username.as_deref().unwrap_or("Anonymous")),
        "user": {
            "id": user.0.id,
            "username": user.0.username,
            "email": user.0.email,
            "display_name": user.0.display_name,
            "avatar_url": user.0.avatar_url,
            "oauth_providers": user.0.get_oauth_providers(),
            "created_at": user.0.created_at,
        }
    }))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Load environment variables from .env file
    dotenv::dotenv().ok();

    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    // OAuth configuration from environment variables
    let google_client_id =
        env::var("GOOGLE_CLIENT_ID").unwrap_or_else(|_| "your_google_client_id".to_string());
    let google_client_secret = env::var("GOOGLE_CLIENT_SECRET")
        .unwrap_or_else(|_| "your_google_client_secret".to_string());

    let github_client_id =
        env::var("GITHUB_CLIENT_ID").unwrap_or_else(|_| "your_github_client_id".to_string());
    let github_client_secret = env::var("GITHUB_CLIENT_SECRET")
        .unwrap_or_else(|_| "your_github_client_secret".to_string());

    // 1. Initialize the UserStore
    let user_store = InMemoryUserStore::default();

    // 2. Create OAuth providers
    let google_provider =
        GoogleOAuthProvider::new(google_client_id.clone(), google_client_secret.clone());
    let github_provider =
        GitHubOAuthProvider::new(github_client_id.clone(), github_client_secret.clone());

    // 3. Use the builder to construct the framework with OAuth providers
    let auth_framework = ActixPassportBuilder::new()
        .with_user_store(user_store)
        .enable_password_auth()
        .with_oauth(google_provider)
        .with_oauth(github_provider)
        .build()
        .expect("Failed to build auth framework");

    log::info!("Starting OAuth example server at http://127.0.0.1:8080");
    log::info!(
        "Google OAuth: {}",
        if google_client_id != "your_google_client_id" {
            "Configured"
        } else {
            "Not configured (using placeholder)"
        }
    );
    log::info!(
        "GitHub OAuth: {}",
        if github_client_id != "your_github_client_id" {
            "Configured"
        } else {
            "Not configured (using placeholder)"
        }
    );

    // 4. Start the Actix-web server
    HttpServer::new(move || {
        App::new()
            // Session middleware for OAuth state management
            .wrap(
                SessionMiddleware::builder(
                    CookieSessionStore::default(),
                    Key::from(&[0; 64]), // In production, use a secure, persistent key
                )
                .cookie_secure(false) // For local HTTP testing
                .build(),
            )
            // Configure OAuth routes
            .configure(|cfg| auth_framework.configure_routes(cfg))
            .route("/api/user", web::get().to(hello_world))
            // Serve static files (frontend)
            .service(Files::new("/", "static").index_file("index.html"))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
