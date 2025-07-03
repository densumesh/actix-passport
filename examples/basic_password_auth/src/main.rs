use actix_files::Files;
use actix_passport::{
    core::UserStore,
    types::{AuthResult, AuthUser},
    ActixPassportBuilder, AuthedUser,
};
use actix_session::{storage::CookieSessionStore, SessionMiddleware};
use actix_web::{cookie::Key, web, App, HttpResponse, HttpServer};
use async_trait::async_trait;
use std::collections::HashMap;
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

    async fn update_user(&self, _user: AuthUser) -> AuthResult<AuthUser> {
        unimplemented!()
    }
    async fn delete_user(&self, _id: &str) -> AuthResult<()> {
        unimplemented!()
    }
}

async fn hello_world(user: AuthedUser) -> HttpResponse {
    HttpResponse::Ok().body(format!("Hello, {:?}!", user.username))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    // 1. Initialize the UserStore
    let user_store = InMemoryUserStore::default();

    // 2. Use the builder to construct the framework
    let auth_framework = ActixPassportBuilder::new()
        .with_user_store(user_store)
        .enable_password_auth()
        .build()
        .expect("Failed to build auth framework");

    log::info!("Starting server at http://127.0.0.1:8080");

    // 3. Start the Actix-web server
    HttpServer::new(move || {
        App::new()
            // IMPORTANT: Session middleware is now the single source of truth for session state.
            // You can swap this with `RedisSessionStore` or another backend.
            .wrap(
                SessionMiddleware::builder(
                    CookieSessionStore::default(),
                    Key::from(&[0; 64]), // In production, use a secure, persistent key
                )
                .cookie_secure(false)
                .build(), // For local HTTP testing
            )
            .configure(|cfg| auth_framework.configure_routes(cfg))
            .route("/hello", web::get().to(hello_world))
            .service(Files::new("/", "static").index_file("index.html"))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
