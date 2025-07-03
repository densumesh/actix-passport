mod models;
mod schema;
mod user_store;

use actix_passport::{ActixPassportBuilder, AuthedUser, OptionalAuthedUser};
use actix_session::{storage::CookieSessionStore, SessionMiddleware};
use actix_web::{
    cookie::Key, get, middleware::Logger, web, App, HttpResponse, HttpServer, Responder, Result,
};
use dotenvy::dotenv;
use env_logger::Env;
use std::env;
use user_store::PostgresUserStore;

#[get("/")]
async fn home(user: OptionalAuthedUser) -> Result<impl Responder> {
    match user.0 {
        Some(user) => {
            let display_name = user.display_name.clone().unwrap_or_else(|| user.id.clone());
            Ok(HttpResponse::Ok().json(serde_json::json!({
                "message": format!("Welcome back, {}!", display_name),
                "user": {
                    "id": user.id,
                    "email": user.email,
                    "username": user.username,
                    "display_name": user.display_name,
                    "created_at": user.created_at,
                    "last_login": user.last_login
                }
            })))
        }
        None => Ok(HttpResponse::Ok().json(serde_json::json!({
            "message": "Welcome! Please log in to continue.",
            "auth_endpoints": {
                "register": "/auth/register",
                "login": "/auth/login",
                "logout": "/auth/logout",
                "profile": "/auth/me"
            }
        }))),
    }
}

#[get("/dashboard")]
async fn dashboard(user: AuthedUser) -> Result<impl Responder> {
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Welcome to your dashboard!",
        "user": {
            "id": user.id,
            "email": user.email,
            "username": user.username,
            "display_name": user.display_name,
            "oauth_providers": user.get_oauth_providers(),
            "metadata": user.metadata
        }
    })))
}

#[get("/profile")]
async fn profile(user: AuthedUser) -> Result<impl Responder> {
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "profile": {
            "id": user.id,
            "email": user.email,
            "username": user.username,
            "display_name": user.display_name,
            "avatar_url": user.avatar_url,
            "created_at": user.created_at,
            "last_login": user.last_login,
            "oauth_providers": user.get_oauth_providers(),
            "metadata_keys": user.metadata.keys().collect::<Vec<_>>()
        }
    })))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Load environment variables
    dotenv().ok();

    // Initialize logger
    env_logger::init_from_env(Env::default().default_filter_or("info"));

    // Get database URL from environment
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    // Create database connection pool
    let db_pool = PostgresUserStore::create_pool(&database_url)
        .await
        .expect("Failed to create database pool");

    // Create user store
    let user_store = PostgresUserStore::new(db_pool);

    // Configure authentication framework
    let auth_framework = ActixPassportBuilder::new(user_store)
        .enable_password_auth()
        .build();

    println!("🚀 Starting server on http://localhost:8080");
    println!("📝 Available endpoints:");
    println!("   GET  /                 - Home page (public)");
    println!("   GET  /dashboard        - Dashboard (requires auth)");
    println!("   GET  /profile          - User profile (requires auth)");
    println!("   POST /auth/register    - Register new user");
    println!("   POST /auth/login       - Login user");
    println!("   POST /auth/logout      - Logout user");
    println!("   GET  /auth/me          - Get current user info");

    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                Key::generate(),
            ))
            .app_data(web::Data::new(auth_framework.clone()))
            .service(home)
            .service(dashboard)
            .service(profile)
            .configure(|cfg| auth_framework.configure_routes(cfg))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
