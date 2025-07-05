mod stores;
mod strategies;
mod token_helpers;

use actix_files::Files;
use actix_passport::prelude::*;
use actix_session::{storage::CookieSessionStore, SessionMiddleware};
use actix_web::{
    cookie::Key, middleware::Logger, web, App, HttpResponse, HttpServer, Responder, Result,
};
use stores::sqlite_store::SqliteUserStore;
use strategies::bearer_strategy::BearerAuthStrategy;

async fn health_check() -> Result<impl Responder> {
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "status": "healthy",
        "service": "advanced-sqlite-bearer-auth"
    })))
}

async fn api_info() -> Result<impl Responder> {
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "endpoints": {
            "auth": {
                "register": "POST /auth/register",
                "login": "POST /auth/login", 
                "logout": "POST /auth/logout",
                "profile": "GET /auth/profile"
            },
            "health": "GET /health"
        },
        "authentication": {
            "type": "Bearer Token",
            "header": "Authorization: Bearer <token>",
            "description": "Include the token returned from login/register in the Authorization header"
        },
        "example_requests": {
            "register": {
                "url": "/auth/register",
                "method": "POST",
                "body": {
                    "email": "user@example.com",
                    "username": "johndoe", 
                    "password": "password123",
                    "display_name": "John Doe"
                }
            },
            "login": {
                "url": "/auth/login",
                "method": "POST", 
                "body": {
                    "identifier": "user@example.com",
                    "password": "password123"
                }
            }
        }
    })))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    // Initialize SQLite user store
    let user_store =
        SqliteUserStore::new("./users.db").expect("Failed to initialize SQLite user store");

    // Create Bearer auth strategy
    let bearer_strategy = BearerAuthStrategy::new(user_store.clone());

    // Build the ActixPassport framework with our custom components
    let auth_framework = ActixPassportBuilder::new(user_store)
        .add_strategy(bearer_strategy)
        .build();

    log::info!("Starting server at http://127.0.0.1:8080");
    log::info!("API documentation available at: http://127.0.0.1:8080/api/info");
    log::info!("Static files served from: http://127.0.0.1:8080/");

    HttpServer::new({
        let auth_framework = auth_framework.clone();
        move || {
            App::new()
                .wrap(Logger::default())
                // Session middleware (required even though we're using Bearer auth)
                .wrap(
                    SessionMiddleware::builder(
                        CookieSessionStore::default(),
                        Key::from(&[0; 64]), // In production, use a secure, persistent key
                    )
                    .cookie_secure(false) // For local HTTP testing
                    .build(),
                )
                // Configure authentication routes under /auth prefix
                .configure(|cfg| auth_framework.configure_routes(cfg, RouteConfig::default()))
                // API routes
                .route("/health", web::get().to(health_check))
                .route("/api/info", web::get().to(api_info))
                // Serve static files
                .service(Files::new("/", "static").index_file("index.html"))
        }
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
