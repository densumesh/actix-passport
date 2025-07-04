use actix_files::Files;
use actix_passport::{ActixPassportBuilder, AuthedUser, PostgresUserStore};
use actix_session::{storage::CookieSessionStore, SessionMiddleware};
use actix_web::{
    cookie::Key, middleware::Logger, web, App, HttpResponse, HttpServer, Responder, Result,
};
use dotenvy::dotenv;
use env_logger::Env;
use std::env;

async fn user_info(user: AuthedUser) -> Result<impl Responder> {
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "display_name": user.display_name,
            "avatar_url": user.avatar_url,
            "oauth_providers": user.get_oauth_providers(),
            "created_at": user.created_at,
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

    // Configure authentication framework
    let user_store = PostgresUserStore::new(&database_url).await.unwrap();

    let auth_framework = ActixPassportBuilder::new(user_store)
        .enable_password_auth()
        .build();

    println!("🚀 Starting server on http://localhost:8080");
    println!("📝 Available endpoints:");
    println!("   GET  /                 - Home page (public)");
    println!("   GET  /api/user         - Get current user info (requires auth)");
    println!("   POST /auth/register    - Register new user");
    println!("   POST /auth/login       - Login user");
    println!("   POST /auth/logout      - Logout user");

    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                Key::generate(),
            ))
            .route("/api/user", web::get().to(user_info))
            .configure(|cfg| auth_framework.configure_routes(cfg))
            .service(Files::new("/", "static").index_file("index.html"))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
