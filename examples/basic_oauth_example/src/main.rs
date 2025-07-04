use actix_files::Files;
use actix_passport::{prelude::*, strategy::strategies::oauth::OAuthStrategy};
use actix_session::{storage::CookieSessionStore, SessionMiddleware};
use actix_web::{cookie::Key, web, App, HttpResponse, HttpServer};

async fn hello_world(user: AuthedUser) -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({
        "message": format!("Hello, {}!", user.username.as_deref().unwrap_or("Anonymous")),
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "display_name": user.display_name,
            "avatar_url": user.avatar_url,
            "oauth_providers": user.get_oauth_providers(),
            "created_at": user.created_at,
        }
    }))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Load environment variables from .env file
    dotenv::dotenv().ok();

    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let user_store = InMemoryUserStore::new();
    let google_provider = GoogleOAuthProvider::from_env();
    let github_provider = GitHubOAuthProvider::from_env();

    let oauth_strategy = OAuthStrategy::new(user_store.clone())
        .with_provider(google_provider)
        .with_provider(github_provider);

    // Create the authentication framework with in-memory store and OAuth providers
    let auth_framework = ActixPassportBuilder::new(user_store)
        .add_strategy(oauth_strategy)
        .build();

    log::info!("Starting OAuth example server at http://127.0.0.1:8080");

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
