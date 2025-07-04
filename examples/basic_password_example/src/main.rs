use actix_files::Files;
use actix_passport::{prelude::*, strategy::strategies::password::PasswordStrategy};
use actix_session::{storage::CookieSessionStore, SessionMiddleware};
use actix_web::{cookie::Key, web, App, HttpResponse, HttpServer, Responder, Result};

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
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    // 1. Use the builder to construct the framework
    let user_store = InMemoryUserStore::new();
    let password_strategy = PasswordStrategy::new(user_store.clone());

    let auth_framework = ActixPassportBuilder::new(user_store)
        .add_strategy(password_strategy)
        .build();

    log::info!("Starting server at http://127.0.0.1:8080");

    // 2. Start the Actix-web server
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
            .route("/api/user", web::get().to(user_info))
            .service(Files::new("/", "static").index_file("index.html"))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
