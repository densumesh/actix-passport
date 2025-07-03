use actix_files::Files;
use actix_passport::prelude::*;
use actix_session::{storage::CookieSessionStore, SessionMiddleware};
use actix_web::{cookie::Key, web, App, HttpResponse, HttpServer};

async fn hello_world(user: AuthedUser) -> HttpResponse {
    HttpResponse::Ok().body(format!("Hello, {:?}!", user.username))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    // 1. Use the builder to construct the framework
    let auth_framework = ActixPassportBuilder::with_in_memory_store()
        .enable_password_auth()
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
            .route("/hello", web::get().to(hello_world))
            .service(Files::new("/", "static").index_file("index.html"))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
