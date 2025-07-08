use actix_files::Files;
use actix_passport::{
    email::{config::EmailConfigBuilder, EmailService, EmailServiceConfig},
    prelude::*,
};
use actix_session::{storage::CookieSessionStore, SessionMiddleware};
use actix_web::{
    cookie::Key,
    middleware::Logger,
    web::{self},
    App, HttpResponse, HttpServer, Responder, Result,
};
use std::env;

async fn user_info(user: AuthedUser) -> Result<impl Responder> {
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "display_name": user.display_name,
            "avatar_url": user.avatar_url,
            "is_email_verified": user.is_email_verified(),
            "oauth_providers": user.get_oauth_providers(),
            "created_at": user.created_at,
        }
    })))
}

// Handle email verification via URL parameter
async fn verify_email_page() -> Result<impl Responder> {
    let html = actix_files::NamedFile::open_async("static/email-verified.html").await?;
    Ok(html)
}

async fn reset_password_page() -> Result<impl Responder> {
    let html = actix_files::NamedFile::open_async("static/reset-password.html").await?;
    Ok(html)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize environment variables
    dotenvy::dotenv().ok();
    env_logger::init();

    // Get SMTP configuration from environment variables
    let smtp_host = env::var("SMTP_HOST").unwrap_or_else(|_| "smtp.fastmail.com".to_string());
    let smtp_port = env::var("SMTP_PORT")
        .unwrap_or_else(|_| "587".to_string())
        .parse::<u16>()
        .unwrap_or(587);
    let smtp_user = env::var("SMTP_USER").expect("SMTP_USER environment variable must be set");
    let smtp_password =
        env::var("SMTP_PASSWORD").expect("SMTP_PASSWORD environment variable must be set");
    let smtp_from = env::var("SMTP_FROM_ADDRESS").unwrap_or_else(|_| smtp_user.clone());
    let base_url = env::var("BASE_URL").unwrap_or_else(|_| "http://localhost:8080".to_string());

    // Configure email service with full functionality (verification + password reset)
    let email_config = EmailConfigBuilder::new()
        .smtp_host(smtp_host)
        .smtp_port(smtp_port)
        .username(smtp_user)
        .password(smtp_password)
        .from_email(smtp_from.clone())
        .from_name("Actix Passport Email Demo")
        .base_url(base_url)
        .use_tls(true)
        .build()
        .expect("Failed to build email configuration");

    let email_service = EmailService::with_service_config(
        email_config,
        EmailServiceConfig::all_enabled(), // Enable both email verification and password reset
        "Actix Passport Email Demo",
        "your-secret-key-here", // In production, use a secure random key
    )
    .await
    .expect("Failed to initialize email service");

    // Create authentication framework with email functionality
    let auth_framework = ActixPassportBuilder::with_in_memory_store()
        .enable_password_auth_with_email(email_service.clone())
        .build();

    let bind_address = "127.0.0.1:8080";
    println!("Starting server at http://{bind_address}");
    println!("\nAvailable endpoints:");
    println!("  GET  /                           - Main application page");
    println!("  GET  /api/user                   - Get current user info");
    println!("  GET  /verify-email?token=...     - Email verification via URL");
    println!("  GET  /reset-password?token=...   - Password reset page via URL");
    println!("  POST /auth/register              - Register a new user");
    println!("  POST /auth/login                 - Login user");
    println!("  POST /auth/verify-email          - Verify email with token");
    println!("  POST /auth/forgot-password       - Send password reset email");
    println!("  POST /auth/reset-password        - Reset password with token");

    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .wrap(
                SessionMiddleware::builder(
                    CookieSessionStore::default(),
                    Key::from(&[0; 64]), // Use a secure random key in production
                )
                .build(),
            )
            // Add application data
            .app_data(web::Data::new(auth_framework.clone()))
            .app_data(web::Data::new(email_service.clone()))
            .service(web::scope("/api").route("/user", web::get().to(user_info)))
            .route("/auth/verify-email", web::get().to(verify_email_page))
            .route("/auth/reset-password", web::get().to(reset_password_page))
            .configure(|cfg| {
                auth_framework
                    .configure_routes(cfg, RouteConfig::default().with_prefix("/auth".to_string()))
            })
            .service(Files::new("/", "static").index_file("index.html"))
    })
    .bind(bind_address)?
    .run()
    .await
}
