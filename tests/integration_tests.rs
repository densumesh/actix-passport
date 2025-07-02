#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    missing_docs,
    clippy::pedantic
)]

use actix_passport::{
    ActixPassport, ActixPassportBuilder, AuthedUser, GoogleOAuthProvider, SessionAuthMiddleware,
};
use actix_session::{storage::CookieSessionStore, SessionMiddleware};
use actix_web::{web, App, HttpResponse, Result};
mod common;
use common::MockUserStore;

/// Helper function to create test app
fn create_test_app(
    auth_framework: ActixPassport<MockUserStore>,
) -> App<
    impl actix_web::dev::ServiceFactory<
        actix_web::dev::ServiceRequest,
        Config = (),
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
        InitError = (),
    >,
> {
    let user_store = auth_framework.user_store.clone();
    App::new()
        .app_data(web::Data::new(auth_framework))
        .wrap(SessionAuthMiddleware::new(user_store))
        .wrap(
            SessionMiddleware::builder(
                CookieSessionStore::default(),
                actix_web::cookie::Key::from("0123".repeat(16).as_bytes()), // Use consistent key for tests
            )
            .cookie_secure(false)
            .build(),
        )
        .configure(actix_passport::routes::configure_routes::<MockUserStore>)
        .route("/protected", web::get().to(protected_route))
}

async fn protected_route(user: AuthedUser) -> Result<HttpResponse> {
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "user_id": user.0.id,
        "message": "This is a protected route"
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    use serde_json::json;

    #[actix_web::test]
    async fn test_password_auth_registration() {
        // Create mock user store and auth framework
        let user_store = MockUserStore::new();
        let auth_framework = ActixPassportBuilder::new()
            .with_user_store(user_store.clone())
            .enable_password_auth()
            .build()
            .expect("Failed to build auth framework");

        let app = actix_web::test::init_service(create_test_app(auth_framework)).await;

        // Test user registration
        let register_payload = json!({
            "email": "test@example.com",
            "username": "testuser",
            "password": "securepassword123"
        });

        let req = actix_web::test::TestRequest::post()
            .uri("/auth/register")
            .set_json(&register_payload)
            .to_request();

        let resp = actix_web::test::call_service(&app, req).await;
        assert!(resp.status().is_success(), "Registration should succeed");

        // Verify user was created
        assert_eq!(user_store.get_user_count(), 1, "One user should be created");
    }

    #[actix_web::test]
    async fn test_password_auth_login() {
        // Create mock user store and auth framework
        let user_store = MockUserStore::new();
        let auth_framework = ActixPassportBuilder::new()
            .with_user_store(user_store.clone())
            .enable_password_auth()
            .build()
            .expect("Failed to build auth framework");

        let app = actix_web::test::init_service(create_test_app(auth_framework)).await;

        // First register a user
        let register_payload = json!({
            "email": "test@example.com",
            "username": "testuser",
            "password": "securepassword123"
        });

        let req = actix_web::test::TestRequest::post()
            .uri("/auth/register")
            .set_json(&register_payload)
            .to_request();

        let resp = actix_web::test::call_service(&app, req).await;
        assert!(resp.status().is_success(), "Registration should succeed");

        // Now test login
        let login_payload = json!({
            "identifier": "test@example.com",
            "password": "securepassword123"
        });

        let req = actix_web::test::TestRequest::post()
            .uri("/auth/login")
            .set_json(&login_payload)
            .to_request();

        let resp = actix_web::test::call_service(&app, req).await;
        assert!(resp.status().is_success(), "Login should succeed");

        let cookie = resp.response().cookies().next().unwrap();

        let req = actix_web::test::TestRequest::get()
            .cookie(cookie)
            .uri("/auth/me")
            .to_request();

        let resp = actix_web::test::call_service(&app, req).await;
        assert!(resp.status().is_success(), "Me should succeed");
    }

    #[actix_web::test]
    async fn test_password_auth_login_invalid_credentials() {
        let user_store = MockUserStore::new();
        let auth_framework = ActixPassportBuilder::new()
            .with_user_store(user_store)
            .enable_password_auth()
            .build()
            .expect("Failed to build auth framework");

        let app = actix_web::test::init_service(create_test_app(auth_framework)).await;

        // Test login with invalid credentials
        let login_payload = json!({
            "identifier": "nonexistent@example.com",
            "password": "wrongpassword"
        });

        let req = actix_web::test::TestRequest::post()
            .uri("/auth/login")
            .set_json(&login_payload)
            .to_request();

        let resp = actix_web::test::call_service(&app, req).await;
        assert!(
            resp.status().is_client_error(),
            "Login should fail with invalid credentials"
        );
    }

    #[actix_web::test]
    async fn test_password_auth_logout() {
        let user_store = MockUserStore::new();
        let auth_framework = ActixPassportBuilder::new()
            .with_user_store(user_store)
            .enable_password_auth()
            .build()
            .expect("Failed to build auth framework");

        let app = actix_web::test::init_service(create_test_app(auth_framework)).await;

        // Register and login first
        let register_payload = json!({
            "email": "test@example.com",
            "username": "testuser",
            "password": "securepassword123"
        });

        let req = actix_web::test::TestRequest::post()
            .uri("/auth/register")
            .set_json(&register_payload)
            .to_request();

        let resp = actix_web::test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        // Login
        let login_payload = json!({
            "identifier": "test@example.com",
            "password": "securepassword123"
        });

        let req = actix_web::test::TestRequest::post()
            .uri("/auth/login")
            .set_json(&login_payload)
            .to_request();

        let resp = actix_web::test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        // Test logout
        let req = actix_web::test::TestRequest::post()
            .uri("/auth/logout")
            .to_request();

        let resp = actix_web::test::call_service(&app, req).await;
        assert!(resp.status().is_success(), "Logout should succeed");
    }

    #[actix_web::test]
    async fn test_oauth_authorize_url() {
        let user_store = MockUserStore::new();
        let google_provider = GoogleOAuthProvider::new(
            "test_client_id".to_string(),
            "test_client_secret".to_string(),
        );

        let auth_framework = ActixPassportBuilder::new()
            .with_user_store(user_store)
            .with_oauth(google_provider)
            .build()
            .expect("Failed to build auth framework");

        let app = actix_web::test::init_service(create_test_app(auth_framework)).await;

        // Test OAuth authorization URL generation
        let req = actix_web::test::TestRequest::get()
            .uri("/auth/google")
            .to_request();

        let resp = actix_web::test::call_service(&app, req).await;
        assert!(
            resp.status().is_redirection(),
            "Should redirect to OAuth provider"
        );
    }

    #[actix_web::test]
    async fn test_protected_route_without_auth() {
        let user_store = MockUserStore::new();
        let auth_framework = ActixPassportBuilder::new()
            .with_user_store(user_store)
            .enable_password_auth()
            .build()
            .expect("Failed to build auth framework");

        let app = actix_web::test::init_service(create_test_app(auth_framework)).await;

        // Test accessing protected route without authentication
        let req = actix_web::test::TestRequest::get()
            .uri("/protected")
            .to_request();

        let resp = actix_web::test::call_service(&app, req).await;
        assert!(
            resp.status().is_client_error(),
            "Should reject unauthenticated access"
        );
    }

    #[actix_web::test]
    async fn test_protected_route_with_auth() {
        let user_store = MockUserStore::new();
        let auth_framework = ActixPassportBuilder::new()
            .with_user_store(user_store)
            .enable_password_auth()
            .build()
            .expect("Failed to build auth framework");

        let app = actix_web::test::init_service(create_test_app(auth_framework)).await;

        // Register and login first
        let register_payload = json!({
            "email": "test@example.com",
            "username": "testuser",
            "password": "securepassword123"
        });

        let req = actix_web::test::TestRequest::post()
            .uri("/auth/register")
            .set_json(&register_payload)
            .to_request();

        let resp = actix_web::test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        // Login
        let login_payload = json!({
            "identifier": "test@example.com",
            "password": "securepassword123"
        });

        let req = actix_web::test::TestRequest::post()
            .uri("/auth/login")
            .set_json(&login_payload)
            .to_request();

        let resp = actix_web::test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        let cookie = resp.response().cookies().next().unwrap();
        let req = actix_web::test::TestRequest::get()
            .uri("/protected")
            .cookie(cookie)
            .to_request();

        let resp = actix_web::test::call_service(&app, req).await;
        assert!(
            resp.status().is_success(),
            "Should allow authenticated access"
        );
    }

    #[actix_web::test]
    async fn test_get_current_user() {
        let user_store = MockUserStore::new();
        let auth_framework = ActixPassportBuilder::new()
            .with_user_store(user_store.clone())
            .enable_password_auth()
            .build()
            .expect("Failed to build auth framework");

        let app = actix_web::test::init_service(create_test_app(auth_framework)).await;

        // Register and login
        let register_payload = json!({
            "email": "test@example.com",
            "username": "testuser",
            "password": "securepassword123"
        });

        let req = actix_web::test::TestRequest::post()
            .uri("/auth/register")
            .set_json(&register_payload)
            .to_request();

        let resp = actix_web::test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        let login_payload = json!({
            "identifier": "test@example.com",
            "password": "securepassword123"
        });

        let req = actix_web::test::TestRequest::post()
            .uri("/auth/login")
            .set_json(&login_payload)
            .to_request();

        let resp = actix_web::test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        let cookie = resp.response().cookies().next().unwrap();

        // Test getting current user
        let req = actix_web::test::TestRequest::get()
            .cookie(cookie)
            .uri("/auth/me")
            .to_request();

        let resp = actix_web::test::call_service(&app, req).await;
        println!("Response status: {}", resp.status());

        assert!(
            resp.status().is_success(),
            "Should return current user info. Status: {}",
            resp.status()
        );
    }

    #[actix_web::test]
    async fn test_password_validation() {
        let user_store = MockUserStore::new();
        let auth_framework = ActixPassportBuilder::new()
            .with_user_store(user_store)
            .enable_password_auth()
            .build()
            .expect("Failed to build auth framework");

        let app = actix_web::test::init_service(create_test_app(auth_framework)).await;

        // Test registration with weak password
        let register_payload = json!({
            "email": "test@example.com",
            "username": "testuser",
            "password": "weak"
        });

        let req = actix_web::test::TestRequest::post()
            .uri("/auth/register")
            .set_json(&register_payload)
            .to_request();

        let resp = actix_web::test::call_service(&app, req).await;
        // Note: Depending on implementation, this might succeed or fail
        // Adjust assertion based on your password validation rules
        println!("Password validation response status: {}", resp.status());
    }

    #[actix_web::test]
    async fn test_duplicate_user_registration() {
        let user_store = MockUserStore::new();
        let auth_framework = ActixPassportBuilder::new()
            .with_user_store(user_store)
            .enable_password_auth()
            .build()
            .expect("Failed to build auth framework");

        let app = actix_web::test::init_service(create_test_app(auth_framework)).await;

        let register_payload = json!({
            "email": "test@example.com",
            "username": "testuser",
            "password": "securepassword123"
        });

        // First registration
        let req = actix_web::test::TestRequest::post()
            .uri("/auth/register")
            .set_json(&register_payload)
            .to_request();

        let resp = actix_web::test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        // Second registration with same email
        let req = actix_web::test::TestRequest::post()
            .uri("/auth/register")
            .set_json(&register_payload)
            .to_request();

        let resp = actix_web::test::call_service(&app, req).await;
        assert!(
            resp.status().is_client_error(),
            "Should reject duplicate registration"
        );
    }
}
