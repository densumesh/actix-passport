#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    missing_docs,
    clippy::missing_panics_doc
)]

use actix_passport::{
    ActixPassport, ActixPassportBuilder, AuthUser, AuthedUser, JwtAuthMiddleware,
};
use actix_web::{http::header::AUTHORIZATION, web, App, HttpResponse, Result};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
mod common;
use common::MockUserStore;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
    iat: usize,
}

/// Helper function to create JWT token
fn create_jwt_token(user_id: &str, secret: &str) -> Result<String, jsonwebtoken::errors::Error> {
    let now = Utc::now();
    let expiration = now + Duration::hours(24);

    let claims = Claims {
        sub: user_id.to_string(),
        exp: usize::try_from(expiration.timestamp()).unwrap(),
        iat: usize::try_from(now.timestamp()).unwrap(),
    };

    let header = Header::new(Algorithm::HS256);
    let encoding_key = EncodingKey::from_secret(secret.as_ref());

    encode(&header, &claims, &encoding_key)
}

/// Helper function to create test app with JWT middleware
fn create_jwt_test_app(
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
    App::new()
        .app_data(web::Data::new(auth_framework))
        .wrap(JwtAuthMiddleware::new("test_jwt_secret".to_string()))
        .route("/jwt-protected", web::get().to(jwt_protected_route))
        .route("/jwt-token", web::post().to(create_token_route))
}

async fn jwt_protected_route(user: AuthedUser) -> Result<HttpResponse> {
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "user_id": user.0.id,
        "message": "JWT authentication successful"
    })))
}

async fn create_token_route(payload: web::Json<serde_json::Value>) -> Result<HttpResponse> {
    let user_id = payload["user_id"].as_str().unwrap_or("test_user");

    create_jwt_token(user_id, "test_jwt_secret").map_or_else(
        |_| {
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to create token"
            })))
        },
        |token| {
            Ok(HttpResponse::Ok().json(serde_json::json!({
                "token": token,
                "token_type": "Bearer"
            })))
        },
    )
}

#[cfg(test)]
mod jwt_tests {
    use super::*;

    use serde_json::json;

    #[actix_web::test]
    async fn test_jwt_token_creation() {
        let user_store = MockUserStore::new();

        // Add a test user
        let test_user = AuthUser::new("test_user_123")
            .with_email("test@example.com")
            .with_username("testuser")
            .with_display_name("Test User");
        user_store.add_user(test_user);

        let auth_framework = ActixPassportBuilder::new()
            .with_user_store(user_store)
            .build()
            .expect("Failed to build auth framework");

        let app = actix_web::test::init_service(create_jwt_test_app(auth_framework)).await;

        // Test JWT token creation
        let token_payload = json!({
            "user_id": "test_user_123"
        });

        let req = actix_web::test::TestRequest::post()
            .uri("/jwt-token")
            .set_json(&token_payload)
            .to_request();

        let resp = actix_web::test::call_service(&app, req).await;
        assert!(resp.status().is_success(), "Token creation should succeed");

        let body: serde_json::Value = actix_web::test::read_body_json(resp).await;
        assert!(body["token"].is_string(), "Response should contain token");
        assert_eq!(
            body["token_type"], "Bearer",
            "Should return Bearer token type"
        );
    }

    #[actix_web::test]
    async fn test_jwt_protected_route_with_valid_token() {
        let user_store = MockUserStore::new();

        // Add a test user
        let test_user = AuthUser::new("test_user_123")
            .with_email("test@example.com")
            .with_username("testuser")
            .with_display_name("Test User");
        user_store.add_user(test_user);

        let auth_framework = ActixPassportBuilder::new()
            .with_user_store(user_store)
            .build()
            .expect("Failed to build auth framework");

        let app = actix_web::test::init_service(create_jwt_test_app(auth_framework)).await;

        // Create a valid JWT token
        let token = create_jwt_token("test_user_123", "test_jwt_secret")
            .expect("Failed to create JWT token");

        // Test accessing protected route with valid token
        let req = actix_web::test::TestRequest::get()
            .uri("/jwt-protected")
            .insert_header((AUTHORIZATION, format!("Bearer {token}")))
            .to_request();

        let resp = actix_web::test::call_service(&app, req).await;
        assert!(
            resp.status().is_success(),
            "Should allow access with valid JWT token"
        );

        let body: serde_json::Value = actix_web::test::read_body_json(resp).await;
        assert_eq!(
            body["user_id"], "test_user_123",
            "Should return correct user ID"
        );
    }

    #[actix_web::test]
    async fn test_jwt_protected_route_without_token() {
        let user_store = MockUserStore::new();
        let auth_framework = ActixPassportBuilder::new()
            .with_user_store(user_store)
            .build()
            .expect("Failed to build auth framework");

        let app = actix_web::test::init_service(create_jwt_test_app(auth_framework)).await;

        // Test accessing protected route without token
        let req = actix_web::test::TestRequest::get()
            .uri("/jwt-protected")
            .to_request();

        let resp = actix_web::test::call_service(&app, req).await;
        assert!(
            resp.status().is_client_error(),
            "Should reject access without token"
        );
    }

    #[actix_web::test]
    async fn test_jwt_protected_route_with_invalid_token() {
        let user_store = MockUserStore::new();
        let auth_framework = ActixPassportBuilder::new()
            .with_user_store(user_store)
            .build()
            .expect("Failed to build auth framework");

        let app = actix_web::test::init_service(create_jwt_test_app(auth_framework)).await;

        // Test accessing protected route with invalid token
        let req = actix_web::test::TestRequest::get()
            .uri("/jwt-protected")
            .insert_header((AUTHORIZATION, "Bearer invalid_token_here"))
            .to_request();

        let resp = actix_web::test::call_service(&app, req).await;
        assert!(
            resp.status().is_client_error(),
            "Should reject access with invalid token"
        );
    }

    #[actix_web::test]
    async fn test_jwt_token_expiration() {
        // Create an expired token
        let now = Utc::now();
        let past_time = now - Duration::hours(1);

        let expired_claims = Claims {
            sub: "test_user_123".to_string(),
            exp: usize::try_from(past_time.timestamp()).unwrap(), // Expired
            iat: usize::try_from((past_time - Duration::hours(1)).timestamp()).unwrap(),
        };

        let header = Header::new(Algorithm::HS256);
        let encoding_key = EncodingKey::from_secret("test_jwt_secret".as_ref());
        let expired_token = encode(&header, &expired_claims, &encoding_key)
            .expect("Failed to create expired token");

        let user_store = MockUserStore::new();
        let auth_framework = ActixPassportBuilder::new()
            .with_user_store(user_store)
            .build()
            .expect("Failed to build auth framework");

        let app = actix_web::test::init_service(create_jwt_test_app(auth_framework)).await;

        // Test accessing protected route with expired token
        let req = actix_web::test::TestRequest::get()
            .uri("/jwt-protected")
            .insert_header((AUTHORIZATION, format!("Bearer {expired_token}")))
            .to_request();

        let resp = actix_web::test::call_service(&app, req).await;
        assert!(
            resp.status().is_client_error(),
            "Should reject expired token"
        );
    }

    #[actix_web::test]
    async fn test_jwt_token_with_wrong_secret() {
        // Create token with different secret
        let token =
            create_jwt_token("test_user_123", "wrong_secret").expect("Failed to create JWT token");

        let user_store = MockUserStore::new();
        let auth_framework = ActixPassportBuilder::new()
            .with_user_store(user_store)
            .build()
            .expect("Failed to build auth framework");

        let app = actix_web::test::init_service(create_jwt_test_app(auth_framework)).await;

        // Test accessing protected route with token signed with wrong secret
        let req = actix_web::test::TestRequest::get()
            .uri("/jwt-protected")
            .insert_header((AUTHORIZATION, format!("Bearer {token}")))
            .to_request();

        let resp = actix_web::test::call_service(&app, req).await;
        assert!(
            resp.status().is_client_error(),
            "Should reject token with wrong signature"
        );
    }

    #[actix_web::test]
    async fn test_jwt_token_validation() {
        let token = create_jwt_token("test_user_123", "test_jwt_secret")
            .expect("Failed to create JWT token");

        // Validate token manually
        let decoding_key = DecodingKey::from_secret("test_jwt_secret".as_ref());
        let validation = Validation::new(Algorithm::HS256);

        let token_data = decode::<Claims>(&token, &decoding_key, &validation);
        assert!(token_data.is_ok(), "Token should be valid");

        let claims = token_data.unwrap().claims;
        assert_eq!(
            claims.sub, "test_user_123",
            "Token should contain correct user ID"
        );
    }
}
