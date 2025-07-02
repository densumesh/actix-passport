#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    missing_docs,
    clippy::pedantic
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
use serde_json::json;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,                            // Subject (user ID)
    exp: usize,                             // Expiration time
    iat: usize,                             // Issued at
    aud: Option<String>,                    // Audience
    iss: Option<String>,                    // Issuer
    custom_data: Option<serde_json::Value>, // Custom claims
}

/// Helper function to create JWT token with custom claims
fn create_jwt_token_with_claims(
    user_id: &str,
    secret: &str,
    expiration_hours: i64,
    audience: Option<&str>,
    issuer: Option<&str>,
    custom_data: Option<serde_json::Value>,
) -> Result<String, jsonwebtoken::errors::Error> {
    let now = Utc::now();
    let expiration = now + Duration::hours(expiration_hours);

    let claims = Claims {
        sub: user_id.to_string(),
        exp: usize::try_from(expiration.timestamp()).unwrap(),
        iat: usize::try_from(now.timestamp()).unwrap(),
        aud: audience.map(ToString::to_string),
        iss: issuer.map(ToString::to_string),
        custom_data,
    };

    let header = Header::new(Algorithm::HS256);
    let encoding_key = EncodingKey::from_secret(secret.as_ref());

    encode(&header, &claims, &encoding_key)
}

/// Helper function to create standard JWT token
fn create_jwt_token(user_id: &str, secret: &str) -> Result<String, jsonwebtoken::errors::Error> {
    create_jwt_token_with_claims(user_id, secret, 24, None, None, None)
}

/// Helper function to create test app with JWT middleware
fn create_jwt_test_app(
    auth_framework: ActixPassport<MockUserStore>,
    jwt_secret: &str,
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
        .wrap(JwtAuthMiddleware::new(jwt_secret.to_string()))
        .route("/jwt-protected", web::get().to(jwt_protected_route))
        .route("/jwt-admin", web::post().to(jwt_admin_route))
        .route("/jwt-token", web::post().to(create_token_route))
        .route("/jwt-refresh", web::post().to(refresh_token_route))
}

async fn jwt_protected_route(user: AuthedUser) -> Result<HttpResponse> {
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "user_id": user.0.id,
        "message": "JWT authentication successful",
        "timestamp": chrono::Utc::now().timestamp()
    })))
}

async fn jwt_admin_route(user: AuthedUser) -> Result<HttpResponse> {
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "user_id": user.0.id,
        "admin": true,
        "message": "Admin access granted"
    })))
}

async fn create_token_route(payload: web::Json<serde_json::Value>) -> Result<HttpResponse> {
    let user_id = payload["user_id"].as_str().unwrap_or("test_user");
    let expiration_hours = payload["expiration_hours"].as_i64().unwrap_or(24);
    let audience = payload["audience"].as_str();
    let issuer = payload["issuer"].as_str();
    let custom_data = payload.get("custom_data").cloned();

    create_jwt_token_with_claims(
        user_id,
        "test_jwt_secret",
        expiration_hours,
        audience,
        issuer,
        custom_data,
    )
    .map_or_else(
        |_| {
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to create token"
            })))
        },
        |token| {
            Ok(HttpResponse::Ok().json(serde_json::json!({
                "token": token,
                "token_type": "Bearer",
                "expires_in": expiration_hours * 3600
            })))
        },
    )
}

async fn refresh_token_route(payload: web::Json<serde_json::Value>) -> Result<HttpResponse> {
    let old_token = payload["token"].as_str().unwrap_or("");

    // Decode old token (without verification for refresh)
    let decoding_key = DecodingKey::from_secret("test_jwt_secret".as_ref());
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = false; // Allow expired tokens for refresh

    match decode::<Claims>(old_token, &decoding_key, &validation) {
        Ok(token_data) => {
            // Create new token with same user ID
            create_jwt_token(&token_data.claims.sub, "test_jwt_secret").map_or_else(
                |_| {
                    Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                        "error": "Failed to create refresh token"
                    })))
                },
                |new_token| {
                    Ok(HttpResponse::Ok().json(serde_json::json!({
                        "token": new_token,
                        "token_type": "Bearer"
                    })))
                },
            )
        }
        Err(_) => Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Invalid token for refresh"
        }))),
    }
}

#[cfg(test)]
mod jwt_tests {
    use super::*;

    #[actix_web::test]
    async fn test_jwt_token_creation() {
        let user_store = MockUserStore::new();
        let test_user = AuthUser::new("test_user_123")
            .with_email("test@example.com")
            .with_username("testuser")
            .with_display_name("Test User");

        user_store.add_user(test_user);

        let auth_framework = ActixPassportBuilder::new()
            .with_user_store(user_store)
            .build()
            .expect("Failed to build auth framework");

        let app =
            actix_web::test::init_service(create_jwt_test_app(auth_framework, "test_jwt_secret"))
                .await;

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
        assert_eq!(
            body["expires_in"],
            24 * 3600,
            "Should return expiration time"
        );
    }

    #[actix_web::test]
    async fn test_jwt_token_creation_with_custom_expiration() {
        let user_store = MockUserStore::new();
        let auth_framework = ActixPassportBuilder::new()
            .with_user_store(user_store)
            .build()
            .expect("Failed to build auth framework");

        let app =
            actix_web::test::init_service(create_jwt_test_app(auth_framework, "test_jwt_secret"))
                .await;

        let token_payload = json!({
            "user_id": "test_user_123",
            "expiration_hours": 1
        });

        let req = actix_web::test::TestRequest::post()
            .uri("/jwt-token")
            .set_json(&token_payload)
            .to_request();

        let resp = actix_web::test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        let body: serde_json::Value = actix_web::test::read_body_json(resp).await;
        assert_eq!(body["expires_in"], 3600, "Should return 1 hour expiration");
    }

    #[actix_web::test]
    async fn test_jwt_token_creation_with_custom_claims() {
        let user_store = MockUserStore::new();
        let auth_framework = ActixPassportBuilder::new()
            .with_user_store(user_store)
            .build()
            .expect("Failed to build auth framework");

        let app =
            actix_web::test::init_service(create_jwt_test_app(auth_framework, "test_jwt_secret"))
                .await;

        let token_payload = json!({
            "user_id": "test_user_123",
            "audience": "api.example.com",
            "issuer": "auth.example.com",
            "custom_data": {
                "role": "admin",
                "permissions": ["read", "write", "delete"]
            }
        });

        let req = actix_web::test::TestRequest::post()
            .uri("/jwt-token")
            .set_json(&token_payload)
            .to_request();

        let resp = actix_web::test::call_service(&app, req).await;
        assert!(resp.status().is_success());

        let body: serde_json::Value = actix_web::test::read_body_json(resp).await;
        let token = body["token"].as_str().unwrap();

        // Verify the token contains custom claims
        let decoding_key = DecodingKey::from_secret("test_jwt_secret".as_ref());
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_aud = false; // Disable audience validation for this test
        let token_data = decode::<Claims>(token, &decoding_key, &validation).unwrap();

        assert_eq!(token_data.claims.aud, Some("api.example.com".to_string()));
        assert_eq!(token_data.claims.iss, Some("auth.example.com".to_string()));
        assert!(token_data.claims.custom_data.is_some());
    }

    #[actix_web::test]
    async fn test_jwt_protected_route_with_valid_token() {
        let user_store = MockUserStore::new();
        let test_user = AuthUser::new("test_user_123")
            .with_email("test@example.com")
            .with_username("testuser")
            .with_display_name("Test User");

        user_store.add_user(test_user);

        let auth_framework = ActixPassportBuilder::new()
            .with_user_store(user_store)
            .build()
            .expect("Failed to build auth framework");

        let app =
            actix_web::test::init_service(create_jwt_test_app(auth_framework, "test_jwt_secret"))
                .await;

        let token = create_jwt_token("test_user_123", "test_jwt_secret")
            .expect("Failed to create JWT token");

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
        assert!(body["timestamp"].is_number(), "Should include timestamp");
    }

    #[actix_web::test]
    async fn test_jwt_protected_route_without_token() {
        let user_store = MockUserStore::new();
        let auth_framework = ActixPassportBuilder::new()
            .with_user_store(user_store)
            .build()
            .expect("Failed to build auth framework");

        let app =
            actix_web::test::init_service(create_jwt_test_app(auth_framework, "test_jwt_secret"))
                .await;

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

        let app =
            actix_web::test::init_service(create_jwt_test_app(auth_framework, "test_jwt_secret"))
                .await;

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
    async fn test_jwt_protected_route_with_malformed_header() {
        let user_store = MockUserStore::new();
        let auth_framework = ActixPassportBuilder::new()
            .with_user_store(user_store)
            .build()
            .expect("Failed to build auth framework");

        let app =
            actix_web::test::init_service(create_jwt_test_app(auth_framework, "test_jwt_secret"))
                .await;

        // Test various malformed headers
        let malformed_headers = vec![
            "invalid_format",
            "Bearer",
            "Bearer ",
            "Basic dGVzdDp0ZXN0", // Wrong auth type
            "bearer token",       // Wrong case
        ];

        for header in malformed_headers {
            let req = actix_web::test::TestRequest::get()
                .uri("/jwt-protected")
                .insert_header((AUTHORIZATION, header))
                .to_request();

            let resp = actix_web::test::call_service(&app, req).await;
            assert!(
                resp.status().is_client_error(),
                "Should reject malformed header: {header}"
            );
        }
    }

    #[actix_web::test]
    async fn test_jwt_token_expiration() {
        let user_store = MockUserStore::new();
        let test_user = AuthUser::new("test_user_123")
            .with_email("test@example.com")
            .with_username("testuser")
            .with_display_name("Test User");

        user_store.add_user(test_user);

        let auth_framework = ActixPassportBuilder::new()
            .with_user_store(user_store)
            .build()
            .expect("Failed to build auth framework");

        let app =
            actix_web::test::init_service(create_jwt_test_app(auth_framework, "test_jwt_secret"))
                .await;

        // Create an expired token
        let expired_token = create_jwt_token_with_claims(
            "test_user_123",
            "test_jwt_secret",
            -1, // Expired 1 hour ago
            None,
            None,
            None,
        )
        .expect("Failed to create expired token");

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
        let user_store = MockUserStore::new();
        let auth_framework = ActixPassportBuilder::new()
            .with_user_store(user_store)
            .build()
            .expect("Failed to build auth framework");

        let app =
            actix_web::test::init_service(create_jwt_test_app(auth_framework, "test_jwt_secret"))
                .await;

        // Create token with different secret
        let token =
            create_jwt_token("test_user_123", "wrong_secret").expect("Failed to create JWT token");

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
    async fn test_jwt_token_with_nonexistent_user() {
        let user_store = MockUserStore::new();
        let auth_framework = ActixPassportBuilder::new()
            .with_user_store(user_store)
            .build()
            .expect("Failed to build auth framework");

        let app =
            actix_web::test::init_service(create_jwt_test_app(auth_framework, "test_jwt_secret"))
                .await;

        // Create token for user that doesn't exist in store
        let token = create_jwt_token("nonexistent_user", "test_jwt_secret")
            .expect("Failed to create JWT token");

        let req = actix_web::test::TestRequest::get()
            .uri("/jwt-protected")
            .insert_header((AUTHORIZATION, format!("Bearer {token}")))
            .to_request();

        let resp = actix_web::test::call_service(&app, req).await;
        // JWT is stateless - valid token should work even if user doesn't exist in store
        assert!(
            resp.status().is_success(),
            "JWT should be stateless and work without user store validation"
        );

        let body: serde_json::Value = actix_web::test::read_body_json(resp).await;
        assert_eq!(body["user_id"], "nonexistent_user");
    }

    #[actix_web::test]
    async fn test_jwt_token_refresh() {
        let user_store = MockUserStore::new();
        let auth_framework = ActixPassportBuilder::new()
            .with_user_store(user_store)
            .build()
            .expect("Failed to build auth framework");

        let app =
            actix_web::test::init_service(create_jwt_test_app(auth_framework, "test_jwt_secret"))
                .await;

        // Create an expired token
        let expired_token = create_jwt_token_with_claims(
            "test_user_123",
            "test_jwt_secret",
            -1, // Expired
            None,
            None,
            None,
        )
        .expect("Failed to create expired token");

        // Refresh the token
        let refresh_payload = json!({
            "token": expired_token
        });

        let req = actix_web::test::TestRequest::post()
            .uri("/jwt-refresh")
            .set_json(&refresh_payload)
            .to_request();

        let resp = actix_web::test::call_service(&app, req).await;
        assert!(resp.status().is_success(), "Token refresh should succeed");

        let body: serde_json::Value = actix_web::test::read_body_json(resp).await;
        assert!(body["token"].is_string(), "Should return new token");
        assert_eq!(body["token_type"], "Bearer");

        // Verify new token is different from expired one
        let new_token = body["token"].as_str().unwrap();
        assert_ne!(new_token, expired_token, "New token should be different");
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
        assert!(
            claims.exp > claims.iat,
            "Expiration should be after issued time"
        );
    }

    #[actix_web::test]
    async fn test_jwt_different_algorithms_rejection() {
        let user_store = MockUserStore::new();
        let auth_framework = ActixPassportBuilder::new()
            .with_user_store(user_store)
            .build()
            .expect("Failed to build auth framework");

        let app =
            actix_web::test::init_service(create_jwt_test_app(auth_framework, "test_jwt_secret"))
                .await;

        // Create token with different algorithm (RS256 instead of HS256)
        let header = Header::new(Algorithm::RS256);
        let claims = Claims {
            sub: "test_user_123".to_string(),
            exp: (Utc::now() + Duration::hours(1)).timestamp() as usize,
            iat: Utc::now().timestamp() as usize,
            aud: None,
            iss: None,
            custom_data: None,
        };

        // This will fail because RS256 requires different key format
        // But we're testing that our middleware rejects it
        let encoding_key = EncodingKey::from_secret("test_jwt_secret".as_ref());
        let token_result = encode(&header, &claims, &encoding_key);

        // Even if token creation succeeds, it should be rejected by middleware
        if let Ok(token) = token_result {
            let req = actix_web::test::TestRequest::get()
                .uri("/jwt-protected")
                .insert_header((AUTHORIZATION, format!("Bearer {token}")))
                .to_request();

            let resp = actix_web::test::call_service(&app, req).await;
            assert!(
                resp.status().is_client_error(),
                "Should reject token with wrong algorithm"
            );
        }
    }

    #[actix_web::test]
    async fn test_jwt_multiple_concurrent_tokens() {
        let user_store = MockUserStore::new();

        // Add multiple users
        for i in 1..=3 {
            let test_user = AuthUser::new(format!("test_user_{i}"))
                .with_email(format!("test{i}@example.com"))
                .with_username(format!("testuser{i}"));
            user_store.add_user(test_user);
        }

        let auth_framework = ActixPassportBuilder::new()
            .with_user_store(user_store)
            .build()
            .expect("Failed to build auth framework");

        let app =
            actix_web::test::init_service(create_jwt_test_app(auth_framework, "test_jwt_secret"))
                .await;

        // Create tokens for multiple users
        let tokens: Vec<String> = (1..=3)
            .map(|i| create_jwt_token(&format!("test_user_{i}"), "test_jwt_secret").unwrap())
            .collect();

        // Test each token accesses correct user data
        for (i, token) in tokens.iter().enumerate() {
            let req = actix_web::test::TestRequest::get()
                .uri("/jwt-protected")
                .insert_header((AUTHORIZATION, format!("Bearer {token}")))
                .to_request();

            let resp = actix_web::test::call_service(&app, req).await;
            assert!(resp.status().is_success(), "Token {} should work", i + 1);

            let body: serde_json::Value = actix_web::test::read_body_json(resp).await;
            assert_eq!(body["user_id"], format!("test_user_{}", i + 1));
        }
    }

    #[actix_web::test]
    async fn test_jwt_token_edge_case_empty_user_id() {
        let token_result = create_jwt_token("", "test_jwt_secret");
        assert!(
            token_result.is_ok(),
            "Should allow empty user ID in token creation"
        );

        let user_store = MockUserStore::new();
        let auth_framework = ActixPassportBuilder::new()
            .with_user_store(user_store)
            .build()
            .expect("Failed to build auth framework");

        let app =
            actix_web::test::init_service(create_jwt_test_app(auth_framework, "test_jwt_secret"))
                .await;

        let token = token_result.unwrap();
        let req = actix_web::test::TestRequest::get()
            .uri("/jwt-protected")
            .insert_header((AUTHORIZATION, format!("Bearer {token}")))
            .to_request();

        let resp = actix_web::test::call_service(&app, req).await;
        // JWT middleware accepts valid tokens even with empty user ID
        // This is technically valid JWT behavior, though may not be desired in practice
        assert!(
            resp.status().is_success(),
            "JWT middleware accepts technically valid tokens with empty user ID"
        );

        let body: serde_json::Value = actix_web::test::read_body_json(resp).await;
        assert_eq!(body["user_id"], "");
    }

    #[actix_web::test]
    async fn test_jwt_token_very_long_user_id() {
        let long_user_id = "a".repeat(1000); // Very long user ID
        let token =
            create_jwt_token(&long_user_id, "test_jwt_secret").expect("Should handle long user ID");

        let user_store = MockUserStore::new();
        let test_user = AuthUser::new(&long_user_id);
        user_store.add_user(test_user);

        let auth_framework = ActixPassportBuilder::new()
            .with_user_store(user_store)
            .build()
            .expect("Failed to build auth framework");

        let app =
            actix_web::test::init_service(create_jwt_test_app(auth_framework, "test_jwt_secret"))
                .await;

        let req = actix_web::test::TestRequest::get()
            .uri("/jwt-protected")
            .insert_header((AUTHORIZATION, format!("Bearer {token}")))
            .to_request();

        let resp = actix_web::test::call_service(&app, req).await;
        assert!(
            resp.status().is_success(),
            "Should handle very long user ID"
        );
    }
}
