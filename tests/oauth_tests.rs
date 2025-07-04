#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    missing_docs,
    clippy::pedantic
)]

use actix_passport::{
    oauth_provider::providers::GenericOAuthProvider,
    oauth_provider::providers::GitHubOAuthProvider, oauth_provider::providers::GoogleOAuthProvider,
    oauth_provider::OAuthConfig, oauth_provider::OAuthProvider, strategies::OAuthStrategy,
    ActixPassport, ActixPassportBuilder, AuthedUser, InMemoryUserStore, RouteConfig,
};
use actix_session::{storage::CookieSessionStore, SessionMiddleware};
use actix_web::{web, App, HttpResponse, Result};

/// Helper function to create OAuth test app
fn create_oauth_test_app(
    auth_framework: ActixPassport,
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
        .wrap(
            SessionMiddleware::builder(
                CookieSessionStore::default(),
                actix_web::cookie::Key::from("0123".repeat(16).as_bytes()),
            )
            .cookie_secure(false)
            .build(),
        )
        .configure(|cfg| auth_framework.configure_routes(cfg, RouteConfig::default()))
        .route("/protected", web::get().to(protected_route))
}

async fn protected_route(user: AuthedUser) -> Result<HttpResponse> {
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "user_id": user.0.id,
        "message": "OAuth authenticated route"
    })))
}

fn build_oauth_framework(providers: Vec<Box<dyn OAuthProvider>>) -> ActixPassport {
    let in_memory_user_store = InMemoryUserStore::new();

    let oauth_strategy = OAuthStrategy::new(providers);

    ActixPassportBuilder::new(in_memory_user_store)
        .add_strategy(oauth_strategy)
        .build()
}

#[cfg(test)]
mod oauth_tests {
    use super::*;

    #[actix_web::test]
    async fn test_google_oauth_provider_creation() {
        let provider = GoogleOAuthProvider::new(
            "test_google_client_id".to_string(),
            "test_google_client_secret".to_string(),
        );

        assert_eq!(provider.name(), "google");
    }

    #[actix_web::test]
    async fn test_github_oauth_provider_creation() {
        let provider = GitHubOAuthProvider::new(
            "test_github_client_id".to_string(),
            "test_github_client_secret".to_string(),
        );

        assert_eq!(provider.name(), "github");
    }

    #[actix_web::test]
    async fn test_generic_oauth_provider_creation() {
        let config = OAuthConfig {
            client_id: "test_client_id".to_string(),
            client_secret: "test_client_secret".to_string(),
            auth_url: "https://auth.example.com/oauth/authorize".to_string(),
            token_url: "https://auth.example.com/oauth/token".to_string(),
            user_info_url: "https://auth.example.com/api/user".to_string(),
            scopes: vec!["read".to_string(), "write".to_string()],
        };

        let provider = GenericOAuthProvider::new("custom", config);
        assert_eq!(provider.name(), "custom");
    }

    #[actix_web::test]
    async fn test_google_oauth_authorization_url() {
        let google_provider = GoogleOAuthProvider::new(
            "test_google_client_id".to_string(),
            "test_google_secret_id".to_string(),
        );
        let auth_framework = build_oauth_framework(vec![Box::new(google_provider)]);

        let app = actix_web::test::init_service(create_oauth_test_app(auth_framework)).await;

        // Test Google OAuth authorization URL generation
        let req = actix_web::test::TestRequest::get()
            .uri("/auth/google")
            .to_request();

        let resp = actix_web::test::call_service(&app, req).await;
        assert!(
            resp.status().is_redirection(),
            "Should redirect to Google OAuth"
        );

        // Check if Location header contains google.com
        let location = resp.headers().get("Location").unwrap().to_str().unwrap();
        println!("Location: {location}");
        assert!(
            location.contains("accounts.google.com"),
            "Should redirect to Google OAuth URL"
        );
        assert!(
            location.contains("client_id=test_google_client_id"),
            "Should include client ID"
        );
        assert!(
            location.contains("response_type=code"),
            "Should use authorization code flow"
        );
    }

    #[actix_web::test]
    async fn test_github_oauth_authorization_url() {
        let github_provider = GitHubOAuthProvider::new(
            "test_github_client_id".to_string(),
            "test_github_secret_id".to_string(),
        );
        let auth_framework = build_oauth_framework(vec![Box::new(github_provider)]);

        let app = actix_web::test::init_service(create_oauth_test_app(auth_framework)).await;

        // Test GitHub OAuth authorization URL generation
        let req = actix_web::test::TestRequest::get()
            .uri("/auth/github")
            .to_request();

        let resp = actix_web::test::call_service(&app, req).await;
        assert!(
            resp.status().is_redirection(),
            "Should redirect to GitHub OAuth"
        );

        let location = resp.headers().get("Location").unwrap().to_str().unwrap();
        assert!(
            location.contains("github.com"),
            "Should redirect to GitHub OAuth URL"
        );
        assert!(
            location.contains("client_id=test_github_client_id"),
            "Should include client ID"
        );
    }

    #[actix_web::test]
    async fn test_oauth_authorization_url_includes_state() {
        let google_provider = GoogleOAuthProvider::new(
            "test_google_client_id".to_string(),
            "test_google_secret_id".to_string(),
        );
        let auth_framework = build_oauth_framework(vec![Box::new(google_provider)]);

        let app = actix_web::test::init_service(create_oauth_test_app(auth_framework)).await;

        let req = actix_web::test::TestRequest::get()
            .uri("/auth/google")
            .to_request();

        let resp = actix_web::test::call_service(&app, req).await;
        let location = resp.headers().get("Location").unwrap().to_str().unwrap();

        assert!(
            location.contains("state="),
            "Should include CSRF state parameter"
        );
    }

    #[actix_web::test]
    async fn test_oauth_callback_without_code() {
        let google_provider = GoogleOAuthProvider::new(
            "test_google_client_id".to_string(),
            "test_google_secret_id".to_string(),
        );
        let auth_framework = build_oauth_framework(vec![Box::new(google_provider)]);

        let app = actix_web::test::init_service(create_oauth_test_app(auth_framework)).await;

        // Test callback without authorization code
        let req = actix_web::test::TestRequest::get()
            .uri("/auth/google/callback")
            .to_request();

        let resp = actix_web::test::call_service(&app, req).await;
        assert!(
            resp.status().is_client_error(),
            "Should reject callback without code"
        );
    }

    #[actix_web::test]
    async fn test_oauth_callback_with_error() {
        let google_provider = GoogleOAuthProvider::new(
            "test_google_client_id".to_string(),
            "test_google_secret_id".to_string(),
        );
        let auth_framework = build_oauth_framework(vec![Box::new(google_provider)]);

        let app = actix_web::test::init_service(create_oauth_test_app(auth_framework)).await;

        // Test callback with error parameter
        let req = actix_web::test::TestRequest::get()
            .uri("/auth/google/callback?error=access_denied&error_description=User%20denied%20access")
            .to_request();

        let resp = actix_web::test::call_service(&app, req).await;
        assert!(
            resp.status().is_client_error(),
            "Should handle OAuth error response"
        );
    }

    #[actix_web::test]
    async fn test_oauth_nonexistent_provider() {
        let store = InMemoryUserStore::new();
        let auth_framework = ActixPassportBuilder::new(store).build();

        let app = actix_web::test::init_service(create_oauth_test_app(auth_framework)).await;

        // Test accessing nonexistent OAuth provider
        let req = actix_web::test::TestRequest::get()
            .uri("/auth/nonexistent")
            .to_request();

        let resp = actix_web::test::call_service(&app, req).await;
        assert!(
            resp.status().is_client_error(),
            "Should reject nonexistent provider"
        );
    }

    #[actix_web::test]
    async fn test_multiple_oauth_providers() {
        let google_provider =
            GoogleOAuthProvider::new("google_client_id".to_string(), "google_secret".to_string());
        let github_provider =
            GitHubOAuthProvider::new("github_client_id".to_string(), "github_secret".to_string());

        let auth_framework =
            build_oauth_framework(vec![Box::new(github_provider), Box::new(google_provider)]);

        let app = actix_web::test::init_service(create_oauth_test_app(auth_framework)).await;

        // Test Google OAuth
        let req = actix_web::test::TestRequest::get()
            .uri("/auth/google")
            .to_request();

        let resp = actix_web::test::call_service(&app, req).await;
        assert!(resp.status().is_redirection(), "Google OAuth should work");

        // Test GitHub OAuth
        let req = actix_web::test::TestRequest::get()
            .uri("/auth/github")
            .to_request();

        let resp = actix_web::test::call_service(&app, req).await;
        assert!(resp.status().is_redirection(), "GitHub OAuth should work");
    }

    #[actix_web::test]
    async fn test_oauth_authorization_url_includes_redirect_uri() {
        let google_provider = GoogleOAuthProvider::new(
            "test_google_client_id".to_string(),
            "test_google_secret_id".to_string(),
        );
        let auth_framework = build_oauth_framework(vec![Box::new(google_provider)]);

        let app = actix_web::test::init_service(create_oauth_test_app(auth_framework)).await;

        let req = actix_web::test::TestRequest::get()
            .uri("/auth/google")
            .to_request();

        let resp = actix_web::test::call_service(&app, req).await;

        if resp.response().error().is_some() {
            println!("Error: {:?}", resp.response().error());
        }

        let location = resp.headers().get("Location").unwrap().to_str().unwrap();

        assert!(
            location.contains("redirect_uri="),
            "Should include redirect URI"
        );
        assert!(
            location.contains("/auth/google/callback")
                || location.contains("%2Fauth%2Fgoogle%2Fcallback"),
            "Should redirect to callback endpoint (URL-encoded or not)"
        );
    }

    #[actix_web::test]
    async fn test_oauth_scopes_included_in_authorization_url() {
        let google_provider = GoogleOAuthProvider::new(
            "test_google_client_id".to_string(),
            "test_google_secret_id".to_string(),
        );
        let auth_framework = build_oauth_framework(vec![Box::new(google_provider)]);

        let app = actix_web::test::init_service(create_oauth_test_app(auth_framework)).await;

        let req = actix_web::test::TestRequest::get()
            .uri("/auth/google")
            .to_request();

        let resp = actix_web::test::call_service(&app, req).await;
        let location = resp.headers().get("Location").unwrap().to_str().unwrap();

        assert!(location.contains("scope="), "Should include OAuth scopes");
        // Google provider includes openid, email, profile scopes
        assert!(
            location.contains("openid") || location.contains("email"),
            "Should include expected scopes"
        );
    }

    #[actix_web::test]
    async fn test_custom_oauth_provider_with_custom_scopes() {
        let config = OAuthConfig {
            client_id: "custom_client_id".to_string(),
            client_secret: "custom_secret".to_string(),
            auth_url: "https://auth.custom.com/oauth/authorize".to_string(),
            token_url: "https://auth.custom.com/oauth/token".to_string(),
            user_info_url: "https://auth.custom.com/api/user".to_string(),
            scopes: vec!["custom:read".to_string(), "custom:write".to_string()],
        };

        let custom_provider = GenericOAuthProvider::new("custom", config);

        let auth_framework = build_oauth_framework(vec![Box::new(custom_provider)]);

        let app = actix_web::test::init_service(create_oauth_test_app(auth_framework)).await;

        let req = actix_web::test::TestRequest::get()
            .uri("/auth/custom")
            .to_request();

        let resp = actix_web::test::call_service(&app, req).await;
        assert!(resp.status().is_redirection(), "Custom OAuth should work");

        let location = resp.headers().get("Location").unwrap().to_str().unwrap();
        assert!(
            location.contains("auth.custom.com"),
            "Should use custom auth URL"
        );
        assert!(
            location.contains("custom:read") || location.contains("custom%3Aread"),
            "Should include custom scopes (URL-encoded or not)"
        );
    }

    #[actix_web::test]
    async fn test_oauth_session_state_persistence() {
        let google_provider = GoogleOAuthProvider::new(
            "test_google_client_id".to_string(),
            "test_google_secret_id".to_string(),
        );
        let auth_framework = build_oauth_framework(vec![Box::new(google_provider)]);

        let app = actix_web::test::init_service(create_oauth_test_app(auth_framework)).await;

        // Initiate OAuth flow
        let req = actix_web::test::TestRequest::get()
            .uri("/auth/google")
            .to_request();

        let resp = actix_web::test::call_service(&app, req).await;
        assert!(resp.status().is_redirection());

        // Check that a session cookie was set
        let cookie = resp.response().cookies().next();
        assert!(
            cookie.is_some(),
            "OAuth initiation should set session cookie"
        );

        // Extract state from redirect URL
        let location = resp.headers().get("Location").unwrap().to_str().unwrap();
        let state_start = location.find("state=").unwrap() + 6;
        let state_end = location[state_start..]
            .find('&')
            .unwrap_or_else(|| location[state_start..].len());
        let state = &location[state_start..state_start + state_end];

        println!("OAuth state: {state}");
        assert!(!state.is_empty(), "State should not be empty");
    }

    #[actix_web::test]
    async fn test_oauth_callback_invalid_state() {
        let google_provider = GoogleOAuthProvider::new(
            "test_google_client_id".to_string(),
            "test_google_secret_id".to_string(),
        );
        let auth_framework = build_oauth_framework(vec![Box::new(google_provider)]);

        let app = actix_web::test::init_service(create_oauth_test_app(auth_framework)).await;

        // Test callback with invalid state (without initiating OAuth first)
        let req = actix_web::test::TestRequest::get()
            .uri("/auth/google/callback?code=test_code&state=invalid_state")
            .to_request();

        let resp = actix_web::test::call_service(&app, req).await;
        assert!(
            resp.status().is_client_error(),
            "Should reject invalid state"
        );
    }
}
