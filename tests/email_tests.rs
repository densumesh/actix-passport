#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    missing_docs,
    clippy::pedantic,
    clippy::future_not_send
)]

#[cfg(feature = "email")]
mod email_integration_tests {
    use actix_passport::{
        email::{EmailConfig, EmailService, EmailServiceConfig, EmailTemplate, SmtpProvider},
        ActixPassport, ActixPassportBuilder, AuthUser,
    };
    use actix_session::{storage::CookieSessionStore, SessionMiddleware};
    use actix_web::{
        cookie::Key,
        test::{self, TestRequest},
        web, App,
    };
    use async_trait::async_trait;
    use serde_json::json;
    use std::sync::{Arc, Mutex};

    /// Mock SMTP provider that captures sent emails for testing
    #[derive(Clone)]
    struct MockSmtpProvider {
        sent_emails: Arc<Mutex<Vec<SentEmail>>>,
        should_fail: Arc<Mutex<bool>>,
    }

    #[derive(Clone, Debug)]
    struct SentEmail {
        to_email: String,
        to_name: Option<String>,
        subject: String,
        html_body: String,
        _text_body: Option<String>,
    }

    impl MockSmtpProvider {
        fn new() -> Self {
            Self {
                sent_emails: Arc::new(Mutex::new(Vec::new())),
                should_fail: Arc::new(Mutex::new(false)),
            }
        }

        fn get_sent_emails(&self) -> Vec<SentEmail> {
            self.sent_emails.lock().unwrap().clone()
        }

        fn clear_sent_emails(&self) {
            self.sent_emails.lock().unwrap().clear();
        }

        fn set_should_fail(&self, should_fail: bool) {
            *self.should_fail.lock().unwrap() = should_fail;
        }

        fn count_sent_emails(&self) -> usize {
            self.sent_emails.lock().unwrap().len()
        }
    }

    #[async_trait]
    impl SmtpProvider for MockSmtpProvider {
        async fn send_email(
            &self,
            to_email: &str,
            to_name: Option<&str>,
            template: &EmailTemplate,
        ) -> actix_passport::types::AuthResult<()> {
            if *self.should_fail.lock().unwrap() {
                return Err(actix_passport::errors::AuthError::EmailError {
                    message: "Mock SMTP failure".to_string(),
                });
            }

            let email = SentEmail {
                to_email: to_email.to_string(),
                to_name: to_name.map(String::from),
                subject: template.subject.clone(),
                html_body: template.html_body.clone(),
                _text_body: template.text_body.clone(),
            };

            self.sent_emails.lock().unwrap().push(email);
            Ok(())
        }

        fn provider_name(&self) -> &str {
            "mock_smtp"
        }

        async fn validate_config(&self) -> actix_passport::types::AuthResult<()> {
            Ok(())
        }
    }

    // Note: We don't need to implement Clone for the trait object in tests
    // since we're using Arc<MockSmtpProvider> directly

    /// Helper function to create a test app with email functionality
    async fn create_test_app_with_email(
        service_config: EmailServiceConfig,
    ) -> (
        impl actix_web::dev::Service<
            actix_http::Request,
            Response = actix_web::dev::ServiceResponse,
            Error = actix_web::Error,
        >,
        Arc<MockSmtpProvider>,
        ActixPassport,
    ) {
        let mock_smtp = Arc::new(MockSmtpProvider::new());

        let email_config = EmailConfig::builder()
            .smtp_host("localhost")
            .smtp_port(587)
            .username("test@example.com")
            .password("password")
            .from_email("test@example.com")
            .from_name("Test App")
            .base_url("https://example.com")
            .build()
            .unwrap();

        let email_service = EmailService::with_smtp_provider_and_service_config(
            mock_smtp.clone(),
            email_config,
            service_config,
            "Test App",
            "test-secret-key-for-tokens",
        )
        .await
        .unwrap();

        let auth_framework = ActixPassportBuilder::with_in_memory_store()
            .enable_password_auth_with_email(email_service)
            .build();

        let app = test::init_service(
            App::new()
                .wrap(
                    SessionMiddleware::builder(CookieSessionStore::default(), Key::from(&[0; 64]))
                        .build(),
                )
                .app_data(web::Data::new(auth_framework.clone()))
                .configure(|cfg| {
                    auth_framework.configure_routes(
                        cfg,
                        actix_passport::RouteConfig::new().with_prefix("/auth".to_string()),
                    );
                }),
        )
        .await;

        (app, mock_smtp, auth_framework)
    }

    /// Helper function to register a test user
    async fn register_test_user(
        app: &impl actix_web::dev::Service<
            actix_http::Request,
            Response = actix_web::dev::ServiceResponse,
            Error = actix_web::Error,
        >,
    ) -> serde_json::Value {
        let registration_data = json!({
            "email": "testuser@example.com",
            "username": "testuser",
            "password": "password123",
            "display_name": "Test User"
        });

        let req = TestRequest::post()
            .uri("/auth/register")
            .set_json(&registration_data)
            .to_request();

        let resp = test::call_service(app, req).await;
        assert_eq!(resp.status(), 200);

        let body = test::read_body(resp).await;
        let body_str = String::from_utf8(body.to_vec()).unwrap();
        serde_json::from_str(&body_str).unwrap()
    }

    #[actix_web::test]
    async fn test_automatic_email_verification_during_registration() {
        let (app, mock_smtp, _framework) =
            create_test_app_with_email(EmailServiceConfig::all_enabled()).await;

        // Register a user - this should automatically send verification email
        let user = register_test_user(&app).await;

        // Verify that an email was automatically sent during registration
        assert_eq!(mock_smtp.count_sent_emails(), 1);

        let sent_emails = mock_smtp.get_sent_emails();
        let sent_email = &sent_emails[0];

        assert_eq!(sent_email.to_email, "testuser@example.com");
        assert_eq!(sent_email.to_name, Some("Test User".to_string()));
        assert!(sent_email.subject.contains("Verify your email"));
        assert!(sent_email.html_body.contains("Test User"));

        // Verify the response indicates email was sent
        assert_eq!(user["email_verification_sent"], true);
    }

    #[actix_web::test]
    async fn test_no_automatic_email_verification_when_disabled() {
        let (app, mock_smtp, _framework) =
            create_test_app_with_email(EmailServiceConfig::password_reset_only()).await;

        // Register a user - this should NOT send verification email
        let user = register_test_user(&app).await;

        // Verify that no email was sent during registration
        assert_eq!(mock_smtp.count_sent_emails(), 0);

        // Since email verification is disabled, the field should not be present or be false
        // The response might not include this field when email verification is disabled
        if let Some(email_sent) = user.get("email_verification_sent") {
            assert_eq!(email_sent, false);
        }
    }

    #[actix_web::test]
    async fn test_email_verification_flow() {
        let (app, mock_smtp, _framework) =
            create_test_app_with_email(EmailServiceConfig::all_enabled()).await;

        // Register a user - this will automatically send verification email
        let _user = register_test_user(&app).await;

        // Verify that an email was automatically sent during registration
        assert_eq!(mock_smtp.count_sent_emails(), 1);

        // Extract the verification token from the sent email
        // In a real application, this would be extracted from the email content
        // For testing, we can use the email service directly to get the token
        let sent_emails = mock_smtp.get_sent_emails();
        let sent_email = &sent_emails[0];

        // Verify the email content
        assert!(sent_email.html_body.contains("https://example.com"));
        assert!(sent_email.subject.contains("Verify your email"));
    }

    #[actix_web::test]
    async fn test_email_service_configuration() {
        // Test with all features enabled
        let email_config = EmailConfig::builder()
            .smtp_host("localhost")
            .smtp_port(587)
            .username("test@example.com")
            .password("password")
            .from_email("test@example.com")
            .from_name("Test App")
            .base_url("https://example.com")
            .build()
            .unwrap();

        let service_config = EmailServiceConfig::all_enabled();
        let email_service = EmailService::with_service_config(
            email_config.clone(),
            service_config,
            "Test App",
            "secret",
        )
        .await
        .unwrap();

        assert!(email_service.is_email_verification_enabled());
        assert!(email_service.is_password_reset_enabled());

        // Test with only email verification enabled
        let service_config = EmailServiceConfig::verification_only();
        let email_service = EmailService::with_service_config(
            email_config.clone(),
            service_config,
            "Test App",
            "secret",
        )
        .await
        .unwrap();

        assert!(email_service.is_email_verification_enabled());
        assert!(!email_service.is_password_reset_enabled());

        // Test with only password reset enabled
        let service_config = EmailServiceConfig::password_reset_only();
        let email_service =
            EmailService::with_service_config(email_config, service_config, "Test App", "secret")
                .await
                .unwrap();

        assert!(!email_service.is_email_verification_enabled());
        assert!(email_service.is_password_reset_enabled());
    }

    #[actix_web::test]
    async fn test_email_verification_disabled() {
        let (app, _mock_smtp, _framework) =
            create_test_app_with_email(EmailServiceConfig::password_reset_only()).await;

        // Register a user
        register_test_user(&app).await;

        // Try to verify email when verification is disabled
        let verification_request = json!({
            "token": "fake-token"
        });

        let req = TestRequest::post()
            .uri("/auth/verify-email")
            .set_json(&verification_request)
            .to_request();

        let resp = test::call_service(&app, req).await;

        // Should return 404 because the route shouldn't be registered
        assert_eq!(resp.status(), 404);
    }

    #[actix_web::test]
    async fn test_password_reset_disabled() {
        let (app, _mock_smtp, _framework) =
            create_test_app_with_email(EmailServiceConfig::verification_only()).await;

        // Register a user
        register_test_user(&app).await;

        // Try to request password reset when it's disabled
        let reset_request = json!({
            "email": "testuser@example.com"
        });

        let req = TestRequest::post()
            .uri("/auth/forgot-password")
            .set_json(&reset_request)
            .to_request();

        let resp = test::call_service(&app, req).await;

        // Should return 404 because the route shouldn't be registered
        assert_eq!(resp.status(), 404);
    }

    #[actix_web::test]
    async fn test_email_service_send_verification_with_mock() {
        let mock_smtp = Arc::new(MockSmtpProvider::new());

        let email_config = EmailConfig::builder()
            .smtp_host("localhost")
            .smtp_port(587)
            .username("test@example.com")
            .password("password")
            .from_email("test@example.com")
            .from_name("Test App")
            .base_url("https://example.com")
            .build()
            .unwrap();

        let email_service = EmailService::with_smtp_provider_and_service_config(
            mock_smtp.clone(),
            email_config,
            EmailServiceConfig::all_enabled(),
            "Test App",
            "test-secret-key",
        )
        .await
        .unwrap();

        let user = AuthUser::new("test-user-id")
            .with_email("user@example.com")
            .with_display_name("Test User");

        // Send verification email
        let token = email_service
            .send_verification_email(&user, None)
            .await
            .unwrap();

        // Verify email was sent
        assert_eq!(mock_smtp.count_sent_emails(), 1);

        let sent_emails = mock_smtp.get_sent_emails();
        let sent_email = &sent_emails[0];

        assert_eq!(sent_email.to_email, "user@example.com");
        assert_eq!(sent_email.to_name, Some("Test User".to_string()));
        assert!(sent_email.subject.contains("Verify your email"));
        assert!(sent_email.html_body.contains("Test User"));
        assert!(sent_email.html_body.contains("https://example.com"));

        // Verify token can be verified
        let (user_id, email) = email_service.verify_email_token(&token).unwrap();
        assert_eq!(user_id, "test-user-id");
        assert_eq!(email, "user@example.com");
    }

    #[actix_web::test]
    async fn test_email_service_send_verification_disabled() {
        let mock_smtp = Arc::new(MockSmtpProvider::new());

        let email_config = EmailConfig::builder()
            .smtp_host("localhost")
            .smtp_port(587)
            .username("test@example.com")
            .password("password")
            .from_email("test@example.com")
            .from_name("Test App")
            .base_url("https://example.com")
            .build()
            .unwrap();

        let email_service = EmailService::with_smtp_provider_and_service_config(
            mock_smtp.clone(),
            email_config,
            EmailServiceConfig::password_reset_only(), // Verification disabled
            "Test App",
            "test-secret-key",
        )
        .await
        .unwrap();

        let user = AuthUser::new("test-user-id")
            .with_email("user@example.com")
            .with_display_name("Test User");

        // Try to send verification email when disabled
        let result = email_service.send_verification_email(&user, None).await;

        // Should fail with configuration error
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Email verification is not enabled"));

        // No emails should be sent
        assert_eq!(mock_smtp.count_sent_emails(), 0);
    }

    #[actix_web::test]
    async fn test_email_service_send_password_reset_with_mock() {
        let mock_smtp = Arc::new(MockSmtpProvider::new());

        let email_config = EmailConfig::builder()
            .smtp_host("localhost")
            .smtp_port(587)
            .username("test@example.com")
            .password("password")
            .from_email("test@example.com")
            .from_name("Test App")
            .base_url("https://example.com")
            .build()
            .unwrap();

        let email_service = EmailService::with_smtp_provider_and_service_config(
            mock_smtp.clone(),
            email_config,
            EmailServiceConfig::all_enabled(),
            "Test App",
            "test-secret-key",
        )
        .await
        .unwrap();

        let user = AuthUser::new("test-user-id")
            .with_email("user@example.com")
            .with_display_name("Test User");

        // Send password reset email
        let token = email_service
            .send_password_reset_email(&user, None)
            .await
            .unwrap();

        // Verify email was sent
        assert_eq!(mock_smtp.count_sent_emails(), 1);

        let sent_emails = mock_smtp.get_sent_emails();
        let sent_email = &sent_emails[0];

        assert_eq!(sent_email.to_email, "user@example.com");
        assert_eq!(sent_email.to_name, Some("Test User".to_string()));
        assert!(sent_email.subject.contains("Reset your password"));
        assert!(sent_email.html_body.contains("Test User"));
        assert!(sent_email.html_body.contains("https://example.com"));

        // Verify token can be verified
        let (user_id, email) = email_service.verify_password_reset_token(&token).unwrap();
        assert_eq!(user_id, "test-user-id");
        assert_eq!(email, "user@example.com");
    }

    #[actix_web::test]
    async fn test_email_service_send_password_reset_disabled() {
        let mock_smtp = Arc::new(MockSmtpProvider::new());

        let email_config = EmailConfig::builder()
            .smtp_host("localhost")
            .smtp_port(587)
            .username("test@example.com")
            .password("password")
            .from_email("test@example.com")
            .from_name("Test App")
            .base_url("https://example.com")
            .build()
            .unwrap();

        let email_service = EmailService::with_smtp_provider_and_service_config(
            mock_smtp.clone(),
            email_config,
            EmailServiceConfig::verification_only(), // Password reset disabled
            "Test App",
            "test-secret-key",
        )
        .await
        .unwrap();

        let user = AuthUser::new("test-user-id")
            .with_email("user@example.com")
            .with_display_name("Test User");

        // Try to send password reset email when disabled
        let result = email_service.send_password_reset_email(&user, None).await;

        // Should fail with configuration error
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Password reset is not enabled"));

        // No emails should be sent
        assert_eq!(mock_smtp.count_sent_emails(), 0);
    }

    #[actix_web::test]
    async fn test_token_verification_with_disabled_features() {
        let mock_smtp = Arc::new(MockSmtpProvider::new());

        let email_config = EmailConfig::builder()
            .smtp_host("localhost")
            .smtp_port(587)
            .username("test@example.com")
            .password("password")
            .from_email("test@example.com")
            .from_name("Test App")
            .base_url("https://example.com")
            .build()
            .unwrap();

        // Create service with all features enabled to generate tokens
        let email_service_full = EmailService::with_smtp_provider_and_service_config(
            mock_smtp.clone(),
            email_config.clone(),
            EmailServiceConfig::all_enabled(),
            "Test App",
            "test-secret-key",
        )
        .await
        .unwrap();

        let user = AuthUser::new("test-user-id").with_email("user@example.com");

        // Generate tokens with full service
        let verification_token = email_service_full
            .send_verification_email(&user, None)
            .await
            .unwrap();
        let reset_token = email_service_full
            .send_password_reset_email(&user, None)
            .await
            .unwrap();

        // Create service with verification disabled
        let email_service_no_verification = EmailService::with_smtp_provider_and_service_config(
            mock_smtp.clone(),
            email_config.clone(),
            EmailServiceConfig::password_reset_only(),
            "Test App",
            "test-secret-key",
        )
        .await
        .unwrap();

        // Try to verify email token when verification is disabled
        let result = email_service_no_verification.verify_email_token(&verification_token);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Email verification is not enabled"));

        // But password reset should still work
        let result = email_service_no_verification.verify_password_reset_token(&reset_token);
        assert!(result.is_ok());

        // Create service with password reset disabled
        let email_service_no_reset = EmailService::with_smtp_provider_and_service_config(
            mock_smtp,
            email_config,
            EmailServiceConfig::verification_only(),
            "Test App",
            "test-secret-key",
        )
        .await
        .unwrap();

        // Try to verify reset token when password reset is disabled
        let result = email_service_no_reset.verify_password_reset_token(&reset_token);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Password reset is not enabled"));

        // But email verification should still work
        let result = email_service_no_reset.verify_email_token(&verification_token);
        assert!(result.is_ok());
    }

    #[actix_web::test]
    async fn test_builder_convenience_methods() {
        let email_config = EmailConfig::builder()
            .smtp_host("localhost")
            .smtp_port(587)
            .username("test@example.com")
            .password("password")
            .from_email("test@example.com")
            .from_name("Test App")
            .base_url("https://example.com")
            .build()
            .unwrap();

        let verification_only_email_service = EmailService::with_service_config(
            email_config.clone(),
            EmailServiceConfig::verification_only(),
            "Test App",
            "secret",
        )
        .await
        .unwrap();

        let password_reset_only_email_service = EmailService::with_service_config(
            email_config.clone(),
            EmailServiceConfig::password_reset_only(),
            "Test App",
            "secret",
        )
        .await
        .unwrap();

        // Test verification only builder
        let _framework = ActixPassportBuilder::with_in_memory_store()
            .enable_password_auth_with_email(verification_only_email_service)
            .build();

        // Test password reset only builder
        let _framework = ActixPassportBuilder::with_in_memory_store()
            .enable_password_auth_with_email(password_reset_only_email_service)
            .build();

        // Test custom config builder
        let email_service = EmailService::with_service_config(
            email_config,
            EmailServiceConfig::all_enabled(),
            "Test App",
            "secret",
        )
        .await
        .unwrap();

        let framework = ActixPassportBuilder::with_in_memory_store()
            .enable_password_auth_with_email(email_service)
            .build();

        // All should build successfully
        assert_eq!(framework.strategies.len(), 1);
    }

    #[actix_web::test]
    async fn test_smtp_failure_handling() {
        let mock_smtp = Arc::new(MockSmtpProvider::new());
        mock_smtp.set_should_fail(true); // Make SMTP fail

        let email_config = EmailConfig::builder()
            .smtp_host("localhost")
            .smtp_port(587)
            .username("test@example.com")
            .password("password")
            .from_email("test@example.com")
            .from_name("Test App")
            .base_url("https://example.com")
            .build()
            .unwrap();

        let email_service = EmailService::with_smtp_provider_and_service_config(
            mock_smtp.clone(),
            email_config,
            EmailServiceConfig::all_enabled(),
            "Test App",
            "test-secret-key",
        )
        .await
        .unwrap();

        let user = AuthUser::new("test-user-id").with_email("user@example.com");

        // Try to send verification email with failing SMTP
        let result = email_service.send_verification_email(&user, None).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Mock SMTP failure"));

        // Try to send password reset email with failing SMTP
        let result = email_service.send_password_reset_email(&user, None).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Mock SMTP failure"));

        // No emails should be recorded
        assert_eq!(mock_smtp.count_sent_emails(), 0);
    }

    #[actix_web::test]
    async fn test_complete_email_verification_flow() {
        let (app, mock_smtp, framework) =
            create_test_app_with_email(EmailServiceConfig::all_enabled()).await;

        // Step 1: Register a user - this automatically sends verification email
        let user = register_test_user(&app).await;
        assert_eq!(mock_smtp.count_sent_emails(), 1);
        assert_eq!(user["email_verification_sent"], true);

        // Get the user from the framework to check initial verification status
        let stored_user = framework
            .user_store
            .find_by_email("testuser@example.com")
            .await
            .unwrap()
            .unwrap();
        assert!(!stored_user.is_email_verified());

        // Step 2: Extract token from email service (simulate what would be in the email)
        // We need to create the email service with the same configuration to generate a token
        let mock_smtp_for_service = Arc::new(MockSmtpProvider::new());
        let email_config = EmailConfig::builder()
            .smtp_host("localhost")
            .smtp_port(587)
            .username("test@example.com")
            .password("password")
            .from_email("test@example.com")
            .from_name("Test App")
            .base_url("https://example.com")
            .build()
            .unwrap();

        let email_service = EmailService::with_smtp_provider_and_service_config(
            mock_smtp_for_service,
            email_config,
            EmailServiceConfig::all_enabled(),
            "Test App",
            "test-secret-key-for-tokens",
        )
        .await
        .unwrap();

        // Generate a verification token for the user
        let auth_user = AuthUser::new(user["id"].as_str().unwrap())
            .with_email("testuser@example.com")
            .with_display_name("Test User");

        let verification_token = email_service
            .send_verification_email(&auth_user, None)
            .await
            .unwrap();

        // Step 3: Call the verify-email route with the token
        let verify_request = json!({
            "token": verification_token
        });

        let req = TestRequest::post()
            .uri("/auth/verify-email")
            .set_json(&verify_request)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);

        // Step 4: Verify that the user's email is now verified in the database
        let verified_user = framework
            .user_store
            .find_by_email("testuser@example.com")
            .await
            .unwrap()
            .unwrap();
        assert!(verified_user.is_email_verified());
    }

    #[actix_web::test]
    async fn test_complete_password_reset_flow() {
        let (app, mock_smtp, framework) =
            create_test_app_with_email(EmailServiceConfig::all_enabled()).await;

        // Step 1: Register a user
        let user = register_test_user(&app).await;
        mock_smtp.clear_sent_emails(); // Clear registration email

        let user_id = user["id"].as_str().unwrap();
        let original_user = framework
            .user_store
            .find_by_id(user_id)
            .await
            .unwrap()
            .unwrap();
        let original_password_hash = original_user
            .metadata
            .get("password_hash")
            .unwrap()
            .as_str()
            .unwrap();

        // Step 2: Request password reset
        let forgot_request = json!({
            "email": "testuser@example.com"
        });

        let req = TestRequest::post()
            .uri("/auth/forgot-password")
            .set_json(&forgot_request)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);

        // Verify password reset email was sent
        assert_eq!(mock_smtp.count_sent_emails(), 1);
        let sent_emails = mock_smtp.get_sent_emails();
        let sent_email = &sent_emails[0];
        assert!(sent_email.subject.contains("Reset your password"));

        // Step 3: Generate a password reset token (simulate what would be in the email)
        let mock_smtp_for_service = Arc::new(MockSmtpProvider::new());
        let email_config = EmailConfig::builder()
            .smtp_host("localhost")
            .smtp_port(587)
            .username("test@example.com")
            .password("password")
            .from_email("test@example.com")
            .from_name("Test App")
            .base_url("https://example.com")
            .build()
            .unwrap();

        let email_service = EmailService::with_smtp_provider_and_service_config(
            mock_smtp_for_service,
            email_config,
            EmailServiceConfig::all_enabled(),
            "Test App",
            "test-secret-key-for-tokens",
        )
        .await
        .unwrap();

        let auth_user = AuthUser::new(user_id)
            .with_email("testuser@example.com")
            .with_display_name("Test User");

        let reset_token = email_service
            .send_password_reset_email(&auth_user, None)
            .await
            .unwrap();

        // Step 4: Reset password using the token
        let reset_request = json!({
            "token": reset_token,
            "new_password": "newpassword456"
        });

        let req = TestRequest::post()
            .uri("/auth/reset-password")
            .set_json(&reset_request)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);

        // Step 5: Verify password was actually changed in the database
        let updated_user = framework
            .user_store
            .find_by_id(user_id)
            .await
            .unwrap()
            .unwrap();
        let new_password_hash = updated_user
            .metadata
            .get("password_hash")
            .unwrap()
            .as_str()
            .unwrap();

        // Password hash should be different
        assert_ne!(original_password_hash, new_password_hash);

        // Step 6: Verify old password no longer works for login
        let old_login_request = json!({
            "email": "testuser@example.com",
            "password": "password123"
        });

        let req = TestRequest::post()
            .uri("/auth/login")
            .set_json(&old_login_request)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 401); // Should fail with old password

        // Step 7: Verify new password works for login
        let new_login_request = json!({
            "email": "testuser@example.com",
            "password": "newpassword456"
        });

        let req = TestRequest::post()
            .uri("/auth/login")
            .set_json(&new_login_request)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200); // Should succeed with new password
    }

    #[actix_web::test]
    async fn test_invalid_verification_token() {
        let (app, _mock_smtp, _framework) =
            create_test_app_with_email(EmailServiceConfig::all_enabled()).await;

        // Register a user
        register_test_user(&app).await;

        // Try to verify with invalid token
        let verify_request = json!({
            "token": "invalid-token-string"
        });

        let req = TestRequest::post()
            .uri("/auth/verify-email")
            .set_json(&verify_request)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400); // Should fail with bad request
    }

    #[actix_web::test]
    async fn test_invalid_password_reset_token() {
        let (app, _mock_smtp, _framework) =
            create_test_app_with_email(EmailServiceConfig::all_enabled()).await;

        // Register a user
        register_test_user(&app).await;

        // Try to reset password with invalid token
        let reset_request = json!({
            "token": "invalid-token-string",
            "new_password": "newpassword123"
        });

        let req = TestRequest::post()
            .uri("/auth/reset-password")
            .set_json(&reset_request)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400); // Should fail with bad request
    }

    #[actix_web::test]
    async fn test_wrong_token_type_verification() {
        let (app, _mock_smtp, _framework) =
            create_test_app_with_email(EmailServiceConfig::all_enabled()).await;

        // Register a user
        let user = register_test_user(&app).await;

        // Generate a password reset token
        let mock_smtp_for_service = Arc::new(MockSmtpProvider::new());
        let email_config = EmailConfig::builder()
            .smtp_host("localhost")
            .smtp_port(587)
            .username("test@example.com")
            .password("password")
            .from_email("test@example.com")
            .from_name("Test App")
            .base_url("https://example.com")
            .build()
            .unwrap();

        let email_service = EmailService::with_smtp_provider_and_service_config(
            mock_smtp_for_service,
            email_config,
            EmailServiceConfig::all_enabled(),
            "Test App",
            "test-secret-key-for-tokens",
        )
        .await
        .unwrap();

        let auth_user = AuthUser::new(user["id"].as_str().unwrap())
            .with_email("testuser@example.com")
            .with_display_name("Test User");

        // Generate a PASSWORD RESET token
        let reset_token = email_service
            .send_password_reset_email(&auth_user, None)
            .await
            .unwrap();

        // Try to use the password reset token for EMAIL VERIFICATION (wrong type)
        let verify_request = json!({
            "token": reset_token
        });

        let req = TestRequest::post()
            .uri("/auth/verify-email")
            .set_json(&verify_request)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400); // Should fail because token type is wrong
    }

    #[actix_web::test]
    async fn test_wrong_token_type_password_reset() {
        let (app, _mock_smtp, _framework) =
            create_test_app_with_email(EmailServiceConfig::all_enabled()).await;

        // Register a user
        let user = register_test_user(&app).await;

        // Generate an email verification token
        let mock_smtp_for_service = Arc::new(MockSmtpProvider::new());
        let email_config = EmailConfig::builder()
            .smtp_host("localhost")
            .smtp_port(587)
            .username("test@example.com")
            .password("password")
            .from_email("test@example.com")
            .from_name("Test App")
            .base_url("https://example.com")
            .build()
            .unwrap();

        let email_service = EmailService::with_smtp_provider_and_service_config(
            mock_smtp_for_service,
            email_config,
            EmailServiceConfig::all_enabled(),
            "Test App",
            "test-secret-key-for-tokens",
        )
        .await
        .unwrap();

        let auth_user = AuthUser::new(user["id"].as_str().unwrap())
            .with_email("testuser@example.com")
            .with_display_name("Test User");

        // Generate an EMAIL VERIFICATION token
        let verification_token = email_service
            .send_verification_email(&auth_user, None)
            .await
            .unwrap();

        // Try to use the email verification token for PASSWORD RESET (wrong type)
        let reset_request = json!({
            "token": verification_token,
            "new_password": "newpassword123"
        });

        let req = TestRequest::post()
            .uri("/auth/reset-password")
            .set_json(&reset_request)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 400); // Should fail because token type is wrong
    }

    #[actix_web::test]
    async fn test_forgot_password_nonexistent_email() {
        let (app, mock_smtp, _framework) =
            create_test_app_with_email(EmailServiceConfig::all_enabled()).await;

        // Try to request password reset for non-existent email
        let forgot_request = json!({
            "email": "nonexistent@example.com"
        });

        let req = TestRequest::post()
            .uri("/auth/forgot-password")
            .set_json(&forgot_request)
            .to_request();

        let resp = test::call_service(&app, req).await;

        // Should return 200 (don't reveal if email exists) but no email should be sent
        assert_eq!(resp.status(), 200);
        assert_eq!(mock_smtp.count_sent_emails(), 0);

        let body = test::read_body(resp).await;
        let body_str = String::from_utf8(body.to_vec()).unwrap();
        let response: serde_json::Value = serde_json::from_str(&body_str).unwrap();

        // Should contain generic message that doesn't reveal if email exists
        assert!(response["message"]
            .as_str()
            .unwrap()
            .contains("If the email address exists"));
    }
}
