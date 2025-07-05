use crate::stores::sqlite_store::SqliteUserStore;
use crate::token_helpers::{generate_salt, generate_token};
use actix_passport::{strategies::AuthStrategy, types::AuthUser};
use actix_web::{
    web::{self, Data},
    HttpRequest, HttpResponse, Result,
};
use argon2::{Argon2, PasswordHasher};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub struct BearerAuthStrategy {
    user_store: SqliteUserStore,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub email: Option<String>,
    pub username: Option<String>,
    pub password: String,
    pub display_name: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginRequest {
    pub identifier: String, // Can be email or username
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub token: String,
    pub user: AuthUser,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
}

impl BearerAuthStrategy {
    pub fn new(user_store: SqliteUserStore) -> Self {
        Self { user_store }
    }

    async fn register_handler(
        strategy: Data<BearerAuthStrategy>,
        payload: web::Json<RegisterRequest>,
    ) -> Result<HttpResponse> {
        let req = payload.into_inner();

        if req.email.is_none() && req.username.is_none() {
            return Ok(HttpResponse::BadRequest().json(ErrorResponse {
                error: "validation_error".to_string(),
                message: "Either email or username must be provided".to_string(),
            }));
        }

        if req.password.len() < 8 {
            return Ok(HttpResponse::BadRequest().json(ErrorResponse {
                error: "validation_error".to_string(),
                message: "Password must be at least 8 characters long".to_string(),
            }));
        }

        // Hash the password
        let salt = generate_salt();
        let password_hash = match Argon2::default().hash_password(req.password.as_bytes(), &salt) {
            Ok(hash) => hash.to_string(),
            Err(e) => {
                log::error!("Password hashing failed: {e}");
                return Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                    error: "server_error".to_string(),
                    message: "Failed to process registration".to_string(),
                }));
            }
        };

        // Create user
        let mut new_user = AuthUser::new("temp_id");
        if let Some(email) = &req.email {
            new_user = new_user.with_email(email);
        }
        if let Some(username) = &req.username {
            new_user = new_user.with_username(username);
        }
        if let Some(display_name) = &req.display_name {
            new_user = new_user.with_display_name(display_name);
        }

        match strategy
            .user_store
            .create_user_with_password(new_user, &password_hash)
        {
            Ok(user) => {
                // Generate auth token
                match generate_token(&user.id) {
                    Ok(token) => {
                        if let Err(e) = strategy.user_store.store_auth_token(&token, &user.id, None)
                        {
                            log::error!("Failed to store auth token: {e}");
                            return Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                                error: "server_error".to_string(),
                                message: "Registration completed but token generation failed"
                                    .to_string(),
                            }));
                        }

                        Ok(HttpResponse::Created().json(AuthResponse { token, user }))
                    }
                    Err(e) => {
                        log::error!("Token generation failed: {e}");
                        Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                            error: "server_error".to_string(),
                            message: "Registration completed but token generation failed"
                                .to_string(),
                        }))
                    }
                }
            }
            Err(e) => {
                log::error!("User creation failed: {e}");
                match e {
                    actix_passport::errors::AuthError::RegistrationFailed { reason, .. } => {
                        Ok(HttpResponse::Conflict().json(ErrorResponse {
                            error: "user_exists".to_string(),
                            message: reason,
                        }))
                    }
                    _ => Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                        error: "server_error".to_string(),
                        message: "Registration failed".to_string(),
                    })),
                }
            }
        }
    }

    async fn login_handler(
        strategy: Data<BearerAuthStrategy>,
        payload: web::Json<LoginRequest>,
    ) -> Result<HttpResponse> {
        let req = payload.into_inner();

        match strategy
            .user_store
            .verify_password(&req.identifier, &req.password)
        {
            Ok(Some(user)) => {
                // Generate auth token
                match generate_token(&user.id) {
                    Ok(token) => {
                        if let Err(e) = strategy.user_store.store_auth_token(&token, &user.id, None)
                        {
                            log::error!("Failed to store auth token: {e}");
                            return Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                                error: "server_error".to_string(),
                                message: "Login successful but token generation failed".to_string(),
                            }));
                        }

                        Ok(HttpResponse::Ok().json(AuthResponse { token, user }))
                    }
                    Err(e) => {
                        log::error!("Token generation failed: {e}");
                        Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                            error: "server_error".to_string(),
                            message: "Login successful but token generation failed".to_string(),
                        }))
                    }
                }
            }
            Ok(None) => Ok(HttpResponse::Unauthorized().json(ErrorResponse {
                error: "invalid_credentials".to_string(),
                message: "Invalid username/email or password".to_string(),
            })),
            Err(e) => {
                log::error!("Login verification failed: {e}");
                Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                    error: "server_error".to_string(),
                    message: "Login failed".to_string(),
                }))
            }
        }
    }

    async fn logout_handler(
        strategy: Data<BearerAuthStrategy>,
        req: HttpRequest,
    ) -> Result<HttpResponse> {
        if let Some(token) = extract_bearer_token(&req) {
            if let Err(e) = strategy.user_store.revoke_token(&token) {
                log::error!("Failed to revoke token: {e}");
            }
        }

        Ok(HttpResponse::Ok().json(serde_json::json!({
            "message": "Logged out successfully"
        })))
    }

    async fn profile_handler(
        strategy: Data<BearerAuthStrategy>,
        req: HttpRequest,
    ) -> Result<HttpResponse> {
        if let Some(token) = extract_bearer_token(&req) {
            match strategy.user_store.find_user_by_token(&token) {
                Ok(Some(user)) => {
                    return Ok(HttpResponse::Ok().json(user));
                }
                Ok(None) => {
                    return Ok(HttpResponse::Unauthorized().json(ErrorResponse {
                        error: "invalid_token".to_string(),
                        message: "Invalid or expired token".to_string(),
                    }));
                }
                Err(e) => {
                    log::error!("Token verification failed: {e}");
                    return Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                        error: "server_error".to_string(),
                        message: "Profile lookup failed".to_string(),
                    }));
                }
            }
        }

        Ok(HttpResponse::Unauthorized().json(ErrorResponse {
            error: "missing_token".to_string(),
            message: "Authorization header with Bearer token required".to_string(),
        }))
    }
}

fn extract_bearer_token(req: &HttpRequest) -> Option<String> {
    req.headers()
        .get("Authorization")
        .and_then(|header| header.to_str().ok())
        .and_then(|auth_header| {
            auth_header
                .strip_prefix("Bearer ")
                .map(|token| token.to_string())
        })
}

#[async_trait(?Send)]
impl AuthStrategy for BearerAuthStrategy {
    fn name(&self) -> &'static str {
        "bearer"
    }

    fn configure(&self, scope: actix_web::Scope) -> actix_web::Scope {
        scope
            .app_data(Data::new(self.clone()))
            .service(web::resource("/register").route(web::post().to(Self::register_handler)))
            .service(web::resource("/login").route(web::post().to(Self::login_handler)))
            .service(web::resource("/logout").route(web::post().to(Self::logout_handler)))
            .service(web::resource("/profile").route(web::get().to(Self::profile_handler)))
    }

    async fn authenticate(&self, req: &HttpRequest) -> Option<AuthUser> {
        let token = extract_bearer_token(req)?;

        match self.user_store.find_user_by_token(&token) {
            Ok(user) => user,
            Err(e) => {
                log::debug!("Bearer authentication failed: {e}");
                None
            }
        }
    }
}
