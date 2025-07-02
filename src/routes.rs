//! Authentication routes for common authentication endpoints.
//!
//! This module provides pre-built route handlers for common authentication
//! operations like login, registration, logout, and OAuth callbacks.

use crate::{
    core::{AuthError, AuthResult, AuthUser, SessionStore, UserStore},
    middleware::{session_utils, AuthenticatedUser, OptionalAuthenticatedUser},
};
use actix_session::Session;
use actix_web::{web, HttpRequest, HttpResponse, Responder, Result};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[cfg(feature = "password")]
use crate::password::{LoginCredentials, PasswordAuthService, RegisterCredentials};

#[cfg(feature = "oauth")]
use crate::oauth::OAuthService;

/// Response for successful authentication.
///
/// This struct represents the response sent to the client after
/// successful authentication operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    /// The authenticated user
    pub user: AuthUser,
    /// Optional message
    pub message: Option<String>,
}

/// Response for authentication errors.
///
/// This struct represents error responses sent to the client
/// when authentication operations fail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthErrorResponse {
    /// Error message
    pub error: String,
    /// Optional error details
    pub details: Option<String>,
}

impl From<AuthError> for AuthErrorResponse {
    fn from(error: AuthError) -> Self {
        Self {
            error: error.to_string(),
            details: None,
        }
    }
}

/// Configuration for authentication routes.
///
/// This struct contains configuration options for the authentication
/// route handlers, such as redirect URLs and success/error messages.
#[derive(Debug, Clone)]
pub struct RouteConfig {
    /// URL to redirect to after successful login
    pub login_success_redirect: Option<String>,
    /// URL to redirect to after logout
    pub logout_redirect: Option<String>,
    /// Base URL for OAuth callbacks
    pub oauth_callback_base: String,
}

impl Default for RouteConfig {
    fn default() -> Self {
        Self {
            login_success_redirect: Some("/dashboard".to_string()),
            logout_redirect: Some("/".to_string()),
            oauth_callback_base: "http://localhost:8080/auth".to_string(),
        }
    }
}

/// Authentication route handlers.
///
/// This struct contains all the route handlers for authentication operations.
/// It can be used to easily add authentication routes to an actix-web application.
///
/// # Examples
///
/// ```rust
/// use actix_web::{web, App};
/// use actix_passport::AuthRoutes;
///
/// let auth_routes = AuthRoutes::new(
///     user_store,
///     session_store,
///     password_service,
///     oauth_service,
/// );
///
/// let app = App::new()
///     .service(
///         web::scope("/auth")
///             .configure(|cfg| auth_routes.configure(cfg))
///     );
/// ```
pub struct AuthRoutes<U, S>
where
    U: UserStore + 'static,
    S: SessionStore + 'static,
{
    user_store: Arc<U>,
    session_store: Arc<S>,
    config: RouteConfig,
    
    #[cfg(feature = "password")]
    password_service: Option<Arc<dyn PasswordAuthService<U> + Send + Sync>>,
    
    #[cfg(feature = "oauth")]
    oauth_service: Option<Arc<OAuthService>>,
}

impl<U, S> AuthRoutes<U, S>
where
    U: UserStore + 'static,
    S: SessionStore + 'static,
{
    /// Creates new authentication routes.
    ///
    /// # Arguments
    ///
    /// * `user_store` - The user store implementation
    /// * `session_store` - The session store implementation
    pub fn new(user_store: U, session_store: S) -> Self {
        Self {
            user_store: Arc::new(user_store),
            session_store: Arc::new(session_store),
            config: RouteConfig::default(),
            
            #[cfg(feature = "password")]
            password_service: None,
            
            #[cfg(feature = "oauth")]
            oauth_service: None,
        }
    }

    /// Sets the route configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - The route configuration
    pub fn with_config(mut self, config: RouteConfig) -> Self {
        self.config = config;
        self
    }

    /// Sets the password authentication service.
    ///
    /// # Arguments
    ///
    /// * `service` - The password authentication service
    #[cfg(feature = "password")]
    pub fn with_password_service<P>(mut self, service: P) -> Self
    where
        P: PasswordAuthService<U> + Send + Sync + 'static,
    {
        self.password_service = Some(Arc::new(service));
        self
    }

    /// Sets the OAuth service.
    ///
    /// # Arguments
    ///
    /// * `service` - The OAuth service
    #[cfg(feature = "oauth")]
    pub fn with_oauth_service(mut self, service: OAuthService) -> Self {
        self.oauth_service = Some(Arc::new(service));
        self
    }

    /// Configures the authentication routes.
    ///
    /// This method adds all the authentication routes to the provided
    /// service configuration.
    ///
    /// # Arguments
    ///
    /// * `cfg` - The service configuration to add routes to
    pub fn configure(&self, cfg: &mut web::ServiceConfig) {
        // Current user endpoint
        cfg.route("/me", web::get().to(Self::get_current_user));
        
        // Logout endpoint
        cfg.route("/logout", web::post().to({
            let session_store = self.session_store.clone();
            move |session: Session| Self::logout(session, session_store.clone())
        }));

        // Password authentication routes
        #[cfg(feature = "password")]
        if let Some(ref password_service) = self.password_service {
            let service = password_service.clone();
            let session_store = self.session_store.clone();
            let config = self.config.clone();
            
            cfg.route("/login", web::post().to(move |credentials: web::Json<LoginCredentials>, session: Session| {
                Self::password_login(credentials, session, service.clone(), session_store.clone(), config.clone())
            }));

            let service = password_service.clone();
            let session_store = self.session_store.clone();
            let config = self.config.clone();
            
            cfg.route("/register", web::post().to(move |credentials: web::Json<RegisterCredentials>, session: Session| {
                Self::password_register(credentials, session, service.clone(), session_store.clone(), config.clone())
            }));
        }

        // OAuth routes
        #[cfg(feature = "oauth")]
        if let Some(ref oauth_service) = self.oauth_service {
            let service = oauth_service.clone();
            let config = self.config.clone();
            
            cfg.route("/{provider}", web::get().to(move |path: web::Path<String>| {
                Self::oauth_authorize(path, service.clone(), config.clone())
            }));

            let service = oauth_service.clone();
            let user_store = self.user_store.clone();
            let session_store = self.session_store.clone();
            let config = self.config.clone();
            
            cfg.route("/{provider}/callback", web::get().to(move |path: web::Path<String>, query: web::Query<OAuthCallbackQuery>, session: Session| {
                Self::oauth_callback(path, query, session, service.clone(), user_store.clone(), session_store.clone(), config.clone())
            }));
        }
    }

    /// Returns the current authenticated user.
    ///
    /// This endpoint returns information about the currently authenticated user.
    /// It requires authentication.
    ///
    /// # Route
    ///
    /// `GET /auth/me`
    pub async fn get_current_user(user: AuthenticatedUser) -> Result<impl Responder> {
        Ok(HttpResponse::Ok().json(AuthResponse {
            user: user.0,
            message: None,
        }))
    }

    /// Logs out the current user.
    ///
    /// This endpoint invalidates the current session and logs out the user.
    ///
    /// # Route
    ///
    /// `POST /auth/logout`
    pub async fn logout(
        session: Session,
        session_store: Arc<S>,
    ) -> Result<impl Responder> {
        // Get session ID from session
        if let Ok(Some(session_id_str)) = session.get::<String>("session_id") {
            if let Ok(session_id) = uuid::Uuid::parse_str(&session_id_str) {
                // Delete session from store
                let _ = session_store.delete_session(session_id).await;
            }
        }

        // Clear the actix session
        session_utils::clear_session(&session);

        Ok(HttpResponse::Ok().json(serde_json::json!({
            "message": "Logged out successfully"
        })))
    }

    /// Handles password-based login.
    ///
    /// This endpoint authenticates users with email/username and password.
    ///
    /// # Route
    ///
    /// `POST /auth/login`
    #[cfg(feature = "password")]
    pub async fn password_login(
        credentials: web::Json<LoginCredentials>,
        session: Session,
        password_service: Arc<dyn PasswordAuthService<U> + Send + Sync>,
        session_store: Arc<S>,
        config: RouteConfig,
    ) -> Result<impl Responder> {
        match password_service.login(credentials.into_inner()).await {
            Ok(user) => {
                // Create session
                let user_session = session_utils::create_user_session(
                    &user,
                    chrono::Duration::days(30),
                );

                // Store session
                match session_store.create_session(user_session.clone()).await {
                    Ok(_) => {
                        // Set session ID in actix session
                        if let Err(e) = session_utils::set_session_id(&session, user_session.id) {
                            return Ok(HttpResponse::InternalServerError().json(
                                AuthErrorResponse::from(e)
                            ));
                        }

                        Ok(HttpResponse::Ok().json(AuthResponse {
                            user,
                            message: Some("Login successful".to_string()),
                        }))
                    }
                    Err(e) => Ok(HttpResponse::InternalServerError().json(
                        AuthErrorResponse::from(e)
                    )),
                }
            }
            Err(e) => Ok(HttpResponse::Unauthorized().json(AuthErrorResponse::from(e))),
        }
    }

    /// Handles user registration.
    ///
    /// This endpoint registers new users with email and password.
    ///
    /// # Route
    ///
    /// `POST /auth/register`
    #[cfg(feature = "password")]
    pub async fn password_register(
        credentials: web::Json<RegisterCredentials>,
        session: Session,
        password_service: Arc<dyn PasswordAuthService<U> + Send + Sync>,
        session_store: Arc<S>,
        config: RouteConfig,
    ) -> Result<impl Responder> {
        match password_service.register(credentials.into_inner()).await {
            Ok(user) => {
                // Create session
                let user_session = session_utils::create_user_session(
                    &user,
                    chrono::Duration::days(30),
                );

                // Store session
                match session_store.create_session(user_session.clone()).await {
                    Ok(_) => {
                        // Set session ID in actix session
                        if let Err(e) = session_utils::set_session_id(&session, user_session.id) {
                            return Ok(HttpResponse::InternalServerError().json(
                                AuthErrorResponse::from(e)
                            ));
                        }

                        Ok(HttpResponse::Created().json(AuthResponse {
                            user,
                            message: Some("Registration successful".to_string()),
                        }))
                    }
                    Err(e) => Ok(HttpResponse::InternalServerError().json(
                        AuthErrorResponse::from(e)
                    )),
                }
            }
            Err(e) => Ok(HttpResponse::BadRequest().json(AuthErrorResponse::from(e))),
        }
    }

    /// Initiates OAuth authorization.
    ///
    /// This endpoint redirects users to the OAuth provider's authorization page.
    ///
    /// # Route
    ///
    /// `GET /auth/{provider}`
    #[cfg(feature = "oauth")]
    pub async fn oauth_authorize(
        path: web::Path<String>,
        oauth_service: Arc<OAuthService>,
        config: RouteConfig,
    ) -> Result<impl Responder> {
        let provider_name = path.into_inner();

        // Generate state for CSRF protection
        let state = base64::encode(rand::random::<[u8; 32]>());

        // Generate redirect URI
        let redirect_uri = format!("{}/{}/callback", config.oauth_callback_base, provider_name);

        match oauth_service.authorize_url(&provider_name, &state, &redirect_uri) {
            Ok(auth_url) => {
                // TODO: Store state in session for verification
                Ok(HttpResponse::Found()
                    .append_header(("Location", auth_url))
                    .finish())
            }
            Err(e) => Ok(HttpResponse::BadRequest().json(AuthErrorResponse::from(e))),
        }
    }

    /// OAuth callback query parameters.
    #[cfg(feature = "oauth")]
    #[derive(Debug, Deserialize)]
    pub struct OAuthCallbackQuery {
        code: Option<String>,
        state: Option<String>,
        error: Option<String>,
        error_description: Option<String>,
    }

    /// Handles OAuth provider callbacks.
    ///
    /// This endpoint handles the callback from OAuth providers after user authorization.
    ///
    /// # Route
    ///
    /// `GET /auth/{provider}/callback`
    #[cfg(feature = "oauth")]
    pub async fn oauth_callback(
        path: web::Path<String>,
        query: web::Query<OAuthCallbackQuery>,
        session: Session,
        oauth_service: Arc<OAuthService>,
        user_store: Arc<U>,
        session_store: Arc<S>,
        config: RouteConfig,
    ) -> Result<impl Responder> {
        let provider_name = path.into_inner();
        let query = query.into_inner();

        // Check for OAuth errors
        if let Some(error) = query.error {
            let description = query.error_description.unwrap_or_default();
            return Ok(HttpResponse::BadRequest().json(AuthErrorResponse {
                error: format!("OAuth error: {}", error),
                details: Some(description),
            }));
        }

        // Get authorization code
        let code = match query.code {
            Some(code) => code,
            None => {
                return Ok(HttpResponse::BadRequest().json(AuthErrorResponse {
                    error: "Missing authorization code".to_string(),
                    details: None,
                }));
            }
        };

        // TODO: Verify state parameter for CSRF protection

        // Generate redirect URI
        let redirect_uri = format!("{}/{}/callback", config.oauth_callback_base, provider_name);

        // Exchange code for user info
        match oauth_service.exchange_code(&provider_name, &code, &redirect_uri).await {
            Ok(oauth_user) => {
                // Find or create user
                let user = match find_or_create_oauth_user(&oauth_user, &*user_store).await {
                    Ok(user) => user,
                    Err(e) => {
                        return Ok(HttpResponse::InternalServerError().json(
                            AuthErrorResponse::from(e)
                        ));
                    }
                };

                // Create session
                let user_session = session_utils::create_user_session(
                    &user,
                    chrono::Duration::days(30),
                );

                // Store session
                match session_store.create_session(user_session.clone()).await {
                    Ok(_) => {
                        // Set session ID in actix session
                        if let Err(e) = session_utils::set_session_id(&session, user_session.id) {
                            return Ok(HttpResponse::InternalServerError().json(
                                AuthErrorResponse::from(e)
                            ));
                        }

                        // Redirect to success URL
                        let redirect_url = config.login_success_redirect.unwrap_or_else(|| "/".to_string());
                        Ok(HttpResponse::Found()
                            .append_header(("Location", redirect_url))
                            .finish())
                    }
                    Err(e) => Ok(HttpResponse::InternalServerError().json(
                        AuthErrorResponse::from(e)
                    )),
                }
            }
            Err(e) => Ok(HttpResponse::BadRequest().json(AuthErrorResponse::from(e))),
        }
    }
}

/// Finds an existing user or creates a new one from OAuth data.
///
/// This function looks for an existing user based on email or creates a new user
/// if one doesn't exist. This is a simple implementation that you might want
/// to customize based on your needs.
#[cfg(feature = "oauth")]
async fn find_or_create_oauth_user<U>(
    oauth_user: &crate::oauth::OAuthUser, 
    user_store: &U
) -> AuthResult<AuthUser>
where
    U: UserStore,
{
    // Try to find existing user by email
    if let Some(ref email) = oauth_user.email {
        if let Some(existing_user) = user_store.find_by_email(email).await? {
            return Ok(existing_user);
        }
    }

    // Create new user
    let mut new_user = AuthUser::new(uuid::Uuid::new_v4().to_string());
    
    if let Some(ref email) = oauth_user.email {
        new_user = new_user.with_email(email);
    }
    
    if let Some(ref username) = oauth_user.username {
        new_user = new_user.with_username(username);
    }
    
    if let Some(ref display_name) = oauth_user.display_name {
        new_user = new_user.with_display_name(display_name);
    }

    // Store OAuth provider info in metadata
    new_user.metadata.insert(
        format!("{}_id", oauth_user.provider),
        serde_json::Value::String(oauth_user.provider_id.clone()),
    );

    if let Some(ref avatar_url) = oauth_user.avatar_url {
        new_user.avatar_url = Some(avatar_url.clone());
    }

    user_store.create_user(new_user).await
}

// Trait for password auth service to make it object-safe
#[cfg(feature = "password")]
trait PasswordAuthService<U: UserStore>: Send + Sync {
    fn login(&self, credentials: LoginCredentials) -> std::pin::Pin<Box<dyn std::future::Future<Output = AuthResult<AuthUser>> + Send + '_>>;
    fn register(&self, credentials: RegisterCredentials) -> std::pin::Pin<Box<dyn std::future::Future<Output = AuthResult<AuthUser>> + Send + '_>>;
}

#[cfg(feature = "password")]
impl<U, H> PasswordAuthService<U> for crate::password::PasswordAuthService<U, H>
where
    U: UserStore,
    H: crate::password::PasswordHasher,
{
    fn login(&self, credentials: LoginCredentials) -> std::pin::Pin<Box<dyn std::future::Future<Output = AuthResult<AuthUser>> + Send + '_>> {
        Box::pin(self.login(credentials))
    }

    fn register(&self, credentials: RegisterCredentials) -> std::pin::Pin<Box<dyn std::future::Future<Output = AuthResult<AuthUser>> + Send + '_>> {
        Box::pin(self.register(credentials))
    }
}