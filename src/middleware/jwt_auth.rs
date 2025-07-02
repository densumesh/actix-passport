use crate::types::AuthUser;
use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    HttpMessage,
};
use futures_util::future::LocalBoxFuture;
use std::{
    future::{ready, Ready},
    rc::Rc,
};

/// JWT authentication middleware factory.
///
/// This middleware handles JWT token-based authentication. It looks for
/// JWT tokens in the Authorization header and validates them.
///
/// # Examples
///
/// ```rust
/// use actix_web::App;
/// use actix_passport::JwtAuthMiddleware;
///
/// let app = App::new()
///     .wrap(JwtAuthMiddleware::new("your_jwt_secret".to_string()));
/// ```
#[cfg(feature = "jwt")]
pub struct JwtAuthMiddleware {
    secret: String,
}

#[cfg(feature = "jwt")]
impl JwtAuthMiddleware {
    /// Creates a new JWT authentication middleware.
    ///
    /// # Arguments
    ///
    /// * `secret` - The secret key used to sign and verify JWT tokens
    pub fn new(secret: String) -> Self {
        Self { secret }
    }
}

#[cfg(feature = "jwt")]
impl<S, B> Transform<S, ServiceRequest> for JwtAuthMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static,
    S::Future: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = actix_web::Error;
    type InitError = ();
    type Transform = JwtAuthMiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(JwtAuthMiddlewareService {
            service: Rc::new(service),
            secret: self.secret.clone(),
        }))
    }
}

/// JWT authentication middleware service.
#[cfg(feature = "jwt")]
pub struct JwtAuthMiddlewareService<S> {
    service: Rc<S>,
    secret: String,
}

#[cfg(feature = "jwt")]
impl<S, B> Service<ServiceRequest> for JwtAuthMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static,
    S::Future: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = actix_web::Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let secret = self.secret.clone();
        let service = self.service.clone();

        Box::pin(async move {
            // Try to get user from JWT token
            if let Some(user) = get_user_from_jwt(&req, &secret).await {
                req.extensions_mut().insert(user);
            }

            service.as_ref().call(req).await
        })
    }
}

/// Extracts authenticated user from JWT token.
///
/// This function looks for a JWT token in the Authorization header,
/// validates it, and extracts the user information.
#[cfg(feature = "jwt")]
async fn get_user_from_jwt(req: &ServiceRequest, secret: &str) -> Option<AuthUser> {
    use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize)]
    struct Claims {
        sub: String, // user ID
        email: Option<String>,
        username: Option<String>,
        display_name: Option<String>,
        exp: usize, // expiration timestamp
    }

    // Get Authorization header
    let auth_header = req.headers().get("Authorization")?;
    let auth_str = auth_header.to_str().ok()?;

    // Extract bearer token
    if !auth_str.starts_with("Bearer ") {
        return None;
    }
    let token = &auth_str[7..];

    // Decode and validate JWT
    let decoding_key = DecodingKey::from_secret(secret.as_ref());
    let validation = Validation::new(Algorithm::HS256);

    let token_data = decode::<Claims>(token, &decoding_key, &validation).ok()?;

    let claims = token_data.claims;

    // Create AuthUser from JWT claims
    Some(AuthUser {
        id: claims.sub,
        email: claims.email,
        username: claims.username,
        display_name: claims.display_name,
        avatar_url: None,
        created_at: chrono::Utc::now(), // We don't have this info in JWT
        last_login: Some(chrono::Utc::now()),
        metadata: std::collections::HashMap::new(),
    })
}
