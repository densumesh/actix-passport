use crate::{core::SessionStore, types::AuthUser};
use actix_session::Session;
use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    FromRequest,
};
use futures_util::future::LocalBoxFuture;
use std::{
    future::{ready, Ready},
    rc::Rc,
};
use uuid::Uuid;

/// Authentication middleware factory.
///
/// This middleware handles session-based authentication and injects the
/// authenticated user into the request extensions so it can be extracted
/// in handler functions.
///
/// # Examples
///
/// ```rust
/// use actix_web::App;
/// use actix_passport::AuthMiddleware;
///
/// let app = App::new()
///     .wrap(AuthMiddleware::new(session_store));
/// ```
pub struct AuthMiddleware<S> {
    session_store: Rc<S>,
}

impl<S> AuthMiddleware<S>
where
    S: SessionStore + 'static,
{
    /// Creates a new authentication middleware.
    ///
    /// # Arguments
    ///
    /// * `session_store` - The session store implementation
    pub fn new(session_store: S) -> Self {
        Self {
            session_store: Rc::new(session_store),
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for AuthMiddleware<B>
where
    // `S` must be `'static` so the boxed future lives long enough.
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static,
    S::Future: 'static,
    B: SessionStore + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = actix_web::Error;
    type InitError = ();
    type Transform = AuthMiddlewareService<S, B>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AuthMiddlewareService {
            service: Rc::new(service),
            session_store: self.session_store.clone(),
        }))
    }
}

/// Authentication middleware service.
///
/// This is the actual middleware service that processes requests and
/// handles authentication logic.
pub struct AuthMiddlewareService<S, B> {
    // Hold the inner service behind an `Rc` so it can be cheaply cloned and
    // moved into async blocks without lifetime issues.
    service: Rc<S>,
    session_store: Rc<B>,
}

impl<S, B> Service<ServiceRequest> for AuthMiddlewareService<S, B>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static,
    S::Future: 'static,
    B: SessionStore + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = actix_web::Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let session_store = self.session_store.clone();
        let service = self.service.clone();

        Box::pin(async move {
            // Try to get user from session
            if let Some(user) = get_user_from_session(&req, session_store).await {
                req.extensions_mut().insert(user);
            }

            service.as_ref().call(req).await
        })
    }
}

/// Extracts authenticated user from session.
///
/// This function checks the current session for a valid user ID and
/// loads the corresponding user from the session store.
async fn get_user_from_session<S>(req: &ServiceRequest, session_store: Rc<S>) -> Option<AuthUser>
where
    S: SessionStore,
{
    // Get session from request
    let session = Session::from_request(req.request(), &mut actix_web::dev::Payload::None)
        .await
        .ok()?;

    // Get session ID from session
    let session_id_str = session.get::<String>("session_id").ok()??;
    let session_id = Uuid::parse_str(&session_id_str).ok()?;

    // Find session in store
    let stored_session = session_store.find_session(session_id).await.ok()??;

    // Check if session is expired
    if stored_session.expires_at < chrono::Utc::now() {
        // Session expired, try to clean it up
        let _ = session_store.delete_session(session_id).await;
        return None;
    }

    // Create AuthUser from session data
    // Note: In a real implementation, you might want to fetch the full user
    // from a UserStore instead of reconstructing from session data
    let user = AuthUser {
        id: stored_session.user_id,
        email: stored_session
            .data
            .get("email")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        username: stored_session
            .data
            .get("username")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        display_name: stored_session
            .data
            .get("display_name")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        avatar_url: stored_session
            .data
            .get("avatar_url")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        created_at: stored_session
            .data
            .get("created_at")
            .and_then(|v| v.as_str())
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&chrono::Utc))
            .unwrap_or_else(|| chrono::Utc::now()),
        last_login: stored_session
            .data
            .get("last_login")
            .and_then(|v| v.as_str())
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&chrono::Utc)),
        metadata: stored_session
            .data
            .get("metadata")
            .and_then(|v| v.as_object())
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(|(k, v)| (k, v))
            .collect(),
    };

    Some(user)
}
