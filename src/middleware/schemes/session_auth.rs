use crate::{core::UserStore, types::AuthUser};
use actix_session::Session;
use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    FromRequest, HttpMessage,
};
use futures_util::future::LocalBoxFuture;
use std::{
    future::{ready, Ready},
    sync::Arc,
};

const USER_ID_KEY: &str = "actix_passport_user_id";

/// Authentication middleware factory.
///
/// This middleware handles session-based authentication and injects the
/// authenticated user into the request extensions so it can be extracted
/// in handler functions.
pub struct SessionAuthMiddleware<U> {
    user_store: Arc<U>,
}

impl<U> SessionAuthMiddleware<U>
where
    U: UserStore + 'static,
{
    /// Creates a new authentication middleware.
    pub const fn new(user_store: Arc<U>) -> Self {
        Self { user_store }
    }
}

impl<S, U, B> Transform<S, ServiceRequest> for SessionAuthMiddleware<U>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static,
    S::Future: 'static,
    U: UserStore + 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = actix_web::Error;
    type InitError = ();
    type Transform = AuthMiddlewareService<S, U>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AuthMiddlewareService {
            service: Arc::new(service),
            user_store: self.user_store.clone(),
        }))
    }
}

/// Authentication middleware service.
pub struct AuthMiddlewareService<S, U> {
    service: Arc<S>,
    user_store: Arc<U>,
}

impl<S, U, B> Service<ServiceRequest> for AuthMiddlewareService<S, U>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static,
    S::Future: 'static,
    U: UserStore + 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = actix_web::Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let user_store = self.user_store.clone();
        let service = self.service.clone();

        Box::pin(async move {
            if let Some(user) = get_user_from_session(&req, user_store).await {
                req.extensions_mut().insert(user);
            }

            service.call(req).await
        })
    }
}

/// Extracts authenticated user from session.
#[allow(clippy::future_not_send)]
async fn get_user_from_session<U>(req: &ServiceRequest, user_store: Arc<U>) -> Option<AuthUser>
where
    U: UserStore,
{
    let session = Session::from_request(req.request(), &mut actix_web::dev::Payload::None)
        .await
        .ok()?;

    let user_id = session.get::<String>(USER_ID_KEY).ok()??;

    user_store.find_by_id(&user_id).await.ok()?
}
