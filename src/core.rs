use std::ops::Deref;

use actix_web::{
    error::{ErrorBadRequest, ErrorUnauthorized},
    web, FromRequest, HttpMessage, HttpRequest,
};
use futures_util::{
    future::{ready, LocalBoxFuture, Ready},
    FutureExt,
};

use crate::{AuthStrategy, AuthUser, UserStore};

/// The main authentication framework object.
///
/// This struct is created by the `ActixPassportBuilder` and holds all the
/// configured services and stores. It is intended to be cloned and stored
/// in the actix-web application data.
///
/// # Type Parameters
///
/// * `U` - The user store implementation that handles user persistence
///
/// # Examples
///
/// ```rust,no_run
/// use actix_passport::{ActixPassportBuilder, user_store::UserStore, prelude::PasswordStrategy};
/// # use actix_passport::types::{AuthResult, AuthUser};
/// # use async_trait::async_trait;
/// # #[derive(Clone)] struct MyUserStore;
/// # #[async_trait]
/// # impl UserStore for MyUserStore {
/// #   async fn find_by_id(&self, id: &str) -> AuthResult<Option<AuthUser>> { Ok(None) }
/// #   async fn find_by_email(&self, email: &str) -> AuthResult<Option<AuthUser>> { Ok(None) }
/// #   async fn find_by_username(&self, username: &str) -> AuthResult<Option<AuthUser>> { Ok(None) }
/// #   async fn create_user(&self, user: AuthUser) -> AuthResult<AuthUser> { Ok(user) }
/// #   async fn update_user(&self, user: AuthUser) -> AuthResult<AuthUser> { Ok(user) }
/// #   async fn delete_user(&self, id: &str) -> AuthResult<()> { Ok(()) }
/// # }
///
/// let password_strategy = PasswordStrategy::new();
/// let auth_framework = ActixPassportBuilder::new(MyUserStore)
///     .add_strategy(password_strategy)
///     .build();
/// ```
#[derive(Clone)]
pub struct ActixPassport {
    /// The user store implementation for persisting user data
    pub user_store: Box<dyn UserStore>,
    /// Registered authentication strategies
    pub strategies: Vec<Box<dyn AuthStrategy>>,
}

impl ActixPassport {
    /// Configures the authentication routes for the application.
    ///
    /// This function adds the following routes to the specified service config:
    ///
    /// ## Password Authentication
    /// - `POST /auth/register`
    /// - `POST /auth/login`
    /// - `POST /auth/logout`
    ///
    /// ## OAuth Authentication
    /// - `GET /auth/{provider}`
    /// - `GET /auth/{provider}/callback`
    ///
    /// ## User Information
    /// - `GET /auth/me`
    ///
    /// # Arguments
    ///
    /// * `cfg` - The service config to add the routes to.
    pub fn configure_routes(&self, cfg: &mut web::ServiceConfig) {
        cfg.app_data(web::Data::new(self.clone()));
        let mut auth_scope = web::scope("/auth");

        for strategy in &self.strategies {
            auth_scope = strategy.configure(auth_scope);
        }

        cfg.service(auth_scope);
    }
}

/// Extractable authenticated user from request.
///
/// This struct can be used in handler functions to extract the authenticated
/// user from the request. It implements `FromRequest` so it can be used
/// as a parameter in handler functions.
///
/// # Examples
///
/// ```rust
/// use actix_web::{get, HttpResponse};
/// use actix_passport::AuthedUser;
///
/// #[get("/profile")]
/// async fn get_profile(user: AuthedUser) -> HttpResponse {
///     HttpResponse::Ok().json(&user.0)
/// }
/// ```
#[derive(Debug, Clone)]
pub struct AuthedUser(pub AuthUser);

impl Deref for AuthedUser {
    type Target = AuthUser;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl FromRequest for AuthedUser {
    type Error = actix_web::Error;
    type Future = LocalBoxFuture<'static, Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut actix_web::dev::Payload) -> Self::Future {
        let req = req.clone();

        async move {
            let framework = req.app_data::<web::Data<ActixPassport>>().map_or_else(
                ||
                Err(ErrorBadRequest(
                    "Could not extract `ActixPassport` from the app data. This usually means that you have not added 
                        `.configure(|cfg| auth_framework.configure_routes(cfg))` or `.app_data(auth_framework)` prior to 
                        defining your routes. ")), 
                Ok)?;
            let mut user = None;
            for strategy in &framework.strategies {
                user = strategy.authenticate(&req).await;
            }

            user.map_or_else(
                || Err(ErrorUnauthorized("Unauthorized"))
                ,
            |user| Ok(Self(user))
            )
        }
        .boxed_local()
    }
}

/// Optional authenticated user extractor.
///
/// Similar to `AuthenticatedUser`, but returns `None` instead of an error
/// when the user is not authenticated. This is useful for endpoints that
/// work differently for authenticated vs unauthenticated users.
///
/// # Examples
///
/// ```rust
/// use actix_web::{get, HttpResponse};
/// use actix_passport::OptionalAuthedUser;
///
/// #[get("/home")]
/// async fn home(user: OptionalAuthedUser) -> HttpResponse {
///     match user.0 {
///         Some(user) => HttpResponse::Ok().json(format!("Welcome, {}!", user.id)),
///         None => HttpResponse::Ok().json("Welcome, guest!"),
///     }
/// }
/// ```
#[derive(Debug, Clone)]
pub struct OptionalAuthedUser(pub Option<AuthUser>);

impl FromRequest for OptionalAuthedUser {
    type Error = actix_web::Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut actix_web::dev::Payload) -> Self::Future {
        let user = req.extensions().get::<AuthUser>().cloned();
        ready(Ok(Self(user)))
    }
}
