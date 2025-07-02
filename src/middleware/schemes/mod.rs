use crate::{types::AuthUser, ActixPassport};
use actix_web::{web, HttpRequest};

/// Session-based authentication middleware.
#[cfg(any(feature = "password", feature = "oauth"))]
pub mod session_auth;

#[allow(clippy::future_not_send)]
pub(crate) async fn get_user_from_request(req: &HttpRequest) -> Option<AuthUser> {
    if let Some(framework) = req.app_data::<web::Data<ActixPassport>>() {
        if framework.config.password_auth || framework.config.oauth_auth {
            if let Some(user) =
                session_auth::get_user_from_session(req, &*framework.user_store).await
            {
                return Some(user);
            }
        }
    }

    None
}
