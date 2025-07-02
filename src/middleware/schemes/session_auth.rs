use crate::{core::UserStore, types::AuthUser};
use actix_session::SessionExt;
use actix_web::HttpRequest;

const USER_ID_KEY: &str = "actix_passport_user_id";

/// Extracts authenticated user from session.
#[allow(clippy::future_not_send)]
pub(crate) async fn get_user_from_session(
    req: &HttpRequest,
    user_store: &dyn UserStore,
) -> Option<AuthUser> {
    let session = req.get_session();

    let user_id = session.get::<String>(USER_ID_KEY).ok()??;

    user_store.find_by_id(&user_id).await.ok()?
}
