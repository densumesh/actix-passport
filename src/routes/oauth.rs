//! Handlers for OAuth 2.0 routes.

use crate::builder::AuthFramework;
use crate::middleware::utils;
use crate::types::AuthUser;
use crate::{
    core::{SessionStore, UserStore},
    password::PasswordHasher,
};
use actix_session::Session;
use actix_web::{web, HttpRequest, HttpResponse, Responder};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct OAuthCallbackParams {
    code: String,
    state: String,
}

/// Initiates the OAuth flow for a given provider.
///
/// **GET /auth/{provider}**
pub async fn oauth_initiate<U, S, H>(
    req: HttpRequest,
    provider: web::Path<String>,
    framework: web::Data<AuthFramework<U, S, H>>,
    session: Session,
) -> impl Responder
where
    U: UserStore,
    S: SessionStore,
    H: PasswordHasher,
{
    let provider_name = provider.into_inner();
    if let Some(ref oauth_service) = framework.oauth_service {
        let state = uuid::Uuid::new_v4().to_string();

        // Store the state in the session for CSRF protection
        if session.insert("oauth_state", &state).is_err() {
            return HttpResponse::InternalServerError().finish();
        }

        let redirect_uri = format!(
            "{}://{}/auth/{}/callback",
            req.connection_info().scheme(),
            req.connection_info().host(),
            provider_name
        );

        match oauth_service.authorize_url(&provider_name, &state, &redirect_uri) {
            Ok(url) => HttpResponse::Found()
                .append_header(("Location", url))
                .finish(),
            Err(_) => {
                HttpResponse::NotFound().body(format!("Provider not found: {}", provider_name))
            }
        }
    } else {
        HttpResponse::NotFound().finish()
    }
}

/// Handles the callback from the OAuth provider.
///
/// **GET /auth/{provider}/callback**
pub async fn oauth_callback<U, S, H>(
    provider: web::Path<String>,
    params: web::Query<OAuthCallbackParams>,
    framework: web::Data<AuthFramework<U, S, H>>,
    session: Session,
    req: HttpRequest,
) -> impl Responder
where
    U: UserStore,
    S: SessionStore,
    H: PasswordHasher,
{
    let provider_name = provider.into_inner();

    if let Some(ref oauth_service) = framework.oauth_service {
        // Verify CSRF state
        if let Ok(Some(saved_state)) = session.get::<String>("oauth_state") {
            if saved_state != params.state {
                return HttpResponse::BadRequest().body("Invalid state");
            }
        } else {
            return HttpResponse::BadRequest().body("State not found");
        }

        let redirect_uri = format!(
            "{}://{}/auth/{}/callback",
            req.connection_info().scheme(),
            req.connection_info().host(),
            provider_name
        );

        let oauth_user = match oauth_service
            .exchange_code(&provider_name, &params.code, &redirect_uri)
            .await
        {
            Ok(user) => user,
            Err(e) => return HttpResponse::InternalServerError().json(e.to_string()),
        };

        // Find or create a user in our system
        let user = match framework.user_store.find_by_email(&oauth_user.email).await {
            Ok(Some(user)) => user, // User exists
            Ok(None) => {
                // Create a new user
                let new_user = AuthUser::new(oauth_user.id)
                    .with_email(oauth_user.email)
                    .with_display_name(oauth_user.name.unwrap_or_default());
                match framework.user_store.create_user(new_user).await {
                    Ok(user) => user,
                    Err(e) => return HttpResponse::InternalServerError().json(e.to_string()),
                }
            }
            Err(e) => return HttpResponse::InternalServerError().json(e.to_string()),
        };

        // Create a session for the user
        let user_session = utils::create_user_session(&user, framework.config.session_duration);
        if let Err(e) = framework
            .session_store
            .create_session(user_session.clone())
            .await
        {
            return HttpResponse::InternalServerError().json(e.to_string());
        }

        if let Err(e) = utils::set_session_id(&session, user_session.id) {
            return HttpResponse::InternalServerError().json(e.to_string());
        }

        HttpResponse::Ok().json(user)
    } else {
        HttpResponse::NotFound().finish()
    }
}
