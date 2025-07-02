//! Handlers for OAuth 2.0 routes.

use crate::builder::ActixPassport;
use crate::types::AuthUser;
use actix_session::Session;
use actix_web::{web, HttpRequest, HttpResponse, Responder};
use serde::Deserialize;

const USER_ID_KEY: &str = "actix_passport_user_id";

/// Parameters received from OAuth provider callback.
///
/// This struct represents the query parameters that OAuth providers
/// send back to the callback URL after user authorization.
#[derive(Deserialize)]
pub struct OAuthCallbackParams {
    /// Authorization code from the OAuth provider
    code: String,
    /// State parameter for CSRF protection
    state: String,
}

/// Initiates the OAuth flow for a given provider.
///
/// **GET /auth/{provider}**
pub async fn oauth_initiate(
    req: HttpRequest,
    provider: web::Path<String>,
    framework: web::Data<ActixPassport>,
    session: Session,
) -> impl Responder {
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

        oauth_service
            .authorize_url(&provider_name, &state, &redirect_uri)
            .map_or_else(
                |_| HttpResponse::NotFound().body(format!("Provider not found: {provider_name}")),
                |url| {
                    HttpResponse::Found()
                        .append_header(("Location", url))
                        .finish()
                },
            )
    } else {
        HttpResponse::NotFound().finish()
    }
}

/// Handles the callback from the OAuth provider.
///
/// **GET /auth/{provider}/callback**
pub async fn oauth_callback(
    provider: web::Path<String>,
    params: web::Query<OAuthCallbackParams>,
    framework: web::Data<ActixPassport>,
    session: Session,
    req: HttpRequest,
) -> impl Responder {
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
        let user = match framework
            .user_store
            .find_by_email(oauth_user.email.as_deref().unwrap_or_default())
            .await
        {
            Ok(Some(user)) => user, // User exists
            Ok(None) => {
                // Create a new user
                let new_user = AuthUser::new(uuid::Uuid::new_v4().to_string())
                    .with_email(oauth_user.email.as_deref().unwrap_or_default())
                    .with_display_name(oauth_user.display_name.as_deref().unwrap_or_default());
                match framework.user_store.create_user(new_user).await {
                    Ok(user) => user,
                    Err(e) => return HttpResponse::InternalServerError().json(e.to_string()),
                }
            }
            Err(e) => return HttpResponse::InternalServerError().json(e.to_string()),
        };

        // Store user ID in session
        if session.insert(USER_ID_KEY, &user.id).is_err() {
            return HttpResponse::InternalServerError().finish();
        }

        HttpResponse::Ok().json(user)
    } else {
        HttpResponse::NotFound().finish()
    }
}
