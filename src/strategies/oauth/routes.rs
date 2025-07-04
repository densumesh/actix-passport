//! Handlers for OAuth 2.0 routes.

use crate::{strategies::oauth::service::OAuthService, ActixPassport, USER_ID_KEY};
use actix_session::Session;
use actix_web::{web, HttpRequest, HttpResponse, Responder};
use serde::Deserialize;
use url::Url;

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

/// Query parameters for OAuth initiation.
#[derive(Deserialize)]
pub struct OAuthInitiateParams {
    /// Optional redirect URL to go to after successful authentication
    redirect_url: Option<String>,
}

/// Validates that a redirect URL is safe to use.
///
/// This prevents open redirect vulnerabilities by ensuring the URL is either:
/// - A relative path (starts with /)
/// - An absolute URL with the same host as the request
fn validate_redirect_url(redirect_url: &str, request_host: &str) -> bool {
    // Allow relative URLs that start with /
    if redirect_url.starts_with('/') {
        return true;
    }

    // For absolute URLs, ensure they have the same host
    if let Ok(url) = Url::parse(redirect_url) {
        if let Some(host) = url.host_str() {
            return host == request_host;
        }
    }

    false
}

/// Initiates the OAuth flow for a given provider.
///
/// `GET /auth/{provider}?redirect_url=/dashboard`
#[allow(clippy::future_not_send)]
pub async fn oauth_initiate(
    req: HttpRequest,
    provider: web::Path<String>,
    params: web::Query<OAuthInitiateParams>,
    oauth_service: web::Data<OAuthService>,
    session: Session,
) -> impl Responder {
    let provider_name = provider.into_inner();
    let state = uuid::Uuid::new_v4().to_string();

    // Store the state in the session for CSRF protection
    if session.insert("oauth_state", &state).is_err() {
        return HttpResponse::InternalServerError().finish();
    }

    // Store redirect URL if provided and valid
    if let Some(ref redirect_url) = params.redirect_url {
        let req = req.connection_info();
        if validate_redirect_url(redirect_url, req.host()) {
            if session.insert("oauth_redirect_url", redirect_url).is_err() {
                return HttpResponse::InternalServerError().finish();
            }
        } else {
            return HttpResponse::BadRequest().body("Invalid redirect URL");
        }
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
}

/// Handles the callback from the OAuth provider.
///
/// `GET /auth/{provider}/callback`
#[allow(clippy::future_not_send)]
pub async fn oauth_callback(
    provider: web::Path<String>,
    params: web::Query<OAuthCallbackParams>,
    oauth_service: web::Data<OAuthService>,
    framework: web::Data<ActixPassport>,
    session: Session,
    req: HttpRequest,
) -> impl Responder {
    let provider_name = provider.into_inner();

    // Verify CSRF state
    if let Ok(Some(saved_state)) = session.get::<String>("oauth_state") {
        if saved_state != params.state {
            return HttpResponse::BadRequest().json("Invalid OAuth state");
        }
    } else {
        return HttpResponse::BadRequest().json("Invalid OAuth state");
    }

    let redirect_uri = format!(
        "{}://{}/auth/{}/callback",
        req.connection_info().scheme(),
        req.connection_info().host(),
        provider_name
    );

    match oauth_service
        .callback(
            framework.user_store.as_ref(),
            &provider_name,
            &params.code,
            &redirect_uri,
        )
        .await
    {
        Ok(user) => {
            // Store user ID in session
            if session.insert(USER_ID_KEY, &user.id).is_err() {
                return HttpResponse::InternalServerError().finish();
            }

            // Clean up OAuth state from session
            let _ = session.remove("oauth_state");

            // Check for stored redirect URL and redirect if present
            if let Ok(Some(redirect_url)) = session.get::<String>("oauth_redirect_url") {
                // Clean up redirect URL from session
                let _ = session.remove("oauth_redirect_url");

                HttpResponse::Found()
                    .append_header(("Location", redirect_url))
                    .finish()
            } else {
                // Default behavior: return JSON (for API clients)
                HttpResponse::Ok().json(user)
            }
        }
        Err(e) => HttpResponse::InternalServerError().json(e.to_string()),
    }
}
