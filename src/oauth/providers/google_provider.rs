use crate::{
    oauth::providers::generic_provider::GenericOAuthProvider,
    oauth::{OAuthConfig, OAuthProvider, OAuthUser},
    types::AuthResult,
};
use async_trait::async_trait;

/// Google OAuth provider implementation.
///
/// This is a specialized OAuth provider for Google authentication.
/// It handles Google-specific OAuth flow and user data extraction.
///
/// Ensure that you have allowed `<domain>/auth/google/callback` as an authorized redirect URI
///
/// # Examples
///
/// ```rust
/// use actix_passport::GoogleOAuthProvider;
///
/// let provider = GoogleOAuthProvider::new(
///     "your_google_client_id".to_string(),
///     "your_google_client_secret".to_string(),
/// );
/// ```
#[derive(Clone)]
pub struct GoogleOAuthProvider {
    inner: GenericOAuthProvider,
}

impl GoogleOAuthProvider {
    /// Creates a new Google OAuth provider.
    ///
    /// # Arguments
    ///
    /// * `client_id` - Google OAuth client ID
    /// * `client_secret` - Google OAuth client secret
    #[must_use]
    pub fn new(client_id: String, client_secret: String) -> Self {
        let config = OAuthConfig {
            client_id,
            client_secret,
            auth_url: "https://accounts.google.com/o/oauth2/v2/auth".to_string(),
            token_url: "https://oauth2.googleapis.com/token".to_string(),
            user_info_url: "https://www.googleapis.com/oauth2/v2/userinfo".to_string(),
            scopes: vec![
                "openid".to_string(),
                "email".to_string(),
                "profile".to_string(),
            ],
        };

        Self {
            inner: GenericOAuthProvider::new("google", config),
        }
    }
}

#[async_trait]
impl OAuthProvider for GoogleOAuthProvider {
    fn name(&self) -> &'static str {
        "google"
    }

    fn authorize_url(&self, state: &str, redirect_uri: &str) -> AuthResult<String> {
        self.inner.authorize_url(state, redirect_uri)
    }

    async fn exchange_code(&self, code: &str, redirect_uri: &str) -> AuthResult<OAuthUser> {
        self.inner.exchange_code(code, redirect_uri).await
    }
}
