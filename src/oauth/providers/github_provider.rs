use crate::{
    oauth::providers::generic_provider::GenericOAuthProvider,
    oauth::{OAuthConfig, OAuthProvider, OAuthUser},
    types::AuthResult,
};
use async_trait::async_trait;

/// GitHub OAuth provider implementation.
///
/// This is a specialized OAuth provider for GitHub authentication.
/// It handles GitHub-specific OAuth flow and user data extraction.
///
/// # Examples
///
/// ```rust
/// use actix_passport::GitHubOAuthProvider;
///
/// let provider = GitHubOAuthProvider::new(
///     "your_github_client_id".to_string(),
///     "your_github_client_secret".to_string(),
/// );
/// ```
#[derive(Clone)]
pub struct GitHubOAuthProvider {
    inner: GenericOAuthProvider,
}

impl GitHubOAuthProvider {
    /// Creates a new GitHub OAuth provider.
    ///
    /// # Arguments
    ///
    /// * `client_id` - GitHub OAuth client ID
    /// * `client_secret` - GitHub OAuth client secret
    #[must_use]
    pub fn new(client_id: String, client_secret: String) -> Self {
        let config = OAuthConfig {
            client_id,
            client_secret,
            auth_url: "https://github.com/login/oauth/authorize".to_string(),
            token_url: "https://github.com/login/oauth/access_token".to_string(),
            user_info_url: "https://api.github.com/user".to_string(),
            scopes: vec!["user:email".to_string()],
        };

        Self {
            inner: GenericOAuthProvider::new("github", config),
        }
    }
}

#[async_trait]
impl OAuthProvider for GitHubOAuthProvider {
    fn name(&self) -> &'static str {
        "github"
    }

    fn authorize_url(&self, state: &str, redirect_uri: &str) -> AuthResult<String> {
        self.inner.authorize_url(state, redirect_uri)
    }

    async fn exchange_code(&self, code: &str, redirect_uri: &str) -> AuthResult<OAuthUser> {
        self.inner.exchange_code(code, redirect_uri).await
    }
}
