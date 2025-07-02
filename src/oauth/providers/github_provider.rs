use crate::{
    errors::AuthError, providers::generic_provider::GenericOAuthProvider, types::AuthResult,
    OAuthConfig, OAuthProvider, OAuthUser,
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
    fn name(&self) -> &str {
        "github"
    }

    fn authorize_url(&self, state: &str, redirect_uri: &str) -> AuthResult<String> {
        self.inner.authorize_url(state, redirect_uri)
    }

    async fn exchange_code(&self, code: &str, redirect_uri: &str) -> AuthResult<OAuthUser> {
        let mut oauth_user = self.inner.exchange_code(code, redirect_uri).await?;

        // GitHub doesn't always include email in the user info response
        // We need to make a separate request to get the user's email
        if oauth_user.email.is_none() {
            if let Ok(email) = self.fetch_github_email(&oauth_user.raw_data).await {
                oauth_user.email = Some(email);
            }
        }

        Ok(oauth_user)
    }
}

impl GitHubOAuthProvider {
    /// Fetches the user's primary email from GitHub API.
    ///
    /// GitHub sometimes doesn't include the email in the user info response,
    /// so we need to make a separate API call to get it.
    async fn fetch_github_email(&self, _user_data: &serde_json::Value) -> AuthResult<String> {
        // This would require the access token from the previous request
        // For now, we'll just return an error
        Err(AuthError::OAuth(
            "Email fetching not implemented yet".to_string(),
        ))
    }
}
