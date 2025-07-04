use std::collections::HashMap;

use crate::{
    errors::AuthError,
    oauth::{OAuthProvider, OAuthUser},
    prelude::UserStore,
    types::AuthResult,
    AuthUser,
};

/// OAuth service for managing multiple OAuth providers.
///
/// This service manages multiple OAuth providers and provides a unified
/// interface for OAuth operations across different providers.
///
/// # Examples
///
/// ```rust
/// use actix_passport::{OAuthService, GoogleOAuthProvider, GitHubOAuthProvider, prelude::InMemoryUserStore};
///
/// let user_store = InMemoryUserStore::new();
/// let mut oauth_service = OAuthService::new(user_store);
/// oauth_service.add_provider(Box::new(GoogleOAuthProvider::new(
///     "google_client_id".to_string(),
///     "google_client_secret".to_string(),
/// )));
/// oauth_service.add_provider(Box::new(GitHubOAuthProvider::new(
///     "github_client_id".to_string(),
///     "github_client_secret".to_string(),
/// )));
/// ```
#[derive(Clone)]
pub struct OAuthService {
    providers: HashMap<String, Box<dyn OAuthProvider>>,
    user_store: Box<dyn UserStore>,
}

impl OAuthService {
    /// Creates a new OAuth service.
    #[must_use]
    pub fn new(user_store: impl UserStore + 'static) -> Self {
        Self {
            user_store: Box::new(user_store),
            providers: HashMap::new(),
        }
    }

    /// Adds an OAuth provider to the service.
    ///
    /// # Arguments
    ///
    /// * `provider` - The OAuth provider to add
    ///
    /// # Examples
    ///
    /// ```rust
    /// use actix_passport::{OAuthService, GoogleOAuthProvider};
    ///
    /// let user_store = actix_passport::prelude::InMemoryUserStore::new();
    /// let mut service = OAuthService::new(user_store);
    /// service.add_provider(Box::new(GoogleOAuthProvider::new(
    ///     "client_id".to_string(),
    ///     "client_secret".to_string(),
    /// )));
    /// ```
    pub fn add_provider(&mut self, provider: Box<dyn OAuthProvider>) {
        let name = provider.name().to_string();
        self.providers.insert(name, provider);
    }

    /// Gets an OAuth provider by name.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the provider
    ///
    /// # Returns
    ///
    /// Returns a reference to the provider if found.
    #[must_use]
    pub fn get_provider(&self, name: &str) -> Option<&dyn OAuthProvider> {
        self.providers.get(name).map(std::convert::AsRef::as_ref)
    }

    /// Lists all available provider names.
    ///
    /// # Returns
    ///
    /// Returns a vector of provider names.
    #[must_use]
    pub fn list_providers(&self) -> Vec<&str> {
        self.providers
            .keys()
            .map(std::string::String::as_str)
            .collect()
    }

    /// Generates an authorization URL for a specific provider.
    ///
    /// # Arguments
    ///
    /// * `provider_name` - The name of the OAuth provider
    /// * `state` - CSRF protection state parameter
    /// * `redirect_uri` - URI to redirect to after authorization
    ///
    /// # Returns
    ///
    /// Returns the authorization URL for the specified provider.
    ///
    /// # Errors
    ///
    /// Returns an error if the provider is not found.
    pub fn authorize_url(
        &self,
        provider_name: &str,
        state: &str,
        redirect_uri: &str,
    ) -> AuthResult<String> {
        let provider = self.get_provider(provider_name).ok_or_else(|| {
            AuthError::OAuthProviderNotConfigured {
                provider: provider_name.to_string(),
            }
        })?;

        provider.authorize_url(state, redirect_uri)
    }

    /// Exchanges an authorization code for user information.
    ///
    /// # Arguments
    ///
    /// * `provider_name` - The name of the OAuth provider
    /// * `code` - The authorization code from the provider
    /// * `redirect_uri` - The redirect URI used in the authorization request
    ///
    /// # Returns
    ///
    /// Returns the user information from the OAuth provider.
    ///
    /// # Errors
    ///
    /// Returns an error if the provider is not found or the code exchange fails.
    pub async fn exchange_code(
        &self,
        provider_name: &str,
        code: &str,
        redirect_uri: &str,
    ) -> AuthResult<OAuthUser> {
        let provider = self.get_provider(provider_name).ok_or_else(|| {
            AuthError::OAuthProviderNotConfigured {
                provider: provider_name.to_string(),
            }
        })?;

        provider.exchange_code(code, redirect_uri).await
    }

    /// Handles the OAuth callback by exchanging the authorization code for user information
    /// and creating or updating the user account.
    ///
    /// # Arguments
    ///
    /// * `provider_name` - The name of the OAuth provider
    /// * `code` - The authorization code from the provider
    /// * `redirect_uri` - The redirect URI used in the authorization request
    ///
    /// # Returns
    ///
    /// Returns the authenticated user information.
    ///
    /// # Errors
    ///
    /// Returns an error if the provider is not found, code exchange fails, or user operations fail.
    pub async fn callback(
        &self,
        provider_name: &str,
        code: &str,
        redirect_uri: &str,
    ) -> AuthResult<AuthUser> {
        let oauth_user = self
            .exchange_code(provider_name, code, redirect_uri)
            .await?;

        let user = match self
            .user_store
            .find_by_email(oauth_user.email.as_deref().unwrap_or_default())
            .await
        {
            Ok(Some(mut existing_user)) => {
                // User exists - add this OAuth provider to their account
                existing_user = existing_user.with_oauth_provider(oauth_user);

                // Update user with new OAuth provider
                self.user_store.update_user(existing_user).await?
            }
            Ok(None) => {
                // Create a new user with OAuth provider information
                let new_user = AuthUser::from(oauth_user);
                self.user_store.create_user(new_user).await?
            }
            Err(e) => return Err(e),
        };
        Ok(user)
    }
}
