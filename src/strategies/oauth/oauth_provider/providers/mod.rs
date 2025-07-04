/// Generic OAuth provider implementation for custom providers.
pub mod generic_provider;
pub use generic_provider::GenericOAuthProvider;
/// GitHub OAuth provider implementation.
pub mod github_provider;
pub use github_provider::GitHubOAuthProvider;
/// Google OAuth provider implementation.
pub mod google_provider;
pub use google_provider::GoogleOAuthProvider;
