//! Authentication strategy trait and implementations.
//!
//! This module provides a pluggable authentication strategy system that allows
//! for extensible authentication methods. Each strategy can define its own
//! authentication logic, routes, and middleware behavior.

use crate::types::AuthUser;
use actix_web::HttpRequest;
use async_trait::async_trait;
use dyn_clone::DynClone;

/// Strategy for OAuth Auth
#[cfg(feature = "oauth")]
pub mod oauth;

/// Strategy for Password Auth
#[cfg(feature = "password")]
pub mod password;

/// Trait for implementing authentication strategies.
///
/// An authentication strategy defines how a specific authentication method
/// works, including its name, route configuration, and authentication logic.
/// This allows for modular authentication approaches like password auth,
/// OAuth, WebAuthn, SAML, magic links, etc.
///
/// # Examples
///
/// ```rust,no_run
/// use actix_passport::strategies::AuthStrategy;
/// use actix_passport::types::AuthUser;
/// use actix_web::HttpRequest;
/// use async_trait::async_trait;
/// use dyn_clone::DynClone;
///
/// #[derive(Clone)]
/// struct CustomStrategy;
///
/// #[async_trait(?Send)]
/// impl AuthStrategy for CustomStrategy {
///     fn name(&self) -> &'static str {
///         "custom"
///     }
///
///     fn configure(&self, scope: actix_web::Scope) -> actix_web::Scope {
///         // Add custom routes
///         scope
///     }
///
///     async fn authenticate(&self, _req: &HttpRequest) -> Option<AuthUser> {
///         // Custom authentication logic
///         None
///     }
/// }
/// ```
#[async_trait(?Send)]
pub trait AuthStrategy: Send + Sync + DynClone {
    /// Returns the name of this authentication strategy.
    ///
    /// This name is used for identification and routing purposes.
    /// Should be a short, URL-safe string (e.g., "password", "oauth", "webauthn").
    fn name(&self) -> &'static str;

    /// Configures the routes for this authentication strategy.
    ///
    /// This method is called during framework initialization to set up
    /// any routes that this strategy needs. The strategy can add handlers
    /// for login, logout, callbacks, or any other endpoints it requires.
    ///
    /// # Arguments
    ///
    /// * `scope` - The scope to add routes to
    fn configure(&self, scope: actix_web::Scope) -> actix_web::Scope;

    /// Attempts to authenticate a user from the given request.
    ///
    /// This method is called by the authentication middleware to check if
    /// the current request can be authenticated using this strategy.
    /// It should return the authenticated user if successful, or an error
    /// if authentication fails or is not applicable.
    ///
    /// # Arguments
    ///
    /// * `req` - The HTTP request to authenticate
    /// * `payload` - The request payload (for strategies that need to read the body)
    ///
    /// # Returns
    ///
    /// * `Ok(AuthUser)` - If authentication succeeds
    /// * `Err(AuthError)` - If authentication fails or is not applicable
    ///
    /// # Note
    ///
    /// Strategies should return `AuthError::Unauthorized` if they cannot
    /// authenticate the request, allowing other strategies to be tried.
    /// Only return other error types for actual authentication failures.
    async fn authenticate(&self, req: &HttpRequest) -> Option<AuthUser>;
}

dyn_clone::clone_trait_object!(AuthStrategy);
