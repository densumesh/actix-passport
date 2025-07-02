pub mod builder;
pub mod core;
pub mod errors;
pub mod middleware;
pub mod routes;
pub mod types;

#[cfg(feature = "password")]
pub mod password;

#[cfg(feature = "oauth")]
pub mod oauth;

pub use crate::builder::{ActixPassport, ActixPassportBuilder};
pub use crate::core::*;
pub use crate::middleware::*;
