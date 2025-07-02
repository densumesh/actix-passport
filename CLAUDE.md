# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

actix-passport is a flexible authentication framework for actix-web applications in Rust. It provides multiple authentication methods including password-based auth, OAuth 2.0, JWT tokens, and session-based authentication.

## Development Commands

### Build and Test
```bash
cargo build                    # Build the project
cargo test                     # Run all tests
cargo clippy                   # Run linter (configured with strict rules)
cargo run --example basic      # Run the basic example
```

### Examples
```bash
cd examples/basic_example && cargo run    # Run basic password auth example
```

## Core Architecture

### Framework Structure
The framework is built around several key components:

1. **ActixPassport** - Main framework object created via `ActixPassportBuilder`
2. **UserStore trait** - Pluggable user persistence (database-agnostic)
3. **Password authentication** - Built-in Argon2 password hashing
4. **OAuthProvider trait** - Extensible OAuth provider system
5. **Authentication middleware** - Session and JWT-based auth middleware

### Module Organization
- `src/core/` - Core traits and types (`UserStore`, `AuthConfig`)
- `src/builder.rs` - Builder pattern for framework configuration
- `src/types.rs` - Core types (`AuthUser`, `AuthResult`)
- `src/middleware/` - Authentication middleware implementations
- `src/routes/` - Built-in authentication route handlers
- `src/password/` - Password hashing and authentication (feature gated)
- `src/oauth/` - OAuth 2.0 providers and service (feature gated)

### Key Traits to Implement
When extending the framework, you'll typically implement:
- `UserStore` for custom database backends
- `OAuthProvider` for custom OAuth providers

### Builder Pattern Usage
The framework uses a builder pattern for configuration:
```rust
let auth = ActixPassportBuilder::new()
    .with_user_store(user_store)
    .enable_password_auth()  // Uses Argon2 hashing internally
    .with_oauth(provider)
    .with_config(config)
    .build()?;
```

### Feature Flags
- `password` (default) - Username/password authentication
- `oauth` (default) - OAuth 2.0 providers  
- `jwt` (default) - JWT token support

### Session Management
The framework relies on actix-session for session management. Session middleware must be configured before the auth middleware.

### Authentication Flow
1. User authentication creates a session via actix-session
2. Middleware extracts user info from session on subsequent requests
3. Route handlers can use `AuthenticatedUser` or `OptionalAuthenticatedUser` extractors

## Code Standards

### Linting
The project uses strict Clippy rules:
- `pedantic`, `nursery`, and `all` warnings enabled
- `unwrap_used` and `expect_used` are denied - use proper error handling
- Always run `cargo clippy` before committing

### Error Handling
- Use `AuthResult<T>` type alias for authentication operations
- Never use `.unwrap()` or `.expect()` - handle errors properly
- Custom errors are defined in `src/errors.rs`

### Documentation
- All public APIs must have comprehensive documentation
- Use doc examples for trait implementations
- Missing docs trigger warnings via Clippy configuration