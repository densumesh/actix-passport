# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

actix-passport is a flexible authentication framework for actix-web applications in Rust. It provides multiple authentication methods including password-based auth, OAuth 2.0, JWT tokens, and session-based authentication.

## Recent Development Context (Updated Dec 2024)

### Pre-Built Database Store Implementation
We have successfully implemented the foundation for pre-built database stores to drastically reduce integration complexity:

**Completed:**
- ✅ Feature flag system (`postgres`, `mysql`, `sqlite`, `mongodb`, `redis`)
- ✅ Comprehensive store infrastructure with shared utilities
- ✅ Production-ready PostgreSQL store using SQLx
- ✅ Builder convenience methods (`ActixPassportBuilder::with_postgres_store()`)
- ✅ Automatic migrations and connection pooling
- ✅ Developer experience: 500+ lines → 5 lines integration

**Current Database Integration Options:**
```rust
// In-memory (development/testing)
let auth = ActixPassportBuilder::with_in_memory_store()
    .enable_password_auth()
    .build();

// PostgreSQL (production-ready)
let auth = ActixPassportBuilder::with_postgres_store("postgres://...")
    .await?
    .enable_password_auth()
    .build();
```

### SQLx vs Diesel Decision
**Current Implementation:** SQLx (chosen for simpler async, better JSON handling)

**Known Issue:** Diesel users face significant pain points:
- Dependency conflicts (dual database drivers)
- Connection pool duplication
- Transaction isolation issues
- Migration system conflicts
- Type system fragmentation

**Recommended Next Steps:** Add Diesel support alongside SQLx to provide choice:
```rust
// Feature flags for both ORMs
postgres-sqlx = ["dep:sqlx", ...]
postgres-diesel = ["dep:diesel", ...]

// Builder methods for both
ActixPassportBuilder::with_postgres_sqlx_store("...")
ActixPassportBuilder::with_postgres_diesel_store(existing_diesel_pool)
```

This would allow Diesel users to integrate with their existing infrastructure without forcing SQLx adoption.

## Development Commands

### Build and Test
```bash
cargo build                         # Build the project (core features only)
cargo build --features postgres     # Build with PostgreSQL support
cargo test                          # Run all tests
cargo test --features postgres      # Test with PostgreSQL features
cargo clippy                        # Run linter (configured with strict rules)
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
- `src/user_store/` - Core UserStore trait and implementations
  - `src/user_store/stores/` - Pre-built store implementations
    - `src/user_store/stores/in_memory.rs` - In-memory store (development)
    - `src/user_store/stores/postgres.rs` - PostgreSQL store (SQLx-based)
    - `src/user_store/stores/common/` - Shared utilities for database stores
      - `sql_helpers.rs` - Common SQL patterns and queries
      - `json_helpers.rs` - JSON serialization utilities
      - `error_mapping.rs` - Database error → AuthError conversion
      - `migrations.rs` - Migration system foundation
- `src/builder.rs` - Builder pattern with convenience methods for stores
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

**Manual UserStore (custom implementations):**
```rust
let auth = ActixPassportBuilder::new(custom_user_store)
    .enable_password_auth()  // Uses Argon2 hashing internally
    .with_oauth(provider)
    .build();
```

**Pre-built Stores (recommended):**
```rust
// In-memory (development)
let auth = ActixPassportBuilder::with_in_memory_store()
    .enable_password_auth()
    .build();

// PostgreSQL (production)
let auth = ActixPassportBuilder::with_postgres_store("postgres://...")
    .await?
    .enable_password_auth()
    .build();
```

### Feature Flags
**Core Features:**
- `password` (default) - Username/password authentication
- `oauth` (default) - OAuth 2.0 providers  

**Database Store Features:**
- `postgres` - PostgreSQL store with SQLx (production-ready)
- `mysql` - MySQL store with SQLx (planned)
- `sqlite` - SQLite store with SQLx (planned)
- `mongodb` - MongoDB store (planned)
- `redis` - Redis store for session-based storage (planned)

### Session Management
The framework relies on actix-session for session management. Session middleware must be configured before the auth middleware.

### Authentication Flow
1. User authentication creates a session via actix-session
2. Middleware extracts user info from session on subsequent requests
3. Route handlers can use `AuthedUser` or `OptionalAuthedUser` extractors

### Database Store Architecture
The framework provides a layered approach to database integration:

**Layer 1: UserStore Trait** - Common interface for all storage backends
**Layer 2: Store Implementations** - Database-specific implementations (PostgreSQL, SQLite, etc.)
**Layer 3: Common Utilities** - Shared code for SQL patterns, JSON handling, error mapping
**Layer 4: Builder Convenience** - One-line setup methods for each database

**Production Benefits:**
- Automatic connection pooling and health checks
- Built-in migration system with proper indexing
- Comprehensive error handling with AuthError conversion
- JSON(B) support for metadata and OAuth providers
- Type-safe database operations with compile-time validation

**Development Experience:**
- Before: ~500 lines of custom UserStore implementation
- After: 1 line with `ActixPassportBuilder::with_postgres_store()`

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