# Advanced SQLite Bearer Auth Example

This example demonstrates how to implement custom authentication components for the `actix-passport` framework:

1. **Custom SQLite UserStore** - A production-ready SQLite-based user storage implementation
2. **Custom Bearer Authentication Strategy** - Token-based authentication using Bearer tokens
3. **Token Management System** - Simple token generation, validation, and revocation
4. **Complete Web Application** - Full-featured demo with frontend and API

## 🏗️ Architecture

### Components

- **SQLiteUserStore** (`src/stores/sqlite_store.rs`): Custom implementation of the `UserStore` trait using SQLite with:
  - Automatic database migrations
  - Connection pooling with `r2d2`
  - Password hashing with Argon2
  - Token storage and validation
  - JSON metadata support

- **BearerAuthStrategy** (`src/strategies/bearer_strategy.rs`): Custom implementation of the `AuthStrategy` trait providing:
  - User registration with password hashing
  - Login with credential validation
  - Bearer token generation and validation
  - Protected profile endpoint
  - Token revocation on logout

- **TokenService** (`src/services/token_service.rs`): Simple token management service with:
  - Secure random token generation
  - Salt generation for password hashing

### Database Schema

The SQLite database includes two tables:

```sql
-- Users table
CREATE TABLE users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE,
    username TEXT UNIQUE,
    password_hash TEXT,
    display_name TEXT,
    avatar_url TEXT,
    created_at TEXT NOT NULL,
    last_login TEXT,
    metadata TEXT NOT NULL DEFAULT '{}'
);

-- Authentication tokens table
CREATE TABLE auth_tokens (
    token TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
```

## 🚀 Running the Example

### Prerequisites

- Rust 1.70+
- Cargo

### Setup and Run

1. **Navigate to the example directory:**
   ```bash
   cd examples/advanced_sqlite_bearer
   ```

2. **Install dependencies:**
   ```bash
   cargo build
   ```

3. **Run the server:**
   ```bash
   cargo run
   ```

4. **Open your browser:**
   Navigate to `http://127.0.0.1:8080`

The server will:
- Create a SQLite database file (`users.db`) in the current directory
- Automatically run database migrations
- Serve the web interface on port 8080

## 📚 API Documentation

### Authentication Endpoints

All authentication endpoints are prefixed with `/auth`:

#### Register User
```http
POST /auth/register
Content-Type: application/json

{
  "email": "user@example.com",      // Optional (either email or username required)
  "username": "johndoe",            // Optional (either email or username required)
  "password": "password123",        // Required (minimum 8 characters)
  "display_name": "John Doe"        // Optional
}
```

**Response:**
```json
{
  "token": "12345678_a1b2c3d4e5f6...",
  "user": {
    "id": "uuid-here",
    "email": "user@example.com",
    "username": "johndoe",
    "display_name": "John Doe",
    "created_at": "2024-01-01T00:00:00Z",
    ...
  }
}
```

#### Login
```http
POST /auth/login
Content-Type: application/json

{
  "identifier": "user@example.com",  // Email or username
  "password": "password123"
}
```

#### Get Profile
```http
GET /auth/profile
Authorization: Bearer <token>
```

#### Logout
```http
POST /auth/logout
Authorization: Bearer <token>
```

### Utility Endpoints

- `GET /health` - Health check
- `GET /api/info` - API documentation

## 🧪 Testing the Implementation

### Using the Web Interface

1. **Register a new user:**
   - Fill in the registration form
   - Either email or username is required
   - Password must be at least 8 characters

2. **Login:**
   - Use either email or username as identifier
   - Enter your password

3. **Test authenticated endpoints:**
   - Get your profile information
   - Logout to revoke the token

### Using curl

```bash
# Register a user
curl -X POST http://127.0.0.1:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "testpass123",
    "display_name": "Test User"
  }'

# Login
curl -X POST http://127.0.0.1:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "identifier": "test@example.com",
    "password": "testpass123"
  }'

# Get profile (replace TOKEN with actual token from login/register)
curl -X GET http://127.0.0.1:8080/auth/profile \
  -H "Authorization: Bearer TOKEN"

# Logout
curl -X POST http://127.0.0.1:8080/auth/logout \
  -H "Authorization: Bearer TOKEN"
```

## 🔧 Implementation Details

### Custom UserStore Implementation

The `SqliteUserStore` demonstrates how to create a custom user storage backend:

```rust
#[async_trait]
impl UserStore for SqliteUserStore {
    async fn find_by_id(&self, id: &str) -> AuthResult<Option<AuthUser>> {
        // SQLite implementation with connection pooling
    }
    
    async fn find_by_email(&self, email: &str) -> AuthResult<Option<AuthUser>> {
        // Email lookup with prepared statements
    }
    
    // ... other methods
}
```

Key features:
- Connection pooling for performance
- Proper error handling and mapping
- Password hashing with Argon2
- Token storage and validation
- Automatic database migrations

### Custom Authentication Strategy

The `BearerAuthStrategy` shows how to implement custom authentication logic:

```rust
#[async_trait(?Send)]
impl AuthStrategy for BearerAuthStrategy {
    fn name(&self) -> &'static str {
        "bearer"
    }

    fn configure(&self, scope: actix_web::Scope) -> actix_web::Scope {
        // Configure routes for registration, login, etc.
    }

    async fn authenticate(&self, req: &HttpRequest) -> Option<AuthUser> {
        // Extract and validate Bearer token
    }
}
```

Key features:
- Bearer token extraction from headers
- Token validation against database
- Custom route handlers for auth operations
- Comprehensive error responses

### Security Considerations

- **Password Hashing**: Uses Argon2 for secure password storage
- **Token Generation**: Cryptographically secure random tokens
- **SQL Injection Protection**: All queries use prepared statements
- **Error Handling**: Detailed error responses without information leakage
- **Token Revocation**: Supports token invalidation on logout

## 🎯 Key Learning Points

This example demonstrates:

1. **Custom UserStore Implementation**:
   - How to implement the `UserStore` trait
   - Database connection management
   - Migration system implementation
   - Error handling patterns

2. **Custom Authentication Strategy**:
   - How to implement the `AuthStrategy` trait
   - Bearer token authentication flow
   - Custom route configuration
   - Request/response handling

3. **Integration Patterns**:
   - How to compose custom components
   - Service layer architecture
   - Dependency injection with Actix Web

4. **Production Considerations**:
   - Connection pooling
   - Error handling
   - Security best practices
   - Testing strategies

## 📝 Extending the Example

You can extend this example by:

- Adding token expiration and refresh
- Implementing role-based authorization
- Adding OAuth provider integration
- Implementing rate limiting
- Adding audit logging
- Supporting multiple database backends
- Adding comprehensive test coverage

## 📄 Dependencies

Key dependencies used in this example:

- `actix-passport` - The authentication framework
- `rusqlite` - SQLite database driver
- `r2d2` / `r2d2_sqlite` - Connection pooling
- `argon2` - Password hashing
- `uuid` - Unique identifier generation
- `chrono` - Date/time handling
- `serde` / `serde_json` - Serialization

This example provides a solid foundation for building production-ready authentication systems with custom storage backends and authentication strategies.