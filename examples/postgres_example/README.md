# PostgreSQL Example with Diesel

This example demonstrates how to use actix-passport with PostgreSQL as the user store using Diesel ORM.

## Note on Implementation Status

This example is currently a **work in progress** and demonstrates the basic structure for integrating PostgreSQL with actix-passport. Due to some complexity with Diesel's JSON field handling in the current version, this example focuses on the core integration patterns.

## What This Example Shows

- PostgreSQL database schema design for actix-passport
- Diesel migration setup
- Basic PostgreSQL UserStore trait implementation structure
- Docker setup for development
- Complete project structure for production use

## For a Working Example

For a fully functional example, please see:
- `../basic_password_example/` - Complete working example with in-memory storage
- `../basic_oauth_example/` - OAuth integration example

## Features Demonstrated

- PostgreSQL database with Diesel ORM setup
- Database migrations with proper schema
- Connection pooling configuration
- Docker development environment
- Production-ready project structure

## Prerequisites

- Rust 1.75+
- PostgreSQL 12+ (or use Docker)
- Diesel CLI

## Quick Start with Docker

1. **Start PostgreSQL:**
   ```bash
   docker-compose up postgres
   ```

2. **Run migrations:**
   ```bash
   diesel migration run
   ```

3. **View the database schema:**
   ```bash
   diesel print-schema
   ```

## Database Schema

The example includes a comprehensive PostgreSQL schema:

```sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR UNIQUE,
    username VARCHAR UNIQUE,
    display_name VARCHAR,
    avatar_url VARCHAR,
    password_hash VARCHAR,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_login TIMESTAMP WITH TIME ZONE,
    metadata JSONB DEFAULT '{}'::JSONB,
);

-- Performance indexes
CREATE INDEX idx_users_email ON users(email) WHERE email IS NOT NULL;
CREATE INDEX idx_users_username ON users(username) WHERE username IS NOT NULL;
CREATE INDEX idx_users_created_at ON users(created_at);
```

## Project Structure

```
postgres_example/
├── Cargo.toml              # Dependencies including Diesel
├── diesel.toml             # Diesel configuration
├── .env                    # Environment variables
├── docker-compose.yml      # Docker setup
├── migrations/             # Database migrations
│   └── 2025-07-03-create_users/
│       ├── up.sql         # Create tables
│       └── down.sql       # Drop tables
└── src/
    ├── main.rs            # Application entry point
    ├── models.rs          # Diesel models
    ├── schema.rs          # Generated schema
    └── user_store.rs      # PostgreSQL UserStore implementation
```

## Key Implementation Patterns

### 1. Database Connection Pool

```rust
use diesel_async::{
    pooled_connection::{bb8::Pool, AsyncDieselConnectionManager},
    AsyncPgConnection,
};

type DbPool = Pool<AsyncPgConnection>;

impl PostgresUserStore {
    pub async fn create_pool(database_url: &str) -> Result<DbPool, Box<dyn std::error::Error>> {
        let config = AsyncDieselConnectionManager::<AsyncPgConnection>::new(database_url);
        let pool = Pool::builder().build(config).await?;
        Ok(pool)
    }
}
```

### 2. UserStore Implementation

```rust
#[async_trait]
impl UserStore for PostgresUserStore {
    async fn find_by_id(&self, id: &str) -> AuthResult<Option<AuthUser>> {
        let user_id = Uuid::parse_str(id)?;
        let mut conn = self.pool.get().await?;
        
        let user = users::table
            .find(user_id)
            .first::<User>(&mut conn)
            .await
            .optional()?;
            
        match user {
            Some(user) => Ok(Some(convert_to_auth_user(user)?)),
            None => Ok(None),
        }
    }
    
    // ... other required methods
}
```

### 3. Migration Management

```bash
# Create new migration
diesel migration generate add_new_field

# Run migrations
diesel migration run

# Revert last migration
diesel migration revert

# Check migration status
diesel migration list
```

## Production Considerations

### Security
- Use connection pooling to prevent connection exhaustion
- Enable SSL for database connections in production
- Use environment variables for sensitive configuration
- Implement proper backup and recovery procedures

### Performance
- Tune connection pool settings based on load
- Monitor query performance and add indexes as needed
- Consider read replicas for high-traffic applications
- Use JSONB for flexible metadata storage with GIN indexes

### Monitoring
- Set up database monitoring and alerting
- Track connection pool utilization
- Monitor slow queries and optimize as needed
- Implement health checks for database connectivity

## Environment Configuration

Create a `.env` file:

```env
DATABASE_URL=postgres://username:password@localhost:5432/database_name
RUST_LOG=debug
```

## Docker Development

The included `docker-compose.yml` provides:
- PostgreSQL 15 with proper configuration
- Automatic database initialization
- Volume persistence for development
- Health checks for reliable startup

## Next Steps

To complete this implementation:

1. **Resolve Diesel JSON handling** - Update to newer Diesel version or implement custom serialization
2. **Add comprehensive error handling** - Implement proper database error mapping
3. **Add integration tests** - Test all UserStore methods with real database
4. **Performance optimization** - Add query optimization and monitoring
5. **Security hardening** - Implement connection encryption and access controls

## Alternative Approaches

For immediate use, consider these alternatives:

1. **SQLx instead of Diesel** - More flexible with async and JSON handling
2. **In-memory development** - Use InMemoryUserStore for rapid development
3. **Simplified schema** - Remove JSON fields until Diesel support improves

## Resources

- [Diesel Documentation](https://diesel.rs/)
- [PostgreSQL JSON Documentation](https://www.postgresql.org/docs/current/datatype-json.html)
- [actix-passport Documentation](../../README.md)
- [Docker PostgreSQL](https://hub.docker.com/_/postgres)