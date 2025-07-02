
# Actix Passport

## Project Overview

Actix Passport is a flexible and extensible authentication framework for the Actix-web framework in Rust. It provides a comprehensive set of features for handling various authentication strategies, making it easier to secure web applications.

The project is structured to be modular and customizable, allowing developers to plug in their own components, such as user stores and session stores, to integrate with different database systems and session management strategies.

## Key Features

- **Multiple Authentication Strategies:**
  - **Password-based:** Securely handles username/password authentication using Argon2 for password hashing.
  - **OAuth 2.0:** Supports popular OAuth providers like Google and GitHub, with an extensible system for adding custom providers.
  - **JWT (JSON Web Tokens):** Provides middleware for stateless authentication using JWTs.
  - **Session-based:** Manages user sessions with persistent or cookie-based session stores.

- **Pluggable Architecture:**
  - **User Stores:** A `UserStore` trait allows for easy integration with any database or storage system for user data.
  - **Session Stores:** A `SessionStore` trait enables the use of different session management backends.
  - **Password Hashers:** A `PasswordHasher` trait allows for the use of custom password hashing algorithms.

- **Developer-Friendly API:**
  - **Builder Pattern:** A `AuthBuilder` provides a fluent interface for configuring the authentication middleware.
  - **Type-safe Extractors:** `AuthenticatedUser` and `OptionalAuthenticatedUser` extractors for use in Actix-web handlers.
  - **Feature Flags:** Allows for enabling or disabling specific authentication features (`password`, `oauth`, `jwt`).

## Codebase Structure

The codebase is organized into the following modules:

- `src/core`: Contains the core authentication logic and traits.
- `src/middleware`: Implements the Actix-web middleware for handling authentication.
- `src/oauth`: Provides the implementation for OAuth 2.0 authentication, including providers for Google and GitHub.
- `src/password`: Handles password-based authentication, including password hashing and verification.
- `src/errors.rs`: Defines custom error types for the application.
- `src/types.rs`: Contains the data structures and types used throughout the application.
- `src/lib.rs`: The main library crate that ties all the modules together.

## How to Run

To run the project, you can use the following command:

```bash
cargo run
```

To run the tests, use:

```bash
cargo test
```

## Dependencies

The project relies on several key dependencies:

- `actix-web`: The web framework for which this authentication library is built.
- `actix-session`: For session management.
- `serde`: For serialization and deserialization of data.
- `jsonwebtoken`: For handling JWTs.
- `reqwest`: For making HTTP requests, used in the OAuth flow.
- `argon2`: For password hashing.
