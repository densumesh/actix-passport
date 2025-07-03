FROM rust:1.75

# Install diesel CLI
RUN cargo install diesel_cli --no-default-features --features postgres

WORKDIR /app

# Copy manifests
COPY Cargo.toml ./
COPY src/ ./src/
COPY migrations/ ./migrations/
COPY diesel.toml ./
COPY .env ./

# Build dependencies (this will be cached unless Cargo.toml changes)
RUN cargo build --release

# Run migrations and start the app
CMD diesel migration run && cargo run --release