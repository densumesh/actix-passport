# Email Example - Actix Passport

This example demonstrates how to use actix-passport with email functionality including:

- Email verification for new user registrations
- Password reset via email
- SMTP configuration with Fastmail
- Custom API endpoints alongside built-in authentication routes

## Features Demonstrated

- **Email Verification**: Users receive an email with a verification token after registration
- **Password Reset**: Users can request password reset emails with secure tokens
- **SMTP Integration**: Uses Fastmail SMTP service for email delivery
- **Dual API Design**: Shows both custom API endpoints and built-in authentication routes
- **Security Best Practices**: No information leakage about user existence in password reset

## Setup

1. **Install dependencies**:
   ```bash
   cd examples/email_example
   cargo build
   ```

2. **Configure environment variables**:
   ```bash
   cp .env.example .env
   # Edit .env with your actual SMTP credentials
   ```

3. **Run the application**:
   ```bash
   cargo run
   ```

   The server will start at `http://localhost:8080`

## Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `SMTP_HOST` | SMTP server hostname | `smtp.fastmail.com` |
| `SMTP_PORT` | SMTP server port | `587` |
| `SMTP_USER` | SMTP username | `contact@vidyoot.dev` |
| `SMTP_PASSWORD` | SMTP password | `your-app-password` |
| `SMTP_FROM_ADDRESS` | From email address | `contact@vidyoot.dev` |
| `BASE_URL` | Base URL for email links | `http://localhost:8080` |
| `RUST_LOG` | Log level | `debug` |

## API Endpoints

### Custom API Routes (`/api/`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Health check |
| `POST` | `/api/register` | Register a new user |
| `POST` | `/api/login` | Login user |
| `POST` | `/api/verify-email` | Verify email with token |
| `POST` | `/api/forgot-password` | Send password reset email |
| `POST` | `/api/reset-password` | Reset password with token |

### Built-in Authentication Routes (`/auth/`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/auth/register` | Built-in register endpoint |
| `POST` | `/auth/login` | Built-in login endpoint |
| `POST` | `/auth/verify-email` | Built-in email verification |
| `POST` | `/auth/forgot-password` | Built-in forgot password |
| `POST` | `/auth/reset-password` | Built-in reset password |

## Usage Examples

### 1. Register a New User (Custom API)

```bash
curl -X POST http://localhost:8080/api/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "secure_password123",
    "username": "johndoe"
  }'
```

**Response:**
```json
{
  "success": true,
  "message": "User registered successfully. Please check your email for verification.",
  "data": {
    "user_id": "uuid-here",
    "email": "user@example.com",
    "username": "johndoe",
    "is_email_verified": false
  }
}
```

### 2. Verify Email

```bash
curl -X POST http://localhost:8080/api/verify-email \
  -H "Content-Type: application/json" \
  -d '{
    "token": "verification-token-from-email"
  }'
```

### 3. Request Password Reset

```bash
curl -X POST http://localhost:8080/api/forgot-password \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com"
  }'
```

### 4. Reset Password

```bash
curl -X POST http://localhost:8080/api/reset-password \
  -H "Content-Type: application/json" \
  -d '{
    "token": "reset-token-from-email",
    "new_password": "new_secure_password123"
  }'
```

## Email Templates

The example uses the default email templates provided by actix-passport:

- **Verification Email**: Contains a link with the verification token
- **Password Reset Email**: Contains a link with the password reset token

Both templates are responsive and include security best practices.

## Security Features

- **Token Validation**: All email tokens are HMAC-signed and have expiration times
- **No Information Leakage**: Password reset doesn't reveal if an email exists
- **Secure Headers**: SMTP connections use TLS/STARTTLS
- **Rate Limiting**: Email service includes built-in rate limiting

## Development Notes

- Uses in-memory user store for simplicity (data is lost on restart)
- SMTP credentials are provided as example (replace with your own)
- In production, use secure random keys for session management
- Consider implementing proper password hashing validation in the login endpoint

## Production Considerations

1. **Database**: Replace `InMemoryUserStore` with `PostgresUserStore` or custom implementation
2. **Environment**: Use proper environment variable management
3. **Security**: Use secure random keys for sessions and email tokens
4. **Logging**: Configure appropriate log levels for production
5. **Rate Limiting**: Implement additional rate limiting for API endpoints
6. **HTTPS**: Use HTTPS in production for secure email links

## Troubleshooting

### Email Not Sending

1. Check SMTP credentials in `.env`
2. Verify SMTP server allows your IP
3. Check firewall settings for port 587
4. Review application logs for detailed error messages

### Token Validation Failures

1. Check that `BASE_URL` matches your server URL
2. Verify token hasn't expired (default: 1 hour)
3. Ensure email service secret key is consistent

### Connection Issues

1. Verify SMTP server is reachable
2. Check for corporate firewall restrictions
3. Try different SMTP ports (25, 465, 587)