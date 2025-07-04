-- Migration 002: Add indexes for performance
-- This migration adds indexes for common query patterns

CREATE INDEX IF NOT EXISTS idx_users_email ON auth.users(email) WHERE email IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_users_username ON auth.users(username) WHERE username IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_users_created_at ON auth.users(created_at);
CREATE INDEX IF NOT EXISTS idx_users_metadata ON auth.users USING GIN(metadata);
