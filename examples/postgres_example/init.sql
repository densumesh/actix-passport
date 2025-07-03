-- This file is run when the PostgreSQL container starts
-- It ensures the database exists and has the required extensions

CREATE DATABASE actix_passport_example;
\c actix_passport_example;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";