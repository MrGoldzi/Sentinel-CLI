"""Configuration file with deliberate secrets exposed for testing Sentinel."""

import os

# AWS Credentials (test values - not real)
# All secrets in this file are INTENTIONAL TEST PLACEHOLDERS.
# They are used to verify Sentinel's secrets scanner detects them.

# AWS Credentials (test placeholders - not real credentials)
AWS_ACCESS_KEY_ID = "SENTINEL_TEST_AWS_ACCESS_KEY_ID_PLACEHOLDER"
AWS_SECRET_ACCESS_KEY = "SENTINEL_TEST_AWS_SECRET_KEY_PLACEHOLDER"

# API Keys
API_KEY = "SENTINEL_TEST_API_KEY_PLACEHOLDER"
GITHUB_TOKEN = "SENTINEL_TEST_GITHUB_TOKEN_PLACEHOLDER"
SLACK_TOKEN = "SENTINEL_TEST_SLACK_TOKEN_PLACEHOLDER"

# Private key (test/example key - not real)
PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
SENTINEL_TEST_PRIVATE_KEY_LINE_1
SENTINEL_TEST_PRIVATE_KEY_LINE_2
-----END RSA PRIVATE KEY-----"""

# JWT token (example - not real)
JWT_TOKEN = "SENTINEL_TEST_JWT_TOKEN_HEADER.SENTINEL_TEST_JWT_TOKEN_PAYLOAD.SENTINEL_TEST_JWT_TOKEN_SIGNATURE"

# Google API key (test value)
GOOGLE_API_KEY = "SENTINEL_TEST_GOOGLE_API_KEY_PLACEHOLDER"

# Database configuration
DB_PASSWORD = "SENTINEL_TEST_DB_PASSWORD_PLACEHOLDER"
SECRET_KEY = "SENTINEL_TEST_SECRET_KEY_PLACEHOLDER"

# PostgreSQL connection string with embedded credentials
DATABASE_URL = "postgresql://SENTINEL_TEST_USER:SENTINEL_TEST_PASS@localhost:5432/SENTINEL_TEST_DB"

# Redis connection string
REDIS_URL = "redis://:SENTINEL_TEST_REDIS_PASS@localhost:6379/0"

# Heroku API key
HEROKU_API_KEY = "SENTINEL_TEST_HEROKU_API_KEY_PLACEHOLDER"

# Generic token
AUTH_TOKEN = "SENTINEL_TEST_AUTH_TOKEN_PLACEHOLDER"
