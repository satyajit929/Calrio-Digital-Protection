"""
Test Suite

This package contains all tests for the SatyaLens application:
- Unit tests
- Integration tests  
- API endpoint tests
- Database tests
- Security tests
"""

# Test configuration
TEST_CONFIG = {
    "test_database_url": "postgresql+asyncpg://postgres:password@localhost:5432/satyalens_test",
    "test_redis_url": "redis://localhost:6379/1",
    "test_secret_key": "test-secret-key-for-testing-only",
    "test_user_email": "test@satyalens.com",
    "test_user_password": "TestPassword123!"
}

# Test categories
TEST_CATEGORIES = {
    "unit_tests": [
        "Model tests",
        "Service tests",
        "Utility tests",
        "Security tests"
    ],
    "integration_tests": [
        "Database integration",
        "Redis integration", 
        "API integration",
        "Protection engine integration"
    ],
    "api_tests": [
        "Authentication tests",
        "Protection endpoint tests",
        "File upload tests",
        "Error handling tests"
    ]
}

# Test utilities
__all__ = [
    "TEST_CONFIG",
    "TEST_CATEGORIES"
]