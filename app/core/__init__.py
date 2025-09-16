"""
Core application components

This package contains the fundamental components of the SatyaLens application:
- Configuration management
- Database connections and utilities
- Security and authentication utilities
- Caching mechanisms
- Logging configuration
"""

from .config import settings
from .database import get_db, cache, redis_client, Base

# Export commonly used components
__all__ = [
    # Configuration
    "settings",
    
    # Database
    "get_db",
    "cache", 
    "redis_client",
    "Base",
]

# Core package info
CORE_INFO = {
    "components": [
        "Configuration Management",
        "Database Connection Pool",
        "Redis Caching",
        "JWT Authentication",
        "Rate Limiting",
        "Input Validation",
        "Password Hashing"
    ],
    "databases": ["PostgreSQL", "Redis"],
    "security_features": [
        "JWT tokens",
        "Password hashing",
        "Rate limiting",
        "Input sanitization",
        "API key management"
    ]
}