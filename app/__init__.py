"""
SatyaLens Backend Application
Complete Digital Protection Platform with AI-powered threat detection

This package contains the main FastAPI application for SatyaLens,
providing comprehensive digital protection across multiple platforms.
"""

__version__ = "1.0.0"
__author__ = "SatyaLens Team"
__description__ = "AI-powered digital protection platform"

# Package metadata
__all__ = [
    "__version__",
    "__author__",
    "__description__",
]

# Application info
APP_INFO = {
    "name": "SatyaLens API",
    "version": __version__,
    "description": __description__,
    "author": __author__,
    "supported_apps": ["whatsapp", "phone", "sms", "email", "telegram"],
    "supported_content": ["message", "call", "url", "image", "audio", "video"],
    "features": [
        "AI-powered threat detection",
        "Real-time protection",
        "Multi-app support",
        "File analysis",
        "User authentication",
        "Protection statistics"
    ]
}