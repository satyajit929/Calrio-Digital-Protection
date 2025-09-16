"""
API Routes

This package contains all FastAPI route handlers for the SatyaLens application:
- Authentication endpoints
- Protection system endpoints
- User management endpoints
- File upload and analysis endpoints
"""

from .auth import router as auth_router
from .protection import router as protection_router

# Export all routers
__all__ = [
    "auth_router",
    "protection_router",
]

# Router registry
ROUTER_REGISTRY = {
    "auth": {
        "router": auth_router,
        "prefix": "/api/auth",
        "tags": ["Authentication"],
        "description": "User authentication and authorization endpoints"
    },
    "protection": {
        "router": protection_router, 
        "prefix": "/api/protection",
        "tags": ["Protection"],
        "description": "Digital protection and threat detection endpoints"
    }
}

# API endpoint summary
API_ENDPOINTS = {
    "authentication": [
        "POST /api/auth/register - Register new user",
        "POST /api/auth/login - User login", 
        "GET /api/auth/me - Get current user info",
        "POST /api/auth/logout - User logout"
    ],
    "protection": [
        "POST /api/protection/toggle - Toggle app protection",
        "POST /api/protection/analyze - Analyze content for threats",
        "POST /api/protection/analyze-file - Analyze uploaded files",
        "GET /api/protection/history - Get protection history",
        "GET /api/protection/stats - Get protection statistics",
        "GET /api/protection/apps - Get app settings"
    ]
}

# API features
API_FEATURES = [
    "JWT Authentication",
    "File Upload Support", 
    "Real-time Threat Analysis",
    "Protection Statistics",
    "Multi-app Support",
    "Content Type Detection",
    "Rate Limiting",
    "Input Validation"
]