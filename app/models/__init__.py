"""
Database Models

This package contains all SQLAlchemy database models for the SatyaLens application:
- User management models
- Protection and security models
- Application settings models
- Logging and statistics models
"""

# Import all models to ensure they're registered with SQLAlchemy
from .user import User, AppSetting, UserSession
from .protection import (
    ProtectionLog,
    ThreatSignature, 
    UserFeedback,
    BlockedContent,
    ProtectionStats
)

# Export all models
__all__ = [
    # User models
    "User",
    "AppSetting", 
    "UserSession",
    
    # Protection models
    "ProtectionLog",
    "ThreatSignature",
    "UserFeedback", 
    "BlockedContent",
    "ProtectionStats",
]

# Model registry for easy access
MODEL_REGISTRY = {
    # User Management
    "user": User,
    "app_setting": AppSetting,
    "user_session": UserSession,
    
    # Protection System
    "protection_log": ProtectionLog,
    "threat_signature": ThreatSignature,
    "user_feedback": UserFeedback,
    "blocked_content": BlockedContent,
    "protection_stats": ProtectionStats,
}

# Model categories
MODEL_CATEGORIES = {
    "user_management": [User, AppSetting, UserSession],
    "protection_system": [ProtectionLog, ThreatSignature, UserFeedback, BlockedContent],
    "analytics": [ProtectionStats],
}

# Database schema info
SCHEMA_INFO = {
    "total_models": len(__all__),
    "categories": list(MODEL_CATEGORIES.keys()),
    "relationships": [
        "User -> AppSetting (one-to-many)",
        "User -> ProtectionLog (one-to-many)", 
        "User -> UserFeedback (one-to-many)",
        "User -> BlockedContent (one-to-many)",
        "User -> ProtectionStats (one-to-many)",
        "ProtectionLog -> UserFeedback (one-to-many)"
    ]
}