from pydantic_settings import BaseSettings
from typing import Optional, List
from pathlib import Path

class Settings(BaseSettings):
    """Application settings"""
    
    # Application
    APP_NAME: str = "SatyaLens API"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    
    # Database
    DATABASE_URL: str = "postgresql+asyncpg://postgres:password@localhost:5432/satyalens"
    
    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"
    REDIS_EXPIRE_TIME: int = 3600
    
    # Security
    SECRET_KEY: str = "your-super-secret-key-change-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    
    # File upload
    MAX_FILE_SIZE: int = 10 * 1024 * 1024  # 10MB
    ALLOWED_FILE_TYPES: List[str] = [
        "image/jpeg", "image/png", "image/gif",
        "audio/mpeg", "audio/wav",
        "video/mp4", "video/avi"
    ]
    UPLOAD_DIR: str = "uploads"
    
    # AI/ML Settings
    HUGGINGFACE_API_KEY: Optional[str] = None
    MODEL_CACHE_DIR: str = "models"
    
    # Google Cloud
    GOOGLE_CLOUD_PROJECT: Optional[str] = None
    CLOUD_SQL_CONNECTION_NAME: Optional[str] = None
    
    # Protection Engine
    THREAT_DETECTION_THRESHOLD: float = 0.7
    AUTO_BLOCK_THRESHOLD: float = 0.9
    
    class Config:
        env_file = ".env"
        case_sensitive = True
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        
        # Create directories
        Path(self.UPLOAD_DIR).mkdir(parents=True, exist_ok=True)
        Path(self.MODEL_CACHE_DIR).mkdir(parents=True, exist_ok=True)
    
    @property
    def is_production(self) -> bool:
        """Check if running in production"""
        return self.GOOGLE_CLOUD_PROJECT is not None

# Create settings instance
settings = Settings()

