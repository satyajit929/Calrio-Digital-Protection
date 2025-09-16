from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
import redis.asyncio as redis
import logging
from typing import AsyncGenerator

from app.core.config import settings

logger = logging.getLogger(__name__)

# Database engine
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
    future=True
)

# Session factory
AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False
)

# Base class for models
Base = declarative_base()

# Redis client
redis_client = redis.from_url(
    settings.REDIS_URL,
    encoding="utf-8",
    decode_responses=True
)

async def create_tables():
    """Create all database tables"""
    try:
        async with engine.begin() as conn:
            # Import models to register them
            from app.models import user, protection
            
            # Create all tables
            await conn.run_sync(Base.metadata.create_all)
            logger.info("✅ Database tables created successfully")
            
    except Exception as e:
        logger.error(f"❌ Failed to create database tables: {e}")
        raise

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency to get database session"""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception as e:
            await session.rollback()
            logger.error(f"Database session error: {e}")
            raise
        finally:
            await session.close()

# Cache utilities
class CacheManager:
    """Redis cache management"""
    
    @staticmethod
    async def get(key: str):
        """Get value from cache"""
        try:
            return await redis_client.get(key)
        except Exception as e:
            logger.error(f"Cache get error: {e}")
            return None
    
    @staticmethod
    async def set(key: str, value: str, expire: int = None):
        """Set value in cache"""
        try:
            expire = expire or settings.REDIS_EXPIRE_TIME
            await redis_client.setex(key, expire, value)
        except Exception as e:
            logger.error(f"Cache set error: {e}")
    
    @staticmethod
    async def delete(key: str):
        """Delete key from cache"""
        try:
            await redis_client.delete(key)
        except Exception as e:
            logger.error(f"Cache delete error: {e}")

# Initialize cache manager
cache = CacheManager()

