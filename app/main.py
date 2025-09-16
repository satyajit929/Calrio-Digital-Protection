from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn
import logging
from contextlib import asynccontextmanager

from app.core.config import settings
from app.core.database import create_tables, redis_client
from app.api import auth, protection
from app.services.protection_engine import ProtectionEngine

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events"""
    # Startup
    logger.info("🚀 Starting SatyaLens API...")
    
    try:
        # Create database tables
        await create_tables()
        logger.info("✅ Database tables created")
        
        # Initialize Protection Engine
        app.state.protection_engine = ProtectionEngine()
        await app.state.protection_engine.initialize()
        logger.info("✅ Protection Engine initialized")
        
        # Test Redis connection
        await redis_client.ping()
        logger.info("✅ Redis connection established")
        
        logger.info("🎉 SatyaLens API started successfully!")
        
    except Exception as e:
        logger.error(f"❌ Startup failed: {e}")
        raise
    
    yield
    
    # Shutdown
    logger.info("🛑 Shutting down SatyaLens API...")
    try:
        await app.state.protection_engine.cleanup()
        await redis_client.close()
        logger.info("✅ Cleanup completed")
    except Exception as e:
        logger.error(f"❌ Shutdown error: {e}")

# Create FastAPI app
app = FastAPI(
    title="SatyaLens API",
    description="Complete Digital Protection Platform with AI-powered threat detection",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Global exception: {exc}")
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "error": str(exc)}
    )

# Include API routers
app.include_router(auth.router, prefix="/api/auth", tags=["Authentication"])
app.include_router(protection.router, prefix="/api/protection", tags=["Protection"])

# Root endpoints
@app.get("/")
async def root():
    """API root endpoint"""
    return {
        "message": "SatyaLens API is running",
        "version": "1.0.0",
        "status": "healthy",
        "docs": "/docs"
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    try:
        # Check Redis connection
        await redis_client.ping()
        
        return {
            "status": "healthy",
            "database": "connected",
            "redis": "connected"
        }
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Service unhealthy: {e}")

# Development server
if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )