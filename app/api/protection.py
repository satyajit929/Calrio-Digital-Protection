from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_
from typing import List, Optional
import hashlib
import json
from datetime import datetime, timedelta
from pydantic import BaseModel
import logging

from app.core.database import get_db
from app.api.auth import get_current_user
from app.models.user import User, AppSetting
from app.models.protection import ProtectionLog, ProtectionStats
from app.services.protection_engine import ProtectionEngine

logger = logging.getLogger(__name__)
router = APIRouter()

# Pydantic models
class AppToggleRequest(BaseModel):
    app: str
    enabled: bool

class ContentAnalysisRequest(BaseModel):
    type: str  # message, call, url, etc.
    content: str
    app: str

class ProtectionResponse(BaseModel):
    threat_level: str
    confidence_score: float
    action_taken: str
    categories: List[str] = []
    message: str
    metadata: dict = {}

class ProtectionLogResponse(BaseModel):
    id: int
    app_name: str
    content_type: str
    threat_level: str
    confidence_score: float
    action_taken: str
    created_at: datetime

class ProtectionStatsResponse(BaseModel):
    total_protected: int
    threats_blocked: int
    suspicious_items: int
    apps_protected: int
    period: str
    breakdown: dict

# Utility functions
def calculate_content_hash(content: str) -> str:
    """Calculate hash of content for deduplication"""
    return hashlib.sha256(content.encode()).hexdigest()

# API endpoints
@router.post("/toggle")
async def toggle_app_protection(
    request: AppToggleRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Toggle protection for specific app"""
    
    # Validate app name
    valid_apps = ["whatsapp", "phone", "sms", "email", "telegram"]
    if request.app not in valid_apps:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid app name. Must be one of: {', '.join(valid_apps)}"
        )
    
    # Find or create app setting
    result = await db.execute(
        select(AppSetting).where(
            and_(
                AppSetting.user_id == current_user.id,
                AppSetting.app_name == request.app
            )
        )
    )
    app_setting = result.scalar_one_or_none()
    
    if not app_setting:
        app_setting = AppSetting(
            user_id=current_user.id,
            app_name=request.app,
            is_enabled=request.enabled
        )
        db.add(app_setting)
    else:
        app_setting.is_enabled = request.enabled
        app_setting.updated_at = datetime.utcnow()
    
    await db.commit()
    
    logger.info(f"User {current_user.id} {'enabled' if request.enabled else 'disabled'} protection for {request.app}")
    
    return {
        "success": True,
        "message": f"{request.app} protection {'enabled' if request.enabled else 'disabled'}",
        "app": request.app,
        "enabled": request.enabled
    }

@router.post("/analyze", response_model=ProtectionResponse)
async def analyze_content(
    request: ContentAnalysisRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Analyze content for threats"""
    
    # Check if app protection is enabled
    result = await db.execute(
        select(AppSetting).where(
            and_(
                AppSetting.user_id == current_user.id,
                AppSetting.app_name == request.app
            )
        )
    )
    app_setting = result.scalar_one_or_none()
    
    if not app_setting or not app_setting.is_enabled:
        return ProtectionResponse(
            threat_level="safe",
            confidence_score=0.0,
            action_taken="allowed",
            message=f"Protection not enabled for {request.app}"
        )
    
    # Calculate content hash
    content_hash = calculate_content_hash(request.content)
    
    # Check if we've seen this content before
    result = await db.execute(
        select(ProtectionLog).where(
            and_(
                ProtectionLog.user_id == current_user.id,
                ProtectionLog.content_hash == content_hash,
                ProtectionLog.created_at >= datetime.utcnow() - timedelta(hours=24)
            )
        ).limit(1)
    )
    existing_log = result.scalar_one_or_none()
    
    if existing_log:
        # Return cached result
        return ProtectionResponse(
            threat_level=existing_log.threat_level,
            confidence_score=existing_log.confidence_score,
            action_taken=existing_log.action_taken,
            categories=json.loads(existing_log.threat_categories) if existing_log.threat_categories else [],
            message=f"Cached analysis result for {request.app}",
            metadata=json.loads(existing_log.metadata) if existing_log.metadata else {}
        )
    
    # Analyze content using protection engine
    protection_engine = ProtectionEngine()
    analysis_result = await protection_engine.analyze_content(
        request.type, 
        request.content, 
        request.app
    )
    
    # Log the analysis
    log_entry = ProtectionLog(
        user_id=current_user.id,
        app_name=request.app,
        content_type=request.type,
        content_hash=content_hash,
        threat_level=analysis_result["threat_level"],
        confidence_score=analysis_result["confidence_score"],
        threat_categories=json.dumps(analysis_result.get("categories", [])),
        action_taken=analysis_result["action_taken"],
        metadata=json.dumps(analysis_result.get("metadata", {}))
    )
    db.add(log_entry)
    await db.commit()
    
    logger.info(f"Content analyzed for user {current_user.id}: {analysis_result['threat_level']}")
    
    return ProtectionResponse(**analysis_result)

@router.post("/analyze-file")
async def analyze_file(
    file: UploadFile = File(...),
    app: str = Form(...),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Analyze uploaded file for threats"""
    
    # Check file size
    if file.size > 10 * 1024 * 1024:  # 10MB limit
        raise HTTPException(status_code=413, detail="File too large")
    
    # Check if app protection is enabled
    result = await db.execute(
        select(AppSetting).where(
            and_(
                AppSetting.user_id == current_user.id,
                AppSetting.app_name == app
            )
        )
    )
    app_setting = result.scalar_one_or_none()
    
    if not app_setting or not app_setting.is_enabled:
        return {
            "threat_level": "safe",
            "confidence_score": 0.0,
            "action_taken": "allowed",
            "message": f"Protection not enabled for {app}"
        }
    
    # Read file content
    file_content = await file.read()
    content_hash = hashlib.sha256(file_content).hexdigest()
    
    # Determine file type
    content_type = "image" if file.content_type.startswith("image/") else \
                  "audio" if file.content_type.startswith("audio/") else \
                  "video" if file.content_type.startswith("video/") else "file"
    
    # Analyze file using protection engine
    protection_engine = ProtectionEngine()
    analysis_result = await protection_engine.analyze_file(
        file_content, 
        file.content_type, 
        app
    )
    
    # Log the analysis
    log_entry = ProtectionLog(
        user_id=current_user.id,
        app_name=app,
        content_type=content_type,
        content_hash=content_hash,
        threat_level=analysis_result["threat_level"],
        confidence_score=analysis_result["confidence_score"],
        action_taken=analysis_result["action_taken"],
        metadata=json.dumps({
            "filename": file.filename,
            "content_type": file.content_type,
            "file_size": file.size
        })
    )
    db.add(log_entry)
    await db.commit()
    
    logger.info(f"File analyzed for user {current_user.id}: {analysis_result['threat_level']}")
    
    return analysis_result

@router.get("/history")
async def get_protection_history(
    limit: int = 50,
    app: Optional[str] = None,
    threat_level: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get protection history"""
    
    # Build query
    query = select(ProtectionLog).where(ProtectionLog.user_id == current_user.id)
    
    if app:
        query = query.where(ProtectionLog.app_name == app)
    
    if threat_level:
        query = query.where(ProtectionLog.threat_level == threat_level)
    
    query = query.order_by(ProtectionLog.created_at.desc()).limit(limit)
    
    result = await db.execute(query)
    logs = result.scalars().all()
    
    return [
        ProtectionLogResponse(
            id=log.id,
            app_name=log.app_name,
            content_type=log.content_type,
            threat_level=log.threat_level,
            confidence_score=log.confidence_score,
            action_taken=log.action_taken,
            created_at=log.created_at
        )
        for log in logs
    ]

@router.get("/stats", response_model=ProtectionStatsResponse)
async def get_protection_stats(
    period: str = "24h",  # 24h, 7d, 30d
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get protection statistics"""
    
    # Calculate time range
    if period == "24h":
        start_time = datetime.utcnow() - timedelta(hours=24)
        period_label = "24 hours"
    elif period == "7d":
        start_time = datetime.utcnow() - timedelta(days=7)
        period_label = "7 days"
    elif period == "30d":
        start_time = datetime.utcnow() - timedelta(days=30)
        period_label = "30 days"
    else:
        start_time = datetime.utcnow() - timedelta(hours=24)
        period_label = "24 hours"
    
    # Get total protected count
    total_result = await db.execute(
        select(func.count(ProtectionLog.id)).where(
            and_(
                ProtectionLog.user_id == current_user.id,
                ProtectionLog.created_at >= start_time
            )
        )
    )
    total_protected = total_result.scalar() or 0
    
    # Get threats blocked count
    blocked_result = await db.execute(
        select(func.count(ProtectionLog.id)).where(
            and_(
                ProtectionLog.user_id == current_user.id,
                ProtectionLog.threat_level == "blocked",
                ProtectionLog.created_at >= start_time
            )
        )
    )
    threats_blocked = blocked_result.scalar() or 0
    
    # Get suspicious items count
    suspicious_result = await db.execute(
        select(func.count(ProtectionLog.id)).where(
            and_(
                ProtectionLog.user_id == current_user.id,
                ProtectionLog.threat_level == "suspicious",
                ProtectionLog.created_at >= start_time
            )
        )
    )
    suspicious_items = suspicious_result.scalar() or 0
    
    # Get apps protected count
    apps_result = await db.execute(
        select(func.count(func.distinct(AppSetting.app_name))).where(
            and_(
                AppSetting.user_id == current_user.id,
                AppSetting.is_enabled == True
            )
        )
    )
    apps_protected = apps_result.scalar() or 0
    
    # Get breakdown by app
    breakdown_result = await db.execute(
        select(
            ProtectionLog.app_name,
            func.count(ProtectionLog.id).label("total"),
            func.count(
                func.case(
                    (ProtectionLog.threat_level == "blocked", 1),
                    else_=None
                )
            ).label("blocked")
        ).where(
            and_(
                ProtectionLog.user_id == current_user.id,
                ProtectionLog.created_at >= start_time
            )
        ).group_by(ProtectionLog.app_name)
    )
    
    breakdown = {}
    for row in breakdown_result:
        breakdown[row.app_name] = {
            "protected": row.total,
            "blocked": row.blocked
        }
    
    return ProtectionStatsResponse(
        total_protected=total_protected,
        threats_blocked=threats_blocked,
        suspicious_items=suspicious_items,
        apps_protected=apps_protected,
        period=period_label,
        breakdown=breakdown
    )

@router.get("/apps")
async def get_app_settings(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get all app protection settings"""
    
    result = await db.execute(
        select(AppSetting).where(AppSetting.user_id == current_user.id)
    )
    settings = result.scalars().all()
    
    # Default apps
    default_apps = ["whatsapp", "phone", "sms", "email", "telegram"]
    app_settings = {}
    
    # Initialize with defaults
    for app in default_apps:
        app_settings[app] = {
            "enabled": False,
            "protection_level": "medium",
            "auto_block": True,
            "notifications": True
        }
    
    # Update with user settings
    for setting in settings:
        app_settings[setting.app_name] = {
            "enabled": setting.is_enabled,
            "protection_level": setting.protection_level,
            "auto_block": setting.auto_block,
            "notifications": setting.notifications
        }
    
    return app_settings