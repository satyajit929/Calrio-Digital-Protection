from sqlalchemy import Column, Integer, String, DateTime, Float, ForeignKey, Text, Boolean
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.core.database import Base

class ProtectionLog(Base):
    __tablename__ = "protection_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    app_name = Column(String(50), nullable=False)  # whatsapp, phone, sms, email, telegram
    content_type = Column(String(20), nullable=False)  # message, call, image, url, audio, video
    content_hash = Column(String(64))  # Hash of content for deduplication
    threat_level = Column(String(20), nullable=False)  # safe, suspicious, blocked
    confidence_score = Column(Float, default=0.0)  # 0.0 to 1.0
    threat_categories = Column(Text)  # JSON array of detected threat types
    action_taken = Column(String(50))  # blocked, flagged, allowed, quarantined
    metadata = Column(Text)  # JSON metadata about the analysis
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    user = relationship("User", back_populates="protection_logs")

class ThreatSignature(Base):
    __tablename__ = "threat_signatures"
    
    id = Column(Integer, primary_key=True, index=True)
    signature_type = Column(String(20), nullable=False)  # text, url, phone, image
    signature_hash = Column(String(64), unique=True, nullable=False)
    threat_category = Column(String(50), nullable=False)  # phishing, spam, fraud, malware
    confidence_score = Column(Float, nullable=False)  # Base confidence for this signature
    pattern = Column(Text)  # The actual pattern or signature
    is_active = Column(Boolean, default=True)
    source = Column(String(100))  # Where this signature came from
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

class UserFeedback(Base):
    __tablename__ = "user_feedback"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    protection_log_id = Column(Integer, ForeignKey("protection_logs.id"), nullable=False)
    feedback_type = Column(String(20), nullable=False)  # correct, incorrect, false_positive
    user_rating = Column(Integer)  # 1-5 rating
    comments = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    user = relationship("User")
    protection_log = relationship("ProtectionLog")

class BlockedContent(Base):
    __tablename__ = "blocked_content"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    content_hash = Column(String(64), nullable=False)
    content_type = Column(String(20), nullable=False)
    app_name = Column(String(50), nullable=False)
    threat_level = Column(String(20), nullable=False)
    block_reason = Column(Text)
    is_permanent = Column(Boolean, default=False)
    expires_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    user = relationship("User")

class ProtectionStats(Base):
    __tablename__ = "protection_stats"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    date = Column(DateTime(timezone=True), nullable=False)
    app_name = Column(String(50), nullable=False)
    total_processed = Column(Integer, default=0)
    threats_detected = Column(Integer, default=0)
    threats_blocked = Column(Integer, default=0)
    false_positives = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    
    # Relationships
    user = relationship("User")