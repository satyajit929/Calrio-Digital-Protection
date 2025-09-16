import re
import asyncio
import hashlib
from typing import Dict, Any, List
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class ProtectionEngine:
    """AI-powered protection engine for threat detection"""
    
    def __init__(self):
        self.threat_patterns = {
            "phishing": [
                r"urgent.*account.*suspend",
                r"verify.*identity.*immediately",
                r"click.*link.*expire",
                r"bank.*account.*frozen",
                r"security.*alert.*verify",
                r"suspended.*account.*verify",
                r"confirm.*identity.*24.*hours"
            ],
            "fraud": [
                r"congratulations.*won.*prize",
                r"lottery.*winner.*claim",
                r"send.*money.*emergency",
                r"inheritance.*million.*dollars",
                r"prince.*nigeria.*money",
                r"tax.*refund.*claim.*now",
                r"covid.*relief.*fund"
            ],
            "spam": [
                r"buy.*now.*limited.*time",
                r"free.*gift.*no.*cost",
                r"earn.*money.*home",
                r"lose.*weight.*fast",
                r"miracle.*cure.*disease",
                r"make.*money.*online"
            ],
            "malware": [
                r"download.*app.*win",
                r"install.*software.*free",
                r"update.*flash.*player",
                r"virus.*detected.*clean"
            ]
        }
        
        self.suspicious_domains = [
            "bit.ly", "tinyurl.com", "t.co", "goo.gl",
            "ow.ly", "is.gd", "buff.ly"
        ]
        
        self.spam_phone_patterns = [
            r"^\+1234567890$",  # Test numbers
            r"^\+9876543210$",
            r"^0000000000$",
            r"^1111111111$"
        ]
        
        self.initialized = False
    
    async def initialize(self):
        """Initialize the protection engine"""
        try:
            logger.info("🔧 Initializing Protection Engine...")
            
            # Load threat signatures
            await self._load_threat_signatures()
            
            # Initialize ML models (placeholder)
            await self._initialize_ml_models()
            
            self.initialized = True
            logger.info("✅ Protection Engine initialized successfully")
            
        except Exception as e:
            logger.error(f"❌ Failed to initialize Protection Engine: {e}")
            raise
    
    async def cleanup(self):
        """Cleanup resources"""
        try:
            logger.info("🧹 Cleaning up Protection Engine...")
            self.initialized = False
            logger.info("✅ Protection Engine cleanup completed")
        except Exception as e:
            logger.error(f"❌ Protection Engine cleanup error: {e}")
    
    async def analyze_content(self, content_type: str, content: str, app_name: str) -> Dict[str, Any]:
        """Main content analysis function"""
        if not self.initialized:
            await self.initialize()
        
        try:
            if content_type == "message":
                return await self._analyze_text(content, app_name)
            elif content_type == "url":
                return await self._analyze_url(content, app_name)
            elif content_type == "call":
                return await self._analyze_phone(content, app_name)
            elif content_type == "email":
                return await self._analyze_email(content, app_name)
            else:
                return {
                    "threat_level": "safe",
                    "confidence_score": 0.0,
                    "action_taken": "allowed",
                    "categories": [],
                    "message": f"Content type '{content_type}' analysis not supported yet",
                    "metadata": {"content_type": content_type}
                }
        except Exception as e:
            logger.error(f"Content analysis error: {e}")
            return {
                "threat_level": "safe",
                "confidence_score": 0.0,
                "action_taken": "allowed",
                "categories": [],
                "message": "Analysis failed, content allowed by default",
                "metadata": {"error": str(e)}
            }
    
    async def analyze_file(self, file_content: bytes, content_type: str, app_name: str) -> Dict[str, Any]:
        """Analyze file content for threats"""
        try:
            if content_type.startswith("image/"):
                return await self._analyze_image(file_content, app_name)
            elif content_type.startswith("audio/"):
                return await self._analyze_audio(file_content, app_name)
            elif content_type.startswith("video/"):
                return await self._analyze_video(file_content, app_name)
            else:
                return await self._analyze_generic_file(file_content, content_type, app_name)
        except Exception as e:
            logger.error(f"File analysis error: {e}")
            return {
                "threat_level": "safe",
                "confidence_score": 0.0,
                "action_taken": "allowed",
                "message": "File analysis failed, allowed by default",
                "metadata": {"error": str(e)}
            }
    
    async def _analyze_text(self, text: str, app_name: str) -> Dict[str, Any]:
        """Analyze text content for threats"""
        threat_score = 0.0
        detected_threats = []
        risk_factors = []
        
        # Convert to lowercase for analysis
        text_lower = text.lower()
        
        # Check against threat patterns
        for category, patterns in self.threat_patterns.items():
            category_score = 0.0
            for pattern in patterns:
                if re.search(pattern, text_lower, re.IGNORECASE):
                    category_score += 0.3
                    risk_factors.append(f"Detected {category} pattern")
            
            if category_score > 0:
                detected_threats.append(category)
                threat_score += min(category_score, 0.8)  # Cap per category
        
        # Check for urgency indicators
        urgency_patterns = [
            r"urgent", r"immediate", r"expire", r"limited time",
            r"act now", r"hurry", r"deadline", r"last chance"
        ]
        urgency_score = 0.0
        for pattern in urgency_patterns:
            if re.search(pattern, text_lower):
                urgency_score += 0.1
                risk_factors.append("Urgency language detected")
        
        threat_score += min(urgency_score, 0.3)
        
        # Check for suspicious URLs
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        urls = re.findall(url_pattern, text)
        
        for url in urls:
            url_score = await self._analyze_url_in_text(url)
            threat_score += url_score
            if url_score > 0.3:
                risk_factors.append("Suspicious URL detected")
        
        # Check for phone numbers
        phone_pattern = r'[\+]?[1-9]?[0-9]{7,15}'
        phones = re.findall(phone_pattern, text)
        
        for phone in phones:
            phone_score = await self._analyze_phone_in_text(phone)
            threat_score += phone_score
            if phone_score > 0.3:
                risk_factors.append("Suspicious phone number")
        
        # Determine final threat level
        threat_score = min(threat_score, 1.0)  # Cap at 1.0
        
        if threat_score >= 0.9:
            threat_level = "blocked"
            action_taken = "blocked"
            message = "High-risk content detected and blocked"
        elif threat_score >= 0.6:
            threat_level = "suspicious"
            action_taken = "flagged"
            message = "Suspicious content flagged for review"
        else:
            threat_level = "safe"
            action_taken = "allowed"
            message = "Content appears safe"
        
        return {
            "threat_level": threat_level,
            "confidence_score": threat_score,
            "action_taken": action_taken,
            "categories": detected_threats,
            "message": f"{message} for {app_name}",
            "metadata": {
                "risk_factors": risk_factors,
                "urls_found": len(urls),
                "phones_found": len(phones),
                "text_length": len(text)
            }
        }
    
    async def _analyze_url(self, url: str, app_name: str) -> Dict[str, Any]:
        """Analyze URL for threats"""
        threat_score = 0.0
        risk_factors = []
        
        # Check for suspicious domains
        for domain in self.suspicious_domains:
            if domain in url.lower():
                threat_score += 0.4
                risk_factors.append(f"URL shortener detected: {domain}")
        
        # Check for IP addresses instead of domains
        ip_pattern = r'http[s]?://(?:[0-9]{1,3}\.){3}[0-9]{1,3}'
        if re.search(ip_pattern, url):
            threat_score += 0.5
            risk_factors.append("Direct IP address used instead of domain")
        
        # Check for suspicious patterns in URL
        suspicious_url_patterns = [
            r'secure.*bank', r'verify.*account', r'update.*payment',
            r'confirm.*identity', r'suspended.*account'
        ]
        
        for pattern in suspicious_url_patterns:
            if re.search(pattern, url.lower()):
                threat_score += 0.3
                risk_factors.append(f"Suspicious URL pattern: {pattern}")
        
        # Check URL length (very long URLs can be suspicious)
        if len(url) > 200:
            threat_score += 0.2
            risk_factors.append("Unusually long URL")
        
        # Check for multiple subdomains
        domain_parts = url.split('//')[1].split('/')[0] if '//' in url else url.split('/')[0]
        subdomain_count = domain_parts.count('.')
        if subdomain_count > 3:
            threat_score += 0.3
            risk_factors.append("Multiple subdomains detected")
        
        # Determine threat level
        threat_score = min(threat_score, 1.0)
        
        if threat_score >= 0.8:
            threat_level = "blocked"
            action_taken = "blocked"
            message = "Malicious URL blocked"
        elif threat_score >= 0.5:
            threat_level = "suspicious"
            action_taken = "flagged"
            message = "Suspicious URL flagged"
        else:
            threat_level = "safe"
            action_taken = "allowed"
            message = "URL appears safe"
        
        return {
            "threat_level": threat_level,
            "confidence_score": threat_score,
            "action_taken": action_taken,
            "categories": ["malicious_url"] if threat_score > 0.5 else [],
            "message": f"{message} for {app_name}",
            "metadata": {
                "risk_factors": risk_factors,
                "url_length": len(url),
                "subdomain_count": subdomain_count
            }
        }
    
    async def _analyze_phone(self, phone: str, app_name: str) -> Dict[str, Any]:
        """Analyze phone number for spam/fraud"""
        threat_score = 0.0
        risk_factors = []
        
        # Clean phone number
        clean_phone = re.sub(r'[^\d+]', '', phone)
        
        # Check against spam patterns
        for pattern in self.spam_phone_patterns:
            if re.match(pattern, clean_phone):
                threat_score += 0.8
                risk_factors.append("Known spam number pattern")
        
        # Check for invalid formats
        if len(clean_phone) < 10:
            threat_score += 0.4
            risk_factors.append("Invalid phone number format")
        
        # Check for repeated digits
        if len(set(clean_phone.replace('+', ''))) <= 2:
            threat_score += 0.6
            risk_factors.append("Suspicious repeated digits")
        
        # Check for premium rate numbers (example patterns)
        premium_patterns = [r'^\+1900', r'^\+1976', r'^\+44871']
        for pattern in premium_patterns:
            if re.match(pattern, clean_phone):
                threat_score += 0.5
                risk_factors.append("Premium rate number detected")
        
        # Determine threat level
        threat_score = min(threat_score, 1.0)
        
        if threat_score >= 0.8:
            threat_level = "blocked"
            action_taken = "blocked"
            message = "Spam/fraud number blocked"
        elif threat_score >= 0.4:
            threat_level = "suspicious"
            action_taken = "flagged"
            message = "Suspicious number flagged"
        else:
            threat_level = "safe"
            action_taken = "allowed"
            message = "Number appears safe"
        
        return {
            "threat_level": threat_level,
            "confidence_score": threat_score,
            "action_taken": action_taken,
            "categories": ["spam_call"] if threat_score > 0.4 else [],
            "message": f"{message} for {app_name}",
            "metadata": {
                "risk_factors": risk_factors,
                "clean_phone": clean_phone,
                "phone_length": len(clean_phone)
            }
        }
    
    async def _analyze_email(self, email_content: str, app_name: str) -> Dict[str, Any]:
        """Analyze email content"""
        # For now, treat email like text analysis
        result = await self._analyze_text(email_content, app_name)
        result["categories"].append("email_threat") if result["threat_level"] != "safe" else None
        return result
    
    async def _analyze_image(self, image_data: bytes, app_name: str) -> Dict[str, Any]:
        """Analyze image for threats (placeholder)"""
        # Basic file analysis
        file_hash = hashlib.md5(image_data).hexdigest()
        
        # Check file size
        if len(image_data) > 5 * 1024 * 1024:  # 5MB
            return {
                "threat_level": "suspicious",
                "confidence_score": 0.3,
                "action_taken": "flagged",
                "categories": ["large_file"],
                "message": f"Large image file flagged for {app_name}",
                "metadata": {"file_size": len(image_data), "file_hash": file_hash}
            }
        
        return {
            "threat_level": "safe",
            "confidence_score": 0.0,
            "action_taken": "allowed",
            "categories": [],
            "message": f"Image appears safe for {app_name}",
            "metadata": {"file_size": len(image_data), "file_hash": file_hash}
        }
    
    async def _analyze_audio(self, audio_data: bytes, app_name: str) -> Dict[str, Any]:
        """Analyze audio for threats (placeholder)"""
        file_hash = hashlib.md5(audio_data).hexdigest()
        
        return {
            "threat_level": "safe",
            "confidence_score": 0.0,
            "action_taken": "allowed",
            "categories": [],
            "message": f"Audio file appears safe for {app_name}",
            "metadata": {"file_size": len(audio_data), "file_hash": file_hash}
        }
    
    async def _analyze_video(self, video_data: bytes, app_name: str) -> Dict[str, Any]:
        """Analyze video for threats (placeholder)"""
        file_hash = hashlib.md5(video_data).hexdigest()
        
        return {
            "threat_level": "safe",
            "confidence_score": 0.0,
            "action_taken": "allowed",
            "categories": [],
            "message": f"Video file appears safe for {app_name}",
            "metadata": {"file_size": len(video_data), "file_hash": file_hash}
        }
    
    async def _analyze_generic_file(self, file_data: bytes, content_type: str, app_name: str) -> Dict[str, Any]:
        """Analyze generic file"""
        file_hash = hashlib.md5(file_data).hexdigest()
        
        # Check for executable files
        if content_type in ["application/x-executable", "application/x-msdownload"]:
            return {
                "threat_level": "blocked",
                "confidence_score": 0.9,
                "action_taken": "blocked",
                "categories": ["executable_file"],
                "message": f"Executable file blocked for {app_name}",
                "metadata": {"file_size": len(file_data), "file_hash": file_hash}
            }
        
        return {
            "threat_level": "safe",
            "confidence_score": 0.0,
            "action_taken": "allowed",
            "categories": [],
            "message": f"File appears safe for {app_name}",
            "metadata": {"file_size": len(file_data), "file_hash": file_hash, "content_type": content_type}
        }
    
    async def _analyze_url_in_text(self, url: str) -> float:
        """Quick URL analysis for text content"""
        score = 0.0
        for domain in self.suspicious_domains:
            if domain in url.lower():
                score += 0.3
        return min(score, 0.5)
    
    async def _analyze_phone_in_text(self, phone: str) -> float:
        """Quick phone analysis for text content"""
        clean_phone = re.sub(r'[^\d+]', '', phone)
        for pattern in self.spam_phone_patterns:
            if re.match(pattern, clean_phone):
                return 0.4
        return 0.0
    
    async def _load_threat_signatures(self):
        """Load threat signatures from database (placeholder)"""
        # In a real implementation, this would load from database
        logger.info("📚 Loading threat signatures...")
        await asyncio.sleep(0.1)  # Simulate loading time
    
    async def _initialize_ml_models(self):
        """Initialize ML models (placeholder)"""
        # In a real implementation, this would load ML models
        logger.info("🤖 Initializing ML models...")
        await asyncio.sleep(0.1)  # Simulate loading time