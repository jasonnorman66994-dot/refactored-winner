"""
Verification Module - Implements Continuous Verification

This module provides continuous verification of requests and identities
for zero-trust architecture.
"""

import hashlib
import time
from typing import Dict, List, Optional, Tuple
from enum import Enum


class VerificationLevel(Enum):
    """Verification strictness levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IdentityVerifier:
    """
    Continuous identity verification - never trust, always verify
    """
    
    def __init__(self):
        """Initialize identity verifier"""
        self.verified_identities: Dict[str, Dict] = {}
        self.verification_history: List[Dict] = []
    
    def verify_identity(
        self,
        identity_id: str,
        credentials: Dict[str, str],
        verification_level: VerificationLevel = VerificationLevel.MEDIUM,
    ) -> Tuple[bool, float]:
        """
        Verify an identity with specified verification level
        
        Args:
            identity_id: Identity to verify
            credentials: Credentials for verification
            verification_level: Required verification level
            
        Returns:
            Tuple of (verified, confidence_score)
        """
        confidence = 0.0
        
        # Verify credentials (simplified for demonstration)
        if "password" in credentials:
            confidence += 0.3
        if "certificate" in credentials:
            confidence += 0.4
        if "biometric" in credentials:
            confidence += 0.3
        
        # Adjust based on verification level
        required_confidence = {
            VerificationLevel.LOW: 0.3,
            VerificationLevel.MEDIUM: 0.6,
            VerificationLevel.HIGH: 0.8,
            VerificationLevel.CRITICAL: 0.95,
        }
        
        verified = confidence >= required_confidence[verification_level]
        
        # Record verification
        self.verification_history.append({
            "identity_id": identity_id,
            "timestamp": time.time(),
            "verified": verified,
            "confidence": confidence,
            "level": verification_level.value,
        })
        
        if verified:
            self.verified_identities[identity_id] = {
                "last_verification": time.time(),
                "confidence": confidence,
            }
        
        return verified, confidence
    
    def require_reverification(self, identity_id: str, max_age: int = 300) -> bool:
        """
        Check if identity requires re-verification
        
        Args:
            identity_id: Identity to check
            max_age: Maximum age of verification in seconds
            
        Returns:
            True if re-verification is required
        """
        if identity_id not in self.verified_identities:
            return True
        
        last_verification = self.verified_identities[identity_id]["last_verification"]
        return time.time() - last_verification > max_age


class RequestVerifier:
    """
    Request verification - validate every request
    """
    
    def __init__(self):
        """Initialize request verifier"""
        self.request_history: List[Dict] = []
        self.blocked_requests: List[Dict] = []
    
    def verify_request(
        self,
        request_id: str,
        source: str,
        destination: str,
        payload: Optional[Dict] = None,
        metadata: Optional[Dict] = None,
    ) -> Tuple[bool, str]:
        """
        Verify a request before processing
        
        Args:
            request_id: Unique request identifier
            source: Source of the request
            destination: Destination/target of the request
            payload: Optional request payload
            metadata: Optional request metadata
            
        Returns:
            Tuple of (allowed, reason)
        """
        metadata = metadata or {}
        payload = payload or {}
        
        # Check source validity
        if not source or source.startswith("unknown"):
            self._record_blocked(request_id, "Invalid source")
            return False, "Invalid or unknown source"
        
        # Check destination validity
        if not destination:
            self._record_blocked(request_id, "Invalid destination")
            return False, "Invalid destination"
        
        # Validate request size
        if len(str(payload)) > 1000000:  # 1MB limit
            self._record_blocked(request_id, "Payload too large")
            return False, "Payload exceeds size limit"
        
        # Check for anomalies
        if self._detect_anomaly(source, destination, metadata):
            self._record_blocked(request_id, "Anomaly detected")
            return False, "Request anomaly detected"
        
        # Record successful verification
        self.request_history.append({
            "request_id": request_id,
            "source": source,
            "destination": destination,
            "timestamp": time.time(),
            "allowed": True,
        })
        
        return True, "Request verified"
    
    def _detect_anomaly(
        self, source: str, destination: str, metadata: Dict
    ) -> bool:
        """
        Detect anomalous request patterns
        
        Args:
            source: Request source
            destination: Request destination
            metadata: Request metadata
            
        Returns:
            True if anomaly detected
        """
        # Simple rate limiting check
        recent_requests = [
            r for r in self.request_history[-100:]
            if r["source"] == source and time.time() - r["timestamp"] < 60
        ]
        
        if len(recent_requests) > 50:
            return True
        
        return False
    
    def _record_blocked(self, request_id: str, reason: str):
        """Record a blocked request"""
        self.blocked_requests.append({
            "request_id": request_id,
            "timestamp": time.time(),
            "reason": reason,
        })
    
    def get_blocked_requests(self, since: Optional[float] = None) -> List[Dict]:
        """
        Get blocked requests
        
        Args:
            since: Optional timestamp to filter from
            
        Returns:
            List of blocked requests
        """
        if since is None:
            return self.blocked_requests
        
        return [
            r for r in self.blocked_requests
            if r["timestamp"] >= since
        ]
