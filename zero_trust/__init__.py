"""
Zero-Trust Architecture Framework

A comprehensive framework implementing zero-trust security principles:
- Never trust, always verify
- Least privilege access
- Assume breach
- Multi-factor authentication
- Continuous monitoring and validation
"""

from .authentication import Authenticator, MFAProvider, AuthMethod
from .authorization import AuthorizationEngine, Policy, Permission
from .verification import RequestVerifier, IdentityVerifier, VerificationLevel
from .monitoring import SecurityMonitor, AuditLogger, SecurityEvent, LogLevel
from .network import NetworkSegmentation, MicroSegment, SegmentType

__version__ = "1.0.0"
__all__ = [
    "Authenticator",
    "MFAProvider",
    "AuthMethod",
    "AuthorizationEngine",
    "Policy",
    "Permission",
    "RequestVerifier",
    "IdentityVerifier",
    "VerificationLevel",
    "SecurityMonitor",
    "AuditLogger",
    "SecurityEvent",
    "LogLevel",
    "NetworkSegmentation",
    "MicroSegment",
    "SegmentType",
]
