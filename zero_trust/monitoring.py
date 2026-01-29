"""
Monitoring Module - Implements Continuous Monitoring

This module provides security monitoring and audit logging
for zero-trust architecture.
"""

import time
import json
from typing import Dict, List, Optional
from enum import Enum
from .constants import FAILED_LOGIN_ALERT_THRESHOLD, ALERT_TIME_WINDOW_SECONDS


class LogLevel(Enum):
    """Log severity levels"""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class SecurityEvent(Enum):
    """Security event types"""
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    ACCESS_GRANTED = "access_granted"
    ACCESS_DENIED = "access_denied"
    POLICY_VIOLATION = "policy_violation"
    ANOMALY_DETECTED = "anomaly_detected"
    SESSION_CREATED = "session_created"
    SESSION_REVOKED = "session_revoked"


class AuditLogger:
    """
    Audit logger for compliance and forensics
    """
    
    def __init__(self, log_file: Optional[str] = None):
        """
        Initialize audit logger
        
        Args:
            log_file: Optional file path for persistent logging
        """
        self.log_file = log_file
        self.audit_trail: List[Dict] = []
    
    def log(
        self,
        event_type: SecurityEvent,
        principal: str,
        resource: Optional[str] = None,
        action: Optional[str] = None,
        result: Optional[str] = None,
        metadata: Optional[Dict] = None,
    ):
        """
        Log an audit event
        
        Args:
            event_type: Type of security event
            principal: User or service involved
            resource: Optional resource involved
            action: Optional action performed
            result: Optional result of action
            metadata: Optional additional metadata
        """
        entry = {
            "timestamp": time.time(),
            "event_type": event_type.value,
            "principal": principal,
            "resource": resource,
            "action": action,
            "result": result,
            "metadata": metadata or {},
        }
        
        self.audit_trail.append(entry)
        
        if self.log_file:
            with open(self.log_file, "a") as f:
                f.write(json.dumps(entry) + "\n")
    
    def query(
        self,
        event_type: Optional[SecurityEvent] = None,
        principal: Optional[str] = None,
        since: Optional[float] = None,
        limit: int = 100,
    ) -> List[Dict]:
        """
        Query audit trail
        
        Args:
            event_type: Filter by event type
            principal: Filter by principal
            since: Filter by timestamp
            limit: Maximum results to return
            
        Returns:
            List of matching audit entries
        """
        results = self.audit_trail
        
        if event_type:
            results = [r for r in results if r["event_type"] == event_type.value]
        
        if principal:
            results = [r for r in results if r["principal"] == principal]
        
        if since:
            results = [r for r in results if r["timestamp"] >= since]
        
        return results[-limit:]


class SecurityMonitor:
    """
    Security monitoring and alerting system
    """
    
    def __init__(self, audit_logger: Optional[AuditLogger] = None):
        """
        Initialize security monitor
        
        Args:
            audit_logger: Optional audit logger instance
        """
        self.audit_logger = audit_logger or AuditLogger()
        self.alerts: List[Dict] = []
        self.metrics: Dict[str, float] = {}
    
    def record_event(
        self,
        event_type: SecurityEvent,
        principal: str,
        resource: Optional[str] = None,
        metadata: Optional[Dict] = None,
    ):
        """
        Record a security event
        
        Args:
            event_type: Type of event
            principal: User or service
            resource: Optional resource
            metadata: Optional metadata
        """
        self.audit_logger.log(
            event_type=event_type,
            principal=principal,
            resource=resource,
            metadata=metadata,
        )
        
        # Update metrics
        metric_key = f"{event_type.value}_count"
        self.metrics[metric_key] = self.metrics.get(metric_key, 0) + 1
        
        # Check for alert conditions
        self._check_alert_conditions(event_type, principal, metadata)
    
    def _check_alert_conditions(
        self, event_type: SecurityEvent, principal: str, metadata: Optional[Dict]
    ):
        """
        Check if alert should be raised
        
        Args:
            event_type: Event type
            principal: Principal involved
            metadata: Event metadata
        """
        # Alert on multiple failed logins
        if event_type == SecurityEvent.LOGIN_FAILURE:
            recent_failures = self.audit_logger.query(
                event_type=SecurityEvent.LOGIN_FAILURE,
                principal=principal,
                since=time.time() - ALERT_TIME_WINDOW_SECONDS,
            )
            
            if len(recent_failures) >= FAILED_LOGIN_ALERT_THRESHOLD:
                self.create_alert(
                    severity=LogLevel.CRITICAL,
                    message=f"Multiple failed login attempts for {principal}",
                    metadata={"failures": len(recent_failures)},
                )
        
        # Alert on policy violations
        if event_type == SecurityEvent.POLICY_VIOLATION:
            self.create_alert(
                severity=LogLevel.WARNING,
                message=f"Policy violation by {principal}",
                metadata=metadata,
            )
        
        # Alert on anomalies
        if event_type == SecurityEvent.ANOMALY_DETECTED:
            self.create_alert(
                severity=LogLevel.ERROR,
                message=f"Anomaly detected for {principal}",
                metadata=metadata,
            )
    
    def create_alert(
        self, severity: LogLevel, message: str, metadata: Optional[Dict] = None
    ):
        """
        Create a security alert
        
        Args:
            severity: Alert severity
            message: Alert message
            metadata: Optional metadata
        """
        alert = {
            "timestamp": time.time(),
            "severity": severity.value,
            "message": message,
            "metadata": metadata or {},
        }
        
        self.alerts.append(alert)
    
    def get_alerts(
        self, severity: Optional[LogLevel] = None, since: Optional[float] = None
    ) -> List[Dict]:
        """
        Get security alerts
        
        Args:
            severity: Filter by severity
            since: Filter by timestamp
            
        Returns:
            List of alerts
        """
        results = self.alerts
        
        if severity:
            results = [a for a in results if a["severity"] == severity.value]
        
        if since:
            results = [a for a in results if a["timestamp"] >= since]
        
        return results
    
    def get_metrics(self) -> Dict[str, float]:
        """
        Get current security metrics
        
        Returns:
            Dictionary of metrics
        """
        return self.metrics.copy()
