"""
Test suite for Zero-Trust Architecture framework
"""

import unittest
import time
from zero_trust.authentication import Authenticator, MFAProvider, AuthMethod
from zero_trust.authorization import AuthorizationEngine, Policy, Permission
from zero_trust.verification import RequestVerifier, IdentityVerifier, VerificationLevel
from zero_trust.monitoring import SecurityMonitor, SecurityEvent
from zero_trust.network import NetworkSegmentation, SegmentType


class TestAuthentication(unittest.TestCase):
    """Test authentication module"""
    
    def setUp(self):
        self.authenticator = Authenticator()
    
    def test_mfa_authentication(self):
        """Test multi-factor authentication"""
        credentials = {
            AuthMethod.PASSWORD: "password123",
            AuthMethod.TOTP: "123456",
        }
        
        token = self.authenticator.authenticate("test_user", credentials)
        self.assertIsNotNone(token)
        self.assertTrue(self.authenticator.verify_session(token))
    
    def test_insufficient_factors(self):
        """Test authentication fails with insufficient factors"""
        credentials = {
            AuthMethod.PASSWORD: "password123",
        }
        
        token = self.authenticator.authenticate("test_user", credentials)
        self.assertIsNone(token)
    
    def test_session_revocation(self):
        """Test session revocation"""
        credentials = {
            AuthMethod.PASSWORD: "password123",
            AuthMethod.TOTP: "123456",
        }
        
        token = self.authenticator.authenticate("test_user", credentials)
        self.assertIsNotNone(token)
        
        self.assertTrue(self.authenticator.revoke_session(token))
        self.assertFalse(self.authenticator.verify_session(token))


class TestAuthorization(unittest.TestCase):
    """Test authorization module"""
    
    def setUp(self):
        self.authz = AuthorizationEngine()
    
    def test_basic_authorization(self):
        """Test basic authorization"""
        policy = Policy(
            policy_id="test-001",
            principal="user1",
            resource="/api/data",
            permissions={Permission.READ},
        )
        
        self.authz.add_policy(policy)
        
        self.assertTrue(
            self.authz.authorize("user1", "/api/data", Permission.READ)
        )
        self.assertFalse(
            self.authz.authorize("user1", "/api/data", Permission.WRITE)
        )
    
    def test_wildcard_resource(self):
        """Test wildcard resource matching"""
        policy = Policy(
            policy_id="test-002",
            principal="user1",
            resource="/api/*",
            permissions={Permission.READ},
        )
        
        self.authz.add_policy(policy)
        
        self.assertTrue(
            self.authz.authorize("user1", "/api/users", Permission.READ)
        )
        self.assertTrue(
            self.authz.authorize("user1", "/api/data", Permission.READ)
        )
    
    def test_expired_policy(self):
        """Test expired policy is not enforced"""
        policy = Policy(
            policy_id="test-003",
            principal="user1",
            resource="/api/data",
            permissions={Permission.READ},
            expiry=time.time() - 100,  # Already expired
        )
        
        self.authz.add_policy(policy)
        
        self.assertFalse(
            self.authz.authorize("user1", "/api/data", Permission.READ)
        )


class TestVerification(unittest.TestCase):
    """Test verification module"""
    
    def setUp(self):
        self.verifier = RequestVerifier()
    
    def test_valid_request(self):
        """Test valid request verification"""
        allowed, reason = self.verifier.verify_request(
            request_id="req-001",
            source="192.168.1.100",
            destination="api.example.com",
        )
        
        self.assertTrue(allowed)
        self.assertEqual(reason, "Request verified")
    
    def test_invalid_source(self):
        """Test request with invalid source is blocked"""
        allowed, reason = self.verifier.verify_request(
            request_id="req-002",
            source="unknown",
            destination="api.example.com",
        )
        
        self.assertFalse(allowed)
    
    def test_rate_limiting(self):
        """Test rate limiting anomaly detection"""
        # Send many requests quickly
        for i in range(60):
            self.verifier.verify_request(
                request_id=f"req-{i}",
                source="192.168.1.100",
                destination="api.example.com",
            )
        
        # Next request should be blocked
        allowed, reason = self.verifier.verify_request(
            request_id="req-final",
            source="192.168.1.100",
            destination="api.example.com",
        )
        
        self.assertFalse(allowed)


class TestMonitoring(unittest.TestCase):
    """Test monitoring module"""
    
    def setUp(self):
        self.monitor = SecurityMonitor()
    
    def test_event_recording(self):
        """Test security event recording"""
        self.monitor.record_event(
            SecurityEvent.LOGIN_SUCCESS,
            principal="test_user",
        )
        
        metrics = self.monitor.get_metrics()
        self.assertEqual(metrics.get("login_success_count"), 1)
    
    def test_failed_login_alert(self):
        """Test alert on multiple failed logins"""
        for i in range(5):
            self.monitor.record_event(
                SecurityEvent.LOGIN_FAILURE,
                principal="test_user",
            )
        
        alerts = self.monitor.get_alerts()
        self.assertTrue(len(alerts) > 0)


class TestNetworkSegmentation(unittest.TestCase):
    """Test network segmentation module"""
    
    def setUp(self):
        self.network = NetworkSegmentation()
    
    def test_segment_creation(self):
        """Test creating network segments"""
        segment = self.network.create_segment(
            "web-tier",
            SegmentType.DMZ,
            "10.0.1.0/24",
        )
        
        self.assertEqual(segment.segment_id, "web-tier")
        self.assertTrue(segment.contains_ip("10.0.1.100"))
        self.assertFalse(segment.contains_ip("10.0.2.100"))
    
    def test_traffic_control(self):
        """Test traffic control between segments"""
        self.network.create_segment("web", SegmentType.DMZ, "10.0.1.0/24")
        self.network.create_segment("app", SegmentType.PRIVATE, "10.0.2.0/24")
        
        # Initially blocked
        self.assertFalse(
            self.network.verify_connection("10.0.1.10", "10.0.2.10")
        )
        
        # Allow traffic
        self.network.allow_traffic("web", "app")
        
        self.assertTrue(
            self.network.verify_connection("10.0.1.10", "10.0.2.10")
        )
    
    def test_segment_isolation(self):
        """Test segment isolation"""
        self.network.create_segment("web", SegmentType.DMZ, "10.0.1.0/24")
        self.network.create_segment("db", SegmentType.RESTRICTED, "10.0.2.0/24")
        
        self.network.allow_traffic("web", "db")
        self.network.isolate_segment("db")
        
        # Connection should now be blocked
        self.assertFalse(
            self.network.verify_connection("10.0.1.10", "10.0.2.10")
        )


if __name__ == "__main__":
    unittest.main()
