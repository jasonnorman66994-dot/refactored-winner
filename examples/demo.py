"""
Example demonstrating Zero-Trust Architecture implementation

This example shows how to use the zero-trust framework to implement
secure authentication, authorization, and monitoring.
"""

from zero_trust import (
    Authenticator,
    AuthorizationEngine,
    Policy,
    Permission,
    RequestVerifier,
    SecurityMonitor,
    NetworkSegmentation,
    SegmentType,
)
from zero_trust.authentication import AuthMethod
from zero_trust.monitoring import SecurityEvent


def main():
    print("=" * 60)
    print("Zero-Trust Architecture Framework Demo")
    print("=" * 60)
    
    # 1. Authentication with MFA
    print("\n1. Multi-Factor Authentication")
    print("-" * 60)
    
    authenticator = Authenticator()
    
    # Authenticate with multiple factors
    credentials = {
        AuthMethod.PASSWORD: "secure_password",
        AuthMethod.TOTP: "123456",
    }
    
    access_token = authenticator.authenticate("user123", credentials)
    
    if access_token:
        print(f"✓ Authentication successful!")
        print(f"  Access token: {access_token[:20]}...")
        
        # Verify session
        if authenticator.verify_session(access_token):
            print(f"✓ Session verified successfully")
    else:
        print("✗ Authentication failed")
    
    # 2. Authorization with Least Privilege
    print("\n2. Least Privilege Authorization")
    print("-" * 60)
    
    authz_engine = AuthorizationEngine()
    
    # Create restrictive policies
    policy1 = Policy(
        policy_id="policy-001",
        principal="user123",
        resource="/api/users/*",
        permissions={Permission.READ},
    )
    
    policy2 = Policy(
        policy_id="policy-002",
        principal="user123",
        resource="/api/users/user123",
        permissions={Permission.READ, Permission.WRITE},
    )
    
    authz_engine.add_policy(policy1)
    authz_engine.add_policy(policy2)
    
    # Check authorization
    tests = [
        ("/api/users/list", Permission.READ, True),
        ("/api/users/user123", Permission.WRITE, True),
        ("/api/users/user456", Permission.WRITE, False),
        ("/api/admin", Permission.READ, False),
    ]
    
    for resource, permission, expected in tests:
        allowed = authz_engine.authorize("user123", resource, permission)
        status = "✓" if allowed == expected else "✗"
        result = "ALLOWED" if allowed else "DENIED"
        print(f"{status} {resource} [{permission.value}]: {result}")
    
    # 3. Request Verification
    print("\n3. Request Verification")
    print("-" * 60)
    
    verifier = RequestVerifier()
    
    # Verify requests
    allowed, reason = verifier.verify_request(
        request_id="req-001",
        source="192.168.1.100",
        destination="api.example.com",
        payload={"action": "get_user"},
    )
    
    status = "✓" if allowed else "✗"
    print(f"{status} Request verification: {reason}")
    
    # 4. Security Monitoring
    print("\n4. Security Monitoring")
    print("-" * 60)
    
    monitor = SecurityMonitor()
    
    # Record security events
    monitor.record_event(
        SecurityEvent.LOGIN_SUCCESS,
        principal="user123",
        resource="authentication_service",
    )
    
    monitor.record_event(
        SecurityEvent.ACCESS_GRANTED,
        principal="user123",
        resource="/api/users/user123",
    )
    
    # Get metrics
    metrics = monitor.get_metrics()
    print("Security Metrics:")
    for key, value in metrics.items():
        print(f"  • {key}: {value}")
    
    # 5. Network Segmentation
    print("\n5. Network Segmentation (Assume Breach)")
    print("-" * 60)
    
    network = NetworkSegmentation()
    
    # Create segments
    web_segment = network.create_segment(
        "web-tier",
        SegmentType.DMZ,
        "10.0.1.0/24",
        allowed_services={"http", "https"},
    )
    
    app_segment = network.create_segment(
        "app-tier",
        SegmentType.PRIVATE,
        "10.0.2.0/24",
        allowed_services={"app-api"},
    )
    
    db_segment = network.create_segment(
        "db-tier",
        SegmentType.RESTRICTED,
        "10.0.3.0/24",
        allowed_services={"postgresql"},
    )
    
    # Configure allowed connections
    network.allow_traffic("web-tier", "app-tier", "app-api")
    network.allow_traffic("app-tier", "db-tier", "postgresql")
    
    # Verify connections
    connection_tests = [
        ("10.0.1.10", "10.0.2.10", "app-api", True),
        ("10.0.2.10", "10.0.3.10", "postgresql", True),
        ("10.0.1.10", "10.0.3.10", "postgresql", False),  # Web cannot access DB
    ]
    
    for source, dest, service, expected in connection_tests:
        allowed = network.verify_connection(source, dest, service)
        status = "✓" if allowed == expected else "✗"
        result = "ALLOWED" if allowed else "BLOCKED"
        print(f"{status} {source} → {dest} [{service}]: {result}")
    
    print("\n" + "=" * 60)
    print("Zero-Trust Architecture Principles Demonstrated:")
    print("  ✓ Never trust, always verify (continuous verification)")
    print("  ✓ Least privilege access (minimal permissions)")
    print("  ✓ Assume breach (network segmentation)")
    print("  ✓ Multi-factor authentication (MFA)")
    print("  ✓ Continuous monitoring (security events)")
    print("=" * 60)


if __name__ == "__main__":
    main()
