"""
Example: API Gateway with Zero-Trust Security

Demonstrates how to build a secure API gateway using
the zero-trust architecture framework.
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from zero_trust import (
    Authenticator,
    AuthorizationEngine,
    Policy,
    Permission,
    RequestVerifier,
    SecurityMonitor,
)
from zero_trust.authentication import AuthMethod
from zero_trust.monitoring import SecurityEvent


class APIGateway:
    """Secure API Gateway with Zero-Trust Architecture"""
    
    def __init__(self):
        self.authenticator = Authenticator()
        self.authz_engine = AuthorizationEngine()
        self.request_verifier = RequestVerifier()
        self.security_monitor = SecurityMonitor()
        
        # Setup default policies
        self._setup_policies()
    
    def _setup_policies(self):
        """Setup default authorization policies"""
        # Users can read their own data
        user_read_policy = Policy(
            policy_id="user-read-own",
            principal="*",
            resource="/api/users/*/profile",
            permissions={Permission.READ},
        )
        self.authz_engine.add_policy(user_read_policy)
    
    def handle_request(self, request):
        """
        Handle incoming API request with zero-trust verification
        
        Args:
            request: Request object with headers, body, etc.
            
        Returns:
            Response object
        """
        # 1. Verify request
        allowed, reason = self.request_verifier.verify_request(
            request_id=request["id"],
            source=request["source_ip"],
            destination=request["endpoint"],
            payload=request.get("body"),
        )
        
        if not allowed:
            self.security_monitor.record_event(
                SecurityEvent.ACCESS_DENIED,
                principal=request.get("user_id", "unknown"),
                resource=request["endpoint"],
                metadata={"reason": reason},
            )
            return {"status": 403, "error": reason}
        
        # 2. Verify authentication
        token = request["headers"].get("Authorization", "").replace("Bearer ", "")
        if not self.authenticator.verify_session(token):
            self.security_monitor.record_event(
                SecurityEvent.ACCESS_DENIED,
                principal=request.get("user_id", "unknown"),
                resource=request["endpoint"],
                metadata={"reason": "Invalid or expired session"},
            )
            return {"status": 401, "error": "Unauthorized"}
        
        # 3. Check authorization
        user_id = request["user_id"]
        endpoint = request["endpoint"]
        method = request["method"]
        
        permission_map = {
            "GET": Permission.READ,
            "POST": Permission.WRITE,
            "PUT": Permission.WRITE,
            "DELETE": Permission.DELETE,
        }
        
        required_permission = permission_map.get(method, Permission.READ)
        
        if not self.authz_engine.authorize(user_id, endpoint, required_permission):
            self.security_monitor.record_event(
                SecurityEvent.ACCESS_DENIED,
                principal=user_id,
                resource=endpoint,
                metadata={"permission": required_permission.value},
            )
            return {"status": 403, "error": "Forbidden"}
        
        # 4. Log successful access
        self.security_monitor.record_event(
            SecurityEvent.ACCESS_GRANTED,
            principal=user_id,
            resource=endpoint,
        )
        
        # 5. Process request (simplified)
        return {
            "status": 200,
            "data": f"Access granted to {endpoint}",
        }


def main():
    print("=" * 60)
    print("Zero-Trust API Gateway Example")
    print("=" * 60)
    
    gateway = APIGateway()
    
    # Setup a user
    print("\n1. User Authentication")
    print("-" * 60)
    
    credentials = {
        AuthMethod.PASSWORD: "secure_password",
        AuthMethod.TOTP: "123456",
    }
    
    token = gateway.authenticator.authenticate("alice", credentials)
    print(f"✓ User 'alice' authenticated")
    print(f"  Token: {token[:20]}...")
    
    # Add user-specific policy
    policy = Policy(
        policy_id="alice-profile",
        principal="alice",
        resource="/api/users/alice/*",
        permissions={Permission.READ, Permission.WRITE},
    )
    gateway.authz_engine.add_policy(policy)
    print("✓ Authorization policy created for alice")
    
    # Simulate API requests
    print("\n2. API Request Processing")
    print("-" * 60)
    
    requests = [
        {
            "id": "req-001",
            "user_id": "alice",
            "source_ip": "192.168.1.100",
            "endpoint": "/api/users/alice/profile",
            "method": "GET",
            "headers": {"Authorization": f"Bearer {token}"},
            "body": {},
        },
        {
            "id": "req-002",
            "user_id": "alice",
            "source_ip": "192.168.1.100",
            "endpoint": "/api/users/bob/profile",
            "method": "GET",
            "headers": {"Authorization": f"Bearer {token}"},
            "body": {},
        },
    ]
    
    for req in requests:
        response = gateway.handle_request(req)
        status_symbol = "✓" if response["status"] == 200 else "✗"
        print(f"{status_symbol} {req['method']} {req['endpoint']}: {response['status']}")
        if "error" in response:
            print(f"  Error: {response['error']}")
    
    # Show security metrics
    print("\n3. Security Metrics")
    print("-" * 60)
    
    metrics = gateway.security_monitor.get_metrics()
    for key, value in metrics.items():
        print(f"  • {key}: {value}")
    
    print("\n" + "=" * 60)


if __name__ == "__main__":
    main()
