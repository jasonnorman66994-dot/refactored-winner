"""
Authorization Module - Implements Least Privilege Access

This module provides fine-grained authorization with the principle
of least privilege for zero-trust architecture.
"""

from typing import Dict, List, Optional, Set
from enum import Enum
import time


class Permission(Enum):
    """Standard permissions"""
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    EXECUTE = "execute"
    ADMIN = "admin"


class Policy:
    """
    Authorization policy with time-based and context-aware rules
    """
    
    def __init__(
        self,
        policy_id: str,
        principal: str,
        resource: str,
        permissions: Set[Permission],
        conditions: Optional[Dict] = None,
        expiry: Optional[float] = None,
    ):
        """
        Initialize a policy
        
        Args:
            policy_id: Unique policy identifier
            principal: User or service the policy applies to
            resource: Resource the policy grants access to
            permissions: Set of granted permissions
            conditions: Optional conditions for policy (e.g., IP range, time)
            expiry: Optional expiry timestamp
        """
        self.policy_id = policy_id
        self.principal = principal
        self.resource = resource
        self.permissions = permissions
        self.conditions = conditions or {}
        self.expiry = expiry
    
    def is_valid(self) -> bool:
        """Check if policy is still valid (not expired)"""
        if self.expiry is None:
            return True
        return time.time() < self.expiry
    
    def check_conditions(self, context: Dict) -> bool:
        """
        Check if conditions are met for this policy
        
        Args:
            context: Request context to check against conditions
            
        Returns:
            True if all conditions are satisfied
        """
        if not self.conditions:
            return True
        
        for key, required_value in self.conditions.items():
            if key not in context:
                return False
            if context[key] != required_value:
                return False
        
        return True


class AuthorizationEngine:
    """
    Authorization engine implementing least privilege access control
    """
    
    def __init__(self):
        """Initialize authorization engine"""
        self.policies: Dict[str, Policy] = {}
        self.principal_policies: Dict[str, List[str]] = {}
    
    def add_policy(self, policy: Policy) -> bool:
        """
        Add a new authorization policy
        
        Args:
            policy: Policy to add
            
        Returns:
            True if policy was added successfully
        """
        self.policies[policy.policy_id] = policy
        
        if policy.principal not in self.principal_policies:
            self.principal_policies[policy.principal] = []
        self.principal_policies[policy.principal].append(policy.policy_id)
        
        return True
    
    def remove_policy(self, policy_id: str) -> bool:
        """
        Remove a policy
        
        Args:
            policy_id: ID of policy to remove
            
        Returns:
            True if policy was removed
        """
        if policy_id not in self.policies:
            return False
        
        policy = self.policies[policy_id]
        if policy.principal in self.principal_policies:
            self.principal_policies[policy.principal].remove(policy_id)
        
        del self.policies[policy_id]
        return True
    
    def authorize(
        self,
        principal: str,
        resource: str,
        permission: Permission,
        context: Optional[Dict] = None,
    ) -> bool:
        """
        Check if principal is authorized to perform action on resource
        
        Args:
            principal: User or service requesting access
            resource: Resource being accessed
            permission: Permission being requested
            context: Optional context for conditional policies
            
        Returns:
            True if authorized, False otherwise
        """
        context = context or {}
        
        # Get all policies for this principal
        if principal not in self.principal_policies:
            return False
        
        for policy_id in self.principal_policies[principal]:
            policy = self.policies[policy_id]
            
            # Check if policy is valid
            if not policy.is_valid():
                continue
            
            # Check if policy applies to this resource
            if not self._resource_matches(policy.resource, resource):
                continue
            
            # Check if conditions are met
            if not policy.check_conditions(context):
                continue
            
            # Check if permission is granted
            if permission in policy.permissions or Permission.ADMIN in policy.permissions:
                return True
        
        return False
    
    def _resource_matches(self, policy_resource: str, requested_resource: str) -> bool:
        """
        Check if a resource matches a policy resource pattern
        
        Args:
            policy_resource: Resource pattern in policy (supports wildcards)
            requested_resource: Actual resource being requested
            
        Returns:
            True if resource matches
        """
        # Simple wildcard matching
        if policy_resource == "*":
            return True
        
        if policy_resource.endswith("/*"):
            prefix = policy_resource[:-2]
            return requested_resource.startswith(prefix)
        
        return policy_resource == requested_resource
    
    def get_permissions(
        self, principal: str, resource: str, context: Optional[Dict] = None
    ) -> Set[Permission]:
        """
        Get all permissions a principal has for a resource
        
        Args:
            principal: User or service
            resource: Resource to check
            context: Optional context
            
        Returns:
            Set of granted permissions
        """
        context = context or {}
        granted_permissions: Set[Permission] = set()
        
        if principal not in self.principal_policies:
            return granted_permissions
        
        for policy_id in self.principal_policies[principal]:
            policy = self.policies[policy_id]
            
            if not policy.is_valid():
                continue
            
            if not self._resource_matches(policy.resource, resource):
                continue
            
            if not policy.check_conditions(context):
                continue
            
            granted_permissions.update(policy.permissions)
        
        return granted_permissions
    
    def cleanup_expired_policies(self):
        """Remove all expired policies"""
        expired_ids = [
            policy_id for policy_id, policy in self.policies.items()
            if not policy.is_valid()
        ]
        
        for policy_id in expired_ids:
            self.remove_policy(policy_id)
