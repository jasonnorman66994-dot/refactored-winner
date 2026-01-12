"""
Network Module - Implements Network Segmentation

This module provides network segmentation and micro-segmentation
for zero-trust architecture (assume breach).
"""

from typing import Dict, List, Optional, Set
from enum import Enum
import ipaddress


class SegmentType(Enum):
    """Network segment types"""
    PUBLIC = "public"
    DMZ = "dmz"
    PRIVATE = "private"
    RESTRICTED = "restricted"
    ISOLATED = "isolated"


class MicroSegment:
    """
    Micro-segment for fine-grained network isolation
    """
    
    def __init__(
        self,
        segment_id: str,
        segment_type: SegmentType,
        cidr: str,
        allowed_services: Optional[Set[str]] = None,
    ):
        """
        Initialize a micro-segment
        
        Args:
            segment_id: Unique segment identifier
            segment_type: Type of segment
            cidr: CIDR notation for segment network range
            allowed_services: Optional set of allowed services
        """
        self.segment_id = segment_id
        self.segment_type = segment_type
        self.network = ipaddress.ip_network(cidr)
        self.allowed_services = allowed_services or set()
        self.connected_segments: Set[str] = set()
    
    def contains_ip(self, ip: str) -> bool:
        """
        Check if IP is in this segment
        
        Args:
            ip: IP address to check
            
        Returns:
            True if IP is in segment
        """
        try:
            ip_addr = ipaddress.ip_address(ip)
            return ip_addr in self.network
        except ValueError:
            return False
    
    def allow_connection(self, target_segment_id: str):
        """
        Allow connections to another segment
        
        Args:
            target_segment_id: Segment to allow connections to
        """
        self.connected_segments.add(target_segment_id)
    
    def deny_connection(self, target_segment_id: str):
        """
        Deny connections to another segment
        
        Args:
            target_segment_id: Segment to deny connections to
        """
        self.connected_segments.discard(target_segment_id)


class NetworkSegmentation:
    """
    Network segmentation engine - assume breach, limit blast radius
    """
    
    def __init__(self):
        """Initialize network segmentation"""
        self.segments: Dict[str, MicroSegment] = {}
        self.firewall_rules: List[Dict] = []
    
    def create_segment(
        self,
        segment_id: str,
        segment_type: SegmentType,
        cidr: str,
        allowed_services: Optional[Set[str]] = None,
    ) -> MicroSegment:
        """
        Create a new network segment
        
        Args:
            segment_id: Unique segment identifier
            segment_type: Type of segment
            cidr: CIDR notation for network range
            allowed_services: Optional allowed services
            
        Returns:
            Created micro-segment
        """
        segment = MicroSegment(segment_id, segment_type, cidr, allowed_services)
        self.segments[segment_id] = segment
        return segment
    
    def get_segment_for_ip(self, ip: str) -> Optional[MicroSegment]:
        """
        Find which segment an IP belongs to
        
        Args:
            ip: IP address
            
        Returns:
            Segment containing the IP, or None
        """
        for segment in self.segments.values():
            if segment.contains_ip(ip):
                return segment
        return None
    
    def allow_traffic(
        self,
        source_segment_id: str,
        destination_segment_id: str,
        service: Optional[str] = None,
    ) -> bool:
        """
        Create firewall rule to allow traffic between segments
        
        Args:
            source_segment_id: Source segment
            destination_segment_id: Destination segment
            service: Optional specific service to allow
            
        Returns:
            True if rule was created
        """
        if source_segment_id not in self.segments:
            return False
        if destination_segment_id not in self.segments:
            return False
        
        source = self.segments[source_segment_id]
        source.allow_connection(destination_segment_id)
        
        rule = {
            "source": source_segment_id,
            "destination": destination_segment_id,
            "service": service,
            "action": "allow",
        }
        self.firewall_rules.append(rule)
        
        return True
    
    def verify_connection(
        self,
        source_ip: str,
        destination_ip: str,
        service: Optional[str] = None,
    ) -> bool:
        """
        Verify if connection is allowed between IPs
        
        Args:
            source_ip: Source IP address
            destination_ip: Destination IP address
            service: Optional service being accessed
            
        Returns:
            True if connection is allowed
        """
        source_segment = self.get_segment_for_ip(source_ip)
        dest_segment = self.get_segment_for_ip(destination_ip)
        
        if not source_segment or not dest_segment:
            return False
        
        # Same segment is always allowed
        if source_segment.segment_id == dest_segment.segment_id:
            return True
        
        # Check if connection is allowed
        if dest_segment.segment_id not in source_segment.connected_segments:
            return False
        
        # Check service restrictions
        if service and service not in dest_segment.allowed_services:
            return False
        
        return True
    
    def isolate_segment(self, segment_id: str):
        """
        Isolate a segment (deny all external connections)
        
        Args:
            segment_id: Segment to isolate
        """
        if segment_id not in self.segments:
            return
        
        segment = self.segments[segment_id]
        segment.connected_segments.clear()
        
        # Remove this segment from all other segments' allowed connections
        for other_segment in self.segments.values():
            if segment_id in other_segment.connected_segments:
                other_segment.connected_segments.discard(segment_id)
        
        # Remove related firewall rules
        self.firewall_rules = [
            rule for rule in self.firewall_rules
            if rule["source"] != segment_id and rule["destination"] != segment_id
        ]
    
    def get_segment_connections(self, segment_id: str) -> Set[str]:
        """
        Get all segments this segment can connect to
        
        Args:
            segment_id: Segment to check
            
        Returns:
            Set of connected segment IDs
        """
        if segment_id not in self.segments:
            return set()
        
        return self.segments[segment_id].connected_segments.copy()
