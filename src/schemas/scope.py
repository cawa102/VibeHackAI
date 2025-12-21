"""
Scope schema for PentestAgent.

Defines the allowed target range and operations for a pentest session.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field, validator

from .base import BaseSchema


class TargetType(str, Enum):
    """Types of targets."""
    IP = "ip"
    CIDR = "cidr"
    DOMAIN = "domain"
    URL = "url"


class TargetSpec(BaseModel):
    """Specification of a single target."""

    value: str = Field(..., description="Target value (IP, CIDR, domain, or URL)")
    type: TargetType = Field(..., description="Type of target")
    description: Optional[str] = Field(None, description="Optional description")

    @validator("value")
    def validate_value(cls, v: str) -> str:
        """Validate target value is not empty."""
        if not v or not v.strip():
            raise ValueError("Target value cannot be empty")
        return v.strip()


class AllowedOperation(str, Enum):
    """Types of allowed operations."""
    # Reconnaissance
    PASSIVE_RECON = "passive_recon"
    ACTIVE_RECON = "active_recon"
    PORT_SCAN = "port_scan"

    # Enumeration
    WEB_CRAWL = "web_crawl"
    DIRECTORY_ENUM = "directory_enum"
    SERVICE_ENUM = "service_enum"

    # Vulnerability Assessment
    VULN_SCAN = "vuln_scan"
    CVE_LOOKUP = "cve_lookup"

    # Exploitation
    EXPLOIT_VERIFY = "exploit_verify"
    EXPLOIT_EXECUTE = "exploit_execute"

    # Other
    MANUAL_TEST = "manual_test"


class Scope(BaseSchema):
    """
    Scope definition for a pentest session.

    Defines what targets are allowed and what operations can be performed.
    All agent actions must be validated against this scope.
    """

    targets: List[TargetSpec] = Field(
        default_factory=list,
        description="List of allowed targets",
    )
    allowed_operations: List[AllowedOperation] = Field(
        default_factory=list,
        description="List of allowed operation types",
    )
    excluded_targets: List[TargetSpec] = Field(
        default_factory=list,
        description="List of explicitly excluded targets",
    )
    expires_at: Optional[datetime] = Field(
        None,
        description="Scope expiration time (UTC)",
    )
    notes: Optional[str] = Field(
        None,
        description="Additional notes about the scope",
    )
    engagement_id: Optional[str] = Field(
        None,
        description="External engagement/project ID reference",
    )

    def is_expired(self) -> bool:
        """Check if the scope has expired."""
        if self.expires_at is None:
            return False
        return datetime.utcnow() > self.expires_at

    def is_target_allowed(self, target: str, target_type: TargetType) -> bool:
        """
        Check if a target is within scope.

        Args:
            target: Target value to check.
            target_type: Type of target.

        Returns:
            True if target is allowed, False otherwise.
        """
        # Check if explicitly excluded
        for excluded in self.excluded_targets:
            if excluded.value == target and excluded.type == target_type:
                return False

        # Check if in allowed targets
        for allowed in self.targets:
            if allowed.value == target and allowed.type == target_type:
                return True

            # For CIDR, check if IP is within range (simplified)
            if allowed.type == TargetType.CIDR and target_type == TargetType.IP:
                if self._ip_in_cidr(target, allowed.value):
                    return True

        return False

    def is_operation_allowed(self, operation: AllowedOperation) -> bool:
        """Check if an operation type is allowed."""
        return operation in self.allowed_operations

    @staticmethod
    def _ip_in_cidr(ip: str, cidr: str) -> bool:
        """
        Check if an IP is within a CIDR range.

        This is a simplified implementation. For production use,
        consider using the ipaddress module.
        """
        try:
            import ipaddress
            network = ipaddress.ip_network(cidr, strict=False)
            return ipaddress.ip_address(ip) in network
        except (ValueError, ImportError):
            return False

    def add_target(self, value: str, target_type: TargetType, description: Optional[str] = None) -> None:
        """Add a target to the scope."""
        self.targets.append(TargetSpec(
            value=value,
            type=target_type,
            description=description,
        ))

    def add_operation(self, operation: AllowedOperation) -> None:
        """Add an allowed operation."""
        if operation not in self.allowed_operations:
            self.allowed_operations.append(operation)
