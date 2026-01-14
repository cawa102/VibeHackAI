"""
Scope schema for PentestAgent.

Defines the allowed target range and operations for a pentest session.
"""

from __future__ import annotations

import re
from datetime import datetime
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field, validator

from .base import BaseSchema


class ProofOfAccessPolicy(BaseModel):
    """
    Proof-of-Access Policy for exploitation verification.

    Defines limits and constraints for file read operations
    during exploitation to verify access without excessive data exposure.
    """

    allow_file_read: bool = Field(
        default=True,
        description="Whether file read operations are allowed for proof of access",
    )
    max_bytes: int = Field(
        default=4096,
        ge=0,
        description="Maximum bytes that can be read per file (0 = unlimited)",
    )
    max_files: int = Field(
        default=5,
        ge=0,
        description="Maximum number of files that can be read (0 = unlimited)",
    )
    max_total_bytes: int = Field(
        default=20480,
        ge=0,
        description="Maximum total bytes across all file reads (0 = unlimited)",
    )
    disallow_paths_regex: List[str] = Field(
        default_factory=lambda: [
            r"^/etc/shadow$",
            r"^/etc/passwd$",
            r".*\.pem$",
            r".*\.key$",
            r".*id_rsa.*",
            r".*\.env$",
            r".*credentials.*",
            r".*secret.*",
            r".*password.*",
            r".*/\.ssh/.*",
            r".*/\.aws/.*",
            r".*/\.kube/.*",
        ],
        description="Regex patterns for disallowed file paths",
    )
    allowed_extensions: List[str] = Field(
        default_factory=lambda: [
            ".txt", ".log", ".conf", ".cfg", ".ini", ".json", ".xml", ".yaml", ".yml",
        ],
        description="Allowed file extensions (empty = all allowed)",
    )
    prefer_canary_files: List[str] = Field(
        default_factory=lambda: [
            "/etc/hostname",
            "/etc/os-release",
            "/proc/version",
            "C:\\Windows\\System32\\license.rtf",
        ],
        description="Preferred canary files for proof of access",
    )
    require_hash_verification: bool = Field(
        default=True,
        description="Require hash of read content for evidence",
    )

    def is_path_allowed(self, path: str) -> bool:
        """
        Check if a file path is allowed by the policy.

        Args:
            path: File path to check.

        Returns:
            True if path is allowed, False otherwise.
        """
        # Check disallowed patterns
        for pattern in self.disallow_paths_regex:
            try:
                if re.match(pattern, path, re.IGNORECASE):
                    return False
            except re.error:
                continue

        # Check allowed extensions if specified
        if self.allowed_extensions:
            ext = "." + path.split(".")[-1].lower() if "." in path else ""
            if ext and ext not in self.allowed_extensions:
                return False

        return True

    def get_preferred_canary(self, os_type: str = "linux") -> str:
        """Get preferred canary file for OS type."""
        if os_type.lower() == "windows":
            return next(
                (f for f in self.prefer_canary_files if "Windows" in f),
                self.prefer_canary_files[0] if self.prefer_canary_files else "/etc/hostname"
            )
        return self.prefer_canary_files[0] if self.prefer_canary_files else "/etc/hostname"

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "allow_file_read": self.allow_file_read,
            "max_bytes": self.max_bytes,
            "max_files": self.max_files,
            "max_total_bytes": self.max_total_bytes,
            "disallow_paths_regex": self.disallow_paths_regex,
            "allowed_extensions": self.allowed_extensions,
            "prefer_canary_files": self.prefer_canary_files,
            "require_hash_verification": self.require_hash_verification,
        }


class ProofOfAccessTracker(BaseModel):
    """
    Tracks proof-of-access operations against policy limits.

    Used by Exploitation Agent to enforce policy compliance.
    """

    policy: ProofOfAccessPolicy = Field(
        default_factory=ProofOfAccessPolicy,
        description="The policy being enforced",
    )
    files_read: int = Field(default=0, description="Number of files read")
    total_bytes_read: int = Field(default=0, description="Total bytes read")
    read_history: List[dict] = Field(
        default_factory=list,
        description="History of file read operations",
    )

    def can_read_file(self, path: str, estimated_size: int = 0) -> tuple[bool, str]:
        """
        Check if a file can be read under policy constraints.

        Args:
            path: File path to read.
            estimated_size: Estimated file size in bytes.

        Returns:
            Tuple of (allowed, reason).
        """
        if not self.policy.allow_file_read:
            return False, "File read not allowed by policy"

        if not self.policy.is_path_allowed(path):
            return False, f"Path not allowed by policy: {path}"

        if self.policy.max_files > 0 and self.files_read >= self.policy.max_files:
            return False, f"Max files limit reached: {self.policy.max_files}"

        if self.policy.max_total_bytes > 0:
            if self.total_bytes_read >= self.policy.max_total_bytes:
                return False, f"Max total bytes limit reached: {self.policy.max_total_bytes}"

        return True, "OK"

    def record_read(self, path: str, bytes_read: int, content_hash: str) -> None:
        """Record a file read operation."""
        self.files_read += 1
        self.total_bytes_read += bytes_read
        self.read_history.append({
            "path": path,
            "bytes": bytes_read,
            "hash": content_hash,
            "timestamp": datetime.utcnow().isoformat() + "Z",
        })

    def get_remaining_quota(self) -> dict:
        """Get remaining quota under policy."""
        return {
            "files_remaining": max(0, self.policy.max_files - self.files_read) if self.policy.max_files > 0 else -1,
            "bytes_remaining": max(0, self.policy.max_total_bytes - self.total_bytes_read) if self.policy.max_total_bytes > 0 else -1,
        }


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
    proof_of_access_policy: ProofOfAccessPolicy = Field(
        default_factory=ProofOfAccessPolicy,
        description="Policy for proof-of-access file read operations",
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
