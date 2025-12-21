"""
Vulnerability Candidate schema for PentestAgent.

Defines potential vulnerabilities identified during assessment.
"""

from __future__ import annotations

from enum import Enum
from typing import List, Optional, Dict, Any

from pydantic import Field, validator

from .base import BaseSchema


class Severity(str, Enum):
    """Vulnerability severity levels (based on CVSS)."""
    CRITICAL = "critical"  # CVSS 9.0-10.0
    HIGH = "high"          # CVSS 7.0-8.9
    MEDIUM = "medium"      # CVSS 4.0-6.9
    LOW = "low"            # CVSS 0.1-3.9
    INFO = "info"          # Informational
    UNKNOWN = "unknown"


class ConfidenceLevel(str, Enum):
    """Confidence level in the vulnerability assessment."""
    CONFIRMED = "confirmed"  # Verified through exploitation
    HIGH = "high"            # Strong indicators
    MEDIUM = "medium"        # Moderate indicators
    LOW = "low"              # Weak indicators
    TENTATIVE = "tentative"  # Unverified hypothesis


class VulnCandidate(BaseSchema):
    """
    A potential vulnerability identified during assessment.

    Represents a vulnerability that has been identified but may not
    yet be confirmed through exploitation.
    """

    title: str = Field(
        ...,
        description="Short title describing the vulnerability",
    )
    description: str = Field(
        ...,
        description="Detailed description of the vulnerability",
    )
    cve_id: Optional[str] = Field(
        None,
        description="CVE identifier if known (e.g., CVE-2021-44228)",
    )
    cwe_id: Optional[str] = Field(
        None,
        description="CWE identifier if known (e.g., CWE-79)",
    )
    severity: Severity = Field(
        default=Severity.UNKNOWN,
        description="Severity level",
    )
    cvss_score: Optional[float] = Field(
        None,
        ge=0.0,
        le=10.0,
        description="CVSS score (0.0-10.0)",
    )
    cvss_vector: Optional[str] = Field(
        None,
        description="CVSS vector string",
    )
    confidence: ConfidenceLevel = Field(
        default=ConfidenceLevel.TENTATIVE,
        description="Confidence level in this assessment",
    )
    affected_component: str = Field(
        ...,
        description="Component affected (host:port, URL, service, etc.)",
    )
    affected_versions: List[str] = Field(
        default_factory=list,
        description="Affected version ranges",
    )
    evidence_ids: List[str] = Field(
        default_factory=list,
        description="Evidence IDs supporting this vulnerability",
    )
    prerequisites: List[str] = Field(
        default_factory=list,
        description="Prerequisites for exploitation",
    )
    impact: Optional[str] = Field(
        None,
        description="Potential impact if exploited",
    )
    remediation: Optional[str] = Field(
        None,
        description="Recommended remediation steps",
    )
    references: List[str] = Field(
        default_factory=list,
        description="Reference URLs (advisories, PoCs, etc.)",
    )
    source: str = Field(
        ...,
        description="Source of the vulnerability info (snyk, cve-research, manual, etc.)",
    )
    false_positive: bool = Field(
        default=False,
        description="Marked as false positive",
    )
    false_positive_reason: Optional[str] = Field(
        None,
        description="Reason for false positive marking",
    )
    tags: List[str] = Field(
        default_factory=list,
        description="Tags for categorization",
    )
    raw_data: Dict[str, Any] = Field(
        default_factory=dict,
        description="Raw data from the source tool",
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional metadata",
    )

    @validator("title")
    def validate_title(cls, v: str) -> str:
        """Validate title is not empty."""
        if not v or not v.strip():
            raise ValueError("title cannot be empty")
        return v.strip()

    @validator("cve_id")
    def validate_cve_id(cls, v: Optional[str]) -> Optional[str]:
        """Validate CVE ID format if provided."""
        if v is None:
            return None
        v = v.strip().upper()
        if not v.startswith("CVE-"):
            raise ValueError("cve_id must start with 'CVE-'")
        return v

    def is_high_severity(self) -> bool:
        """Check if vulnerability is high or critical severity."""
        return self.severity in (Severity.HIGH, Severity.CRITICAL)

    def has_sufficient_evidence(self) -> bool:
        """Check if there's at least one evidence item."""
        return len(self.evidence_ids) > 0

    def mark_false_positive(self, reason: str) -> None:
        """Mark this vulnerability as a false positive."""
        self.false_positive = True
        self.false_positive_reason = reason

    def add_evidence(self, evidence_id: str) -> None:
        """Add an evidence ID."""
        if evidence_id not in self.evidence_ids:
            self.evidence_ids.append(evidence_id)

    def add_reference(self, url: str) -> None:
        """Add a reference URL."""
        if url not in self.references:
            self.references.append(url)
