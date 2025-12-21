"""
Finding Candidate schema for PentestAgent.

Defines potential findings that may be included in the final report.
"""

from __future__ import annotations

from enum import Enum
from typing import List, Optional

from pydantic import Field, validator, root_validator

from .base import BaseSchema


class FindingSeverity(str, Enum):
    """Severity levels for findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingCandidate(BaseSchema):
    """
    A potential finding for the pentest report.

    Findings must be backed by evidence. High/critical severity
    findings require at least 2 pieces of evidence.
    """

    title: str = Field(
        ...,
        description="Short, descriptive title",
    )
    severity: FindingSeverity = Field(
        ...,
        description="Severity level",
    )
    description: str = Field(
        ...,
        description="Detailed description of the finding",
    )
    impact: str = Field(
        ...,
        description="Business/security impact of the finding",
    )
    affected_component: str = Field(
        ...,
        description="Affected component (host, URL, service, etc.)",
    )
    reproduction_steps: List[str] = Field(
        default_factory=list,
        description="Step-by-step reproduction instructions",
    )
    evidence_ids: List[str] = Field(
        default_factory=list,
        description="Evidence IDs supporting this finding",
    )
    vuln_candidate_id: Optional[str] = Field(
        None,
        description="Associated vulnerability candidate ID",
    )
    exploit_candidate_id: Optional[str] = Field(
        None,
        description="Associated exploit candidate ID",
    )
    execution_result_ids: List[str] = Field(
        default_factory=list,
        description="Associated execution result IDs",
    )
    cve_id: Optional[str] = Field(
        None,
        description="CVE identifier if applicable",
    )
    cvss_score: Optional[float] = Field(
        None,
        ge=0.0,
        le=10.0,
        description="CVSS score",
    )
    remediation: str = Field(
        ...,
        description="Recommended remediation steps",
    )
    references: List[str] = Field(
        default_factory=list,
        description="Reference URLs",
    )
    promoted: bool = Field(
        default=False,
        description="Whether this has been promoted to final finding",
    )
    promoted_by: Optional[str] = Field(
        None,
        description="Who promoted this finding",
    )
    promoted_at: Optional[str] = Field(
        None,
        description="When this was promoted",
    )
    rejected: bool = Field(
        default=False,
        description="Whether this has been rejected",
    )
    rejection_reason: Optional[str] = Field(
        None,
        description="Reason for rejection",
    )
    tags: List[str] = Field(
        default_factory=list,
        description="Tags for categorization",
    )
    notes: Optional[str] = Field(
        None,
        description="Additional notes",
    )

    @validator("title")
    def validate_title(cls, v: str) -> str:
        """Validate title is not empty."""
        if not v or not v.strip():
            raise ValueError("title cannot be empty")
        return v.strip()

    @validator("description")
    def validate_description(cls, v: str) -> str:
        """Validate description is not empty."""
        if not v or not v.strip():
            raise ValueError("description cannot be empty")
        return v.strip()

    @validator("impact")
    def validate_impact(cls, v: str) -> str:
        """Validate impact is not empty."""
        if not v or not v.strip():
            raise ValueError("impact cannot be empty")
        return v.strip()

    @validator("remediation")
    def validate_remediation(cls, v: str) -> str:
        """Validate remediation is not empty."""
        if not v or not v.strip():
            raise ValueError("remediation cannot be empty")
        return v.strip()

    @root_validator
    def validate_evidence_for_severity(cls, values):
        """
        Validate that high/critical findings have sufficient evidence.

        High and critical severity findings require at least 2 evidence items.
        """
        severity = values.get("severity")
        evidence_ids = values.get("evidence_ids", [])
        if severity in (FindingSeverity.HIGH, FindingSeverity.CRITICAL):
            if len(evidence_ids) < 2:
                raise ValueError(
                    f"{severity.value} severity findings require at least "
                    f"2 evidence items, got {len(evidence_ids)}"
                )
        return values

    def is_high_severity(self) -> bool:
        """Check if finding is high or critical severity."""
        return self.severity in (FindingSeverity.HIGH, FindingSeverity.CRITICAL)

    def can_be_promoted(self) -> bool:
        """Check if this finding can be promoted."""
        if self.promoted or self.rejected:
            return False

        # Check evidence requirements
        if self.is_high_severity() and len(self.evidence_ids) < 2:
            return False

        if len(self.evidence_ids) < 1:
            return False

        return True

    def promote(self, promoted_by: str) -> None:
        """Promote this finding to final status."""
        if not self.can_be_promoted():
            raise ValueError("Finding cannot be promoted - check evidence requirements")

        from datetime import datetime
        self.promoted = True
        self.promoted_by = promoted_by
        self.promoted_at = datetime.utcnow().isoformat() + "Z"

    def reject(self, reason: str) -> None:
        """Reject this finding."""
        self.rejected = True
        self.rejection_reason = reason

    def add_evidence(self, evidence_id: str) -> None:
        """Add an evidence ID."""
        if evidence_id not in self.evidence_ids:
            self.evidence_ids.append(evidence_id)

    def add_reproduction_step(self, step: str) -> None:
        """Add a reproduction step."""
        self.reproduction_steps.append(step)

    def add_reference(self, url: str) -> None:
        """Add a reference URL."""
        if url not in self.references:
            self.references.append(url)
